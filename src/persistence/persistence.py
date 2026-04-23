"""
Persistence: serialización y deserialización del CFG enriquecido.

Responsabilidades:
- Guardar EnrichedCFG a fichero JSON conforme al esquema v1.0.0.
- Cargar EnrichedCFG desde fichero JSON.
- Validar contra el JSON Schema antes de cargar.
- Gestionar las rutas de los artefactos del pipeline.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import jsonschema

from src.cfg.model import EnrichedCFG, CFGValidationError

logger = logging.getLogger(__name__)

# Ruta al JSON Schema relativa a este fichero.
# Ajusta si cambias la estructura del proyecto.
_SCHEMA_PATH = Path(__file__).parent.parent.parent / 'schemas' / 'cfg_v1.0.0.json'


class PersistenceError(Exception):
    """Error durante la carga o guardado del CFG."""


class Persistence:
    """
    Gestiona la serialización del CFG a/desde disco.

    Uso:
        p = Persistence()
        p.save(cfg, 'hello.cfg.json')
        cfg = p.load('hello.cfg.json')
    """

    def __init__(self, schema_path: str | None = None):
        self._schema = None
        self._schema_path = Path(schema_path) if schema_path else _SCHEMA_PATH
        self._load_schema()

    def _load_schema(self) -> None:
        """Carga el JSON Schema para validación."""
        if not self._schema_path.exists():
            logger.warning(
                f'JSON Schema no encontrado en {self._schema_path}. '
                f'La validación sintáctica estará desactivada.'
            )
            return
        with open(self._schema_path, encoding='utf-8') as f:
            self._schema = json.load(f)
        logger.debug(f'JSON Schema cargado desde {self._schema_path}')

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def save(self, cfg: EnrichedCFG, path: str, indent: int = 2) -> Path:
        """
        Guarda el CFG a disco en formato JSON.
        Devuelve el Path donde se ha guardado.
        """
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f'Guardando CFG en {output_path}')
        cfg.save(str(output_path), indent=indent)
        logger.info(f'CFG guardado: {output_path.stat().st_size} bytes')
        return output_path

    def load(self, path: str, validate: bool = True) -> EnrichedCFG:
        """
        Carga un CFG desde un fichero JSON.
        Si validate=True, valida contra el JSON Schema y los invariantes.
        """
        input_path = Path(path)
        if not input_path.exists():
            raise PersistenceError(f'Fichero no encontrado: {input_path}')

        logger.info(f'Cargando CFG desde {input_path}')
        with open(input_path, encoding='utf-8') as f:
            data = json.load(f)

        if validate and self._schema:
            self._validate_schema(data, input_path)

        cfg = EnrichedCFG.from_dict(data)

        if validate:
            try:
                cfg.validate()
                logger.debug('Invariantes del CFG verificados')
            except CFGValidationError as e:
                raise PersistenceError(f'CFG inválido en {input_path}: {e}') from e

        logger.info(
            f'CFG cargado: {len(cfg.functions)} funciones, '
            f'{len(cfg.basic_blocks)} bloques, '
            f'{len(cfg.instructions)} instrucciones'
        )
        return cfg

    def artifact_path(self, binary_path: str, stage: str) -> Path:
        """
        Devuelve la ruta convencional del artefacto del pipeline.

        Convención:
            stage='initial'   → hello.cfg.json
            stage='enriched'  → hello.ecfg.json
            stage='c'         → hello.c
        """
        p = Path(binary_path)
        suffixes = {
            'initial':  '.cfg.json',
            'enriched': '.ecfg.json',
            'c':        '.c',
        }
        suffix = suffixes.get(stage, f'.{stage}')
        return p.parent / (p.stem + suffix)

    # ------------------------------------------------------------------
    # Validación
    # ------------------------------------------------------------------

    def _validate_schema(self, data: dict, path: Path) -> None:
        """Valida el JSON contra el JSON Schema."""
        try:
            jsonschema.validate(data, self._schema)
            logger.debug(f'Validación JSON Schema OK: {path}')
        except jsonschema.ValidationError as e:
            raise PersistenceError(
                f'El fichero {path} no cumple el JSON Schema:\n'
                f'  Campo: {list(e.absolute_path)}\n'
                f'  Error: {e.message}'
            ) from e
