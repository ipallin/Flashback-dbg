"""
Extractor: construye el CFG inicial a partir de un binario ELF.

Responsabilidades:
- Cargar el binario con angr.
- Ejecutar CFGFast(normalize=True) para recuperar el CFG.
- Iterar funciones, bloques básicos e instrucciones.
- Serializar el resultado conforme al esquema v1.0.0 (pipeline_stage='initial').

Lo que NO hace el Extractor:
- Añadir anotaciones semánticas (eso es el Enricher).
- Serializar a disco (eso es Persistence).
- Decidir granularidad de trazabilidad (eso es el Enricher).
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import angr

from src.cfg.model import (
    BinaryInfo,
    BasicBlock,
    EnrichedCFG,
    Function,
    Instruction,
    Edge,
    MemoryAccess,
    Metadata,
    hex_addr,
)

logger = logging.getLogger(__name__)

# Funciones del runtime de C que angr detecta pero que no pertenecen
# al código de usuario. El Extractor las incluye igualmente pero las
# marca con is_external=True para que el Traductor las trate correctamente.
_C_RUNTIME_NAMES = frozenset({
    '_start', 'frame_dummy', '_init', '_fini',
    '__libc_csu_init', '__libc_csu_fini',
    'register_tm_clones', 'deregister_tm_clones',
    '__do_global_dtors_aux', '__libc_start_main',
})


class ExtractorError(Exception):
    """Error durante la extracción del CFG."""


class Extractor:
    """
    Extrae el CFG inicial de un binario ELF x86-64.

    Uso:
        extractor = Extractor('binarios_prueba/hello')
        cfg = extractor.extract()
    """

    def __init__(self, binary_path: str, generator_version: str = '0.1.0'):
        self.binary_path = Path(binary_path)
        self.generator_version = generator_version
        self._project: angr.Project | None = None
        self._cfg_analysis = None

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def extract(self) -> EnrichedCFG:
        """
        Punto de entrada principal. Devuelve un EnrichedCFG con
        pipeline_stage='initial' y anotaciones vacías.
        """
        logger.info(f'Extrayendo CFG de {self.binary_path}')

        self._validate_binary()
        self._load_project()
        self._run_cfg_analysis()

        cfg = EnrichedCFG(
            metadata=self._build_metadata(),
            binary_info=self._build_binary_info(),
        )

        self._populate_functions(cfg)
        self._populate_edges(cfg)

        logger.info(
            f'Extracción completada: {len(cfg.functions)} funciones, '
            f'{len(cfg.basic_blocks)} bloques, '
            f'{len(cfg.instructions)} instrucciones, '
            f'{len(cfg.edges)} aristas'
        )
        return cfg

    # ------------------------------------------------------------------
    # Pasos internos
    # ------------------------------------------------------------------

    def _validate_binary(self) -> None:
        """Verifica que el fichero existe y tiene formato ELF x86-64."""
        if not self.binary_path.exists():
            raise ExtractorError(f'Binario no encontrado: {self.binary_path}')
        if not self.binary_path.is_file():
            raise ExtractorError(f'La ruta no es un fichero: {self.binary_path}')

        # Leer los primeros bytes para verificar la magic de ELF
        with open(self.binary_path, 'rb') as f:
            magic = f.read(4)
        if magic != b'\x7fELF':
            raise ExtractorError(
                f'El fichero no tiene formato ELF: {self.binary_path}'
            )
        logger.debug(f'Binario ELF verificado: {self.binary_path}')

    def _load_project(self) -> None:
        """Carga el binario con angr."""
        logger.debug('Cargando proyecto angr...')

        # Silenciar logging de angr durante la carga
        logging.getLogger('angr').setLevel(logging.ERROR)
        logging.getLogger('cle').setLevel(logging.ERROR)
        logging.getLogger('pyvex').setLevel(logging.ERROR)

        self._project = angr.Project(
            str(self.binary_path),
            auto_load_libs=False,  # No cargar libc completa
        )

        arch = self._project.arch.name
        if arch not in ('AMD64', 'amd64', 'x86_64'):
            raise ExtractorError(
                f'Arquitectura no soportada: {arch}. Solo AMD64/x86-64.'
            )
        logger.debug(f'Proyecto cargado. Arquitectura: {arch}')

    def _run_cfg_analysis(self) -> None:
        """Ejecuta CFGFast con normalización."""
        logger.debug('Ejecutando CFGFast(normalize=True)...')
        self._cfg_analysis = self._project.analyses.CFGFast(normalize=True)
        logger.debug(
            f'CFG construido: {len(self._cfg_analysis.functions)} funciones'
        )

    def _build_metadata(self) -> Metadata:
        import angr as _angr
        import capstone as _capstone
        import elftools as _elftools

        return Metadata(
            generator='tfe-reconstructor',
            generator_version=self.generator_version,
            pipeline_stage='initial',
            angr_version=_angr.__version__,
            capstone_version=str(_capstone.__version__),
            pyelftools_version=str(_elftools.__version__),
        )

    def _build_binary_info(self) -> BinaryInfo:
        return BinaryInfo(
            filename=self.binary_path.name,
            path=str(self.binary_path.resolve()),
            sha256=_sha256(self.binary_path),
            entry_point=hex_addr(self._project.entry),
            is_pie=self._project.loader.main_object.pic,
            is_stripped=self._is_stripped(),
        )

    def _is_stripped(self) -> bool:
        """Heurística: si no hay símbolos de función, está stripped."""
        symbols = list(self._project.loader.main_object.symbols)
        func_symbols = [s for s in symbols if s.is_function and s.name]
        return len(func_symbols) == 0

    def _populate_functions(self, cfg: EnrichedCFG) -> None:
        """Rellena functions, basic_blocks e instructions del CFG."""
        for func_addr, func in self._cfg_analysis.functions.items():
            addr_str = hex_addr(func_addr)

            is_external = func.is_plt or func.name in _C_RUNTIME_NAMES

            # Construir bloques e instrucciones de esta función
            block_addrs = []
            for block in func.blocks:
                block_addr_str = hex_addr(block.addr)
                block_addrs.append(block_addr_str)

                insn_addrs = self._populate_instructions(cfg, block, block_addr_str)

                successors = []
                predecessors = []
                for _, dst, _ in func.transition_graph.out_edges(block, data=True):
                    if hasattr(dst, 'addr') and isinstance(dst.addr, int):
                        successors.append(hex_addr(dst.addr))
                for src, _, _ in func.transition_graph.in_edges(block, data=True):
                    if hasattr(src, 'addr') and isinstance(src.addr, int):
                        predecessors.append(hex_addr(src.addr))

                cfg.basic_blocks[block_addr_str] = BasicBlock(
                    address=block_addr_str,
                    size=block.size,
                    function=addr_str,
                    instructions=insn_addrs,
                    successors=successors,
                    predecessors=predecessors,
                    annotations=[],
                )

            # Llamadas externas e internas
            calls_to = []
            for called in func.functions_called():
                if hasattr(called, 'addr') and isinstance(called.addr, int):
                    calls_to.append(hex_addr(called.addr))

            called_from = []
            for caller in func.functions_calling():
                if hasattr(caller, 'addr') and isinstance(caller.addr, int):
                    called_from.append(hex_addr(caller.addr))

            cfg.functions[addr_str] = Function(
                address=addr_str,
                name=func.name or f'sub_{func_addr:x}',
                is_plt=bool(func.is_plt),
                is_external=is_external,
                entry_block=hex_addr(func.addr),
                blocks=block_addrs,
                called_from=called_from,
                calls_to=calls_to,
                annotations=[],
            )

    def _populate_instructions(
        self,
        cfg: EnrichedCFG,
        block,
        block_addr_str: str,
    ) -> list[str]:
        """
        Extrae las instrucciones de un bloque y las añade a cfg.instructions.
        Devuelve la lista de direcciones en orden.
        """
        insn_addrs = []

        for insn in block.capstone.insns:
            addr_str = hex_addr(insn.address)
            insn_addrs.append(addr_str)

            regs_read, regs_written = [], []
            try:
                r, w = insn.regs_access()
                regs_read = [insn.reg_name(r_) for r_ in r]
                regs_written = [insn.reg_name(w_) for w_ in w]
            except Exception:
                pass  # capstone no siempre puede inferir regs_access

            memory_accesses = _extract_memory_accesses(insn)

            cfg.instructions[addr_str] = Instruction(
                address=addr_str,
                mnemonic=insn.mnemonic,
                operands=insn.op_str,
                bytes=insn.bytes.hex(),
                size=insn.size,
                block=block_addr_str,
                registers_read=regs_read,
                registers_written=regs_written,
                memory_accesses=memory_accesses,
                annotations=[],
            )

        return insn_addrs

    def _populate_edges(self, cfg: EnrichedCFG) -> None:
        """Construye la lista de aristas del CFG."""
        seen = set()

        for func_addr, func in self._cfg_analysis.functions.items():
            for src, dst, data in func.transition_graph.edges(data=True):
                if not (hasattr(src, 'addr') and hasattr(dst, 'addr')):
                    continue
                if not (isinstance(src.addr, int) and isinstance(dst.addr, int)):
                    continue

                # Usamos como source la última instrucción del bloque origen
                src_block = cfg.basic_blocks.get(hex_addr(src.addr))
                if src_block is None or not src_block.instructions:
                    continue
                source_insn = src_block.instructions[-1]
                target = hex_addr(dst.addr)

                key = (source_insn, target)
                if key in seen:
                    continue
                seen.add(key)

                edge_type = _map_edge_type(data.get('type', 'fall_through'))

                cfg.edges.append(Edge(
                    source=source_insn,
                    target=target,
                    type=edge_type,
                    condition=None,
                    annotations=[],
                ))


# ------------------------------------------------------------------
# Utilidades privadas
# ------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _map_edge_type(angr_type: str) -> str:
    """Mapea los tipos de arista de angr a los del esquema."""
    mapping = {
        'fall_through': 'fall_through',
        'transition': 'unconditional_jump',
        'call': 'call',
        'fake_ret': 'fall_through',   # arista artificial post-call
        'return': 'return',
        'syscall': 'syscall',
        'Ijk_Call': 'call',
        'Ijk_Ret': 'return',
        'Ijk_Boring': 'unconditional_jump',
        'Ijk_NoDecode': 'unconditional_jump',
    }
    return mapping.get(angr_type, 'unconditional_jump')


def _extract_memory_accesses(insn) -> list[MemoryAccess]:
    """
    Extrae accesos a memoria de una instrucción capstone.
    Solo soporta x86-64 con grupos de memoria explícitos.
    Versión inicial: muy conservadora, no infiere lo que no puede saber.
    """
    # TODO semana 3: implementar análisis de operandos de memoria
    # usando insn.operands cuando insn.id tiene grupos de memoria.
    # Por ahora devolvemos lista vacía para no bloquear el pipeline.
    return []
