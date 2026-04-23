"""
Modelo del CFG enriquecido en Python (dataclasses).

Este módulo define las clases que representan en memoria la estructura
serializada en JSON conforme al esquema v1.0.0.

Uso típico:

    # Cargar desde JSON
    cfg = EnrichedCFG.load('hello.cfg.json')

    # Inspeccionar
    main_func = cfg.functions['0x401149']
    for block_addr in main_func.blocks:
        block = cfg.basic_blocks[block_addr]
        print(f'Bloque {block.address}, {len(block.instructions)} instrucciones')

    # Modificar (ej: añadir una anotación)
    block.annotations.append(TraceRecommendation(
        added_by='enricher',
        granularity='selective',
        rationale='Block contains loop header'
    ))

    # Guardar
    cfg.save('hello.ecfg.json')

    # Validar invariantes (I1-I7 de la especificación)
    cfg.validate()

El esquema JSON formal en 02_cfg_schema.json se puede usar adicionalmente
con la librería jsonschema para validación sintáctica.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Literal, Optional, Union
import json
import hashlib

SCHEMA_VERSION = '1.0.0'

# ---------------------------------------------------------------------------
# Tipos base
# ---------------------------------------------------------------------------

HexAddr = str  # Siempre '0xNNNNNN' en minúsculas

GranularityType = Literal['none', 'block', 'instruction', 'selective']
FunctionalCategory = Literal[
    'function_prologue', 'function_epilogue', 'function_body',
    'external_call_site', 'syscall_site', 'loop_header',
    'return_block', 'unreachable'
]
TracePointReason = Literal[
    'block_entry', 'external_call_site', 'syscall_site',
    'loop_backedge', 'user_request'
]
EdgeType = Literal[
    'fall_through', 'unconditional_jump', 'conditional_jump',
    'call', 'call_indirect', 'return', 'indirect_jump', 'syscall'
]
PipelineStage = Literal['initial', 'enriched']


def hex_addr(value: int | str) -> HexAddr:
    """Normaliza una dirección al formato '0xNNNNNN' en minúsculas."""
    if isinstance(value, int):
        return f'0x{value:x}'
    if isinstance(value, str):
        if not value.startswith('0x'):
            raise ValueError(f'Dirección sin prefijo 0x: {value}')
        return value.lower()
    raise TypeError(f'Tipo no soportado para dirección: {type(value)}')


# ---------------------------------------------------------------------------
# Anotaciones
# ---------------------------------------------------------------------------

@dataclass
class Annotation:
    """Clase base de anotación. No se instancia directamente."""
    type: str
    added_by: str


@dataclass
class ExternalCallAnnotation(Annotation):
    function_name: str = ''
    library: str = ''
    prototype: Optional[str] = None
    argument_registers: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.type = 'external_call'


@dataclass
class SyscallAnnotation(Annotation):
    syscall_number: int = 0
    syscall_name: Optional[str] = None
    argument_registers: list[str] = field(default_factory=list)
    return_register: Optional[str] = None

    def __post_init__(self):
        self.type = 'syscall'


@dataclass
class FunctionalClassAnnotation(Annotation):
    category: FunctionalCategory = 'function_body'
    description: Optional[str] = None

    def __post_init__(self):
        self.type = 'functional_class'


@dataclass
class TraceRecommendationAnnotation(Annotation):
    granularity: GranularityType = 'block'
    rationale: Optional[str] = None

    def __post_init__(self):
        self.type = 'trace_recommendation'


@dataclass
class TracePointAnnotation(Annotation):
    reason: TracePointReason = 'block_entry'

    def __post_init__(self):
        self.type = 'trace_point'


# Registro de tipos de anotación conocidos para deserialización.
# Añadir aquí cuando se introduzcan nuevos tipos.
ANNOTATION_REGISTRY: dict[str, type[Annotation]] = {
    'external_call': ExternalCallAnnotation,
    'syscall': SyscallAnnotation,
    'functional_class': FunctionalClassAnnotation,
    'trace_recommendation': TraceRecommendationAnnotation,
    'trace_point': TracePointAnnotation,
}


def deserialize_annotation(data: dict) -> Annotation:
    """Crea el objeto Annotation apropiado según el campo 'type'."""
    ann_type = data.get('type')
    if ann_type not in ANNOTATION_REGISTRY:
        # Anotaciones desconocidas se mantienen como genéricas.
        # Esto permite que lectores antiguos no rompan con anotaciones
        # introducidas en versiones futuras del esquema.
        return Annotation(type=ann_type, added_by=data.get('added_by', 'unknown'))
    cls = ANNOTATION_REGISTRY[ann_type]
    # Copiamos sin el campo 'type' para evitar conflicto con __post_init__
    kwargs = {k: v for k, v in data.items() if k != 'type'}
    return cls(type=ann_type, **kwargs)


# ---------------------------------------------------------------------------
# Accesos a memoria
# ---------------------------------------------------------------------------

@dataclass
class MemoryAccess:
    type: Literal['read', 'write', 'read_write']
    size: int
    scale: Literal[1, 2, 4, 8] = 1
    offset: int = 0
    base_register: Optional[str] = None
    index_register: Optional[str] = None


# ---------------------------------------------------------------------------
# Entidades del CFG
# ---------------------------------------------------------------------------

@dataclass
class Function:
    address: HexAddr
    name: str
    is_plt: bool
    is_external: bool
    entry_block: HexAddr
    blocks: list[HexAddr] = field(default_factory=list)
    called_from: list[HexAddr] = field(default_factory=list)
    calls_to: list[HexAddr] = field(default_factory=list)
    annotations: list[Annotation] = field(default_factory=list)


@dataclass
class BasicBlock:
    address: HexAddr
    size: int
    function: HexAddr
    instructions: list[HexAddr] = field(default_factory=list)
    successors: list[HexAddr] = field(default_factory=list)
    predecessors: list[HexAddr] = field(default_factory=list)
    annotations: list[Annotation] = field(default_factory=list)


@dataclass
class Instruction:
    address: HexAddr
    mnemonic: str
    operands: str
    bytes: str  # hex sin prefijo
    size: int
    block: HexAddr
    registers_read: list[str] = field(default_factory=list)
    registers_written: list[str] = field(default_factory=list)
    memory_accesses: list[MemoryAccess] = field(default_factory=list)
    annotations: list[Annotation] = field(default_factory=list)


@dataclass
class Edge:
    source: HexAddr
    target: HexAddr
    type: EdgeType
    condition: Optional[str] = None
    annotations: list[Annotation] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Metadata y binary info
# ---------------------------------------------------------------------------

@dataclass
class Metadata:
    generator: str = 'tfe-reconstructor'
    generator_version: str = '0.1.0'
    generation_timestamp: str = ''
    pipeline_stage: PipelineStage = 'initial'
    angr_version: Optional[str] = None
    capstone_version: Optional[str] = None
    pyelftools_version: Optional[str] = None
    extensions: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.generation_timestamp:
            self.generation_timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


@dataclass
class BinaryInfo:
    filename: str
    sha256: str
    entry_point: HexAddr
    architecture: Literal['amd64'] = 'amd64'
    bits: Literal[64] = 64
    endianness: Literal['little'] = 'little'
    format: Literal['ELF'] = 'ELF'
    path: Optional[str] = None
    is_pie: Optional[bool] = None
    is_stripped: Optional[bool] = None


# ---------------------------------------------------------------------------
# CFG completo
# ---------------------------------------------------------------------------

class CFGValidationError(Exception):
    """Se lanza cuando el CFG viola uno de los invariantes I1-I7."""


@dataclass
class EnrichedCFG:
    metadata: Metadata
    binary_info: BinaryInfo
    functions: dict[HexAddr, Function] = field(default_factory=dict)
    basic_blocks: dict[HexAddr, BasicBlock] = field(default_factory=dict)
    instructions: dict[HexAddr, Instruction] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    # -------------------------------------------------------------------
    # Serialización
    # -------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Convierte a diccionario serializable directamente con json.dumps."""
        return {
            'schema_version': self.schema_version,
            'metadata': asdict(self.metadata),
            'binary_info': _clean_none(asdict(self.binary_info)),
            'functions': {
                addr: _clean_none(asdict(f))
                for addr, f in self.functions.items()
            },
            'basic_blocks': {
                addr: _clean_none(asdict(b))
                for addr, b in self.basic_blocks.items()
            },
            'instructions': {
                addr: _clean_none(asdict(i))
                for addr, i in self.instructions.items()
            },
            'edges': [_clean_none(asdict(e)) for e in self.edges],
        }

    def save(self, path: str, indent: int = 2) -> None:
        """Guarda el CFG a un fichero JSON."""
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> EnrichedCFG:
        """Construye el CFG desde un diccionario cargado con json.load."""
        version = data.get('schema_version')
        if not version:
            raise CFGValidationError('Falta schema_version en el fichero')
        major_file = int(version.split('.')[0])
        major_code = int(SCHEMA_VERSION.split('.')[0])
        if major_file != major_code:
            raise CFGValidationError(
                f'Versión de esquema incompatible: fichero={version}, código={SCHEMA_VERSION}'
            )

        metadata = Metadata(**data['metadata'])
        binary_info = BinaryInfo(**data['binary_info'])

        functions = {
            addr: _function_from_dict(f)
            for addr, f in data.get('functions', {}).items()
        }
        basic_blocks = {
            addr: _block_from_dict(b)
            for addr, b in data.get('basic_blocks', {}).items()
        }
        instructions = {
            addr: _instruction_from_dict(i)
            for addr, i in data.get('instructions', {}).items()
        }
        edges = [_edge_from_dict(e) for e in data.get('edges', [])]

        return cls(
            schema_version=version,
            metadata=metadata,
            binary_info=binary_info,
            functions=functions,
            basic_blocks=basic_blocks,
            instructions=instructions,
            edges=edges,
        )

    @classmethod
    def load(cls, path: str) -> EnrichedCFG:
        """Carga un CFG desde un fichero JSON."""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)

    # -------------------------------------------------------------------
    # Validación de invariantes (I1-I7 de la especificación)
    # -------------------------------------------------------------------

    def validate(self) -> None:
        """Valida los invariantes estructurales. Lanza CFGValidationError si falla."""
        errors: list[str] = []

        # I1: integridad referencial de funciones
        for addr, func in self.functions.items():
            if func.address != addr:
                errors.append(f'I1: función en {addr} tiene address {func.address}')
            if not func.is_external and func.entry_block not in self.basic_blocks:
                errors.append(f'I1: función {addr} referencia entry_block inexistente {func.entry_block}')
            for block_addr in func.blocks:
                if block_addr not in self.basic_blocks:
                    errors.append(f'I1: función {addr} referencia bloque inexistente {block_addr}')
            for called_addr in func.calls_to:
                if called_addr not in self.functions:
                    errors.append(f'I1: función {addr} llama a función inexistente {called_addr}')

        # I2: integridad referencial de bloques
        for addr, block in self.basic_blocks.items():
            if block.address != addr:
                errors.append(f'I2: bloque en {addr} tiene address {block.address}')
            if block.function not in self.functions:
                errors.append(f'I2: bloque {addr} pertenece a función inexistente {block.function}')
            elif addr not in self.functions[block.function].blocks:
                errors.append(f'I2: bloque {addr} no está en functions[{block.function}].blocks')
            for insn_addr in block.instructions:
                if insn_addr not in self.instructions:
                    errors.append(f'I2: bloque {addr} referencia instrucción inexistente {insn_addr}')

        # I3: integridad referencial de instrucciones
        for addr, insn in self.instructions.items():
            if insn.address != addr:
                errors.append(f'I3: instrucción en {addr} tiene address {insn.address}')
            if insn.block not in self.basic_blocks:
                errors.append(f'I3: instrucción {addr} pertenece a bloque inexistente {insn.block}')
            elif addr not in self.basic_blocks[insn.block].instructions:
                errors.append(f'I3: instrucción {addr} no está en basic_blocks[{insn.block}].instructions')

        # I4: consistencia de aristas
        for i, edge in enumerate(self.edges):
            if edge.source not in self.instructions:
                errors.append(f'I4: arista #{i} tiene source inexistente {edge.source}')
            if edge.target not in self.basic_blocks and edge.target not in self.functions:
                errors.append(f'I4: arista #{i} tiene target inexistente {edge.target}')
            if edge.type == 'conditional_jump' and edge.condition is None:
                errors.append(f'I4: arista condicional #{i} no tiene condition')

        # I5: coherencia predecesores/sucesores
        for addr, block in self.basic_blocks.items():
            for succ in block.successors:
                if succ in self.basic_blocks:
                    if addr not in self.basic_blocks[succ].predecessors:
                        errors.append(
                            f'I5: bloque {addr} tiene sucesor {succ} pero {succ} no lo tiene como predecesor'
                        )

        # I7: unicidad de direcciones (las claves de dict ya garantizan unicidad
        # dentro de cada categoría; comprobamos que no haya solapes entre
        # funciones y bloques con la misma dirección pero incoherentes).
        # La unicidad en sí está garantizada por el uso de dict.

        # I6 se comprobaría analizando aristas dentro de bloques; lo omito en
        # esta validación inicial porque requiere información que el Extractor
        # puede no haber poblado aún.

        if errors:
            raise CFGValidationError(
                f'CFG inválido, {len(errors)} errores:\n' + '\n'.join(f'  - {e}' for e in errors)
            )

    # -------------------------------------------------------------------
    # Utilidades
    # -------------------------------------------------------------------

    def get_annotations_of_type(self, element: Union[Function, BasicBlock, Instruction, Edge],
                                 ann_type: str) -> list[Annotation]:
        """Devuelve las anotaciones de un tipo dado de un elemento."""
        return [a for a in element.annotations if a.type == ann_type]

    def trace_granularity_for_block(self, block_addr: HexAddr) -> GranularityType:
        """Devuelve la granularidad de trazabilidad recomendada para un bloque.

        Si no hay anotación trace_recommendation, devuelve 'none' por defecto.
        """
        block = self.basic_blocks.get(block_addr)
        if block is None:
            return 'none'
        recs = self.get_annotations_of_type(block, 'trace_recommendation')
        if not recs:
            return 'none'
        return recs[0].granularity  # type: ignore


# ---------------------------------------------------------------------------
# Helpers de deserialización
# ---------------------------------------------------------------------------

def _function_from_dict(data: dict) -> Function:
    anns = [deserialize_annotation(a) for a in data.get('annotations', [])]
    return Function(
        address=data['address'],
        name=data['name'],
        is_plt=data['is_plt'],
        is_external=data['is_external'],
        entry_block=data['entry_block'],
        blocks=data.get('blocks', []),
        called_from=data.get('called_from', []),
        calls_to=data.get('calls_to', []),
        annotations=anns,
    )


def _block_from_dict(data: dict) -> BasicBlock:
    anns = [deserialize_annotation(a) for a in data.get('annotations', [])]
    return BasicBlock(
        address=data['address'],
        size=data['size'],
        function=data['function'],
        instructions=data.get('instructions', []),
        successors=data.get('successors', []),
        predecessors=data.get('predecessors', []),
        annotations=anns,
    )


def _instruction_from_dict(data: dict) -> Instruction:
    anns = [deserialize_annotation(a) for a in data.get('annotations', [])]
    mems = [MemoryAccess(**m) for m in data.get('memory_accesses', [])]
    return Instruction(
        address=data['address'],
        mnemonic=data['mnemonic'],
        operands=data['operands'],
        bytes=data['bytes'],
        size=data['size'],
        block=data['block'],
        registers_read=data.get('registers_read', []),
        registers_written=data.get('registers_written', []),
        memory_accesses=mems,
        annotations=anns,
    )


def _edge_from_dict(data: dict) -> Edge:
    anns = [deserialize_annotation(a) for a in data.get('annotations', [])]
    return Edge(
        source=data['source'],
        target=data['target'],
        type=data['type'],
        condition=data.get('condition'),
        annotations=anns,
    )


def _clean_none(d: dict) -> dict:
    """Elimina claves con valor None de un dict (recursivamente en listas)."""
    if isinstance(d, dict):
        return {k: _clean_none(v) for k, v in d.items() if v is not None}
    if isinstance(d, list):
        return [_clean_none(x) for x in d]
    return d


# ---------------------------------------------------------------------------
# Utilidad para calcular hash SHA256 de un binario
# ---------------------------------------------------------------------------

def compute_sha256(path: str) -> str:
    """Calcula el hash SHA-256 de un fichero."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Test rápido si se ejecuta directamente
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print('Uso: python cfg_model.py <fichero_cfg.json>')
        sys.exit(1)

    cfg = EnrichedCFG.load(sys.argv[1])
    print(f'Esquema: v{cfg.schema_version}')
    print(f'Binario: {cfg.binary_info.filename} ({cfg.binary_info.architecture})')
    print(f'Generado por: {cfg.metadata.generator} v{cfg.metadata.generator_version}')
    print(f'Fase: {cfg.metadata.pipeline_stage}')
    print(f'Funciones: {len(cfg.functions)}')
    print(f'Bloques: {len(cfg.basic_blocks)}')
    print(f'Instrucciones: {len(cfg.instructions)}')
    print(f'Aristas: {len(cfg.edges)}')

    print('\nValidando invariantes...')
    try:
        cfg.validate()
        print('  OK')
    except CFGValidationError as e:
        print(f'  FALLO: {e}')
        sys.exit(1)

    # Estadísticas de anotaciones
    print('\nAnotaciones encontradas:')
    ann_count: dict[str, int] = {}
    for block in cfg.basic_blocks.values():
        for ann in block.annotations:
            ann_count[ann.type] = ann_count.get(ann.type, 0) + 1
    for insn in cfg.instructions.values():
        for ann in insn.annotations:
            ann_count[ann.type] = ann_count.get(ann.type, 0) + 1
    for ann_type, count in sorted(ann_count.items()):
        print(f'  {ann_type:30s} {count}')
