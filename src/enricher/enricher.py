"""
Enricher: añade anotaciones semánticas al CFG inicial.

Responsabilidades:
- Clasificar funcionalmente cada bloque básico (functional_class).
- Identificar llamadas externas y añadir prototipos (external_call).
- Detectar syscalls directas (syscall).
- Calcular y añadir recomendaciones de trazabilidad (trace_recommendation).
- Marcar los trace_points concretos según la granularidad elegida.

Lo que NO hace el Enricher:
- Leer ni escribir JSON (eso es Persistence).
- Generar código C (eso es el Translator).
- Recuperar el CFG del binario (eso es el Extractor).
"""

from __future__ import annotations

import logging
from copy import deepcopy

from src.cfg.model import (
    EnrichedCFG,
    BasicBlock,
    Function,
    FunctionalClassAnnotation,
    ExternalCallAnnotation,
    SyscallAnnotation,
    TraceRecommendationAnnotation,
    TracePointAnnotation,
    GranularityType,
)

logger = logging.getLogger(__name__)

# Tabla de prototipos de funciones de libc más comunes.
# Se amplía progresivamente durante la implementación.
_LIBC_PROTOTYPES: dict[str, dict] = {
    'printf':   {'proto': 'int printf(const char *format, ...)',           'args': ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']},  # noqa: E501
    'scanf':    {'proto': 'int scanf(const char *format, ...)',            'args': ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']},  # noqa: E501
    'puts':     {'proto': 'int puts(const char *s)',                       'args': ['rdi']},
    'putchar':  {'proto': 'int putchar(int c)',                            'args': ['rdi']},
    'getchar':  {'proto': 'int getchar(void)',                             'args': []},
    'malloc':   {'proto': 'void *malloc(size_t size)',                     'args': ['rdi']},
    'calloc':   {'proto': 'void *calloc(size_t nmemb, size_t size)',       'args': ['rdi', 'rsi']},
    'realloc':  {'proto': 'void *realloc(void *ptr, size_t size)',         'args': ['rdi', 'rsi']},
    'free':     {'proto': 'void free(void *ptr)',                          'args': ['rdi']},
    'memcpy':   {'proto': 'void *memcpy(void *dest, const void *src, size_t n)', 'args': ['rdi', 'rsi', 'rdx']},  # noqa: E501
    'memset':   {'proto': 'void *memset(void *s, int c, size_t n)',        'args': ['rdi', 'rsi', 'rdx']},  # noqa: E501
    'strlen':   {'proto': 'size_t strlen(const char *s)',                  'args': ['rdi']},
    'strcpy':   {'proto': 'char *strcpy(char *dest, const char *src)',     'args': ['rdi', 'rsi']},
    'strncpy':  {'proto': 'char *strncpy(char *dest, const char *src, size_t n)', 'args': ['rdi', 'rsi', 'rdx']},  # noqa: E501
    'strcmp':   {'proto': 'int strcmp(const char *s1, const char *s2)',    'args': ['rdi', 'rsi']},
    'strncmp':  {'proto': 'int strncmp(const char *s1, const char *s2, size_t n)', 'args': ['rdi', 'rsi', 'rdx']},  # noqa: E501
    'open':     {'proto': 'int open(const char *pathname, int flags, ...)', 'args': ['rdi', 'rsi', 'rdx']},  # noqa: E501
    'read':     {'proto': 'ssize_t read(int fd, void *buf, size_t count)', 'args': ['rdi', 'rsi', 'rdx']},  # noqa: E501
    'write':    {'proto': 'ssize_t write(int fd, const void *buf, size_t count)', 'args': ['rdi', 'rsi', 'rdx']},  # noqa: E501
    'close':    {'proto': 'int close(int fd)',                             'args': ['rdi']},
    'exit':     {'proto': 'void exit(int status)',                         'args': ['rdi']},
    'atoi':     {'proto': 'int atoi(const char *nptr)',                    'args': ['rdi']},
    'strtol':   {'proto': 'long strtol(const char *nptr, char **endptr, int base)', 'args': ['rdi', 'rsi', 'rdx']},  # noqa: E501
    'fopen':    {'proto': 'FILE *fopen(const char *pathname, const char *mode)', 'args': ['rdi', 'rsi']},  # noqa: E501
    'fclose':   {'proto': 'int fclose(FILE *stream)',                      'args': ['rdi']},
    'fread':    {'proto': 'size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)', 'args': ['rdi', 'rsi', 'rdx', 'rcx']},  # noqa: E501
    'fwrite':   {'proto': 'size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)', 'args': ['rdi', 'rsi', 'rdx', 'rcx']},  # noqa: E501
    'fprintf':  {'proto': 'int fprintf(FILE *stream, const char *format, ...)', 'args': ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']},  # noqa: E501
    'perror':   {'proto': 'void perror(const char *s)',                    'args': ['rdi']},
}

# Tabla parcial de syscalls de Linux x86-64.
# TODO semana 4: ampliar con tabla completa.
_SYSCALL_TABLE: dict[int, dict] = {
    0:  {'name': 'read',    'args': ['rdi', 'rsi', 'rdx'], 'ret': 'rax'},
    1:  {'name': 'write',   'args': ['rdi', 'rsi', 'rdx'], 'ret': 'rax'},
    2:  {'name': 'open',    'args': ['rdi', 'rsi', 'rdx'], 'ret': 'rax'},
    3:  {'name': 'close',   'args': ['rdi'],                'ret': 'rax'},
    60: {'name': 'exit',    'args': ['rdi'],                'ret': 'rax'},
    231:{'name': 'exit_group', 'args': ['rdi'],             'ret': 'rax'},
}


class Enricher:
    """
    Enriquece un CFG inicial añadiendo anotaciones semánticas.

    Uso:
        enricher = Enricher(granularity='selective')
        enriched_cfg = enricher.enrich(initial_cfg)

    El parámetro granularity controla la política de trazabilidad:
    - 'block': una traza por bloque básico (recomendado para la mayoría de casos).
    - 'instruction': una traza por instrucción (máxima resolución, mayor overhead).
    - 'selective': el Enricher decide según el tipo funcional del bloque.
    - 'none': sin trazabilidad runtime.
    """

    def __init__(self, granularity: GranularityType = 'selective'):
        self.granularity = granularity

    def enrich(self, cfg: EnrichedCFG) -> EnrichedCFG:
        """
        Devuelve un nuevo EnrichedCFG con las anotaciones añadidas.
        No modifica el CFG de entrada.
        """
        logger.info(f'Enriqueciendo CFG (granularidad: {self.granularity})')

        enriched = deepcopy(cfg)
        enriched.metadata.pipeline_stage = 'enriched'

        self._annotate_external_calls(enriched)
        self._annotate_syscalls(enriched)
        self._classify_blocks(enriched)
        self._annotate_trace_recommendations(enriched)
        self._annotate_trace_points(enriched)

        ann_count = sum(
            len(b.annotations) for b in enriched.basic_blocks.values()
        ) + sum(
            len(i.annotations) for i in enriched.instructions.values()
        )
        logger.info(f'Enriquecimiento completado: {ann_count} anotaciones añadidas')
        return enriched

    # ------------------------------------------------------------------
    # Pasos de enriquecimiento
    # ------------------------------------------------------------------

    def _annotate_external_calls(self, cfg: EnrichedCFG) -> None:
        """
        Identifica llamadas a funciones PLT y anota las instrucciones
        call correspondientes con sus prototipos.
        """
        for addr, insn in cfg.instructions.items():
            if insn.mnemonic != 'call':
                continue

            # Resolver el destino de la llamada
            target_addr = _resolve_call_target(insn.operands)
            if target_addr is None:
                continue

            target_func = cfg.functions.get(hex(target_addr))
            if target_func is None or not target_func.is_plt:
                continue

            # Normalizar el nombre (quitar @plt, @@GLIBC, etc.)
            func_name = _normalize_symbol_name(target_func.name)
            proto_info = _LIBC_PROTOTYPES.get(func_name)

            insn.annotations.append(ExternalCallAnnotation(
                added_by='enricher',
                function_name=func_name,
                library='libc.so.6',
                prototype=proto_info['proto'] if proto_info else None,
                argument_registers=proto_info['args'] if proto_info else [],
            ))

    def _annotate_syscalls(self, cfg: EnrichedCFG) -> None:
        """
        Detecta instrucciones syscall y las anota con número y nombre.
        Intenta recuperar el número de la instrucción mov rax, <N> precedente.
        """
        for addr, insn in cfg.instructions.items():
            if insn.mnemonic != 'syscall':
                continue

            syscall_number = _recover_syscall_number(addr, cfg)
            syscall_info = _SYSCALL_TABLE.get(syscall_number) if syscall_number is not None else None

            insn.annotations.append(SyscallAnnotation(
                added_by='enricher',
                syscall_number=syscall_number if syscall_number is not None else -1,
                syscall_name=syscall_info['name'] if syscall_info else 'unknown',
                argument_registers=syscall_info['args'] if syscall_info else [],
                return_register='rax',
            ))

    def _classify_blocks(self, cfg: EnrichedCFG) -> None:
        """
        Clasifica funcionalmente cada bloque básico y añade
        una anotación functional_class.
        """
        for addr, block in cfg.basic_blocks.items():
            category = self._classify_block(block, cfg)
            block.annotations.append(FunctionalClassAnnotation(
                added_by='enricher',
                category=category,
            ))

    def _classify_block(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        """
        Heurística de clasificación funcional de un bloque.
        El orden de evaluación importa: las categorías más específicas
        tienen prioridad sobre las más generales.
        """
        insns = [cfg.instructions[a] for a in block.instructions if a in cfg.instructions]
        if not insns:
            return 'function_body'

        mnemonics = [i.mnemonic for i in insns]

        # Bloques inalcanzables (sin predecesores salvo el de entrada)
        func = cfg.functions.get(block.function)
        if func and block.address != func.entry_block and not block.predecessors:
            return 'unreachable'

        # Llamada externa (contiene call a PLT) — prioridad alta
        for insn in insns:
            if any(a.type == 'external_call' for a in insn.annotations):
                return 'external_call_site'

        # Syscall directa
        if 'syscall' in mnemonics:
            return 'syscall_site'

        # Retorno
        if 'ret' in mnemonics:
            return 'return_block'

        # Cabecera de bucle: tiene un predecesor que es un sucesor propio (back-edge)
        for pred in block.predecessors:
            if pred in block.successors:
                return 'loop_header'

        return 'function_body'

    def _annotate_trace_recommendations(self, cfg: EnrichedCFG) -> None:
        """
        Añade una anotación trace_recommendation a cada bloque
        basándose en su clasificación funcional y la política de granularidad.
        """
        for addr, block in cfg.basic_blocks.items():
            granularity, rationale = self._decide_granularity(block)
            block.annotations.append(TraceRecommendationAnnotation(
                added_by='enricher',
                granularity=granularity,
                rationale=rationale,
            ))

    def _decide_granularity(self, block: BasicBlock) -> tuple[GranularityType, str]:
        """
        Política de granularidad por tipo funcional.

        En modo 'selective', el CFG enriquecido gobierna las decisiones:
        - Prólogos/epílogos: sin traza (ruido sin valor semántico).
        - Bloques inalcanzables: sin traza.
        - Llamadas externas / syscalls: traza fina (por instrucción).
        - Cabeceras de bucle: traza por bloque (para detectar iteraciones).
        - Resto: traza por bloque.

        Esta política es la contribución central del diseño:
        el CFG enriquecido, no el traductor, decide la granularidad.
        """
        if self.granularity != 'selective':
            return self.granularity, f'Global policy: {self.granularity}'

        # Obtener la categoría funcional del bloque
        func_class_anns = [a for a in block.annotations if a.type == 'functional_class']
        category = func_class_anns[0].category if func_class_anns else 'function_body'

        policy: dict[str, tuple[GranularityType, str]] = {
            'function_prologue':  ('none',        'Prologue: no semantic value in tracing'),
            'function_epilogue':  ('none',        'Epilogue: no semantic value in tracing'),
            'unreachable':        ('none',        'Unreachable block'),
            'external_call_site': ('instruction', 'External call: fine-grained trace for call site'),
            'syscall_site':       ('instruction', 'Syscall: fine-grained trace for syscall site'),
            'loop_header':        ('block',       'Loop header: block trace sufficient to count iterations'),
            'return_block':       ('block',       'Return block: block trace for exit point'),
            'function_body':      ('block',       'General body: block-level trace sufficient'),
        }
        return policy.get(category, ('block', 'Default block-level trace'))

    def _annotate_trace_points(self, cfg: EnrichedCFG) -> None:
        """
        Añade anotaciones trace_point a instrucciones concretas
        según la recomendación del bloque.
        """
        for addr, block in cfg.basic_blocks.items():
            rec_anns = [a for a in block.annotations if a.type == 'trace_recommendation']
            if not rec_anns:
                continue
            granularity = rec_anns[0].granularity

            if granularity == 'none':
                continue

            insns = [cfg.instructions[a] for a in block.instructions if a in cfg.instructions]
            if not insns:
                continue

            if granularity == 'block':
                # Una sola traza al inicio del bloque
                insns[0].annotations.append(TracePointAnnotation(
                    added_by='enricher',
                    reason='block_entry',
                ))

            elif granularity == 'instruction':
                # Traza en cada instrucción, con reason diferenciada
                for insn in insns:
                    reason = 'block_entry'
                    if any(a.type == 'external_call' for a in insn.annotations):
                        reason = 'external_call_site'
                    elif insn.mnemonic == 'syscall':
                        reason = 'syscall_site'
                    insn.annotations.append(TracePointAnnotation(
                        added_by='enricher',
                        reason=reason,
                    ))


# ------------------------------------------------------------------
# Utilidades privadas
# ------------------------------------------------------------------

def _resolve_call_target(operands: str) -> int | None:
    """
    Intenta resolver el destino de un call a partir del string de operandos.
    Solo funciona para llamadas directas: 'call 0x401030'.
    Devuelve None para llamadas indirectas.
    """
    operands = operands.strip()
    try:
        if operands.startswith('0x') or operands.startswith('-0x'):
            return int(operands, 16)
        if operands.lstrip('-').isdigit():
            return int(operands)
    except ValueError:
        pass
    return None


def _normalize_symbol_name(name: str) -> str:
    """Quita sufijos de versión y decoraciones de PLT."""
    # Quitar @plt, @GLIBC_2.17, etc.
    for sep in ('@', '@@'):
        if sep in name:
            name = name.split(sep)[0]
    return name.strip()


def _recover_syscall_number(syscall_addr: str, cfg: EnrichedCFG) -> int | None:
    """
    Busca la instrucción mov rax, <N> inmediatamente anterior a la syscall
    en el mismo bloque y recupera el número de syscall.
    Devuelve None si no puede determinarlo.
    """
    # Encontrar el bloque que contiene esta instrucción
    insn = cfg.instructions.get(syscall_addr)
    if insn is None:
        return None

    block = cfg.basic_blocks.get(insn.block)
    if block is None:
        return None

    # Buscar hacia atrás en el bloque
    insn_list = block.instructions
    try:
        idx = insn_list.index(syscall_addr)
    except ValueError:
        return None

    for prev_addr in reversed(insn_list[:idx]):
        prev_insn = cfg.instructions.get(prev_addr)
        if prev_insn is None:
            continue
        if prev_insn.mnemonic == 'mov' and prev_insn.operands.startswith('rax,'):
            # Intentar parsear el valor inmediato
            parts = prev_insn.operands.split(',', 1)
            if len(parts) == 2:
                val_str = parts[1].strip()
                try:
                    return int(val_str, 0)
                except ValueError:
                    return None
        # Si encontramos otra instrucción que escribe rax, paramos
        if 'rax' in prev_insn.registers_written:
            break

    return None
