"""
CFGBuilder: construye el EnrichedCFG a partir de instrucciones ya desensambladas.

Recibe datos crudos producidos por un Disassembler y produce la estructura
de grafos completa (bloques básicos, aristas, funciones) con integridad
referencial garantizada.

La separación Disassembler → CFGBuilder permite que la lógica de construcción
del grafo sea agnóstica de arquitectura: cambia el Disassembler (x86_64, arm64),
no este módulo.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

from flashback.core.models import (
    EnrichedCFG, Function, BasicBlock, Instruction, Edge,
    Metadata, BinaryInfo, hex_addr,
)

logger = logging.getLogger(__name__)


@dataclass
class RawInstruction:
    """Instrucción desensamblada tal como la produce el Disassembler."""
    address: int
    mnemonic: str
    operands: str
    bytes_hex: str
    size: int
    registers_read: list[str] = field(default_factory=list)
    registers_written: list[str] = field(default_factory=list)


@dataclass
class BinaryMeta:
    """Metadatos del binario extraídos por el Disassembler."""
    path: str
    sha256: str
    entry_point: int
    architecture: str = 'amd64'
    is_pie: bool = False
    is_stripped: bool = False
    # addr → name para todas las funciones (incluyendo PLT)
    func_symbols: dict[int, str] = field(default_factory=dict)
    # addr → name solo para funciones PLT (externas)
    plt_symbols: dict[int, str] = field(default_factory=dict)


class CFGBuilder:
    """
    Construye un EnrichedCFG (pipeline_stage='initial') a partir de:
      - Un dict[int, RawInstruction] con todas las instrucciones desensambladas.
      - Un BinaryMeta con metadatos del binario.
      - Versión de la herramienta y versiones de las librerías usadas.
    """

    def __init__(self, tool_version: str = '0.1.0',
                 capstone_version: str = '', lief_version: str = ''):
        self.tool_version = tool_version
        self.capstone_version = capstone_version
        self.lief_version = lief_version

    def build(self, raw_insns: dict[int, RawInstruction], meta: BinaryMeta) -> EnrichedCFG:
        logger.info(f'Construyendo CFG: {len(raw_insns)} instrucciones, '
                    f'{len(meta.func_symbols)} funciones')

        cfg = EnrichedCFG(
            metadata=Metadata(
                generator='flashback',
                generator_version=self.tool_version,
                pipeline_stage='initial',
                capstone_version=self.capstone_version or None,
                lief_version=self.lief_version or None,
            ),
            binary_info=BinaryInfo(
                filename=Path(meta.path).name,
                path=meta.path,
                sha256=meta.sha256,
                entry_point=hex_addr(meta.entry_point),
                is_pie=meta.is_pie,
                is_stripped=meta.is_stripped,
            ),
        )

        # 1. Añadir funciones PLT (externas, sin bloques)
        for plt_addr, plt_name in meta.plt_symbols.items():
            addr_str = hex_addr(plt_addr)
            cfg.functions[addr_str] = Function(
                address=addr_str, name=plt_name,
                is_plt=True, is_external=True,
                entry_block=addr_str,
            )

        # 2. Identificar todos los bloques básicos
        func_starts = set(meta.func_symbols.keys())
        block_starts = _identify_block_starts(raw_insns, func_starts)
        raw_blocks   = _build_raw_blocks(raw_insns, block_starts)

        # 3. Asignar cada bloque a una función
        block_to_func = _assign_blocks_to_functions(raw_blocks, func_starts)

        # 4. Añadir funciones de usuario
        func_blocks: dict[int, list[int]] = {f: [] for f in func_starts}
        for block_addr, func_addr in block_to_func.items():
            if func_addr in func_blocks:
                func_blocks[func_addr].append(block_addr)

        for func_addr, func_name in meta.func_symbols.items():
            addr_str   = hex_addr(func_addr)
            block_list = sorted(func_blocks.get(func_addr, []))
            cfg.functions[addr_str] = Function(
                address=addr_str, name=func_name,
                is_plt=False, is_external=False,
                entry_block=addr_str,
                blocks=[hex_addr(b) for b in block_list],
            )

        # 5. Construir bloques e instrucciones
        for block_start, insn_addrs in raw_blocks.items():
            func_addr = block_to_func.get(block_start)
            if func_addr is None:
                continue

            block_addr_str = hex_addr(block_start)
            func_addr_str  = hex_addr(func_addr)

            for addr in insn_addrs:
                ri = raw_insns[addr]
                cfg.instructions[hex_addr(addr)] = Instruction(
                    address=hex_addr(addr),
                    mnemonic=ri.mnemonic,
                    operands=ri.operands,
                    bytes=ri.bytes_hex,
                    size=ri.size,
                    block=block_addr_str,
                    registers_read=ri.registers_read,
                    registers_written=ri.registers_written,
                )

            successors = _compute_successors(
                raw_insns[insn_addrs[-1]], raw_insns, block_starts,
                meta.plt_symbols, meta.func_symbols,
            )
            total_size = sum(raw_insns[a].size for a in insn_addrs)

            cfg.basic_blocks[block_addr_str] = BasicBlock(
                address=block_addr_str, size=total_size,
                function=func_addr_str,
                instructions=[hex_addr(a) for a in insn_addrs],
                successors=[hex_addr(s) for s in successors],
            )

        # 6. Rellenar predecessors
        for block_addr, block in cfg.basic_blocks.items():
            for succ_addr in block.successors:
                if succ_addr in cfg.basic_blocks:
                    if block_addr not in cfg.basic_blocks[succ_addr].predecessors:
                        cfg.basic_blocks[succ_addr].predecessors.append(block_addr)

        # 7. Construir aristas
        cfg.edges = _build_edges(raw_insns, cfg.basic_blocks, cfg.functions)

        # 8. Rellenar calls_to / called_from entre funciones
        _fill_call_relations(cfg, raw_insns)

        n_funcs  = sum(1 for f in cfg.functions.values() if not f.is_plt)
        n_blocks = len(cfg.basic_blocks)
        n_insns  = len(cfg.instructions)
        logger.info(f'CFG construido: {n_funcs} funciones, {n_blocks} bloques, '
                    f'{n_insns} instrucciones, {len(cfg.edges)} aristas')
        return cfg


# ---------------------------------------------------------------------------
# Algoritmo de construcción de bloques
# ---------------------------------------------------------------------------

_BRANCH_MNEMONICS = frozenset({
    'jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge',
    'jb', 'jbe', 'ja', 'jae', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
    'jrcxz', 'jecxz', 'loop', 'loope', 'loopne',
})
_CALL_MNEMONICS  = frozenset({'call'})
_RET_MNEMONICS   = frozenset({'ret', 'retn', 'retf'})
_TERM_MNEMONICS  = _BRANCH_MNEMONICS | _RET_MNEMONICS | frozenset({'syscall', 'int', 'hlt'})


def _is_terminator(ri: RawInstruction) -> bool:
    return ri.mnemonic in _TERM_MNEMONICS


def _is_conditional_branch(m: str) -> bool:
    return m in _BRANCH_MNEMONICS and m != 'jmp'


def _resolve_direct_addr(operands: str) -> int | None:
    o = operands.strip()
    try:
        if o.startswith('0x') or o.startswith('-0x'):
            return int(o, 16)
        if o.lstrip('-').isdigit():
            return int(o)
    except ValueError:
        pass
    return None


def _identify_block_starts(raw_insns: dict[int, RawInstruction],
                            func_starts: set[int]) -> set[int]:
    """Identifica todas las direcciones que inician un bloque básico."""
    starts = set(func_starts)

    for addr, ri in sorted(raw_insns.items()):
        if ri.mnemonic in _CALL_MNEMONICS:
            # La instrucción siguiente a un call abre un nuevo bloque (return address)
            ret_addr = addr + ri.size
            if ret_addr in raw_insns:
                starts.add(ret_addr)

        elif ri.mnemonic == 'jmp':
            target = _resolve_direct_addr(ri.operands)
            if target and target in raw_insns:
                starts.add(target)
            fall = addr + ri.size
            if fall in raw_insns:
                starts.add(fall)

        elif _is_conditional_branch(ri.mnemonic):
            target = _resolve_direct_addr(ri.operands)
            if target and target in raw_insns:
                starts.add(target)
            fall = addr + ri.size
            if fall in raw_insns:
                starts.add(fall)

        elif ri.mnemonic in _RET_MNEMONICS or ri.mnemonic == 'syscall':
            fall = addr + ri.size
            if fall in raw_insns:
                starts.add(fall)

    return starts


def _build_raw_blocks(raw_insns: dict[int, RawInstruction],
                      block_starts: set[int]) -> dict[int, list[int]]:
    """
    Construye bloques básicos: cada bloque es una lista de direcciones de
    instrucciones en orden. Un bloque termina en un terminador O cuando
    la siguiente instrucción es un block_start conocido.
    """
    sorted_starts = sorted(block_starts)
    starts_set    = set(sorted_starts)
    blocks: dict[int, list[int]] = {}

    for i, start in enumerate(sorted_starts):
        if start not in raw_insns:
            continue
        next_start = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else float('inf')

        insn_list: list[int] = []
        addr = start
        while addr in raw_insns:
            insn_list.append(addr)
            ri = raw_insns[addr]
            if _is_terminator(ri):
                break
            next_addr = addr + ri.size
            # Cortar si la siguiente dirección es un block_start
            if next_addr in starts_set and next_addr != start:
                break
            if next_addr >= next_start:
                break
            addr = next_addr

        if insn_list:
            blocks[start] = insn_list

    return blocks


def _assign_blocks_to_functions(raw_blocks: dict[int, list[int]],
                                  func_starts: set[int]) -> dict[int, int]:
    """
    Asigna cada bloque a la función cuya entrada está más próxima por abajo.
    Heurística válida para código compilado sin CFG obfuscation.
    """
    sorted_funcs = sorted(func_starts)
    assignment: dict[int, int] = {}

    for block_addr in raw_blocks:
        # Función más cercana por abajo
        func = None
        for fs in sorted_funcs:
            if fs <= block_addr:
                func = fs
            else:
                break
        if func is not None:
            assignment[block_addr] = func

    return assignment


def _compute_successors(ri: RawInstruction, raw_insns: dict[int, RawInstruction],
                         block_starts: set[int],
                         plt_symbols: dict[int, str],
                         func_symbols: dict[int, str]) -> list[int]:
    """Calcula los sucesores de un bloque a partir de su última instrucción."""
    m    = ri.mnemonic
    addr = ri.address

    if m in _RET_MNEMONICS:
        return []
    if m == 'syscall':
        fall = addr + ri.size
        return [fall] if fall in raw_insns else []
    if m == 'hlt':
        return []
    if m in _CALL_MNEMONICS:
        # El sucesor es la instrucción siguiente (return address)
        fall = addr + ri.size
        return [fall] if fall in raw_insns else []
    if m == 'jmp':
        target = _resolve_direct_addr(ri.operands)
        if target and target in raw_insns:
            return [target]
        return []  # Salto indirecto no resuelto
    if _is_conditional_branch(m):
        target = _resolve_direct_addr(ri.operands)
        fall   = addr + ri.size
        succs  = []
        if target and target in raw_insns:
            succs.append(target)
        if fall in raw_insns:
            succs.append(fall)
        return succs
    # Fall-through normal
    fall = addr + ri.size
    return [fall] if fall in raw_insns else []


def _build_edges(raw_insns: dict[int, RawInstruction],
                 basic_blocks: dict,
                 functions: dict) -> list[Edge]:
    """Construye la lista de aristas del CFG."""
    edges: list[Edge] = []
    seen: set[tuple] = set()

    for block_addr, block in basic_blocks.items():
        if not block.instructions:
            continue
        last_insn_addr = block.instructions[-1]
        last_insn = raw_insns.get(int(last_insn_addr, 16)) if last_insn_addr.startswith('0x') else None
        if last_insn is None:
            # Buscar por dirección en el CFG
            last_cfg_insn = None
            for a, i in raw_insns.items():
                if hex_addr(a) == last_insn_addr:
                    last_cfg_insn = i
                    break
            if last_cfg_insn is None:
                continue
            last_insn = last_cfg_insn

        m = last_insn.mnemonic

        for succ_addr in block.successors:
            key = (last_insn_addr, succ_addr)
            if key in seen:
                continue
            seen.add(key)

            if m in _RET_MNEMONICS:
                edge_type = 'return'
            elif m == 'syscall':
                edge_type = 'syscall'
            elif m in _CALL_MNEMONICS:
                edge_type = 'call'
            elif m == 'jmp':
                edge_type = 'unconditional_jump'
            elif _is_conditional_branch(m):
                edge_type = 'conditional_jump'
            else:
                edge_type = 'fall_through'

            condition = None
            if edge_type == 'conditional_jump':
                condition = m  # e.g. 'je', 'jne', etc.

            edges.append(Edge(
                source=last_insn_addr,
                target=succ_addr,
                type=edge_type,
                condition=condition,
            ))

    return edges


def _fill_call_relations(cfg: EnrichedCFG, raw_insns: dict[int, RawInstruction]) -> None:
    """Rellena calls_to / called_from entre funciones."""
    for block_addr, block in cfg.basic_blocks.items():
        if not block.instructions:
            continue
        last_addr_str = block.instructions[-1]
        last_insn = next(
            (ri for ri in raw_insns.values() if hex_addr(ri.address) == last_addr_str),
            None,
        )
        if last_insn is None or last_insn.mnemonic not in _CALL_MNEMONICS:
            continue

        target_int = _resolve_direct_addr(last_insn.operands)
        if target_int is None:
            continue

        target_str = hex_addr(target_int)
        caller_str = block.function

        if target_str not in cfg.functions or caller_str not in cfg.functions:
            continue

        caller_func = cfg.functions[caller_str]
        callee_func = cfg.functions[target_str]

        if target_str not in caller_func.calls_to:
            caller_func.calls_to.append(target_str)
        if caller_str not in callee_func.called_from:
            callee_func.called_from.append(caller_str)
