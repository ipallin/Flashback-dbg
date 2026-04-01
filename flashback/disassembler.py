"""
Phase 1: Disassembly and CFG Construction.

Responsibilities:
  - Parse ELF binary structure (pyelftools)
  - Resolve PLT stubs to symbol names
  - Disassemble code sections with capstone
  - Identify function boundaries (symbol table + heuristics)
  - Build basic blocks (leader algorithm)
  - Build CFG edges (control-flow analysis of terminators)
"""

from __future__ import annotations

import logging
import struct
from collections import defaultdict
from typing import Iterator

import capstone
from capstone import x86 as cs_x86
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.dynamic import DynamicSegment

from .models import (
    BasicBlock, CFGEdge, EnrichedCFG, Function,
    Instruction, PLTEntry, INDIRECT_SENTINEL, RETURN_SENTINEL,
)

log = logging.getLogger(__name__)

# ── x86-64 branch mnemonics ───────────────────────────────────────────────────

# All conditional jump mnemonics capstone emits
COND_JUMPS = frozenset({
    "je",  "jz",  "jne", "jnz", "jl",  "jnge","jle", "jng",
    "jg",  "jnle","jge", "jnl", "jb",  "jnae","jc",  "jbe",
    "jna", "ja",  "jnbe","jae", "jnb", "jnc", "js",  "jns",
    "jo",  "jno", "jp",  "jpe", "jnp", "jpo", "jrcxz","jecxz",
    "jcxz","loop","loope","loopz","loopne","loopnz",
})

# Unconditional transfers that end a block
UNCOND_JUMPS = frozenset({"jmp", "jmpq"})

# Instructions that terminate a basic block (but may have fallthrough)
CALL_MNEMONICS = frozenset({"call", "callq"})

# Instructions that definitively terminate a block with no fallthrough
HARD_TERMINATORS = frozenset({"ret", "retq", "retn", "hlt", "ud2", "int3",
                               "int1", "into"})


class Disassembler:
    """
    Parses an ELF x86-64 binary and returns an EnrichedCFG
    (partially enriched — PLT resolved, basic blocks built, edges built).
    Semantic enrichment is left to enricher.py.
    """

    def __init__(self, binary_path: str, verbose: bool = False) -> None:
        self.binary_path = binary_path
        self.verbose = verbose
        self._cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._cs.detail = True
        self._cs.syntax = capstone.CS_OPT_SYNTAX_ATT  # AT&T / Intel both work; keep Intel
        self._cs.syntax = capstone.CS_OPT_SYNTAX_DEFAULT  # Intel syntax

    # ─────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────────────────────────────────

    def disassemble(self) -> EnrichedCFG:
        """Full pipeline: parse ELF → resolve PLT → disassemble → build CFG."""
        with open(self.binary_path, "rb") as f:
            elf = ELFFile(f)

            is_pie   = elf.header.e_type == "ET_DYN"
            entry_pt = elf.header.e_entry

            log.info("ELF type=%s  PIE=%s  entry=0x%x",
                     elf.header.e_type, is_pie, entry_pt)

            # ── 1. Collect all code bytes ────────────────────────────────────
            code_regions = self._collect_code_regions(elf)
            if not code_regions:
                raise ValueError("No executable sections found in binary.")

            # ── 2. Resolve PLT entries ───────────────────────────────────────
            plt_entries = self._resolve_plt(elf, is_pie)
            log.info("Resolved %d PLT entries", len(plt_entries))

            # ── 3. Identify function boundaries ──────────────────────────────
            func_starts = self._find_function_starts(elf, code_regions, entry_pt)
            log.info("Found %d function candidates", len(func_starts))

            # ── 4. Disassemble and build per-function CFGs ───────────────────
            functions: list[Function] = []
            for (start, end, name) in func_starts:
                func = self._build_function(start, end, name,
                                            code_regions, plt_entries)
                if func:
                    functions.append(func)

        cfg = EnrichedCFG(
            binary_path=self.binary_path,
            functions=functions,
            plt_entries=plt_entries,
            arch="x86_64",
            is_pie=is_pie,
            entry_point=entry_pt,
        )
        return cfg

    # ─────────────────────────────────────────────────────────────────────────
    # ELF helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _collect_code_regions(
        self, elf: ELFFile
    ) -> dict[int, tuple[int, bytes]]:
        """
        Return {start_addr: (end_addr, bytes)} for all EXEC sections.
        Prefers .text but includes any SHF_EXECINSTR section.
        """
        regions: dict[int, tuple[int, bytes]] = {}
        for sec in elf.iter_sections():
            if sec["sh_flags"] & 0x4 and sec["sh_size"] > 0:  # SHF_EXECINSTR
                start = sec["sh_addr"]
                data  = sec.data()
                end   = start + len(data)
                regions[start] = (end, data)
                log.debug("  Code region: %s  0x%x–0x%x  (%d bytes)",
                          sec.name, start, end, len(data))
        return regions

    def _resolve_plt(
        self, elf: ELFFile, is_pie: bool
    ) -> dict[int, PLTEntry]:
        """
        Build a map {plt_stub_addr: PLTEntry} by correlating .plt, .rela.plt
        and .dynsym sections.
        """
        entries: dict[int, PLTEntry] = {}

        plt_sec   = elf.get_section_by_name(".plt")
        plt_sec2  = elf.get_section_by_name(".plt.sec")  # IBT/CET binaries
        rela_plt  = elf.get_section_by_name(".rela.plt")
        dynsym    = elf.get_section_by_name(".dynsym")

        if not dynsym:
            log.warning(".dynsym section not found; no PLT resolution possible")
            return entries

        # Build symbol index → name lookup
        sym_names: dict[int, str] = {
            i: sym.name for i, sym in enumerate(dynsym.iter_symbols())
        }

        # Iterate relocation entries
        if rela_plt:
            relocs = list(rela_plt.iter_relocations())
            # Choose which PLT section to use
            active_plt = plt_sec2 if plt_sec2 else plt_sec
            if active_plt is None:
                log.warning("No .plt section found despite .rela.plt present")
                return entries

            plt_base = active_plt["sh_addr"]
            # For .plt (classic lazy): stub 0 is resolver (16 bytes), stubs start at +16
            # For .plt.sec (IBT): stubs start at base+0
            stub_offset = 0 if plt_sec2 else 16
            stub_size   = 16  # always 16 bytes for x86-64

            for idx, reloc in enumerate(relocs):
                sym_idx  = reloc["r_info_sym"]
                sym_name = sym_names.get(sym_idx, f"unknown_{sym_idx}")
                got_addr = reloc["r_offset"]
                plt_addr = plt_base + stub_offset + idx * stub_size

                entry = PLTEntry(
                    plt_addr=plt_addr,
                    got_addr=got_addr,
                    symbol_name=sym_name,
                    is_pie=is_pie,
                )
                entries[plt_addr] = entry
                log.debug("  PLT: 0x%x → %s  (GOT 0x%x)", plt_addr, sym_name, got_addr)

        # Also handle .rela.dyn for GOT-direct calls (no-plt binaries)
        rela_dyn = elf.get_section_by_name(".rela.dyn")
        if rela_dyn:
            for reloc in rela_dyn.iter_relocations():
                # R_X86_64_GLOB_DAT (6) and R_X86_64_JUMP_SLOT (7)
                r_type = reloc["r_info_type"]
                if r_type not in (6, 7):
                    continue
                sym_idx  = reloc["r_info_sym"]
                sym_name = sym_names.get(sym_idx, "")
                if sym_name and reloc["r_offset"] not in {e.got_addr for e in entries.values()}:
                    # Record as GOT-only (no PLT stub known)
                    pass  # handled at call-site resolution time

        return entries

    def _find_function_starts(
        self,
        elf: ELFFile,
        code_regions: dict[int, tuple[int, bytes]],
        entry_pt: int,
    ) -> list[tuple[int, int, str]]:
        """
        Return sorted list of (start_addr, end_addr, name) for each function.
        Sources: .symtab symbols, .dynsym symbols, entry point.
        """
        # Collect all code address ranges
        region_list = sorted(
            [(s, e) for s, (e, _) in code_regions.items()]
        )

        # Helper: is addr inside any code region?
        def in_code(addr: int) -> bool:
            for (s, e) in region_list:
                if s <= addr < e:
                    return True
            return False

        func_map: dict[int, str] = {}

        # Entry point
        if in_code(entry_pt):
            func_map[entry_pt] = "_start"

        # Symbol tables
        for sec_name in (".symtab", ".dynsym"):
            sym_sec = elf.get_section_by_name(sec_name)
            if not isinstance(sym_sec, SymbolTableSection):
                continue
            for sym in sym_sec.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC":
                    continue
                addr = sym["st_value"]
                size = sym["st_size"]
                if addr == 0 or not in_code(addr):
                    continue
                name = sym.name or f"sub_{addr:#x}"
                if addr not in func_map or sym.name:
                    func_map[addr] = name

        # Build list of (start, end, name)
        starts_sorted = sorted(func_map)
        result: list[tuple[int, int, str]] = []
        for i, start in enumerate(starts_sorted):
            # Determine end: either next function start or end of code region
            if i + 1 < len(starts_sorted):
                end = starts_sorted[i + 1]
            else:
                # Find end of region containing start
                end = start + 0x10000  # fallback
                for (rs, re) in region_list:
                    if rs <= start < re:
                        end = re
                        break

            # Clamp to code region boundary
            for (rs, re) in region_list:
                if rs <= start < re:
                    end = min(end, re)
                    break

            if end > start:
                result.append((start, end, func_map[start]))

        # If we found nothing useful (stripped binary), fall back to entry only
        if not result and in_code(entry_pt):
            for (rs, re) in region_list:
                if rs <= entry_pt < re:
                    result.append((entry_pt, re, "main"))
                    break

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # Per-function CFG construction
    # ─────────────────────────────────────────────────────────────────────────

    def _get_bytes_for_range(
        self,
        start: int,
        end: int,
        code_regions: dict[int, tuple[int, bytes]],
    ) -> bytes:
        for (sec_start, (sec_end, sec_bytes)) in code_regions.items():
            if sec_start <= start and end <= sec_end:
                off_s = start - sec_start
                off_e = end   - sec_start
                return sec_bytes[off_s:off_e]
        return b""

    def _disasm_range(
        self,
        start: int,
        end: int,
        code_regions: dict[int, tuple[int, bytes]],
    ) -> dict[int, Instruction]:
        """
        Linearly disassemble [start, end) and return ordered dict
        {addr: Instruction}.
        """
        raw = self._get_bytes_for_range(start, end, code_regions)
        if not raw:
            return {}

        result: dict[int, Instruction] = {}
        for cs_insn in self._cs.disasm(raw, start):
            instr = Instruction(
                address=cs_insn.address,
                size=cs_insn.size,
                mnemonic=cs_insn.mnemonic,
                op_str=cs_insn.op_str,
                raw_bytes=bytes(cs_insn.bytes),
            )
            result[cs_insn.address] = instr
        return result

    def _build_function(
        self,
        start: int,
        end: int,
        name: str,
        code_regions: dict[int, tuple[int, bytes]],
        plt_entries: dict[int, PLTEntry],
    ) -> Function | None:
        """Disassemble one function and build its CFG."""
        all_instrs = self._disasm_range(start, end, code_regions)
        if not all_instrs:
            log.debug("No instructions for %s at 0x%x", name, start)
            return None

        # ── Identify leaders ──────────────────────────────────────────────────
        leaders: set[int] = {start}
        instr_list = list(all_instrs.values())

        for i, instr in enumerate(instr_list):
            mn = instr.mnemonic.lower()

            if mn in HARD_TERMINATORS:
                # Instruction after a hard terminator is a leader (if exists)
                if i + 1 < len(instr_list):
                    leaders.add(instr_list[i + 1].address)

            elif mn in UNCOND_JUMPS:
                target = self._jump_target(instr, all_instrs)
                if target and start <= target < end:
                    leaders.add(target)
                if i + 1 < len(instr_list):
                    leaders.add(instr_list[i + 1].address)

            elif mn in COND_JUMPS:
                target = self._jump_target(instr, all_instrs)
                if target and start <= target < end:
                    leaders.add(target)
                if i + 1 < len(instr_list):
                    leaders.add(instr_list[i + 1].address)

            elif mn in CALL_MNEMONICS:
                # Instruction after call is always a leader (return site)
                if i + 1 < len(instr_list):
                    leaders.add(instr_list[i + 1].address)

        # ── Build basic blocks ─────────────────────────────────────────────────
        leaders_sorted = sorted(leaders)
        blocks: dict[int, BasicBlock] = {}

        for li, leader in enumerate(leaders_sorted):
            if leader not in all_instrs:
                continue
            next_leader = leaders_sorted[li + 1] if li + 1 < len(leaders_sorted) else end
            block_instrs: list[Instruction] = []
            addr = leader
            while addr < next_leader and addr in all_instrs:
                instr = all_instrs[addr]
                block_instrs.append(instr)
                mn = instr.mnemonic.lower()
                if mn in HARD_TERMINATORS or mn in UNCOND_JUMPS or mn in COND_JUMPS:
                    break
                addr += instr.size

            if block_instrs:
                last = block_instrs[-1]
                bb = BasicBlock(
                    start_addr=leader,
                    end_addr=last.address,
                    instructions=block_instrs,
                )
                if leader == start:
                    bb.is_function_entry = True
                    bb.block_type = "entry"
                blocks[leader] = bb

        # ── Build edges ────────────────────────────────────────────────────────
        edges: list[CFGEdge] = []
        for bb in blocks.values():
            term = bb.terminator
            mn = term.mnemonic.lower()

            if mn in HARD_TERMINATORS:
                if mn in ("ret", "retq", "retn"):
                    edges.append(CFGEdge(bb.start_addr, RETURN_SENTINEL, "ret_edge"))
                # hlt/ud2: no edge

            elif mn in UNCOND_JUMPS:
                target = self._jump_target(term, all_instrs)
                if target is None:
                    edges.append(CFGEdge(bb.start_addr, INDIRECT_SENTINEL, "indirect"))
                elif target in blocks:
                    edges.append(CFGEdge(bb.start_addr, target, "unconditional"))
                elif target in plt_entries or target < start or target >= end:
                    # Tail call to external or other function
                    edges.append(CFGEdge(bb.start_addr, target, "tail_call"))
                else:
                    edges.append(CFGEdge(bb.start_addr, INDIRECT_SENTINEL, "indirect"))

            elif mn in COND_JUMPS:
                target = self._jump_target(term, all_instrs)
                fallthrough = term.address + term.size
                if target and target in blocks:
                    edges.append(CFGEdge(bb.start_addr, target, "true_branch"))
                elif target:
                    edges.append(CFGEdge(bb.start_addr, target, "true_branch"))
                else:
                    edges.append(CFGEdge(bb.start_addr, INDIRECT_SENTINEL, "indirect"))
                if fallthrough in blocks:
                    edges.append(CFGEdge(bb.start_addr, fallthrough, "false_branch"))

            elif mn in CALL_MNEMONICS:
                # Call does NOT create a CFG split for now; just fallthrough
                fallthrough = term.address + term.size
                if fallthrough in blocks:
                    edges.append(CFGEdge(bb.start_addr, fallthrough, "fallthrough"))

            else:
                # Normal fallthrough
                fallthrough = term.address + term.size
                if fallthrough in blocks:
                    edges.append(CFGEdge(bb.start_addr, fallthrough, "fallthrough"))

        func = Function(
            name=name,
            start_addr=start,
            end_addr=end,
            blocks=blocks,
            edges=edges,
        )
        log.debug("Built %s: %d blocks, %d edges", name, len(blocks), len(edges))
        return func

    # ─────────────────────────────────────────────────────────────────────────
    # Utility: extract jump target from a branch instruction
    # ─────────────────────────────────────────────────────────────────────────

    def _jump_target(
        self,
        instr: Instruction,
        all_instrs: dict[int, Instruction],
    ) -> int | None:
        """
        Extract the numeric target address from a jump/branch instruction.
        Returns None for register-indirect jumps.
        """
        op = instr.op_str.strip()

        # Capstone emits immediate targets as hex in Intel syntax: e.g. "0x401234"
        # and register operands like "rax" or memory like "[rax]"
        if not op:
            return None

        # Register operand → indirect
        clean = op.lstrip("*")  # AT&T uses *, Intel doesn't
        if clean.startswith("[") or clean.lower() in _REG64_NAMES:
            return None

        # Try to parse as integer
        try:
            return int(clean, 0)
        except ValueError:
            pass

        # Some capstone versions emit "0x..." with spaces
        try:
            return int(op.split()[0], 0)
        except (ValueError, IndexError):
            pass

        return None


# Register names to detect indirect jumps
_REG64_NAMES = frozenset({
    "rax","rbx","rcx","rdx","rsi","rdi","rsp","rbp",
    "r8","r9","r10","r11","r12","r13","r14","r15","rip",
    "eax","ebx","ecx","edx","esi","edi","esp","ebp",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
})


def disassemble(binary_path: str, verbose: bool = False) -> EnrichedCFG:
    """Convenience function: create Disassembler and run it."""
    d = Disassembler(binary_path, verbose=verbose)
    return d.disassemble()
