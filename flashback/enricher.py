"""
Phase 2: Semantic CFG Enrichment.

Responsibilities:
  - Identify and annotate external library calls (PLT resolution)
  - Resolve syscall numbers to names and signatures
  - Detect loops (back edges via iterative DFS)
  - Classify basic blocks by functional type
  - Collect required C #include headers
"""

from __future__ import annotations

import logging
from typing import Iterator

from .models import (
    BasicBlock, CFGEdge, EnrichedCFG, Function,
    Instruction, INDIRECT_SENTINEL, RETURN_SENTINEL,
)
from .data.syscalls_x64 import resolve_syscall
from .data.libc_signatures import get_signature

log = logging.getLogger(__name__)


class Enricher:
    """Adds semantic annotations to a partially-built EnrichedCFG."""

    def __init__(self, cfg: EnrichedCFG) -> None:
        self.cfg = cfg

    def enrich(self) -> EnrichedCFG:
        """Run all enrichment passes and return the modified CFG."""
        for func in self.cfg.functions:
            if func.is_plt_stub:
                continue
            log.debug("Enriching function %s", func.name)
            self._annotate_extern_calls(func)
            self._annotate_syscalls(func)
            self._detect_loops(func)
            self._classify_blocks(func)

        # Collect required headers from all annotated instructions
        self._collect_headers()

        # Always need these
        self.cfg.required_headers.update({"<stdint.h>", "<stddef.h>"})

        return self.cfg

    # ─────────────────────────────────────────────────────────────────────────
    # Pass 1: Annotate external calls
    # ─────────────────────────────────────────────────────────────────────────

    def _annotate_extern_calls(self, func: Function) -> None:
        """
        For every `call` instruction whose target resolves to a PLT entry,
        annotate it with the extern function name and prototype.
        """
        for bb in func.blocks.values():
            for instr in bb.instructions:
                if instr.mnemonic.lower() not in ("call", "callq"):
                    continue

                target = self._parse_imm_operand(instr.op_str)
                if target is None:
                    continue

                # Direct PLT call
                plt_entry = self.cfg.plt_entries.get(target)
                if plt_entry:
                    instr.ext_call_name = plt_entry.symbol_name
                    sig = get_signature(plt_entry.symbol_name)
                    if sig:
                        instr.ext_call_proto   = sig["proto"]
                        instr.ext_call_headers = list(sig.get("headers", []))
                    else:
                        instr.ext_call_proto   = f"/* unknown prototype: {plt_entry.symbol_name} */"
                        instr.ext_call_headers = []
                    log.debug("  Annotated call to %s at 0x%x",
                              plt_entry.symbol_name, instr.address)

    # ─────────────────────────────────────────────────────────────────────────
    # Pass 2: Annotate syscalls
    # ─────────────────────────────────────────────────────────────────────────

    def _annotate_syscalls(self, func: Function) -> None:
        """
        For every `syscall` instruction, walk backwards in the block to find
        the most recent `mov rax, <imm>` and resolve the syscall number.
        """
        for bb in func.blocks.values():
            instrs = bb.instructions
            for i, instr in enumerate(instrs):
                if instr.mnemonic.lower() != "syscall":
                    continue

                # Look backward for `mov rax, <imm>` or `xor rax, rax`
                syscall_nr: int | None = None
                for j in range(i - 1, -1, -1):
                    prev = instrs[j]
                    mn = prev.mnemonic.lower()
                    ops = prev.op_str.lower().replace(" ", "")

                    if mn == "mov" and ops.startswith("rax,"):
                        # Try to parse the immediate
                        imm_str = prev.op_str.split(",", 1)[1].strip()
                        nr = self._parse_imm_operand(imm_str)
                        if nr is not None:
                            syscall_nr = nr
                            break

                    elif mn == "xor" and ops in ("rax,rax", "eax,eax"):
                        syscall_nr = 0
                        break

                    # Stop backward search at another branch or call
                    elif mn in ("call", "callq", "ret", "retq"):
                        break

                if syscall_nr is not None:
                    info = resolve_syscall(syscall_nr)
                    if info:
                        instr.syscall_name    = info["name"]
                        instr.syscall_args    = info["args"]
                        instr.syscall_headers = list(info.get("headers", ["<unistd.h>"]))
                        instr.comment = f"syscall {syscall_nr}: {info['name']}"
                        log.debug("  Syscall %d → %s at 0x%x",
                                  syscall_nr, info["name"], instr.address)
                    else:
                        instr.comment = f"syscall {syscall_nr} (UNKNOWN)"
                else:
                    instr.comment = "syscall (number unknown at static analysis time)"
                    # Add unistd.h for the fallback syscall() wrapper
                    instr.syscall_headers = ["<unistd.h>"]

    # ─────────────────────────────────────────────────────────────────────────
    # Pass 3: Loop detection (back edges via DFS)
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_loops(self, func: Function) -> None:
        """
        Find back edges using iterative DFS coloring.
        Mark loop headers and latches on BasicBlocks.
        """
        if not func.entry_block:
            return

        # Build adjacency list (excluding sentinel destinations)
        adj: dict[int, list[tuple[int, CFGEdge]]] = {
            a: [] for a in func.blocks
        }
        for edge in func.edges:
            if edge.src in func.blocks and edge.dst in func.blocks:
                adj[edge.src].append((edge.dst, edge))

        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[int, int] = {a: WHITE for a in func.blocks}

        # Iterative DFS with explicit stack
        # Stack items: (node, iterator over children, parent_edge)
        stack: list[tuple[int, Iterator[tuple[int, CFGEdge]]]] = []
        entry = func.start_addr
        color[entry] = GRAY
        stack.append((entry, iter(adj[entry])))

        loop_id_counter = [0]

        while stack:
            node, children = stack[-1]
            try:
                child, edge = next(children)
                if color[child] == GRAY:
                    # Back edge found
                    edge.back_edge = True
                    # Mark header (child) and latch (node)
                    func.blocks[child].loop_header = True
                    func.blocks[node].loop_latch   = True
                    # Assign loop ID
                    lid = loop_id_counter[0]
                    loop_id_counter[0] += 1
                    func.blocks[child].loop_id = lid
                    func.blocks[node].loop_id  = lid
                    log.debug("  Back edge %s → loop header at 0x%x", edge, child)
                elif color[child] == WHITE:
                    color[child] = GRAY
                    stack.append((child, iter(adj[child])))
            except StopIteration:
                color[node] = BLACK
                stack.pop()

    # ─────────────────────────────────────────────────────────────────────────
    # Pass 4: Block classification
    # ─────────────────────────────────────────────────────────────────────────

    def _classify_blocks(self, func: Function) -> None:
        """Assign a semantic block_type to each block."""
        for bb in func.blocks.values():
            if bb.is_function_entry:
                bb.block_type = "entry"
                continue

            # Check terminator
            term = bb.terminator
            mn = term.mnemonic.lower()

            if mn in ("ret", "retq", "retn"):
                bb.block_type = "exit"
                continue

            # Check for tail call
            for edge in func.edges:
                if edge.src == bb.start_addr and edge.kind == "tail_call":
                    bb.block_type = "tail_call"
                    break

            if bb.block_type != "generic":
                continue

            # Check for extern call
            for instr in bb.instructions:
                if instr.ext_call_name:
                    bb.block_type = "call_site"
                    break
                if instr.syscall_name is not None or instr.mnemonic.lower() == "syscall":
                    bb.block_type = "syscall_site"
                    break

            # Loop annotations take priority over generic call labeling
            if bb.loop_header:
                bb.block_type = "loop_header"
            elif bb.loop_latch:
                bb.block_type = "loop_latch"

    # ─────────────────────────────────────────────────────────────────────────
    # Pass 5: Collect all required headers
    # ─────────────────────────────────────────────────────────────────────────

    def _collect_headers(self) -> None:
        for func in self.cfg.functions:
            for bb in func.blocks.values():
                for instr in bb.instructions:
                    if instr.ext_call_headers:
                        self.cfg.required_headers.update(instr.ext_call_headers)
                    if instr.syscall_headers:
                        self.cfg.required_headers.update(instr.syscall_headers)

    # ─────────────────────────────────────────────────────────────────────────
    # Utility
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_imm_operand(op_str: str) -> int | None:
        """Try to parse an immediate value from an operand string."""
        s = op_str.strip()
        # Strip Intel segment overrides, brackets
        s = s.lstrip("*").strip("[]").strip()
        # Handle negative hex: e.g. "-0x10" or "0xfffffff0"
        try:
            return int(s, 0)
        except ValueError:
            pass
        # Sometimes capstone emits just a decimal
        try:
            return int(s)
        except ValueError:
            pass
        return None


def enrich(cfg: EnrichedCFG) -> EnrichedCFG:
    """Convenience function."""
    return Enricher(cfg).enrich()
