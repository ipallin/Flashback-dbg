"""
Phase 3: C Code Generator.

Responsibilities:
  - Emit compilable C source from an EnrichedCFG
  - Declare global register and flag variables
  - Emit forward declarations for all translated functions
  - Translate each Function → C function with labeled blocks
  - Emit a main() stub that bootstraps the entry point
  - Embed traceability comments (address + original assembly)
"""

from __future__ import annotations

import datetime
import logging
from typing import Optional

from . import __version__
from .models import (
    BasicBlock, CFGEdge, EnrichedCFG, Function,
    INDIRECT_SENTINEL, RETURN_SENTINEL,
)
from .instruction_translator import translate_instruction

log = logging.getLogger(__name__)

# ─── Register and flag declarations ─────────────────────────────────────────

_GPR_NAMES = [
    "rax", "rbx", "rcx", "rdx",
    "rsi", "rdi", "rbp", "rsp",
    "r8",  "r9",  "r10", "r11",
    "r12", "r13", "r14", "r15",
    "rip",
]

_FLAG_NAMES = ["CF", "PF", "AF", "ZF", "SF", "OF", "DF"]

_C_FUNC_PREFIX = "fb_"   # prefix for translated function names
_BLOCK_LABEL_PREFIX = "L_"


def _c_func_name(func: Function) -> str:
    """Return a safe C function name for a Function."""
    name = func.name
    # Strip leading underscores and dots that are invalid in C identifiers
    safe = name.lstrip("_.")
    # Replace non-alphanumeric characters
    safe = "".join(c if c.isalnum() or c == "_" else "_" for c in safe)
    if not safe or safe[0].isdigit():
        safe = "fn_" + safe
    return _C_FUNC_PREFIX + safe


def _block_label(bb: BasicBlock) -> str:
    """Return the C goto label for a basic block."""
    return f"{_BLOCK_LABEL_PREFIX}{bb.start_addr:#010x}"


class CTranslator:
    """
    Translates an EnrichedCFG into a single compilable C source file.
    """

    def __init__(
        self,
        cfg: EnrichedCFG,
        *,
        emit_comments: bool = True,
        only_function: Optional[str] = None,
    ) -> None:
        self.cfg = cfg
        self.emit_comments = emit_comments
        self.only_function = only_function
        self._lines: list[str] = []

    # ─────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────────────────────────────────

    def translate(self) -> str:
        """Return a string containing the full C source file."""
        self._lines = []

        self._emit_file_header()
        self._emit_includes()
        self._emit_globals()
        self._emit_forward_decls()
        self._emit_functions()
        self._emit_main_stub()

        return "\n".join(self._lines) + "\n"

    # ─────────────────────────────────────────────────────────────────────────
    # Section emitters
    # ─────────────────────────────────────────────────────────────────────────

    def _emit_file_header(self) -> None:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._w("/*")
        self._w(f" * Flashback v{__version__} — auto-generated C reconstruction")
        self._w(f" * Source binary : {self.cfg.binary_path}")
        self._w(f" * Architecture  : {self.cfg.arch}")
        self._w(f" * Generated at  : {ts}")
        self._w(" *")
        self._w(" * WARNING: This file is machine-generated.  Do NOT edit by hand.")
        self._w(" * Compile with:  gcc -O0 -o out <this_file>")
        self._w(" */")
        self._w("")

    def _emit_includes(self) -> None:
        # Always present
        mandatory = {"<stdint.h>", "<stddef.h>", "<stdio.h>", "<stdlib.h>"}
        headers = sorted(mandatory | self.cfg.required_headers)
        for h in headers:
            self._w(f"#include {h}")
        self._w("")

    def _emit_globals(self) -> None:
        self._w("/* ── General-purpose registers ─────────────────────────────── */")
        # Emit all GPRs as static uint64_t
        for reg in _GPR_NAMES:
            self._w(f"static uint64_t {reg} = 0;")
        self._w("")

        self._w("/* ── EFLAGS individual bits ─────────────────────────────────── */")
        for flag in _FLAG_NAMES:
            self._w(f"static int FLAG_{flag} = 0;")
        self._w("")

        # Scratch space used by div/mul/string ops
        self._w("/* ── Scratch / temporaries ─────────────────────────────────── */")
        self._w("static uint64_t _tmp = 0;")
        self._w("static uint64_t _tmp2 = 0;")
        self._w("")

    def _emit_forward_decls(self) -> None:
        funcs = self._functions_to_emit()
        if not funcs:
            return
        self._w("/* ── Forward declarations ──────────────────────────────────── */")
        for func in funcs:
            self._w(f"uint64_t {_c_func_name(func)}(void);")
        self._w("")

    def _emit_functions(self) -> None:
        for func in self._functions_to_emit():
            self._emit_function(func)

    def _emit_main_stub(self) -> None:
        """
        Emit a main() that seeds rdi/rsi with argc/argv and calls the binary
        entry function (or the first non-PLT function if entry is not found).
        """
        entry_func = self.cfg.function_by_addr(self.cfg.entry_point)
        if entry_func is None:
            # Fall back to first non-PLT function
            for f in self.cfg.functions:
                if not f.is_plt_stub:
                    entry_func = f
                    break

        self._w("/* ── Entry point stub ──────────────────────────────────────── */")
        self._w("int main(int argc, char **argv) {")
        self._w("    rdi = (uint64_t)argc;")
        self._w("    rsi = (uint64_t)(uintptr_t)argv;")
        if entry_func and not entry_func.is_plt_stub:
            self._w(f"    {_c_func_name(entry_func)}();")
        self._w("    return (int)(uint32_t)rax;")
        self._w("}")
        self._w("")

    # ─────────────────────────────────────────────────────────────────────────
    # Per-function emission
    # ─────────────────────────────────────────────────────────────────────────

    def _emit_function(self, func: Function) -> None:
        log.debug("Translating function %s", func.name)

        self._w(f"/* {'─' * 68} */")
        self._w(f"/* Function: {func.name}  @  {func.start_addr:#x} */")
        self._w(f"/* Blocks: {len(func.blocks)}  |  Edges: {len(func.edges)} */")
        self._w(f"/* {'─' * 68} */")
        self._w(f"uint64_t {_c_func_name(func)}(void) {{")

        if not func.blocks:
            self._w("    return rax;")
            self._w("}")
            self._w("")
            return

        # Emit blocks in address order
        for bb in func.sorted_blocks:
            self._emit_block(bb, func)

        self._w("    return rax;")
        self._w("}")
        self._w("")

    def _emit_block(self, bb: BasicBlock, func: Function) -> None:
        label = _block_label(bb)
        block_comment = f"[{bb.block_type}]"
        if bb.loop_header:
            block_comment += " [loop_header]"
        if bb.loop_latch:
            block_comment += " [loop_latch]"

        self._w(f"  {label}: /* {block_comment} */")

        # Build a set of successor label targets for use in terminator emission
        succs = {
            e.dst: e
            for e in func.edges
            if e.src == bb.start_addr
        }

        for i, instr in enumerate(bb.instructions):
            is_terminator = (i == len(bb.instructions) - 1)
            self._emit_instruction(instr, func, bb, succs, is_terminator)

        # After last instruction, if we fell off without a goto/return,
        # add a fallthrough goto if there is exactly one non-special successor.
        # (The instruction translator should already emit this, but belt+suspenders)

    def _emit_instruction(
        self,
        instr,
        func: Function,
        bb: BasicBlock,
        succs: dict[int, CFGEdge],
        is_terminator: bool,
    ) -> None:
        """
        Translate one instruction and write the resulting C lines.
        """
        # Build successor label map for this instruction (used by branches/jumps)
        label_map: dict[str, str] = {}
        for dst, edge in succs.items():
            if dst == RETURN_SENTINEL or dst == INDIRECT_SENTINEL:
                continue
            if dst in func.blocks:
                label_map[edge.kind] = _block_label(func.blocks[dst])

        # Derive true/false branch targets
        true_label  = label_map.get("true_branch")
        false_label = label_map.get("false_branch")
        jump_label  = label_map.get("unconditional") or label_map.get("fallthrough")

        # For indirect jumps build a computed-goto table if possible
        indirect_targets = [
            _block_label(func.blocks[dst])
            for dst, edge in succs.items()
            if edge.kind == "indirect" and dst in func.blocks
        ]

        c_lines = translate_instruction(
            instr,
            rip_next=instr.address + instr.size,
            true_label=true_label,
            false_label=false_label,
            jump_label=jump_label,
            func_name=_c_func_name(func),
            indirect_targets=indirect_targets,
            emit_comment=self.emit_comments,
        )

        for line in c_lines:
            self._w(f"    {line}")

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _functions_to_emit(self) -> list[Function]:
        if self.only_function:
            f = self.cfg.function_by_name(self.only_function)
            return [f] if f else []
        return [f for f in self.cfg.functions if not f.is_plt_stub]

    def _w(self, line: str) -> None:
        self._lines.append(line)


# ─── Convenience function ────────────────────────────────────────────────────

def translate(
    cfg: EnrichedCFG,
    *,
    emit_comments: bool = True,
    only_function: Optional[str] = None,
) -> str:
    """Return a C source string for the given EnrichedCFG."""
    return CTranslator(cfg, emit_comments=emit_comments, only_function=only_function).translate()
