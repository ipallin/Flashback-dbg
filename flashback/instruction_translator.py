"""
x86-64 instruction → C statement translation.

This module is the core of Phase 3.  For each Instruction it returns a list
of C statement strings (without trailing newline) that reproduce the semantics
of that instruction using the global register/flag variables.

Design principles (from the thesis):
  • Executability over readability: gotos, uint64_t registers, explicit flags
  • Trazabilidad: every output statement starts with a comment containing the
    original address and assembly text
  • Sub-register writes follow x86-64 partial-update semantics
  • Flags are updated by dedicated macros defined in the file header
  • External calls use actual C function calls with proper casts
  • Syscalls are resolved to libc wrappers or the syscall() fallback
"""

from __future__ import annotations

import logging
from typing import NamedTuple

from .models import Instruction, PLTEntry
from .data.libc_signatures import LIBC_SIGNATURES, ABI_ARG_REGS, get_signature

log = logging.getLogger(__name__)

# ── Register metadata ─────────────────────────────────────────────────────────

class RegInfo(NamedTuple):
    parent: str   # 64-bit parent register variable name
    width:  int   # bit-width: 64, 32, 16, 8
    kind:   str   # "full" | "zero_extend" | "partial_low" | "partial_high"

# fmt: off
REG_MAP: dict[str, RegInfo] = {
    # 64-bit
    "rax": RegInfo("rax", 64, "full"),  "rbx": RegInfo("rbx", 64, "full"),
    "rcx": RegInfo("rcx", 64, "full"),  "rdx": RegInfo("rdx", 64, "full"),
    "rsi": RegInfo("rsi", 64, "full"),  "rdi": RegInfo("rdi", 64, "full"),
    "rsp": RegInfo("rsp", 64, "full"),  "rbp": RegInfo("rbp", 64, "full"),
    "r8":  RegInfo("r8",  64, "full"),  "r9":  RegInfo("r9",  64, "full"),
    "r10": RegInfo("r10", 64, "full"),  "r11": RegInfo("r11", 64, "full"),
    "r12": RegInfo("r12", 64, "full"),  "r13": RegInfo("r13", 64, "full"),
    "r14": RegInfo("r14", 64, "full"),  "r15": RegInfo("r15", 64, "full"),
    # 32-bit (write zero-extends to 64)
    "eax": RegInfo("rax", 32, "zero_extend"),  "ebx": RegInfo("rbx", 32, "zero_extend"),
    "ecx": RegInfo("rcx", 32, "zero_extend"),  "edx": RegInfo("rdx", 32, "zero_extend"),
    "esi": RegInfo("rsi", 32, "zero_extend"),  "edi": RegInfo("rdi", 32, "zero_extend"),
    "esp": RegInfo("rsp", 32, "zero_extend"),  "ebp": RegInfo("rbp", 32, "zero_extend"),
    "r8d":  RegInfo("r8",  32, "zero_extend"), "r9d":  RegInfo("r9",  32, "zero_extend"),
    "r10d": RegInfo("r10", 32, "zero_extend"), "r11d": RegInfo("r11", 32, "zero_extend"),
    "r12d": RegInfo("r12", 32, "zero_extend"), "r13d": RegInfo("r13", 32, "zero_extend"),
    "r14d": RegInfo("r14", 32, "zero_extend"), "r15d": RegInfo("r15", 32, "zero_extend"),
    # 16-bit (partial write, no zero-extend)
    "ax": RegInfo("rax", 16, "partial_low"), "bx": RegInfo("rbx", 16, "partial_low"),
    "cx": RegInfo("rcx", 16, "partial_low"), "dx": RegInfo("rdx", 16, "partial_low"),
    "si": RegInfo("rsi", 16, "partial_low"), "di": RegInfo("rdi", 16, "partial_low"),
    "sp": RegInfo("rsp", 16, "partial_low"), "bp": RegInfo("rbp", 16, "partial_low"),
    "r8w":  RegInfo("r8",  16, "partial_low"), "r9w":  RegInfo("r9",  16, "partial_low"),
    "r10w": RegInfo("r10", 16, "partial_low"), "r11w": RegInfo("r11", 16, "partial_low"),
    "r12w": RegInfo("r12", 16, "partial_low"), "r13w": RegInfo("r13", 16, "partial_low"),
    "r14w": RegInfo("r14", 16, "partial_low"), "r15w": RegInfo("r15", 16, "partial_low"),
    # 8-bit low
    "al": RegInfo("rax", 8, "partial_low"),  "bl": RegInfo("rbx", 8, "partial_low"),
    "cl": RegInfo("rcx", 8, "partial_low"),  "dl": RegInfo("rdx", 8, "partial_low"),
    "sil": RegInfo("rsi", 8, "partial_low"), "dil": RegInfo("rdi", 8, "partial_low"),
    "spl": RegInfo("rsp", 8, "partial_low"), "bpl": RegInfo("rbp", 8, "partial_low"),
    "r8b":  RegInfo("r8",  8, "partial_low"), "r9b":  RegInfo("r9",  8, "partial_low"),
    "r10b": RegInfo("r10", 8, "partial_low"), "r11b": RegInfo("r11", 8, "partial_low"),
    "r12b": RegInfo("r12", 8, "partial_low"), "r13b": RegInfo("r13", 8, "partial_low"),
    "r14b": RegInfo("r14", 8, "partial_low"), "r15b": RegInfo("r15", 8, "partial_low"),
    # 8-bit high
    "ah": RegInfo("rax", 8, "partial_high"),
    "bh": RegInfo("rbx", 8, "partial_high"),
    "ch": RegInfo("rcx", 8, "partial_high"),
    "dh": RegInfo("rdx", 8, "partial_high"),
}
# fmt: on

# Condition code → C expression using flag globals
CC_EXPRS: dict[str, str] = {
    "e": "FLAG_ZF", "z": "FLAG_ZF",
    "ne": "!FLAG_ZF", "nz": "!FLAG_ZF",
    "b": "FLAG_CF", "nae": "FLAG_CF", "c": "FLAG_CF",
    "ae": "!FLAG_CF", "nb": "!FLAG_CF", "nc": "!FLAG_CF",
    "a": "(!FLAG_CF && !FLAG_ZF)", "nbe": "(!FLAG_CF && !FLAG_ZF)",
    "be": "(FLAG_CF || FLAG_ZF)", "na": "(FLAG_CF || FLAG_ZF)",
    "l": "(FLAG_SF != FLAG_OF)", "nge": "(FLAG_SF != FLAG_OF)",
    "ge": "(FLAG_SF == FLAG_OF)", "nl": "(FLAG_SF == FLAG_OF)",
    "le": "(FLAG_ZF || (FLAG_SF != FLAG_OF))", "ng": "(FLAG_ZF || (FLAG_SF != FLAG_OF))",
    "g": "(!FLAG_ZF && (FLAG_SF == FLAG_OF))", "nle": "(!FLAG_ZF && (FLAG_SF == FLAG_OF))",
    "s": "FLAG_SF", "ns": "!FLAG_SF",
    "o": "FLAG_OF", "no": "!FLAG_OF",
    "p": "FLAG_PF", "pe": "FLAG_PF",
    "np": "!FLAG_PF", "po": "!FLAG_PF",
    "rcxz": "(rcx == 0)", "ecxz": "(ecx == 0)", "cxz": "(cx == 0)",
}

# Instructions that never update flags
NO_FLAG_INSTRS = frozenset({
    "mov", "movq", "movl", "movw", "movb",
    "movzx", "movsx", "movsxd",
    "lea",
    "push", "pop", "pushq", "popq",
    "nop",
    "call", "callq", "ret", "retq", "retn",
    "xchg",
    "jmp", "jmpq",
    "cmov",   # handled per-variant
    "not",
    "endbr64", "endbr32",
})

_PARITY_MACRO = "__builtin_parityll"


def _read_reg(name: str) -> str:
    """C expression to read a register (with proper cast for sub-registers)."""
    info = REG_MAP.get(name.lower())
    if info is None:
        # Unknown register (e.g. rip, segment regs) — return as-is
        return name
    if info.width == 64:
        return info.parent
    if info.kind == "zero_extend":
        return f"(uint32_t){info.parent}"
    if info.kind == "partial_low":
        mask = {16: "0xFFFF", 8: "0xFF"}[info.width]
        cast = {16: "uint16_t", 8: "uint8_t"}[info.width]
        return f"(uint{info.width}_t){info.parent}"
    if info.kind == "partial_high":
        return f"(uint8_t)({info.parent} >> 8)"
    return info.parent


def _write_reg(name: str, value_expr: str) -> str:
    """C assignment statement for writing a register."""
    info = REG_MAP.get(name.lower())
    if info is None:
        return f"/* unknown reg {name} = {value_expr}; */"
    p = info.parent
    if info.width == 64:
        return f"{p} = {value_expr};"
    if info.kind == "zero_extend":
        return f"{p} = (uint64_t)(uint32_t)({value_expr});"
    if info.kind == "partial_low":
        mask = {16: "0xFFFFULL", 8: "0xFFULL"}[info.width]
        cast = {16: "uint16_t", 8: "uint8_t"}[info.width]
        return f"{p} = ({p} & ~{mask}) | ((uint64_t)({cast})({value_expr}));"
    if info.kind == "partial_high":
        return f"{p} = ({p} & ~0xFF00ULL) | (((uint64_t)(uint8_t)({value_expr})) << 8);"
    return f"{p} = {value_expr};"


# ── Size-to-C-type helpers ────────────────────────────────────────────────────

_UINT = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}
_INT  = {1: "int8_t",  2: "int16_t",  4: "int32_t",  8: "int64_t"}


def _ptr_type(size: int, signed: bool = False) -> str:
    t = (_INT if signed else _UINT).get(size, "uint64_t")
    return f"{t}*"


def _flag_width_suffix(width: int) -> int:
    """Return 8/16/32/64 for flag macro calls."""
    return width if width in (8, 16, 32, 64) else 64


# ── Operand parsing ───────────────────────────────────────────────────────────

def _parse_operands(op_str: str) -> list[str]:
    """
    Split 'op_str' into individual operand strings, respecting brackets.
    e.g. "rax, [rbx + rcx*4 + 8]" → ["rax", "[rbx + rcx*4 + 8]"]
    """
    operands: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in op_str:
        if ch == "[":
            depth += 1
            cur.append(ch)
        elif ch == "]":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            operands.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        operands.append("".join(cur).strip())
    return [o for o in operands if o]


def _mem_to_c(mem_str: str, instr_addr: int, instr_size: int, access_size: int) -> str:
    """
    Convert a memory operand string like "[rbp - 0x10]" or "[rip + 0x200]"
    to a C dereference expression.
    """
    inner = mem_str.strip()
    # Remove segment prefix if any (e.g. "qword ptr [...]" or "fs:[...]")
    for prefix in ("qword ptr ", "dword ptr ", "word ptr ", "byte ptr ",
                   "xmmword ptr ", "ymmword ptr "):
        if inner.lower().startswith(prefix):
            inner = inner[len(prefix):]
    inner = inner.strip()
    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1]

    # Handle segment override like "fs:[0]"
    if ":[" in inner:
        seg, rest = inner.split(":[", 1)
        inner = rest.rstrip("]")

    # Handle RIP-relative: compute absolute address
    rip_abs: int | None = None
    inner_low = inner.lower()
    if "rip" in inner_low:
        # Compute absolute address: rip + disp = instr_addr + instr_size + disp
        import re
        disp_match = re.search(r"[+-]\s*(?:0x[0-9a-fA-F]+|\d+)", inner)
        disp = 0
        if disp_match:
            try:
                disp = int(disp_match.group(0).replace(" ", ""), 0)
            except ValueError:
                disp = 0
        rip_abs = instr_addr + instr_size + disp
        inner = f"0x{rip_abs:x}ULL"
    else:
        # Normalise: convert register names, handle scale
        import re
        # Replace register names with their C read expressions
        inner = _normalise_mem_expr(inner)

    utype = _UINT.get(access_size, "uint64_t")
    return f"*(({utype}*)({inner}))"


def _normalise_mem_expr(expr: str) -> str:
    """
    Normalise a memory expression (inside brackets) to valid C arithmetic.
    Handles: base reg, index*scale, displacement.
    """
    import re
    result = expr.strip()

    # Expand register names in order (longest first to avoid partial matches)
    all_regs = sorted(REG_MAP.keys(), key=len, reverse=True)
    for reg in all_regs:
        # Word-boundary replacement
        pattern = r'\b' + re.escape(reg) + r'\b'
        parent = REG_MAP[reg].parent
        result = re.sub(pattern, parent, result, flags=re.IGNORECASE)

    # Replace hex literals to ensure they have ULL suffix for 64-bit safety
    def add_ull(m: re.Match) -> str:
        val = int(m.group(0), 0)
        if val > 0x7FFFFFFF:
            return f"0x{val:x}ULL"
        return m.group(0)

    result = re.sub(r'0x[0-9a-fA-F]+', add_ull, result)

    return result


def _operand_to_c_read(op: str, instr_addr: int, instr_size: int,
                        size_hint: int = 8) -> str:
    """
    Convert an Intel-syntax operand to a C read expression.
    size_hint: operand size in bytes (for memory casts).
    """
    op = op.strip()

    # Memory operand
    if "[" in op or "ptr" in op.lower():
        return _mem_to_c(op, instr_addr, instr_size, size_hint)

    # Register operand
    reg = op.lower()
    if reg in REG_MAP:
        return _read_reg(reg)

    # Immediate operand — numeric literal
    try:
        val = int(op, 0)
        if val < 0:
            return f"((uint64_t){val}LL)"
        if val > 0xFFFFFFFF:
            return f"0x{val:x}ULL"
        return hex(val)
    except ValueError:
        pass

    # Fallback: return as-is
    return op


def _operand_to_c_write(op: str, value_expr: str,
                         instr_addr: int, instr_size: int,
                         size_hint: int = 8) -> str:
    """
    Generate a C assignment statement to write 'value_expr' into operand 'op'.
    """
    op = op.strip()

    # Memory write
    if "[" in op or "ptr" in op.lower():
        mem = _mem_to_c(op, instr_addr, instr_size, size_hint)
        utype = _UINT.get(size_hint, "uint64_t")
        # Strip the dereference to get the pointer expression
        # mem is of form "(*(type*)(expr))" — we need "*(type*)(expr) = val"
        return f"{mem} = ({utype})({value_expr});"

    # Register write
    reg = op.lower()
    if reg in REG_MAP:
        return _write_reg(reg, value_expr)

    return f"/* WRITE to unknown operand {op!r} = {value_expr}; */"


# ── Flag update helpers ───────────────────────────────────────────────────────

def _size_for_reg(reg_name: str) -> int:
    info = REG_MAP.get(reg_name.lower())
    return info.width // 8 if info else 8


def _flags_after_add(dst_c: str, src_c: str, result_c: str, bits: int) -> list[str]:
    utype = f"uint{bits}_t" if bits <= 64 else "uint64_t"
    itype = f"int{bits}_t"  if bits <= 64 else "int64_t"
    mask  = f"(({utype}){result_c})"
    return [
        f"FLAG_ZF = ({mask} == 0);",
        f"FLAG_SF = (({mask} >> {bits-1}) & 1);",
        f"FLAG_CF = (({utype}){result_c} < ({utype}){src_c});",
        f"FLAG_OF = (((~(({dst_c})^({src_c}))) & (({dst_c})^({result_c}))) >> {bits-1}) & 1;",
        f"FLAG_PF = {_PARITY_MACRO}({mask} & 0xFF);",
    ]


def _flags_after_sub(dst_c: str, src_c: str, result_c: str, bits: int) -> list[str]:
    utype = f"uint{bits}_t" if bits <= 64 else "uint64_t"
    mask  = f"(({utype}){result_c})"
    return [
        f"FLAG_ZF = ({mask} == 0);",
        f"FLAG_SF = (({mask} >> {bits-1}) & 1);",
        f"FLAG_CF = (({utype}){dst_c} < ({utype}){src_c});",
        f"FLAG_OF = ((((dst_c)^({src_c})) & (({dst_c})^({result_c}))) >> {bits-1}) & 1;",
        f"FLAG_PF = {_PARITY_MACRO}({mask} & 0xFF);",
    ]


def _flags_after_logic(result_c: str) -> list[str]:
    return [
        "FLAG_CF = 0;",
        "FLAG_OF = 0;",
        f"FLAG_ZF = (({result_c}) == 0);",
        f"FLAG_SF = ((uint64_t)({result_c}) >> 63) & 1;",
        f"FLAG_PF = {_PARITY_MACRO}((uint64_t)({result_c}) & 0xFF);",
    ]


# ── Main translation dispatcher ───────────────────────────────────────────────

def translate_instruction(
    instr: Instruction,
    plt_entries: dict[int, PLTEntry],
    show_comments: bool = True,
    func_map: dict[int, str] | None = None,
) -> list[str]:
    """
    Translate a single Instruction to a list of C statement strings.

    Returns a list where the first element is always the traceability comment
    (if show_comments=True) and subsequent elements are C statements.
    """
    lines: list[str] = []

    # Traceability comment
    if show_comments:
        comment = f"/* {instr.address:#010x}: {instr.full_asm}"
        if instr.comment:
            comment += f"  [{instr.comment}]"
        comment += " */"
        lines.append(comment)

    mn  = instr.mnemonic.lower()
    ops = _parse_operands(instr.op_str)

    # ── NOP / endbr ──────────────────────────────────────────────────────────
    if mn in ("nop", "endbr64", "endbr32", "nopw", "nopl"):
        return lines  # comment only

    # ── HLT / UD2 ────────────────────────────────────────────────────────────
    if mn == "hlt":
        lines.append("__builtin_unreachable(); /* hlt */")
        return lines
    if mn in ("ud2", "ud1", "int3"):
        lines.append("__builtin_trap(); /* ud2/int3 */")
        return lines

    # ── RET ──────────────────────────────────────────────────────────────────
    if mn in ("ret", "retq", "retn"):
        lines.append("return rax;")
        return lines

    # ── LEAVE ────────────────────────────────────────────────────────────────
    if mn == "leave":
        lines.append("rsp = rbp;")
        lines.append("rbp = *(uint64_t*)rsp; rsp += 8;")
        return lines

    # ── PUSH ─────────────────────────────────────────────────────────────────
    if mn in ("push", "pushq"):
        src = ops[0] if ops else "0"
        src_c = _operand_to_c_read(src, instr.address, instr.size, 8)
        lines.append("rsp -= 8;")
        lines.append(f"*(uint64_t*)rsp = {src_c};")
        return lines

    # ── POP ──────────────────────────────────────────────────────────────────
    if mn in ("pop", "popq"):
        dst = ops[0] if ops else "rax"
        lines.append(_operand_to_c_write(dst, "*(uint64_t*)rsp",
                                          instr.address, instr.size, 8))
        lines.append("rsp += 8;")
        return lines

    # ── CALL ─────────────────────────────────────────────────────────────────
    if mn in ("call", "callq"):
        lines.extend(_translate_call(instr, ops, plt_entries, func_map))
        return lines

    # ── JMP ──────────────────────────────────────────────────────────────────
    if mn in ("jmp", "jmpq"):
        target_str = ops[0] if ops else ""
        target_int = _parse_imm(target_str)
        if target_int is not None:
            # Check if it's a tail call to PLT
            if target_int in plt_entries:
                sym = plt_entries[target_int].symbol_name
                lines.extend(_make_extern_call(sym, instr, is_tail=True))
                lines.append("return rax;")
            elif func_map and target_int in func_map:
                lines.append(f"rax = func_{func_map[target_int]}(rdi, rsi, rdx, rcx, r8, r9);")
                lines.append("return rax;")
            else:
                lines.append(f"goto block_{target_int:#010x};")
        else:
            # Register indirect jump
            lines.append(f"/* INDIRECT JMP: {instr.op_str} */")
            lines.append(f"goto *((void*)(uint64_t){_operand_to_c_read(target_str, instr.address, instr.size, 8)});")
        return lines

    # ── Conditional jumps ────────────────────────────────────────────────────
    for cc, cond_expr in CC_EXPRS.items():
        for prefix in ("j", "loop"):
            full_mn = prefix + cc
            if mn == full_mn:
                target_str = ops[0] if ops else ""
                target_int = _parse_imm(target_str)
                # loop/loope/loopne decrement rcx
                if mn.startswith("loop"):
                    lines.append("rcx--;")
                if target_int is not None:
                    fall_addr = instr.address + instr.size
                    lines.append(
                        f"if ({cond_expr}) goto block_{target_int:#010x}; "
                        f"else goto block_{fall_addr:#010x};"
                    )
                else:
                    lines.append(f"if ({cond_expr}) {{ /* indirect cond jump */ }}")
                return lines

    # ── SYSCALL ──────────────────────────────────────────────────────────────
    if mn == "syscall":
        lines.extend(_translate_syscall(instr))
        return lines

    # ── MOV ──────────────────────────────────────────────────────────────────
    if mn in ("mov", "movq", "movl", "movw", "movb"):
        if len(ops) < 2:
            lines.append(f"/* SKIPPED: {instr.full_asm} */")
            return lines
        dst, src = ops[0], ops[1]
        sz = _op_size(dst, src)
        src_c = _operand_to_c_read(src, instr.address, instr.size, sz)
        lines.append(_operand_to_c_write(dst, src_c, instr.address, instr.size, sz))
        return lines

    # ── MOVZX ────────────────────────────────────────────────────────────────
    if mn in ("movzx", "movzbl", "movzbq", "movzwl", "movzwq"):
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        src_sz = _infer_src_size(src, mn)
        src_c = _operand_to_c_read(src, instr.address, instr.size, src_sz)
        utype = _UINT.get(src_sz, "uint8_t")
        lines.append(_operand_to_c_write(dst, f"(uint64_t)({utype})({src_c})",
                                          instr.address, instr.size, 8))
        return lines

    # ── MOVSX / MOVSXD ───────────────────────────────────────────────────────
    if mn in ("movsx", "movsbl", "movsbq", "movswl", "movswq", "movsxd", "movslq"):
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        src_sz = _infer_src_size(src, mn)
        src_c = _operand_to_c_read(src, instr.address, instr.size, src_sz)
        itype = _INT.get(src_sz, "int8_t")
        lines.append(_operand_to_c_write(dst, f"(uint64_t)(int64_t)({itype})({src_c})",
                                          instr.address, instr.size, 8))
        return lines

    # ── LEA ──────────────────────────────────────────────────────────────────
    if mn == "lea":
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        addr_c = _lea_addr(src, instr.address, instr.size)
        lines.append(_operand_to_c_write(dst, addr_c, instr.address, instr.size, 8))
        return lines

    # ── XCHG ─────────────────────────────────────────────────────────────────
    if mn == "xchg":
        if len(ops) < 2:
            return lines
        a, b = ops[0], ops[1]
        sz = _op_size(a, b)
        a_c = _operand_to_c_read(a, instr.address, instr.size, sz)
        b_c = _operand_to_c_read(b, instr.address, instr.size, sz)
        lines.append(f"{{ uint64_t _xchg_tmp = {a_c}; "
                     f"{_operand_to_c_write(a, b_c, instr.address, instr.size, sz)} "
                     f"{_operand_to_c_write(b, '_xchg_tmp', instr.address, instr.size, sz)} }}")
        return lines

    # ── ADD ──────────────────────────────────────────────────────────────────
    if mn in ("add", "addq", "addl", "addw", "addb"):
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        sz = _op_size(dst, src)
        bits = sz * 8
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        src_c = _operand_to_c_read(src, instr.address, instr.size, sz)
        tmp = f"_add_{instr.address:#x}"
        lines.append(f"{{ uint64_t {tmp} = {dst_c} + {src_c};")
        lines.extend(_flags_after_add(dst_c, src_c, tmp, bits))
        lines.append(_operand_to_c_write(dst, tmp, instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── SUB ──────────────────────────────────────────────────────────────────
    if mn in ("sub", "subq", "subl", "subw", "subb"):
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        sz = _op_size(dst, src)
        bits = sz * 8
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        src_c = _operand_to_c_read(src, instr.address, instr.size, sz)
        tmp = f"_sub_{instr.address:#x}"
        lines.append(f"{{ uint64_t {tmp} = {dst_c} - {src_c};")
        lines.extend(_flags_after_sub(dst_c, src_c, tmp, bits))
        lines.append(_operand_to_c_write(dst, tmp, instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── ADC (add with carry) ─────────────────────────────────────────────────
    if mn in ("adc", "adcq", "adcl"):
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        sz = _op_size(dst, src)
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        src_c = _operand_to_c_read(src, instr.address, instr.size, sz)
        lines.append(_operand_to_c_write(dst, f"{dst_c} + {src_c} + FLAG_CF",
                                          instr.address, instr.size, sz))
        lines.append("/* adc: flags updated approximately */")
        return lines

    # ── SBB (sub with borrow) ─────────────────────────────────────────────────
    if mn in ("sbb", "sbbq", "sbbl"):
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        sz = _op_size(dst, src)
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        src_c = _operand_to_c_read(src, instr.address, instr.size, sz)
        lines.append(_operand_to_c_write(dst, f"{dst_c} - {src_c} - FLAG_CF",
                                          instr.address, instr.size, sz))
        return lines

    # ── INC ──────────────────────────────────────────────────────────────────
    if mn in ("inc", "incq", "incl", "incw", "incb"):
        dst = ops[0] if ops else "rax"
        sz = _op_size(dst)
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        tmp = f"_inc_{instr.address:#x}"
        bits = sz * 8
        lines.append(f"{{ uint64_t {tmp} = {dst_c} + 1;")
        # INC does NOT modify CF
        lines.append(f"FLAG_ZF = ({tmp} == 0);")
        lines.append(f"FLAG_SF = (({tmp} >> {bits-1}) & 1);")
        lines.append(f"FLAG_OF = ({dst_c} == 0x{'7F'+'FF'*(sz-1)}) ? 1 : 0;")
        lines.append(f"FLAG_PF = {_PARITY_MACRO}({tmp} & 0xFF);")
        lines.append(_operand_to_c_write(dst, tmp, instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── DEC ──────────────────────────────────────────────────────────────────
    if mn in ("dec", "decq", "decl", "decw", "decb"):
        dst = ops[0] if ops else "rax"
        sz = _op_size(dst)
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        tmp = f"_dec_{instr.address:#x}"
        bits = sz * 8
        lines.append(f"{{ uint64_t {tmp} = {dst_c} - 1;")
        lines.append(f"FLAG_ZF = ({tmp} == 0);")
        lines.append(f"FLAG_SF = (({tmp} >> {bits-1}) & 1);")
        lines.append(f"FLAG_OF = ({dst_c} == 0x{'80'+'00'*(sz-1)}) ? 1 : 0;")
        lines.append(f"FLAG_PF = {_PARITY_MACRO}({tmp} & 0xFF);")
        lines.append(_operand_to_c_write(dst, tmp, instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── NEG ──────────────────────────────────────────────────────────────────
    if mn in ("neg", "negq", "negl"):
        dst = ops[0] if ops else "rax"
        sz = _op_size(dst)
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        tmp = f"_neg_{instr.address:#x}"
        lines.append(f"{{ uint64_t {tmp} = 0 - {dst_c};")
        lines.append(f"FLAG_CF = ({dst_c} != 0) ? 1 : 0;")
        lines.append(f"FLAG_ZF = ({tmp} == 0);")
        lines.append(f"FLAG_SF = ((int64_t){tmp} < 0) ? 1 : 0;")
        lines.append(_operand_to_c_write(dst, tmp, instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── IMUL ─────────────────────────────────────────────────────────────────
    if mn in ("imul", "imulq", "imull"):
        if len(ops) == 1:
            # rdx:rax = rax * src
            src_c = _operand_to_c_read(ops[0], instr.address, instr.size, 8)
            lines.append(f"{{ __int128 _imul = (__int128)(int64_t)rax * (int64_t){src_c};")
            lines.append("rax = (uint64_t)_imul; rdx = (uint64_t)(_imul >> 64); }")
        elif len(ops) == 2:
            dst_c = _operand_to_c_read(ops[0], instr.address, instr.size, 8)
            src_c = _operand_to_c_read(ops[1], instr.address, instr.size, 8)
            lines.append(_operand_to_c_write(ops[0],
                          f"(uint64_t)((int64_t){dst_c} * (int64_t){src_c})",
                          instr.address, instr.size, 8))
        elif len(ops) >= 3:
            src_c = _operand_to_c_read(ops[1], instr.address, instr.size, 8)
            imm_c = _operand_to_c_read(ops[2], instr.address, instr.size, 8)
            lines.append(_operand_to_c_write(ops[0],
                          f"(uint64_t)((int64_t){src_c} * (int64_t){imm_c})",
                          instr.address, instr.size, 8))
        return lines

    # ── MUL ──────────────────────────────────────────────────────────────────
    if mn in ("mul", "mulq", "mull"):
        src_c = _operand_to_c_read(ops[0], instr.address, instr.size, 8) if ops else "rdi"
        lines.append(f"{{ unsigned __int128 _mul = (unsigned __int128)rax * {src_c};")
        lines.append("rax = (uint64_t)_mul; rdx = (uint64_t)(_mul >> 64); }")
        lines.append("FLAG_CF = (rdx != 0); FLAG_OF = FLAG_CF;")
        return lines

    # ── DIV ──────────────────────────────────────────────────────────────────
    if mn in ("div", "divq", "divl"):
        src_c = _operand_to_c_read(ops[0], instr.address, instr.size, 8) if ops else "rdi"
        lines.append(f"if ({src_c} != 0) {{")
        lines.append(f"  unsigned __int128 _dividend = ((unsigned __int128)rdx << 64) | rax;")
        lines.append(f"  rax = (uint64_t)(_dividend / (uint64_t){src_c});")
        lines.append(f"  rdx = (uint64_t)(_dividend % (uint64_t){src_c});")
        lines.append("}")
        return lines

    # ── IDIV ─────────────────────────────────────────────────────────────────
    if mn in ("idiv", "idivq", "idivl"):
        src_c = _operand_to_c_read(ops[0], instr.address, instr.size, 8) if ops else "rdi"
        lines.append(f"if ({src_c} != 0) {{")
        lines.append(f"  __int128 _sdividend = ((__int128)(int64_t)rdx << 64) | (uint64_t)rax;")
        lines.append(f"  rax = (uint64_t)(int64_t)(_sdividend / (int64_t){src_c});")
        lines.append(f"  rdx = (uint64_t)(int64_t)(_sdividend % (int64_t){src_c});")
        lines.append("}")
        return lines

    # ── AND ──────────────────────────────────────────────────────────────────
    if mn in ("and", "andq", "andl", "andw", "andb"):
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        sz = _op_size(dst, src)
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        src_c = _operand_to_c_read(src, instr.address, instr.size, sz)
        tmp = f"_and_{instr.address:#x}"
        lines.append(f"{{ uint64_t {tmp} = {dst_c} & {src_c};")
        lines.extend(_flags_after_logic(tmp))
        lines.append(_operand_to_c_write(dst, tmp, instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── OR ───────────────────────────────────────────────────────────────────
    if mn in ("or", "orq", "orl", "orw", "orb"):
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        sz = _op_size(dst, src)
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        src_c = _operand_to_c_read(src, instr.address, instr.size, sz)
        tmp = f"_or_{instr.address:#x}"
        lines.append(f"{{ uint64_t {tmp} = {dst_c} | {src_c};")
        lines.extend(_flags_after_logic(tmp))
        lines.append(_operand_to_c_write(dst, tmp, instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── XOR ──────────────────────────────────────────────────────────────────
    if mn in ("xor", "xorq", "xorl", "xorw", "xorb"):
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        sz = _op_size(dst, src)
        # Detect zero-idiom: xor reg, reg
        if dst.lower() == src.lower():
            lines.append(_operand_to_c_write(dst, "0", instr.address, instr.size, sz))
            lines.append("FLAG_ZF = 1; FLAG_CF = 0; FLAG_OF = 0; FLAG_SF = 0; FLAG_PF = 1;")
            return lines
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        src_c = _operand_to_c_read(src, instr.address, instr.size, sz)
        tmp = f"_xor_{instr.address:#x}"
        lines.append(f"{{ uint64_t {tmp} = {dst_c} ^ {src_c};")
        lines.extend(_flags_after_logic(tmp))
        lines.append(_operand_to_c_write(dst, tmp, instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── NOT ──────────────────────────────────────────────────────────────────
    if mn in ("not", "notq", "notl", "notw", "notb"):
        dst = ops[0] if ops else "rax"
        sz = _op_size(dst)
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        lines.append(_operand_to_c_write(dst, f"~{dst_c}", instr.address, instr.size, sz))
        return lines

    # ── SHL / SAL ────────────────────────────────────────────────────────────
    if mn in ("shl", "sal", "shlq", "sall"):
        if not ops:
            return lines
        dst = ops[0]
        cnt = ops[1] if len(ops) > 1 else "1"
        sz = _op_size(dst)
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        cnt_c = _operand_to_c_read(cnt, instr.address, instr.size, 1)
        bits = sz * 8
        tmp = f"_shl_{instr.address:#x}"
        lines.append(f"{{ uint{bits}_t {tmp} = (uint{bits}_t){dst_c} << ({cnt_c} & {bits-1});")
        lines.append(f"FLAG_CF = ({dst_c} >> ({bits} - ({cnt_c} & {bits-1}))) & 1;")
        lines.append(f"FLAG_ZF = ({tmp} == 0); FLAG_SF = (({tmp} >> {bits-1}) & 1);")
        lines.append(f"FLAG_PF = {_PARITY_MACRO}({tmp} & 0xFF);")
        lines.append(_operand_to_c_write(dst, f"(uint64_t){tmp}", instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── SHR ──────────────────────────────────────────────────────────────────
    if mn in ("shr", "shrq", "shrl", "shrw"):
        if not ops:
            return lines
        dst = ops[0]
        cnt = ops[1] if len(ops) > 1 else "1"
        sz = _op_size(dst)
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        cnt_c = _operand_to_c_read(cnt, instr.address, instr.size, 1)
        bits = sz * 8
        tmp = f"_shr_{instr.address:#x}"
        lines.append(f"{{ uint{bits}_t {tmp} = (uint{bits}_t){dst_c} >> ({cnt_c} & {bits-1});")
        lines.append(f"FLAG_CF = ({dst_c} >> (({cnt_c} & {bits-1}) - 1)) & 1;")
        lines.append(f"FLAG_ZF = ({tmp} == 0); FLAG_SF = 0;")
        lines.append(f"FLAG_PF = {_PARITY_MACRO}({tmp} & 0xFF);")
        lines.append(_operand_to_c_write(dst, f"(uint64_t){tmp}", instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── SAR ──────────────────────────────────────────────────────────────────
    if mn in ("sar", "sarq", "sarl", "sarw"):
        if not ops:
            return lines
        dst = ops[0]
        cnt = ops[1] if len(ops) > 1 else "1"
        sz = _op_size(dst)
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        cnt_c = _operand_to_c_read(cnt, instr.address, instr.size, 1)
        bits = sz * 8
        itype = f"int{bits}_t" if bits <= 64 else "int64_t"
        tmp = f"_sar_{instr.address:#x}"
        lines.append(f"{{ {itype} {tmp} = ({itype}){dst_c} >> ({cnt_c} & {bits-1});")
        lines.append(f"FLAG_CF = ({dst_c} >> (({cnt_c} & {bits-1}) - 1)) & 1;")
        lines.append(f"FLAG_ZF = ({tmp} == 0); FLAG_SF = ({tmp} < 0) ? 1 : 0;")
        lines.append(f"FLAG_PF = {_PARITY_MACRO}((uint64_t){tmp} & 0xFF);")
        lines.append(_operand_to_c_write(dst, f"(uint64_t){tmp}", instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── ROL / ROR ────────────────────────────────────────────────────────────
    if mn in ("rol", "rolq", "rorl", "ror", "rorq", "rorl"):
        if not ops:
            return lines
        dst = ops[0]
        cnt = ops[1] if len(ops) > 1 else "1"
        sz = _op_size(dst)
        bits = sz * 8
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        cnt_c = _operand_to_c_read(cnt, instr.address, instr.size, 1)
        is_ror = mn.startswith("ror")
        if is_ror:
            rot = f"(uint{bits}_t){dst_c} >> (n & {bits-1}) | (uint{bits}_t){dst_c} << ({bits} - (n & {bits-1}))"
        else:
            rot = f"(uint{bits}_t){dst_c} << (n & {bits-1}) | (uint{bits}_t){dst_c} >> ({bits} - (n & {bits-1}))"
        lines.append(f"{{ unsigned n = {cnt_c}; uint{bits}_t _rot = {rot};")
        lines.append(_operand_to_c_write(dst, "(uint64_t)_rot", instr.address, instr.size, sz))
        lines.append("}")
        return lines

    # ── CMP ──────────────────────────────────────────────────────────────────
    if mn in ("cmp", "cmpq", "cmpl", "cmpw", "cmpb"):
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        sz = _op_size(dst, src)
        bits = sz * 8
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        src_c = _operand_to_c_read(src, instr.address, instr.size, sz)
        utype = f"uint{bits}_t" if bits <= 64 else "uint64_t"
        tmp = f"_cmp_{instr.address:#x}"
        lines.append(f"{{ uint64_t {tmp} = {dst_c} - {src_c};")
        lines.append(f"FLAG_ZF = ({tmp} == 0);")
        lines.append(f"FLAG_SF = (({tmp} >> {bits-1}) & 1);")
        lines.append(f"FLAG_CF = (({utype}){dst_c} < ({utype}){src_c});")
        lines.append(f"FLAG_OF = ((((dst_c)^({src_c})) & (({dst_c})^({tmp}))) >> {bits-1}) & 1;")
        lines.append(f"FLAG_PF = {_PARITY_MACRO}({tmp} & 0xFF); }}")
        return lines

    # ── TEST ─────────────────────────────────────────────────────────────────
    if mn in ("test", "testq", "testl", "testw", "testb"):
        if len(ops) < 2:
            return lines
        dst, src = ops[0], ops[1]
        sz = _op_size(dst, src)
        bits = sz * 8
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, sz)
        src_c = _operand_to_c_read(src, instr.address, instr.size, sz)
        tmp = f"_test_{instr.address:#x}"
        lines.append(f"{{ uint64_t {tmp} = {dst_c} & {src_c};")
        lines.extend(_flags_after_logic(tmp))
        lines.append("}")
        return lines

    # ── SETCC ────────────────────────────────────────────────────────────────
    for cc, cond_expr in CC_EXPRS.items():
        if mn == "set" + cc:
            dst = ops[0] if ops else "al"
            lines.append(_operand_to_c_write(dst, f"(uint8_t)({cond_expr} ? 1 : 0)",
                                              instr.address, instr.size, 1))
            return lines

    # ── CMOVCC ───────────────────────────────────────────────────────────────
    for cc, cond_expr in CC_EXPRS.items():
        if mn == "cmov" + cc or mn in (f"cmov{cc}q", f"cmov{cc}l"):
            if len(ops) >= 2:
                dst, src = ops[0], ops[1]
                sz = _op_size(dst, src)
                src_c = _operand_to_c_read(src, instr.address, instr.size, sz)
                lines.append(f"if ({cond_expr}) {{")
                lines.append("  " + _operand_to_c_write(dst, src_c, instr.address, instr.size, sz))
                lines.append("}")
                return lines

    # ── Sign extension ────────────────────────────────────────────────────────
    if mn == "cbw":   # al → ax (sign-extend)
        lines.append("rax = (rax & ~0xFFFFULL) | (uint16_t)(int16_t)(int8_t)(uint8_t)rax;")
        return lines
    if mn == "cwde":  # ax → eax
        lines.append("rax = (uint64_t)(uint32_t)(int32_t)(int16_t)(uint16_t)rax;")
        return lines
    if mn == "cdqe":  # eax → rax
        lines.append("rax = (uint64_t)(int64_t)(int32_t)(uint32_t)rax;")
        return lines
    if mn in ("cwd", "cwtd"):   # ax → dx:ax
        lines.append("rdx = (rax & 0x8000) ? 0xFFFFFFFFFFFFFFFFULL : 0;")
        return lines
    if mn in ("cdq", "cltd"):   # eax → edx:eax
        lines.append("rdx = (rax & 0x80000000) ? 0xFFFFFFFFFFFFFFFFULL : 0;")
        return lines
    if mn == "cqo":   # rax → rdx:rax
        lines.append("rdx = ((int64_t)rax < 0) ? 0xFFFFFFFFFFFFFFFFULL : 0;")
        return lines

    # ── BSF / BSR ────────────────────────────────────────────────────────────
    if mn == "bsf":
        if len(ops) >= 2:
            dst, src = ops[0], ops[1]
            src_c = _operand_to_c_read(src, instr.address, instr.size, 8)
            lines.append(f"FLAG_ZF = ({src_c} == 0);")
            lines.append(f"if (!FLAG_ZF) {{")
            lines.append(f"  {_operand_to_c_write(dst, f'__builtin_ctzll({src_c})', instr.address, instr.size, 8)}")
            lines.append("}")
        return lines
    if mn == "bsr":
        if len(ops) >= 2:
            dst, src = ops[0], ops[1]
            src_c = _operand_to_c_read(src, instr.address, instr.size, 8)
            lines.append(f"FLAG_ZF = ({src_c} == 0);")
            lines.append(f"if (!FLAG_ZF) {{")
            lines.append(f"  {_operand_to_c_write(dst, f'63 - __builtin_clzll({src_c})', instr.address, instr.size, 8)}")
            lines.append("}")
        return lines

    # ── BSWAP ────────────────────────────────────────────────────────────────
    if mn == "bswap":
        dst = ops[0] if ops else "rax"
        dst_c = _operand_to_c_read(dst, instr.address, instr.size, 8)
        lines.append(_operand_to_c_write(dst, f"__builtin_bswap64({dst_c})",
                                          instr.address, instr.size, 8))
        return lines

    # ── POPCNT ───────────────────────────────────────────────────────────────
    if mn == "popcnt":
        if len(ops) >= 2:
            dst, src = ops[0], ops[1]
            src_c = _operand_to_c_read(src, instr.address, instr.size, 8)
            lines.append(_operand_to_c_write(dst, f"__builtin_popcountll({src_c})",
                                              instr.address, instr.size, 8))
            lines.append("FLAG_ZF = (rax == 0);")
        return lines

    # ── LZCNT / TZCNT ────────────────────────────────────────────────────────
    if mn == "lzcnt":
        if len(ops) >= 2:
            src_c = _operand_to_c_read(ops[1], instr.address, instr.size, 8)
            lines.append(_operand_to_c_write(ops[0], f"__builtin_clzll({src_c})",
                                              instr.address, instr.size, 8))
        return lines
    if mn == "tzcnt":
        if len(ops) >= 2:
            src_c = _operand_to_c_read(ops[1], instr.address, instr.size, 8)
            lines.append(_operand_to_c_write(ops[0], f"__builtin_ctzll({src_c})",
                                              instr.address, instr.size, 8))
        return lines

    # ── XORPS / PXOR (zero-idiom SSE) ────────────────────────────────────────
    if mn in ("xorps", "xorpd", "pxor") and len(ops) >= 2 and ops[0].lower() == ops[1].lower():
        # Used to zero XMM registers — not modelled
        lines.append(f"/* SSE zero-idiom: {instr.full_asm} (XMM not modelled) */")
        return lines

    # ── String operations (REP prefix) ────────────────────────────────────────
    if mn.startswith("rep") or mn in ("movsb","movsw","movsd","movsq",
                                       "stosb","stosw","stosd","stosq",
                                       "lodsb","lodsw","lodsd","lodsq",
                                       "scasb","scasw","scasd","scasq",
                                       "cmpsb","cmpsw","cmpsd","cmpsq"):
        lines.extend(_translate_string_op(instr))
        return lines

    # ── CLD / STD ────────────────────────────────────────────────────────────
    if mn == "cld":
        lines.append("FLAG_DF = 0;")
        return lines
    if mn == "std":
        lines.append("FLAG_DF = 1;")
        return lines

    # ── LAHF / SAHF ──────────────────────────────────────────────────────────
    if mn == "lahf":
        lines.append("rax = (rax & ~0xFF00ULL) | "
                     "((uint64_t)((FLAG_SF<<7)|(FLAG_ZF<<6)|(FLAG_AF<<4)|(FLAG_PF<<2)|1|(FLAG_CF)) << 8);")
        return lines
    if mn == "sahf":
        lines.append("{ uint8_t _ah = (uint8_t)(rax >> 8);")
        lines.append("FLAG_SF = (_ah >> 7) & 1; FLAG_ZF = (_ah >> 6) & 1;")
        lines.append("FLAG_AF = (_ah >> 4) & 1; FLAG_PF = (_ah >> 2) & 1;")
        lines.append("FLAG_CF = _ah & 1; }")
        return lines

    # ── PUSHFQ / POPFQ ───────────────────────────────────────────────────────
    if mn == "pushfq":
        rflags = "((uint64_t)FLAG_CF|(FLAG_PF<<2)|(FLAG_AF<<4)|(FLAG_ZF<<6)|(FLAG_SF<<7)|(FLAG_OF<<11))"
        lines.append(f"rsp -= 8; *(uint64_t*)rsp = {rflags};")
        return lines
    if mn == "popfq":
        lines.append("{ uint64_t _rfl = *(uint64_t*)rsp; rsp += 8;")
        lines.append("FLAG_CF = _rfl & 1; FLAG_PF = (_rfl >> 2) & 1;")
        lines.append("FLAG_AF = (_rfl >> 4) & 1; FLAG_ZF = (_rfl >> 6) & 1;")
        lines.append("FLAG_SF = (_rfl >> 7) & 1; FLAG_OF = (_rfl >> 11) & 1; }")
        return lines

    # ── MFENCE / SFENCE / LFENCE (memory barriers — NOP in C) ────────────────
    if mn in ("mfence", "sfence", "lfence", "pause"):
        lines.append(f"/* memory barrier: {mn} — treated as NOP */")
        return lines

    # ── INT ──────────────────────────────────────────────────────────────────
    if mn == "int":
        nr = ops[0] if ops else "0"
        lines.append(f"/* INT {nr} — not translated */")
        return lines

    # ── Unknown / unsupported ─────────────────────────────────────────────────
    lines.append(f"/* UNSUPPORTED: {instr.full_asm} */")
    return lines


# ── Internal helpers ──────────────────────────────────────────────────────────

def _parse_imm(s: str) -> int | None:
    """Parse an immediate string, return None if it looks like a register/memory."""
    s = s.strip().lstrip("*")
    if "[" in s:
        return None
    low = s.lower()
    if low in REG_MAP:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def _op_size(*operands: str) -> int:
    """Infer operand size in bytes from operand strings."""
    for op in operands:
        op = op.lower().strip()
        # Size keywords
        if "qword" in op:
            return 8
        if "dword" in op:
            return 4
        if "word" in op:
            return 2
        if "byte" in op:
            return 1
        # Register name lookup
        clean = op.strip("[]").strip()
        info = REG_MAP.get(clean)
        if info:
            return info.width // 8
    return 8  # default to 64-bit


def _infer_src_size(src: str, mnemonic: str) -> int:
    """Infer source size for movzx/movsx from operand or mnemonic."""
    # Mnemonic suffixes: movzbl = byte→long, movzbq = byte→quad
    if mnemonic.endswith("bl") or mnemonic.endswith("bq") or mnemonic.endswith("b"):
        return 1
    if mnemonic.endswith("wl") or mnemonic.endswith("wq") or mnemonic.endswith("w"):
        return 2
    if mnemonic.endswith("lq") or mnemonic.endswith("l"):
        return 4
    return _op_size(src)


def _lea_addr(mem_str: str, instr_addr: int, instr_size: int) -> str:
    """Compute the address expression for a LEA operand (no dereference)."""
    inner = mem_str.strip()
    for prefix in ("qword ptr ", "dword ptr ", "word ptr ", "byte ptr "):
        if inner.lower().startswith(prefix):
            inner = inner[len(prefix):]
    inner = inner.strip()
    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1]

    import re
    if "rip" in inner.lower():
        disp_match = re.search(r"[+-]\s*(?:0x[0-9a-fA-F]+|\d+)", inner)
        disp = 0
        if disp_match:
            try:
                disp = int(disp_match.group(0).replace(" ", ""), 0)
            except ValueError:
                disp = 0
        abs_addr = instr_addr + instr_size + disp
        return f"0x{abs_addr:x}ULL"
    else:
        return _normalise_mem_expr(inner)


def _translate_call(
    instr: Instruction,
    ops: list[str],
    plt_entries: dict[int, PLTEntry],
    func_map: dict[int, str] | None,
) -> list[str]:
    """Generate C for a call instruction."""
    lines: list[str] = []
    target_str = ops[0] if ops else ""
    target_int = _parse_imm(target_str)

    # Direct PLT call
    if target_int is not None and target_int in plt_entries:
        sym = plt_entries[target_int].symbol_name
        lines.extend(_make_extern_call(sym, instr))
        return lines

    # Intra-function call (to another known function)
    if target_int is not None and func_map and target_int in func_map:
        fname = func_map[target_int]
        lines.append(f"rax = func_{fname}(rdi, rsi, rdx, rcx, r8, r9); "
                     f"/* call {fname} */")
        return lines

    # Indirect call through register
    if target_int is None:
        target_c = _operand_to_c_read(target_str, instr.address, instr.size, 8)
        lines.append(
            f"rax = ((uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t))"
            f"(void*){target_c})(rdi, rsi, rdx, rcx, r8, r9); /* indirect call */"
        )
        return lines

    # Direct internal call (address known but not in func_map)
    if target_int is not None:
        lines.append(f"rax = func_{target_int:#010x}(rdi, rsi, rdx, rcx, r8, r9); "
                     f"/* call {target_int:#x} */")
    return lines


def _make_extern_call(sym: str, instr: Instruction, is_tail: bool = False) -> list[str]:
    """Generate the C call statement for a known external function."""
    lines: list[str] = []
    sig = get_signature(sym)

    # Prototype comment
    if sig:
        lines.append(f"/* [EXTERN: {sig['proto']}] */")
    else:
        lines.append(f"/* [EXTERN: {sym} — prototype unknown] */")

    if sig:
        arg_regs = ABI_ARG_REGS
        args_info = sig.get("args", [])
        c_args: list[str] = []
        for i, (ctype, _) in enumerate(args_info):
            if i >= len(arg_regs):
                break
            reg = arg_regs[i]
            if ctype in ("...", "va_list"):
                break
            c_args.append(f"({ctype}){reg}")
        # Variadic: append remaining arg registers with uint64_t cast
        if sig.get("variadic") and len(args_info) < len(arg_regs):
            for reg in arg_regs[len(args_info):]:
                c_args.append(f"(uint64_t){reg}")

        args_str = ", ".join(c_args)
        ret_type = sig["ret_type"]

        if ret_type == "void":
            lines.append(f"{sym}({args_str});")
            lines.append("rax = 0;")
        else:
            # Cast return value back to uint64_t
            if "*" in ret_type:
                lines.append(f"rax = (uint64_t)(uintptr_t){sym}({args_str});")
            elif ret_type in ("float", "double"):
                lines.append(f"{sym}({args_str}); /* float return — rax undefined */")
            else:
                lines.append(f"rax = (uint64_t)(int64_t)({ret_type}){sym}({args_str});")
    else:
        # Unknown: call with all 6 integer arg registers
        lines.append(
            f"rax = (uint64_t)(int64_t){sym}("
            "rdi, rsi, rdx, rcx, r8, r9); /* unknown proto */"
        )
    return lines


def _translate_syscall(instr: Instruction) -> list[str]:
    """Generate C for a syscall instruction."""
    lines: list[str] = []

    if instr.syscall_name:
        name = instr.syscall_name
        sig = get_signature(name)
        if sig:
            lines.append(f"/* [SYSCALL → {sig['proto']}] */")
            arg_regs = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]  # syscall ABI
            args_info = sig.get("args", [])
            c_args = []
            for i, (ctype, _) in enumerate(args_info):
                if i >= len(arg_regs):
                    break
                reg = arg_regs[i]
                c_args.append(f"({ctype}){reg}")
            args_str = ", ".join(c_args)
            ret_type = sig["ret_type"]
            if ret_type == "void":
                lines.append(f"{name}({args_str});")
                lines.append("rax = 0;")
            elif "*" in ret_type:
                lines.append(f"rax = (uint64_t)(uintptr_t){name}({args_str});")
            else:
                lines.append(f"rax = (uint64_t)(int64_t)({ret_type}){name}({args_str});")
        else:
            # Fallback to syscall() wrapper
            lines.append(f"/* [SYSCALL {name} — using syscall() fallback] */")
            lines.append(f"rax = (uint64_t)syscall(rax, rdi, rsi, rdx, r10, r8, r9);")
    else:
        # Unresolved syscall number
        lines.append("/* [SYSCALL — number unknown, using syscall() wrapper] */")
        lines.append("rax = (uint64_t)syscall(rax, rdi, rsi, rdx, r10, r8, r9);")

    return lines


def _translate_string_op(instr: Instruction) -> list[str]:
    """Translate rep movs/stos/lods/scas/cmps string operations."""
    lines: list[str] = []
    mn = instr.mnemonic.lower()
    has_rep  = "rep" in mn and "repe" not in mn and "repne" not in mn and "repnz" not in mn
    has_repe = "repe" in mn or "repz" in mn
    has_repne = "repne" in mn or "repnz" in mn

    if "movs" in mn:
        size = 8 if mn.endswith("q") else 4 if mn.endswith("d") else 2 if mn.endswith("w") else 1
        ctype = _UINT.get(size, "uint8_t")
        step = size if True else -size  # assume DF=0
        if has_rep:
            lines.append(f"while (rcx--) {{ *({ctype}*)rdi = *({ctype}*)rsi; rdi += {step}; rsi += {step}; }}")
        else:
            lines.append(f"*({ctype}*)rdi = *({ctype}*)rsi; rdi += {step}; rsi += {step};")
    elif "stos" in mn:
        size = 8 if mn.endswith("q") else 4 if mn.endswith("d") else 2 if mn.endswith("w") else 1
        ctype = _UINT.get(size, "uint8_t")
        reg = {"q": "rax", "d": "eax", "w": "ax", "b": "al"}.get(mn[-1], "rax")
        step = size
        if has_rep:
            lines.append(f"while (rcx--) {{ *({ctype}*)rdi = ({ctype}){_read_reg(reg)}; rdi += {step}; }}")
        else:
            lines.append(f"*({ctype}*)rdi = ({ctype}){_read_reg(reg)}; rdi += {step};")
    elif "lods" in mn:
        size = 8 if mn.endswith("q") else 4 if mn.endswith("d") else 2 if mn.endswith("w") else 1
        ctype = _UINT.get(size, "uint8_t")
        reg = {"q": "rax", "d": "eax", "w": "ax", "b": "al"}.get(mn[-1], "rax")
        lines.append(f"{_write_reg(reg, f'*({ctype}*)rsi')} rsi += {size};")
    elif "scas" in mn:
        size = 8 if mn.endswith("q") else 4 if mn.endswith("d") else 2 if mn.endswith("w") else 1
        ctype = _UINT.get(size, "uint8_t")
        reg = {"q": "rax", "d": "eax", "w": "ax", "b": "al"}.get(mn[-1], "rax")
        if has_repne:
            lines.append(f"while (rcx-- && *({ctype}*)rdi != ({ctype}){_read_reg(reg)}) rdi += {size};")
        elif has_repe:
            lines.append(f"while (rcx-- && *({ctype}*)rdi == ({ctype}){_read_reg(reg)}) rdi += {size};")
        else:
            lines.append(f"FLAG_ZF = (*({ctype}*)rdi == ({ctype}){_read_reg(reg)}); rdi += {size};")
    elif "cmps" in mn:
        size = 8 if mn.endswith("q") else 4 if mn.endswith("d") else 2 if mn.endswith("w") else 1
        ctype = _UINT.get(size, "uint8_t")
        if has_repne:
            lines.append(f"while (rcx-- && *({ctype}*)rdi == *({ctype}*)rsi) {{ rdi += {size}; rsi += {size}; }}")
            lines.append(f"FLAG_ZF = (*({ctype}*)rdi == *({ctype}*)rsi);")
        else:
            lines.append(f"FLAG_ZF = (*({ctype}*)rdi == *({ctype}*)rsi); rdi += {size}; rsi += {size};")
    else:
        lines.append(f"/* UNSUPPORTED string op: {instr.full_asm} */")
    return lines
