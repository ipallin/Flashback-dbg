"""
Intermediate representation data models for Flashback.

All three pipeline stages communicate through these data classes:
  Disassembler → List[Function]  (raw CFG)
  Enricher     → EnrichedCFG     (annotated)
  Translator   → str             (C source)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

# Sentinel for "return" edge destinations
RETURN_SENTINEL: int  = 0xFFFF_FFFF_FFFF_FFFE
# Sentinel for unresolved indirect jumps
INDIRECT_SENTINEL: int = 0xFFFF_FFFF_FFFF_FFFF


@dataclass
class Instruction:
    """A single disassembled x86-64 instruction with enrichment annotations."""
    address:   int
    size:      int
    mnemonic:  str
    op_str:    str
    raw_bytes: bytes

    # Filled by Enricher — None until enrichment pass
    syscall_name:     Optional[str]        = None
    syscall_args:     Optional[int]        = None  # arity
    syscall_headers:  Optional[list[str]]  = None
    ext_call_name:    Optional[str]        = None  # PLT symbol
    ext_call_proto:   Optional[str]        = None  # C prototype string
    ext_call_headers: Optional[list[str]]  = None
    comment:          Optional[str]        = None  # annotation note

    @property
    def full_asm(self) -> str:
        """Human-readable assembly string."""
        if self.op_str:
            return f"{self.mnemonic} {self.op_str}"
        return self.mnemonic

    @property
    def hex_bytes(self) -> str:
        return self.raw_bytes.hex(" ")


@dataclass
class BasicBlock:
    """
    A maximal straight-line sequence of instructions with a single entry point
    and potentially multiple exits.  The terminator is always the last instruction.
    """
    start_addr:   int
    end_addr:     int   # address of last instruction (inclusive)
    instructions: list[Instruction] = field(default_factory=list)

    # Structural annotations (filled by Enricher)
    loop_header:       bool          = False
    loop_latch:        bool          = False
    loop_id:           Optional[int] = None
    block_type:        str           = "generic"
    # block_type values: "entry" | "exit" | "loop_header" | "loop_latch" |
    #                    "call_site" | "syscall_site" | "tail_call" | "generic"
    is_function_entry: bool          = False
    label:             str           = ""

    def __post_init__(self) -> None:
        if not self.label:
            self.label = f"block_{self.start_addr:#010x}"

    @property
    def terminator(self) -> Instruction:
        return self.instructions[-1]

    @property
    def size(self) -> int:
        return sum(i.size for i in self.instructions)

    def __repr__(self) -> str:
        return (f"BasicBlock({self.start_addr:#x}..{self.end_addr:#x}, "
                f"{len(self.instructions)} instrs, type={self.block_type})")


@dataclass
class CFGEdge:
    """A directed control-flow edge between two basic blocks."""
    src:       int
    dst:       int
    kind:      str    # "unconditional" | "true_branch" | "false_branch" |
                      # "call_edge" | "ret_edge" | "indirect" | "fallthrough" | "tail_call"
    back_edge: bool = False

    def __repr__(self) -> str:
        be = " [BACK]" if self.back_edge else ""
        return f"CFGEdge({self.src:#x} --{self.kind}--> {self.dst:#x}{be})"


@dataclass
class PLTEntry:
    """A resolved PLT stub entry."""
    plt_addr:    int
    got_addr:    int
    symbol_name: str
    is_pie:      bool = False

    def __repr__(self) -> str:
        return f"PLTEntry({self.plt_addr:#x} → {self.symbol_name!r})"


@dataclass
class Function:
    """A single function with its complete CFG."""
    name:        str
    start_addr:  int
    end_addr:    int
    blocks:      dict[int, BasicBlock] = field(default_factory=dict)
    edges:       list[CFGEdge]         = field(default_factory=list)
    is_plt_stub: bool                  = False

    @property
    def entry_block(self) -> Optional[BasicBlock]:
        return self.blocks.get(self.start_addr)

    @property
    def sorted_blocks(self) -> list[BasicBlock]:
        return [self.blocks[a] for a in sorted(self.blocks)]

    def successors(self, addr: int) -> list[int]:
        """Return successor block addresses for the block at addr."""
        return [e.dst for e in self.edges if e.src == addr
                and e.dst not in (RETURN_SENTINEL, INDIRECT_SENTINEL)]

    def predecessors(self, addr: int) -> list[int]:
        return [e.src for e in self.edges if e.dst == addr]

    def __repr__(self) -> str:
        return (f"Function({self.name!r}, {self.start_addr:#x}, "
                f"{len(self.blocks)} blocks)")


@dataclass
class EnrichedCFG:
    """
    Top-level container produced by the Enricher and consumed by the Translator.
    Collects all functions, PLT entries, and required C headers into one place.
    """
    binary_path:      str
    functions:        list[Function]       = field(default_factory=list)
    plt_entries:      dict[int, PLTEntry]  = field(default_factory=dict)
    required_headers: set[str]             = field(default_factory=set)
    arch:             str                  = "x86_64"
    is_pie:           bool                 = False
    entry_point:      int                  = 0

    def function_by_addr(self, addr: int) -> Optional[Function]:
        for f in self.functions:
            if f.start_addr == addr:
                return f
        return None

    def function_by_name(self, name: str) -> Optional[Function]:
        for f in self.functions:
            if f.name == name:
                return f
        return None
