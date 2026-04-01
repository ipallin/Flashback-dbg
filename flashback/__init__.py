"""
Flashback — Reconstruction of low-level executable code from disassembled binaries
via enriched control flow graph analysis.

Pipeline:
  1. Disassembler  → builds CFG from ELF binary (basic blocks + edges + PLT stubs)
  2. Enricher      → annotates CFG with semantic information (syscalls, extern calls, loops)
  3. Translator    → converts enriched CFG to compilable low-level C code
"""

__version__ = "0.1.0"
__author__  = "Igor Pallin Toquero"
