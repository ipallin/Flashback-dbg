"""
Flashback CLI entry point.

Usage:
    python -m flashback <binary> [options]
    flashback <binary> [options]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .disassembler import Disassembler
from .enricher import Enricher
from .translator import translate


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="flashback",
        description=(
            "Flashback — reconstruct compilable C code from x86-64 ELF binaries.\n"
            "Translates disassembled binary code into low-level C via enriched CFG analysis."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  flashback ./hello            # translate all functions, write to stdout
  flashback ./hello -o out.c   # write translated C to out.c
  flashback ./hello -f main    # translate only 'main'
  flashback ./hello --list-functions
  flashback ./hello --list-plt
""",
    )

    p.add_argument(
        "binary",
        metavar="BINARY",
        help="path to the x86-64 ELF binary to analyse",
    )
    p.add_argument(
        "-o", "--output",
        metavar="FILE",
        default=None,
        help="write generated C to FILE instead of stdout",
    )
    p.add_argument(
        "-f", "--function",
        metavar="NAME",
        default=None,
        help="translate only the function named NAME",
    )
    p.add_argument(
        "--no-comments",
        action="store_true",
        default=False,
        help="suppress traceability comments in generated C",
    )
    p.add_argument(
        "--list-functions",
        action="store_true",
        default=False,
        help="list all discovered functions and exit",
    )
    p.add_argument(
        "--list-plt",
        action="store_true",
        default=False,
        help="list all resolved PLT entries and exit",
    )
    p.add_argument(
        "--base-addr",
        metavar="ADDR",
        default=None,
        help="override load base address (hex or decimal)",
    )
    p.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="increase verbosity (-v = INFO, -vv = DEBUG)",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return p


def _setup_logging(verbosity: int) -> None:
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(verbosity, len(levels) - 1)]
    logging.basicConfig(
        level=level,
        format="%(levelname)s  %(name)s: %(message)s",
        stream=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)

    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"error: file not found: {binary_path}", file=sys.stderr)
        return 1
    if not binary_path.is_file():
        print(f"error: not a file: {binary_path}", file=sys.stderr)
        return 1

    # Optional base-address override
    base_addr: int | None = None
    if args.base_addr is not None:
        try:
            base_addr = int(args.base_addr, 0)
        except ValueError:
            print(f"error: invalid --base-addr value: {args.base_addr!r}", file=sys.stderr)
            return 1

    # ── Phase 1: Disassemble ──────────────────────────────────────────────────
    try:
        dis = Disassembler(str(binary_path), base_addr=base_addr)
        cfg = dis.disassemble()
    except Exception as exc:
        print(f"error: disassembly failed — {exc}", file=sys.stderr)
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        return 1

    # ── Informational listing modes ───────────────────────────────────────────
    if args.list_functions:
        _print_functions(cfg)
        return 0

    if args.list_plt:
        _print_plt(cfg)
        return 0

    # ── Phase 2: Enrich ───────────────────────────────────────────────────────
    try:
        cfg = Enricher(cfg).enrich()
    except Exception as exc:
        print(f"error: enrichment failed — {exc}", file=sys.stderr)
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        return 1

    # ── Phase 3: Translate ────────────────────────────────────────────────────
    try:
        c_source = translate(
            cfg,
            emit_comments=not args.no_comments,
            only_function=args.function,
        )
    except Exception as exc:
        print(f"error: translation failed — {exc}", file=sys.stderr)
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        return 1

    # ── Output ────────────────────────────────────────────────────────────────
    if args.output:
        out_path = Path(args.output)
        try:
            out_path.write_text(c_source, encoding="utf-8")
            print(f"Written to {out_path}", file=sys.stderr)
        except OSError as exc:
            print(f"error: cannot write output file — {exc}", file=sys.stderr)
            return 1
    else:
        sys.stdout.write(c_source)

    return 0


# ─── Listing helpers ─────────────────────────────────────────────────────────

def _print_functions(cfg) -> None:
    funcs = sorted(cfg.functions, key=lambda f: f.start_addr)
    print(f"{'Address':<18}  {'Name':<40}  {'Blocks':>6}  {'PLT'}")
    print("-" * 72)
    for f in funcs:
        is_plt = "yes" if f.is_plt_stub else ""
        print(f"  {f.start_addr:#016x}  {f.name:<40}  {len(f.blocks):>6}  {is_plt}")
    print(f"\n{len(funcs)} function(s) found.")


def _print_plt(cfg) -> None:
    entries = sorted(cfg.plt_entries.values(), key=lambda e: e.plt_addr)
    if not entries:
        print("No PLT entries found.")
        return
    print(f"{'PLT addr':<18}  {'GOT addr':<18}  {'Symbol'}")
    print("-" * 60)
    for e in entries:
        print(f"  {e.plt_addr:#016x}  {e.got_addr:#016x}  {e.symbol_name}")
    print(f"\n{len(entries)} PLT entry/entries found.")


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(main())
