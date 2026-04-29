"""
CLI de Flashback.

Uso:
    python flashback.py <binario.elf> -o <salida.c>
    python flashback.py <binario.elf> -o <salida.c> --export-cfg <salida.json>
    python flashback.py <binario.elf> -o <salida.c> --functions main,foo
    python flashback.py <binario.elf> -o <salida.c> --granularity block
    python flashback.py <binario.elf> -o <salida.c> --verbose
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

VERSION = '0.1.0'


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='flashback',
        description='Binary-to-C reconstruction with bidirectional traceability.',
    )
    p.add_argument('binary', help='Binario ELF x86-64 de entrada')
    p.add_argument('-o', '--output', help='Fichero C de salida (default: <binario>.c)')
    p.add_argument(
        '--export-cfg', metavar='FILE',
        help='Exportar el CFG enriquecido a JSON',
    )
    p.add_argument(
        '--functions', metavar='FUNC1,FUNC2',
        help='Traducir solo estas funciones (separadas por coma)',
    )
    p.add_argument(
        '--granularity',
        choices=['none', 'block', 'instruction', 'selective'],
        default='selective',
        help='Política de trazabilidad (default: selective)',
    )
    p.add_argument('--tui', action='store_true', help='Lanzar interfaz TUI (roadmap)')
    p.add_argument('-v', '--verbose', action='store_true', help='Logging detallado')
    p.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    return p


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S',
    )


def run(args: argparse.Namespace) -> int:
    from flashback.arch.x86_64.disassembler import X86_64Disassembler, DisassemblerError
    from flashback.arch.x86_64.enricher import X86_64Enricher
    from flashback.core.translator import Translator, TranslatorError
    from flashback.core.exporter import Exporter, ExporterError

    binary = Path(args.binary)
    output = Path(args.output) if args.output else binary.with_suffix('.c')
    logger = logging.getLogger('flashback')

    try:
        # 1. Desensamblar
        logger.info(f'[*] Cargando ELF: {binary.name}')
        dis = X86_64Disassembler()
        cfg = dis.disassemble(str(binary))
        logger.info(
            f'[*] Desensamblado: {sum(1 for f in cfg.functions.values() if not f.is_plt)} funciones, '
            f'{len(cfg.instructions)} instrucciones'
        )
        logger.info(f'[*] CFG construido: {len(cfg.basic_blocks)} bloques, {len(cfg.edges)} aristas')

        # 2. Enriquecer
        enricher = X86_64Enricher()
        enriched = enricher.enrich(cfg, granularity=args.granularity)
        ext_calls = sum(
            1 for i in enriched.instructions.values()
            if any(a.type == 'external_call' for a in i.annotations)
        )
        syscalls = sum(
            1 for i in enriched.instructions.values()
            if any(a.type == 'syscall' for a in i.annotations)
        )
        logger.info(f'[*] Enriquecimiento: {ext_calls} llamadas externas, {syscalls} syscalls')

        # 3. Exportar CFG si se pidió
        if args.export_cfg:
            exp = Exporter()
            exp.save(enriched, args.export_cfg)
            logger.info(f'[*] CFG exportado en {args.export_cfg}')

        # 4. Traducir
        translator = Translator(tool_version=VERSION)
        c_code = translator.translate(enriched)
        logger.info(f'[*] Traducción: {len(enriched.basic_blocks)} bloques → {c_code.count(chr(10))} líneas de C')

        # 5. Guardar
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(c_code, encoding='utf-8')
        logger.info(f'[*] Salida escrita en {output}')
        print(f'{output}')
        return 0

    except DisassemblerError as e:
        print(f'Error de desensamblado: {e}', file=sys.stderr)
        return 1
    except (TranslatorError, ExporterError) as e:
        print(f'Error: {e}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Interrumpido', file=sys.stderr)
        return 130


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    if args.tui:
        print('TUI no implementada todavía (roadmap v0.3)', file=sys.stderr)
        return 1

    return run(args)


if __name__ == '__main__':
    sys.exit(main())
