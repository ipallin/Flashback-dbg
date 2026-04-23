"""
CLI principal del prototipo tfe-reconstructor.

Subcomandos:
    extract  <binario>              → CFG inicial (.cfg.json)
    enrich   <cfg.json>             → CFG enriquecido (.ecfg.json)
    translate <ecfg.json>           → código C (.c)
    compile  <fichero.c>            → binario recompilado
    compare  <original> <recompilado> [input] → comparar trazas
    all      <binario>              → pipeline completo end-to-end

Uso:
    python -m src.cli.main extract binarios_prueba/hello
    python -m src.cli.main all binarios_prueba/hello
    python -m src.cli.main all binarios_prueba/hello --granularity instruction
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

from src.extractor.extractor import Extractor, ExtractorError
from src.enricher.enricher import Enricher
from src.translator.translator import Translator, TranslatorError
from src.persistence.persistence import Persistence, PersistenceError

# Versión de la herramienta
VERSION = '0.1.0'


def main() -> int:
    """Punto de entrada de la CLI. Devuelve el código de salida."""
    parser = _build_parser()
    args = parser.parse_args()

    _configure_logging(args.verbose)
    logger = logging.getLogger(__name__)

    try:
        if args.command == 'extract':
            return cmd_extract(args)
        elif args.command == 'enrich':
            return cmd_enrich(args)
        elif args.command == 'translate':
            return cmd_translate(args)
        elif args.command == 'compile':
            return cmd_compile(args)
        elif args.command == 'compare':
            return cmd_compare(args)
        elif args.command == 'all':
            return cmd_all(args)
        else:
            parser.print_help()
            return 1
    except (ExtractorError, PersistenceError, TranslatorError) as e:
        logger.error(str(e))
        return 1
    except KeyboardInterrupt:
        logger.info('Interrumpido por el usuario')
        return 130


# ------------------------------------------------------------------
# Comandos
# ------------------------------------------------------------------

def cmd_extract(args) -> int:
    logger = logging.getLogger('extract')
    p = Persistence()

    extractor = Extractor(args.binary, generator_version=VERSION)
    cfg = extractor.extract()

    output = p.artifact_path(args.binary, 'initial')
    p.save(cfg, str(output))
    print(f'CFG inicial guardado en: {output}')
    return 0


def cmd_enrich(args) -> int:
    logger = logging.getLogger('enrich')
    p = Persistence()

    cfg = p.load(args.cfg_file)
    enricher = Enricher(granularity=args.granularity)
    enriched = enricher.enrich(cfg)

    # La ruta de salida: sustituir .cfg.json por .ecfg.json
    output = Path(args.cfg_file).with_suffix('').with_suffix('.ecfg.json')
    if args.cfg_file.endswith('.cfg.json'):
        output = Path(args.cfg_file.replace('.cfg.json', '.ecfg.json'))

    p.save(enriched, str(output))
    print(f'CFG enriquecido guardado en: {output}')
    return 0


def cmd_translate(args) -> int:
    p = Persistence()

    cfg = p.load(args.ecfg_file)
    translator = Translator(tool_version=VERSION)
    c_code = translator.translate(cfg)

    output = Path(args.ecfg_file.replace('.ecfg.json', '.c'))
    output.write_text(c_code, encoding='utf-8')
    print(f'Código C generado en: {output}')
    return 0


def cmd_compile(args) -> int:
    c_file = Path(args.c_file)
    target  = getattr(args, 'target', 'native')
    suffix  = f'.{target}' if target != 'native' else '.reconstruido'
    output_bin = c_file.with_suffix(suffix)

    # Seleccionar compilador segun arquitectura destino
    compilers = {
        'native':   'gcc',
        'x86_64':   'gcc',
        'arm64':    'aarch64-linux-gnu-gcc',
        'aarch64':  'aarch64-linux-gnu-gcc',
        'riscv64':  'riscv64-linux-gnu-gcc',
    }
    compiler = compilers.get(target, 'gcc')

    cmd = [compiler, '-O0', '-g', str(c_file), '-o', str(output_bin)]
    print(f'Compilando ({target}): {" ".join(cmd)}')

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print('Error de compilacion:')
        print(result.stderr)
        return result.returncode

    print(f'Binario recompilado ({target}): {output_bin}')
    return 0


def cmd_compare(args) -> int:
    """
    Compara las trazas de ejecución del binario original y el recompilado.
    Versión inicial: compara las trazas de syscalls usando strace.
    TODO semana 9: implementar comparación de trazas __trace() vs gdb.
    """
    import shutil

    if not shutil.which('strace'):
        print('strace no disponible. Instalar con: apt install strace')
        return 1

    original = Path(args.original)
    recompiled = Path(args.recompiled)
    input_data = args.input if hasattr(args, 'input') else None

    def run_strace(binary: Path) -> str:
        cmd = ['strace', '-e', 'trace=all', '-o', '/dev/stderr', str(binary)]
        result = subprocess.run(cmd, capture_output=True, text=True, input=input_data)
        return result.stderr

    print('Ejecutando binario original...')
    trace_orig = run_strace(original)

    print('Ejecutando binario recompilado...')
    trace_recomp = run_strace(recompiled)

    # Comparación muy básica
    orig_lines = set(trace_orig.splitlines())
    recomp_lines = set(trace_recomp.splitlines())

    only_orig = orig_lines - recomp_lines
    only_recomp = recomp_lines - orig_lines

    report_lines = [
        f'Comparación de trazas: {original.name} vs {recompiled.name}',
        f'Syscalls solo en original: {len(only_orig)}',
        f'Syscalls solo en recompilado: {len(only_recomp)}',
    ]

    if only_orig:
        report_lines.append('\nPresentes solo en original:')
        for line in sorted(only_orig)[:10]:
            report_lines.append(f'  - {line}')

    if only_recomp:
        report_lines.append('\nPresentes solo en recompilado:')
        for line in sorted(only_recomp)[:10]:
            report_lines.append(f'  + {line}')

    report = '\n'.join(report_lines)
    print(report)

    output = original.with_suffix('.comparacion.txt')
    output.write_text(report, encoding='utf-8')
    print(f'\nInforme guardado en: {output}')

    return 0 if not only_orig and not only_recomp else 1


def cmd_all(args) -> int:
    """Ejecuta el pipeline completo: extract → enrich → translate → compile."""
    logger = logging.getLogger('all')
    binary = args.binary

    print(f'Pipeline completo sobre: {binary}')
    print('─' * 50)

    # 1. Extract
    print('[1/4] Extrayendo CFG...')
    result = cmd_extract(args)
    if result != 0:
        return result

    # 2. Enrich
    p = Persistence()
    cfg_file = str(p.artifact_path(binary, 'initial'))
    args.cfg_file = cfg_file
    print('[2/4] Enriqueciendo CFG...')
    result = cmd_enrich(args)
    if result != 0:
        return result

    # 3. Translate
    ecfg_file = cfg_file.replace('.cfg.json', '.ecfg.json')
    args.ecfg_file = ecfg_file
    print('[3/4] Traduciendo a C...')
    result = cmd_translate(args)
    if result != 0:
        return result

    # 4. Compile
    c_file = ecfg_file.replace('.ecfg.json', '.c')
    args.c_file = c_file
    print('[4/4] Compilando...')
    result = cmd_compile(args)
    if result != 0:
        return result

    print('─' * 50)
    print('Pipeline completado.')
    return 0


# ------------------------------------------------------------------
# Parser
# ------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='reconstructor',
        description='Binary-to-C reconstruction via enriched CFG',
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('-v', '--verbose', action='store_true', help='Logging detallado')

    sub = parser.add_subparsers(dest='command', metavar='COMMAND')

    # extract
    p_extract = sub.add_parser('extract', help='Extraer CFG inicial de un binario')
    p_extract.add_argument('binary', help='Ruta al binario ELF')

    # enrich
    p_enrich = sub.add_parser('enrich', help='Enriquecer un CFG inicial')
    p_enrich.add_argument('cfg_file', help='Ruta al fichero .cfg.json')
    p_enrich.add_argument(
        '--granularity',
        choices=['none', 'block', 'instruction', 'selective'],
        default='selective',
        help='Política de trazabilidad (default: selective)',
    )

    # translate
    p_translate = sub.add_parser('translate', help='Traducir CFG enriquecido a C')
    p_translate.add_argument('ecfg_file', help='Ruta al fichero .ecfg.json')

    # compile
    p_compile = sub.add_parser('compile', help='Compilar código C generado')
    p_compile.add_argument('c_file', help='Ruta al fichero .c')

    # compare
    p_compare = sub.add_parser('compare', help='Comparar trazas de ejecución')
    p_compare.add_argument('original', help='Binario original')
    p_compare.add_argument('recompiled', help='Binario recompilado')
    p_compare.add_argument('--input', help='Entrada estándar para ambos binarios', default=None)

    # all
    p_all = sub.add_parser('all', help='Pipeline completo end-to-end')
    p_all.add_argument('binary', help='Ruta al binario ELF')
    p_all.add_argument(
        '--granularity',
        choices=['none', 'block', 'instruction', 'selective'],
        default='selective',
        help='Política de trazabilidad (default: selective)',
    )

    return parser


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S',
    )
    # Silenciar librerías ruidosas salvo en modo verbose
    if not verbose:
        for lib in ('angr', 'cle', 'pyvex', 'claripy'):
            logging.getLogger(lib).setLevel(logging.ERROR)


if __name__ == '__main__':
    sys.exit(main())
