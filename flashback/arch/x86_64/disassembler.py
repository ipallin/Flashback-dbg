"""
Disassembler x86-64: parsea binarios ELF con lief y desensambla con capstone.

Reemplaza el extractor basado en angr. No usa IR intermedio: trabaja
directamente sobre los bytes del binario.

Responsabilidades:
  - Validar que el binario es ELF x86-64.
  - Encontrar funciones desde la tabla de símbolos y el entry point.
  - Resolver entradas de la PLT (funciones de librería importadas).
  - Desensamblar las secciones ejecutables con capstone.
  - Devolver RawInstruction[] + BinaryMeta para que CFGBuilder construya el grafo.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import capstone
import lief

from flashback.arch.base import Disassembler
from flashback.core.cfg_builder import BinaryMeta, RawInstruction

logger = logging.getLogger(__name__)

# Funciones del runtime de C que no forman parte del código de usuario.
_C_RUNTIME = frozenset({
    '_start', 'frame_dummy', '_init', '_fini',
    '__libc_csu_init', '__libc_csu_fini',
    'register_tm_clones', 'deregister_tm_clones',
    '__do_global_dtors_aux', '__libc_start_main',
    'deregister_tm_clones', '__x86.get_pc_thunk.bx',
})


class DisassemblerError(Exception):
    pass


class X86_64Disassembler(Disassembler):
    """
    Implementación del Disassembler para ELF x86-64 con lief + capstone.
    """

    def __init__(self):
        try:
            self.capstone_version = str(capstone.__version__)
        except Exception:
            self.capstone_version = 'unknown'
        try:
            self.lief_version = lief.__version__
        except Exception:
            self.lief_version = 'unknown'

    def load(self, binary_path: str) -> tuple[dict[int, RawInstruction], BinaryMeta]:
        path = Path(binary_path)
        self._validate(path)

        logger.info(f'Cargando {path.name} con lief')
        elf = lief.parse(str(path))
        if elf is None:
            raise DisassemblerError(f'lief no pudo parsear: {path}')

        self._validate_arch(elf)

        func_symbols = self._find_func_symbols(elf)
        plt_symbols  = self._find_plt_symbols(elf)
        all_insns    = self._disassemble(elf)

        meta = BinaryMeta(
            path=str(path.resolve()),
            sha256=_sha256(path),
            entry_point=elf.entrypoint,
            architecture='amd64',
            is_pie=bool(elf.is_pie),
            is_stripped=_is_stripped(elf),
            func_symbols=func_symbols,
            plt_symbols=plt_symbols,
        )

        logger.info(
            f'Desensamblado: {len(func_symbols)} funciones, '
            f'{len(plt_symbols)} PLT, {len(all_insns)} instrucciones'
        )
        return all_insns, meta

    # ------------------------------------------------------------------
    # Validación
    # ------------------------------------------------------------------

    def _validate(self, path: Path) -> None:
        if not path.exists():
            raise DisassemblerError(f'Binario no encontrado: {path}')
        if not path.is_file():
            raise DisassemblerError(f'La ruta no es un fichero: {path}')
        with open(path, 'rb') as f:
            magic = f.read(4)
        if magic != b'\x7fELF':
            raise DisassemblerError(f'El fichero no es ELF: {path}')

    def _validate_arch(self, elf) -> None:
        arch = elf.header.machine_type
        if arch != lief.ELF.ARCH.X86_64:
            raise DisassemblerError(f'Arquitectura no soportada: {arch}. Solo x86-64.')

    # ------------------------------------------------------------------
    # Descubrimiento de funciones
    # ------------------------------------------------------------------

    def _find_func_symbols(self, elf) -> dict[int, str]:
        """Encuentra funciones de usuario desde la tabla de símbolos."""
        funcs: dict[int, str] = {}

        # Entry point siempre incluido
        if elf.entrypoint:
            funcs[elf.entrypoint] = '_start'

        # Símbolos estáticos
        for sym in elf.symbols:
            if (sym.type == lief.ELF.Symbol.TYPE.FUNC
                    and sym.value != 0
                    and sym.name
                    and sym.name not in _C_RUNTIME):
                funcs[sym.value] = sym.name

        # Símbolos dinámicos definidos en este binario (no importados)
        for sym in elf.dynamic_symbols:
            if (sym.type == lief.ELF.Symbol.TYPE.FUNC
                    and sym.value != 0
                    and sym.name
                    and sym.name not in _C_RUNTIME
                    and sym.value not in funcs):
                funcs[sym.value] = sym.name

        return funcs

    def _find_plt_symbols(self, elf) -> dict[int, str]:
        """
        Resuelve las entradas de la PLT (stubs de funciones importadas).

        Estrategia:
        1. Ordenar las relocalizaciones JUMP_SLOT por dirección GOT.
        2. Cada relocalización corresponde a una entrada PLT consecutiva.
        3. La primera entrada PLT es el resolver; las siguientes son los stubs.
        """
        plt_map: dict[int, str] = {}

        # Encontrar la sección PLT
        plt_section = None
        for sect_name in ('.plt', '.plt.sec', '.plt.got'):
            try:
                s = elf.get_section(sect_name)
                if s:
                    plt_section = s
                    break
            except Exception:
                continue

        if plt_section is None:
            return plt_map

        plt_base      = plt_section.virtual_address
        plt_entry_size = 16  # tamaño estándar en x86-64
        is_plt_sec     = plt_section.name in ('.plt.sec', '.plt.got')
        if is_plt_sec:
            plt_entry_size = 8  # .plt.sec usa entradas de 8 bytes

        # Recolectar relocalizaciones PLT/GOT ordenadas
        try:
            relocs = sorted(
                [r for r in elf.pltgot_relocations if r.symbol and r.symbol.name],
                key=lambda r: r.address,
            )
        except Exception:
            return plt_map

        start_idx = 0 if is_plt_sec else 1  # Saltar el resolver en .plt estándar

        for i, reloc in enumerate(relocs):
            plt_addr = plt_base + (start_idx + i) * plt_entry_size
            name = _strip_symbol_decorations(reloc.symbol.name)
            if name:
                plt_map[plt_addr] = name

        return plt_map

    # ------------------------------------------------------------------
    # Desensamblado
    # ------------------------------------------------------------------

    def _disassemble(self, elf) -> dict[int, RawInstruction]:
        """Desensambla todas las secciones ejecutables."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True

        all_insns: dict[int, RawInstruction] = {}

        for section in elf.sections:
            if not section.has(lief.ELF.Section.FLAGS.EXECINSTR):
                continue
            # Saltar la PLT (stubs externos, no son código de usuario)
            if section.name in ('.plt', '.plt.sec', '.plt.got'):
                continue

            data = bytes(section.content)
            base = section.virtual_address

            for cs_insn in cs.disasm(data, base):
                regs_read, regs_written = _get_reg_access(cs_insn)
                all_insns[cs_insn.address] = RawInstruction(
                    address=cs_insn.address,
                    mnemonic=cs_insn.mnemonic,
                    operands=cs_insn.op_str,
                    bytes_hex=cs_insn.bytes.hex(),
                    size=cs_insn.size,
                    registers_read=regs_read,
                    registers_written=regs_written,
                )

        return all_insns


# ---------------------------------------------------------------------------
# Utilidades privadas
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _is_stripped(elf) -> bool:
    func_syms = [
        s for s in elf.symbols
        if s.type == lief.ELF.Symbol.TYPE.FUNC and s.name
    ]
    return len(func_syms) == 0


def _strip_symbol_decorations(name: str) -> str:
    """Quita @plt, @@GLIBC_2.x, etc."""
    for sep in ('@@', '@'):
        if sep in name:
            name = name.split(sep)[0]
    return name.strip()


def _get_reg_access(cs_insn) -> tuple[list[str], list[str]]:
    """Extrae registros leídos y escritos de una instrucción capstone."""
    try:
        r_ids, w_ids = cs_insn.regs_access()
        return (
            [cs_insn.reg_name(r) for r in r_ids],
            [cs_insn.reg_name(w) for w in w_ids],
        )
    except Exception:
        return [], []
