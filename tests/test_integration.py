"""
Pruebas de integración del pipeline completo (PI01-PI04).

Requieren los binarios en tests/binaries/.
Se saltan automáticamente si el binario no está presente.
"""

import pytest
from pathlib import Path

BINARIES_DIR = Path(__file__).parent / 'binaries'


def _binary(name: str) -> Path:
    return BINARIES_DIR / name


def _require(name: str):
    p = _binary(name)
    if not p.exists():
        pytest.skip(f'Binario de prueba no disponible: {p}')
    return p


# ------------------------------------------------------------------
# PI01 – Desensamblado produce CFG válido
# ------------------------------------------------------------------

class TestPI01_Desensamblado:

    def test_hello_world_produce_cfg(self):
        from flashback.arch.x86_64.disassembler import X86_64Disassembler
        p = _require('hello_world.elf')
        dis = X86_64Disassembler()
        cfg = dis.disassemble(str(p))
        assert len(cfg.functions) > 0
        assert len(cfg.basic_blocks) > 0
        assert len(cfg.instructions) > 0

    def test_hello_world_tiene_main(self):
        from flashback.arch.x86_64.disassembler import X86_64Disassembler
        p = _require('hello_world.elf')
        cfg = X86_64Disassembler().disassemble(str(p))
        names = {f.name for f in cfg.functions.values()}
        assert 'main' in names

    def test_binario_invalido_lanza_error(self, tmp_path):
        from flashback.arch.x86_64.disassembler import X86_64Disassembler, DisassemblerError
        not_elf = tmp_path / 'fake.elf'
        not_elf.write_bytes(b'This is not ELF')
        with pytest.raises(DisassemblerError):
            X86_64Disassembler().disassemble(str(not_elf))


# ------------------------------------------------------------------
# PI02 – Enriquecimiento anota correctamente
# ------------------------------------------------------------------

class TestPI02_Enriquecimiento:

    def test_hello_world_tiene_external_calls(self):
        from flashback.arch.x86_64.disassembler import X86_64Disassembler
        from flashback.arch.x86_64.enricher import X86_64Enricher
        p = _require('hello_world.elf')
        cfg = X86_64Disassembler().disassemble(str(p))
        enriched = X86_64Enricher().enrich(cfg)
        n_ext = sum(
            1 for i in enriched.instructions.values()
            if any(a.type == 'external_call' for a in i.annotations)
        )
        assert n_ext > 0

    def test_todos_los_bloques_tienen_functional_class(self):
        from flashback.arch.x86_64.disassembler import X86_64Disassembler
        from flashback.arch.x86_64.enricher import X86_64Enricher
        p = _require('hello_world.elf')
        cfg = X86_64Disassembler().disassemble(str(p))
        enriched = X86_64Enricher().enrich(cfg)
        for block in enriched.basic_blocks.values():
            assert any(a.type == 'functional_class' for a in block.annotations), \
                f'Bloque {block.address} sin functional_class'


# ------------------------------------------------------------------
# PI03 – Traducción produce C compilable
# ------------------------------------------------------------------

class TestPI03_Traduccion:

    def test_hello_world_genera_c(self):
        from flashback.arch.x86_64.disassembler import X86_64Disassembler
        from flashback.arch.x86_64.enricher import X86_64Enricher
        from flashback.core.translator import Translator
        p = _require('hello_world.elf')
        cfg = X86_64Disassembler().disassemble(str(p))
        enriched = X86_64Enricher().enrich(cfg)
        c_code = Translator().translate(enriched)
        assert len(c_code) > 0
        assert 'int main(' in c_code
        assert '#include <stdint.h>' in c_code

    def test_hello_world_c_compila(self, tmp_path):
        import subprocess
        from flashback.arch.x86_64.disassembler import X86_64Disassembler
        from flashback.arch.x86_64.enricher import X86_64Enricher
        from flashback.core.translator import Translator
        p = _require('hello_world.elf')
        cfg = X86_64Disassembler().disassemble(str(p))
        enriched = X86_64Enricher().enrich(cfg)
        c_code = Translator().translate(enriched)

        c_file = tmp_path / 'out.c'
        c_file.write_text(c_code, encoding='utf-8')
        result = subprocess.run(
            ['gcc', '-O0', '-Wall', '-Wno-unused-label', str(c_file), '-o', str(tmp_path / 'out')],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f'Compilación fallida:\n{result.stderr}'


# ------------------------------------------------------------------
# PI04 – Pipeline CLI completo
# ------------------------------------------------------------------

class TestPI04_CLI:

    def test_cli_hello_world(self, tmp_path):
        from flashback.ui.cli import main
        p = _require('hello_world.elf')
        out = tmp_path / 'hello_world.c'
        ret = main([str(p), '-o', str(out)])
        assert ret == 0
        assert out.exists()
        assert out.stat().st_size > 0

    def test_cli_export_cfg(self, tmp_path):
        from flashback.ui.cli import main
        p = _require('hello_world.elf')
        out_c   = tmp_path / 'out.c'
        out_cfg = tmp_path / 'out.json'
        ret = main([str(p), '-o', str(out_c), '--export-cfg', str(out_cfg)])
        assert ret == 0
        assert out_cfg.exists()
