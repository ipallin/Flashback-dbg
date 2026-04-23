"""
Tests del Translator (v0.2.0 - modo portable).
"""
import pytest
from src.cfg.model import (
    EnrichedCFG, BinaryInfo, Metadata, Function, BasicBlock, Instruction,
    TracePointAnnotation, ExternalCallAnnotation, SyscallAnnotation,
)
from src.translator.translator import (
    Translator, TranslatorError, _reg_to_c, _split_operands, _mem_addr_expr,
)


def _make_enriched_cfg() -> EnrichedCFG:
    cfg = EnrichedCFG(
        metadata=Metadata(generator='test', generator_version='0.0.1',
                          pipeline_stage='enriched'),
        binary_info=BinaryInfo(filename='test.elf', sha256='b'*64,
                               entry_point='0x401000'),
    )
    cfg.functions['0x401000'] = Function(
        address='0x401000', name='main', is_plt=False, is_external=False,
        entry_block='0x401000', blocks=['0x401000'],
        called_from=[], calls_to=[], annotations=[],
    )
    cfg.basic_blocks['0x401000'] = BasicBlock(
        address='0x401000', size=4, function='0x401000',
        instructions=['0x401000', '0x401001'],
        successors=[], predecessors=[], annotations=[],
    )
    cfg.instructions['0x401000'] = Instruction(
        address='0x401000', mnemonic='push', operands='rbp',
        bytes='55', size=1, block='0x401000',
        registers_read=[], registers_written=[], memory_accesses=[], annotations=[],
    )
    cfg.instructions['0x401001'] = Instruction(
        address='0x401001', mnemonic='ret', operands='',
        bytes='c3', size=1, block='0x401000',
        registers_read=[], registers_written=[], memory_accesses=[], annotations=[],
    )
    return cfg


# ------------------------------------------------------------------
# Tests básicos
# ------------------------------------------------------------------

class TestTranslatorBasic:

    def test_translate_returns_string(self):
        assert isinstance(Translator().translate(_make_enriched_cfg()), str)

    def test_translate_fails_on_initial_cfg(self):
        cfg = _make_enriched_cfg()
        cfg.metadata.pipeline_stage = 'initial'
        with pytest.raises(TranslatorError):
            Translator().translate(cfg)

    def test_output_includes_stdint(self):
        assert '#include <stdint.h>' in Translator().translate(_make_enriched_cfg())

    def test_output_includes_registers(self):
        out = Translator().translate(_make_enriched_cfg())
        assert 'static uint64_t rax' in out
        assert 'static uint64_t rsp' in out

    def test_output_includes_flags(self):
        out = Translator().translate(_make_enriched_cfg())
        assert 'static uint8_t ZF' in out

    def test_output_includes_trace_runtime(self):
        out = Translator().translate(_make_enriched_cfg())
        assert '__trace_buffer' in out

    def test_output_includes_main(self):
        assert 'int main(' in Translator().translate(_make_enriched_cfg())

    def test_output_has_function_label(self):
        assert 'func_401000' in Translator().translate(_make_enriched_cfg())


# ------------------------------------------------------------------
# Tests de portabilidad (los más importantes ahora)
# ------------------------------------------------------------------

class TestPortability:

    def test_sim_stack_array_present(self):
        out = Translator().translate(_make_enriched_cfg())
        assert '__sim_stack' in out

    def test_rsp_initialised_to_sim_stack(self):
        out = Translator().translate(_make_enriched_cfg())
        assert '__sim_stack + SIM_STACK_SIZE' in out

    def test_no_builtin_frame_address(self):
        """El código NO debe usar el stack real del proceso."""
        out = Translator().translate(_make_enriched_cfg())
        assert '__builtin_frame_address' not in out

    def test_sim_read_write_macros_present(self):
        out = Translator().translate(_make_enriched_cfg())
        assert 'SIM_READ64' in out
        assert 'SIM_WRITE64' in out

    def test_push_uses_sim_write(self):
        """push debe escribir en el stack simulado, no en el stack real."""
        out = Translator().translate(_make_enriched_cfg())
        assert 'SIM_WRITE64(rsp,' in out

    def test_pop_uses_sim_read(self):
        cfg = _make_enriched_cfg()
        cfg.basic_blocks['0x401000'].instructions.append('0x401002')
        cfg.instructions['0x401002'] = Instruction(
            address='0x401002', mnemonic='pop', operands='rbp',
            bytes='5d', size=1, block='0x401000',
            registers_read=[], registers_written=[], memory_accesses=[], annotations=[],
        )
        out = Translator().translate(cfg)
        assert 'SIM_READ64(rsp)' in out

    def test_uintptr_t_used_in_casts(self):
        """Los casts de puntero deben usar uintptr_t para portabilidad."""
        out = Translator().translate(_make_enriched_cfg())
        assert 'uintptr_t' in out

    def test_compile_time_assertion_64bit(self):
        """Debe haber una asercion en tiempo de compilacion para sistemas de 64 bits."""
        out = Translator().translate(_make_enriched_cfg())
        assert '__assert_64bit_ptr' in out

    def test_header_mentions_arm64(self):
        """La cabecera debe mencionar que compila en ARM64."""
        out = Translator().translate(_make_enriched_cfg())
        assert 'ARM64' in out or 'arm64' in out.lower() or 'aarch64' in out

    def test_custom_stack_size(self):
        t = Translator(sim_stack_mb=16)
        out = t.translate(_make_enriched_cfg())
        assert str(16 * 1024 * 1024) in out


# ------------------------------------------------------------------
# Tests de llamadas externas portables
# ------------------------------------------------------------------

class TestExternalCallPortable:

    def _make_cfg_with_call(self, func_name: str) -> EnrichedCFG:
        cfg = _make_enriched_cfg()
        cfg.functions['0x401030'] = Function(
            address='0x401030', name=func_name, is_plt=True, is_external=True,
            entry_block='0x401030', blocks=[], called_from=[], calls_to=[], annotations=[],
        )
        cfg.basic_blocks['0x401000'].instructions.append('0x401005')
        cfg.instructions['0x401005'] = Instruction(
            address='0x401005', mnemonic='call', operands='0x401030',
            bytes='e8000000', size=5, block='0x401000',
            registers_read=[], registers_written=[], memory_accesses=[],
            annotations=[ExternalCallAnnotation(
                added_by='enricher', function_name=func_name,
                library='libc.so.6',
            )],
        )
        return cfg

    def test_printf_call_uses_uintptr_t_cast(self):
        out = Translator().translate(self._make_cfg_with_call('printf'))
        assert 'printf(' in out
        assert 'uintptr_t' in out

    def test_known_function_emits_direct_call(self):
        out = Translator().translate(self._make_cfg_with_call('printf'))
        assert 'printf(' in out
        assert 'TODO' not in out

    def test_void_function_no_rax_assignment(self):
        out = Translator().translate(self._make_cfg_with_call('free'))
        assert 'free(' in out
        # free es void: no debe asignar rax
        lines_with_free = [l for l in out.splitlines() if 'free(' in l and 'rax' in l]
        assert len(lines_with_free) == 0

    def test_malloc_returns_to_rax(self):
        out = Translator().translate(self._make_cfg_with_call('malloc'))
        lines = [l for l in out.splitlines() if 'malloc(' in l]
        assert any('rax' in l for l in lines)

    def test_unknown_function_emits_generic_call(self):
        out = Translator().translate(self._make_cfg_with_call('funcion_xyz_desconocida'))
        assert 'funcion_xyz_desconocida(' in out


# ------------------------------------------------------------------
# Tests de syscalls portables
# ------------------------------------------------------------------

class TestSyscallPortable:

    def _make_cfg_with_syscall(self, num: int, name: str) -> EnrichedCFG:
        cfg = _make_enriched_cfg()
        cfg.basic_blocks['0x401000'].instructions.append('0x401010')
        cfg.instructions['0x401010'] = Instruction(
            address='0x401010', mnemonic='syscall', operands='',
            bytes='0f05', size=2, block='0x401000',
            registers_read=[], registers_written=[], memory_accesses=[],
            annotations=[SyscallAnnotation(
                added_by='enricher', syscall_number=num, syscall_name=name,
                argument_registers=['rdi', 'rsi', 'rdx'],
            )],
        )
        return cfg

    def test_write_syscall_becomes_libc_write(self):
        out = Translator().translate(self._make_cfg_with_syscall(1, 'write'))
        assert 'write(' in out
        # No debe emitir el numero de syscall directamente
        assert 'syscall(1,' not in out.replace(' ', '')

    def test_unknown_syscall_uses_portable_syscall(self):
        out = Translator().translate(self._make_cfg_with_syscall(999, 'unknown_syscall'))
        assert 'syscall(' in out

    def test_exit_syscall_becomes_libc_exit(self):
        out = Translator().translate(self._make_cfg_with_syscall(60, 'exit'))
        assert 'exit(' in out


# ------------------------------------------------------------------
# Tests de trazabilidad
# ------------------------------------------------------------------

class TestTraceability:

    def test_trace_point_emits_trace_call(self):
        cfg = _make_enriched_cfg()
        cfg.instructions['0x401000'].annotations.append(
            TracePointAnnotation(added_by='enricher', reason='block_entry')
        )
        out = Translator().translate(cfg)
        assert '__trace(0x401000ULL)' in out

    def test_no_trace_point_no_trace_call(self):
        out = Translator().translate(_make_enriched_cfg())
        assert '__trace(0x401000ULL)' not in out

    def test_static_traceability_comment_always_present(self):
        out = Translator().translate(_make_enriched_cfg())
        assert '/* 0x401000: push rbp */' in out


# ------------------------------------------------------------------
# Tests de instrucciones
# ------------------------------------------------------------------

class TestInstructionTranslation:

    def test_nop(self):
        cfg = _make_enriched_cfg()
        cfg.instructions['0x401000'].mnemonic = 'nop'
        cfg.instructions['0x401000'].operands = ''
        assert '/* nop */' in Translator().translate(cfg)

    def test_ret_translates(self):
        assert 'return;' in Translator().translate(_make_enriched_cfg())

    def test_xor_same_reg_zeroes(self):
        cfg = _make_enriched_cfg()
        cfg.instructions['0x401000'].mnemonic = 'xor'
        cfg.instructions['0x401000'].operands = 'eax, eax'
        out = Translator().translate(cfg)
        assert '= 0;' in out

    def test_cmp_updates_flags(self):
        cfg = _make_enriched_cfg()
        cfg.instructions['0x401000'].mnemonic = 'cmp'
        cfg.instructions['0x401000'].operands = 'rax, rbx'
        out = Translator().translate(cfg)
        assert 'ZF' in out
        assert 'CF' in out


# ------------------------------------------------------------------
# Tests de utilidades
# ------------------------------------------------------------------

class TestRegToC:

    def test_64bit(self):
        assert _reg_to_c('rax') == 'rax'

    def test_32bit_cast(self):
        r = _reg_to_c('eax')
        assert 'uint32_t' in r and 'rax' in r

    def test_8bit_high(self):
        r = _reg_to_c('ah')
        assert 'rax' in r and '>> 8' in r

    def test_hex_immediate(self):
        assert '0x10' in _reg_to_c('0x10')

    def test_negative_immediate(self):
        r = _reg_to_c('-4')
        assert 'int64_t' in r

    def test_memory_operand_returns_none(self):
        assert _reg_to_c('qword ptr [rbp - 8]') is None


class TestMemAddrExpr:

    def test_simple(self):
        assert _mem_addr_expr('[rbp - 8]') == 'rbp - 8'

    def test_with_size_prefix(self):
        assert _mem_addr_expr('qword ptr [rbp - 8]') == 'rbp - 8'

    def test_not_memory(self):
        assert _mem_addr_expr('rax') is None
