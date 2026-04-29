"""
Translator: genera código C portable a partir del CFG enriquecido.

Tres decisiones de diseño que habilitan la portabilidad:
  1. Stack simulado: el stack original se modela como array estático.
  2. Llamadas libc nativas: las external_call se emiten como llamadas directas,
     con argumentos casteados desde uint64_t. El compilador destino resuelve la ABI.
  3. Syscalls vía libc: las instrucciones syscall se mapean a funciones wrapper
     de la libc destino, cuyo número varía por arquitectura.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from flashback.core.models import EnrichedCFG, BasicBlock, Instruction, ExternalCallAnnotation

logger = logging.getLogger(__name__)

_REGISTERS_64 = [
    'rax', 'rbx', 'rcx', 'rdx',
    'rsi', 'rdi', 'rbp', 'rsp',
    'r8',  'r9',  'r10', 'r11',
    'r12', 'r13', 'r14', 'r15',
    'rip', 'rflags',
]

_FLAGS = ['ZF', 'CF', 'SF', 'OF', 'PF']

_REG_32_TO_64 = {
    'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
    'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
    'r8d': 'r8',  'r9d': 'r9',  'r10d': 'r10', 'r11d': 'r11',
    'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15',
}
_REG_16_TO_64 = {
    'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
    'si': 'rsi', 'di': 'rdi', 'bp': 'rbp', 'sp': 'rsp',
}
_REG_8L_TO_64 = {
    'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx',
    'sil': 'rsi', 'dil': 'rdi', 'bpl': 'rbp', 'spl': 'rsp',
}
_REG_8H_TO_64 = {'ah': 'rax', 'bh': 'rbx', 'ch': 'rcx', 'dh': 'rdx'}

_INCLUDES = [
    '#include <stdint.h>',
    '#include <stdio.h>',
    '#include <stdlib.h>',
    '#include <string.h>',
    '#include <unistd.h>',
    '#include <sys/syscall.h>',
    '#include <sys/mman.h>',
    '#include <fcntl.h>',
]

_SIM_STACK_SIZE_MB = 8
_SIM_HEAP_SIZE_MB  = 64

# Mapeo de función libc → (tipo_retorno, [argumentos_con_cast])
_LIBC_CALL_MAP: dict[str, tuple[str, list[str]]] = {
    'printf':   ('int',     ['(const char*)(uintptr_t)rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']),
    'fprintf':  ('int',     ['(FILE*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi', 'rdx', 'rcx', 'r8', 'r9']),
    'scanf':    ('int',     ['(const char*)(uintptr_t)rdi', '(void*)(uintptr_t)rsi']),
    'puts':     ('int',     ['(const char*)(uintptr_t)rdi']),
    'putchar':  ('int',     ['(int)rdi']),
    'getchar':  ('int',     []),
    'malloc':   ('void*',   ['(size_t)rdi']),
    'calloc':   ('void*',   ['(size_t)rdi', '(size_t)rsi']),
    'realloc':  ('void*',   ['(void*)(uintptr_t)rdi', '(size_t)rsi']),
    'free':     ('void',    ['(void*)(uintptr_t)rdi']),
    'memcpy':   ('void*',   ['(void*)(uintptr_t)rdi', '(const void*)(uintptr_t)rsi', '(size_t)rdx']),
    'memset':   ('void*',   ['(void*)(uintptr_t)rdi', '(int)rsi', '(size_t)rdx']),
    'strlen':   ('size_t',  ['(const char*)(uintptr_t)rdi']),
    'strcpy':   ('char*',   ['(char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi']),
    'strncpy':  ('char*',   ['(char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi', '(size_t)rdx']),
    'strcmp':   ('int',     ['(const char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi']),
    'strncmp':  ('int',     ['(const char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi', '(size_t)rdx']),
    'open':     ('int',     ['(const char*)(uintptr_t)rdi', '(int)rsi', '(int)rdx']),
    'read':     ('ssize_t', ['(int)rdi', '(void*)(uintptr_t)rsi', '(size_t)rdx']),
    'write':    ('ssize_t', ['(int)rdi', '(const void*)(uintptr_t)rsi', '(size_t)rdx']),
    'close':    ('int',     ['(int)rdi']),
    'exit':     ('void',    ['(int)rdi']),
    'atoi':     ('int',     ['(const char*)(uintptr_t)rdi']),
    'strtol':   ('long',    ['(const char*)(uintptr_t)rdi', '(char**)(uintptr_t)rsi', '(int)rdx']),
    'fopen':    ('FILE*',   ['(const char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi']),
    'fclose':   ('int',     ['(FILE*)(uintptr_t)rdi']),
    'fread':    ('size_t',  ['(void*)(uintptr_t)rdi', '(size_t)rsi', '(size_t)rdx', '(FILE*)(uintptr_t)rcx']),
    'fwrite':   ('size_t',  ['(const void*)(uintptr_t)rdi', '(size_t)rsi', '(size_t)rdx', '(FILE*)(uintptr_t)rcx']),
    'perror':   ('void',    ['(const char*)(uintptr_t)rdi']),
    'mmap':     ('void*',   ['(void*)(uintptr_t)rdi', '(size_t)rsi', '(int)rdx', '(int)rcx', '(int)r8', '(off_t)r9']),
    'munmap':   ('int',     ['(void*)(uintptr_t)rdi', '(size_t)rsi']),
    'socket':   ('int',     ['(int)rdi', '(int)rsi', '(int)rdx']),
    'connect':  ('int',     ['(int)rdi', '(const struct sockaddr*)(uintptr_t)rsi', '(socklen_t)rdx']),
    'send':     ('ssize_t', ['(int)rdi', '(const void*)(uintptr_t)rsi', '(size_t)rdx', '(int)rcx']),
    'recv':     ('ssize_t', ['(int)rdi', '(void*)(uintptr_t)rsi', '(size_t)rdx', '(int)rcx']),
    'fork':     ('pid_t',   []),
    'execve':   ('int',     ['(const char*)(uintptr_t)rdi', '(char* const*)(uintptr_t)rsi', '(char* const*)(uintptr_t)rdx']),
    'waitpid':  ('pid_t',   ['(pid_t)rdi', '(int*)(uintptr_t)rsi', '(int)rdx']),
}

_SYSCALL_LIBC_MAP: dict[str, str] = {
    'read': 'read', 'write': 'write', 'open': 'open', 'close': 'close',
    'exit': 'exit', 'exit_group': 'exit', 'mmap': 'mmap', 'munmap': 'munmap',
    'fork': 'fork', 'execve': 'execve', 'waitpid': 'waitpid',
}


class TranslatorError(Exception):
    pass


class Translator:
    def __init__(self, tool_version: str = '0.1.0',
                 sim_stack_mb: int = _SIM_STACK_SIZE_MB,
                 sim_heap_mb: int = _SIM_HEAP_SIZE_MB):
        self.tool_version = tool_version
        self.sim_stack_mb = sim_stack_mb
        self.sim_heap_mb = sim_heap_mb

    def translate(self, cfg: EnrichedCFG) -> str:
        if cfg.metadata.pipeline_stage != 'enriched':
            raise TranslatorError(
                f'Se esperaba pipeline_stage=enriched, recibido: {cfg.metadata.pipeline_stage}'
            )
        logger.info(f'Traduciendo CFG de {cfg.binary_info.filename}')

        # Addresses that will have a C function definition (non-PLT, non-external)
        self._defined_funcs: set[str] = {
            addr for addr, func in cfg.functions.items()
            if not func.is_plt and not func.is_external
        }

        sections = [
            self._emit_header(cfg),
            self._emit_includes(),
            self._emit_portability_macros(),
            self._emit_simulated_memory(),
            self._emit_trace_runtime(),
            self._emit_registers(),
            self._emit_flags(),
            self._emit_function_declarations(cfg),
            self._emit_functions(cfg),
            self._emit_entry_point(cfg),
        ]
        return '\n\n'.join(s for s in sections if s)

    # ------------------------------------------------------------------
    # Secciones del fichero C generado
    # ------------------------------------------------------------------

    def _emit_header(self, cfg: EnrichedCFG) -> str:
        now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        fn = cfg.binary_info.filename
        return (
            f'/*\n'
            f' * Generado por Flashback v{self.tool_version} — {now}\n'
            f' *\n'
            f' * Binario: {fn} ({cfg.binary_info.architecture})\n'
            f' * SHA256 : {cfg.binary_info.sha256}\n'
            f' * Entry  : {cfg.binary_info.entry_point}\n'
            f' *\n'
            f' * Compila en cualquier plataforma de 64 bits:\n'
            f' *   x86-64 : gcc -O0 -g {fn}.c -o output\n'
            f' *   ARM64  : aarch64-linux-gnu-gcc -O0 {fn}.c -o output\n'
            f' *   RISC-V : riscv64-linux-gnu-gcc -O0 {fn}.c -o output\n'
            f' *\n'
            f' * No editar manualmente — generado por Flashback.\n'
            f' */'
        )

    def _emit_includes(self) -> str:
        return '\n'.join(_INCLUDES)

    def _emit_portability_macros(self) -> str:
        return (
            '/* Macros portables para accesos a memoria simulada */\n'
            '#define SIM_READ8(addr)        (*(uint8_t  *)(uintptr_t)(addr))\n'
            '#define SIM_READ16(addr)       (*(uint16_t *)(uintptr_t)(addr))\n'
            '#define SIM_READ32(addr)       (*(uint32_t *)(uintptr_t)(addr))\n'
            '#define SIM_READ64(addr)       (*(uint64_t *)(uintptr_t)(addr))\n'
            '#define SIM_WRITE8(addr, val)  (*(uint8_t  *)(uintptr_t)(addr) = (uint8_t )(val))\n'
            '#define SIM_WRITE16(addr, val) (*(uint16_t *)(uintptr_t)(addr) = (uint16_t)(val))\n'
            '#define SIM_WRITE32(addr, val) (*(uint32_t *)(uintptr_t)(addr) = (uint32_t)(val))\n'
            '#define SIM_WRITE64(addr, val) (*(uint64_t *)(uintptr_t)(addr) = (uint64_t)(val))\n'
            '#define SIM_PTR(addr)          ((void *)(uintptr_t)(addr))\n'
            '#define SIM_CSTR(addr)         ((const char *)(uintptr_t)(addr))'
        )

    def _emit_simulated_memory(self) -> str:
        stack_bytes = self.sim_stack_mb * 1024 * 1024
        heap_bytes  = self.sim_heap_mb  * 1024 * 1024
        return (
            f'/* Stack y heap simulados — aíslan el programa del stack real del proceso */\n'
            f'#define SIM_STACK_SIZE ((size_t){stack_bytes}U)\n'
            f'#define SIM_HEAP_SIZE  ((size_t){heap_bytes}U)\n'
            f'static uint8_t __sim_stack[SIM_STACK_SIZE];\n'
            f'static uint8_t __sim_heap[SIM_HEAP_SIZE];\n'
            f'static uint8_t *__sim_heap_ptr = __sim_heap;\n'
            f'typedef char __assert_64bit_ptr[(sizeof(uintptr_t) == 8) ? 1 : -1];\n'
            f'typedef char __assert_uint64_size[(sizeof(uint64_t) == 8) ? 1 : -1];'
        )

    def _emit_trace_runtime(self) -> str:
        return (
            '/* Runtime de trazabilidad — __trace(addr) registra cada punto de ejecución */\n'
            '#define TRACE_BUFFER_SIZE ((uint64_t)(1u << 20))\n'
            'static uint64_t __trace_buffer[TRACE_BUFFER_SIZE];\n'
            'static uint64_t __trace_idx = 0;\n'
            'static inline void __trace(uint64_t addr) {\n'
            '    __trace_buffer[__trace_idx & (TRACE_BUFFER_SIZE - 1)] = addr;\n'
            '    __trace_idx++;\n'
            '}\n'
            'static void __trace_dump(const char *path) {\n'
            '    FILE *f = fopen(path, "wb");\n'
            '    if (!f) { perror("__trace_dump"); return; }\n'
            '    uint64_t n = (__trace_idx < TRACE_BUFFER_SIZE) ? __trace_idx : TRACE_BUFFER_SIZE;\n'
            '    if (fwrite(__trace_buffer, sizeof(uint64_t), (size_t)n, f) != (size_t)n)\n'
            '        perror("__trace_dump: fwrite");\n'
            '    fclose(f);\n'
            '}'
        )

    def _emit_registers(self) -> str:
        lines = ['/* Registros x86-64 simulados como variables globales */']
        for reg in _REGISTERS_64:
            lines.append(f'static uint64_t {reg} = 0;')
        return '\n'.join(lines)

    def _emit_flags(self) -> str:
        lines = ['/* Flags de CPU simulados */']
        for flag in _FLAGS:
            lines.append(f'static uint8_t {flag} = 0;')
        return '\n'.join(lines)

    def _emit_function_declarations(self, cfg: EnrichedCFG) -> str:
        lines = ['/* Declaraciones adelantadas */']
        for addr, func in cfg.functions.items():
            if func.is_plt or func.is_external:
                continue
            lines.append(f'static void func_{addr.replace("0x", "")}(void);  /* {func.name} */')
        return '\n'.join(lines)

    def _emit_functions(self, cfg: EnrichedCFG) -> str:
        parts = []
        for addr, func in cfg.functions.items():
            if func.is_plt or func.is_external:
                continue
            parts.append(self._emit_function(func, cfg))
        return '\n\n'.join(parts)

    def _emit_function(self, func, cfg: EnrichedCFG) -> str:
        func_id = func.address.replace('0x', '')
        lines = [
            f'/* {"=" * 60} */',
            f'/* {func.name}  @  {func.address} */',
            f'/* {"=" * 60} */',
            f'static void func_{func_id}(void) {{',
        ]
        for block_addr in func.blocks:
            block = cfg.basic_blocks.get(block_addr)
            if block:
                lines.append(self._emit_block(block, cfg))
        lines.append('}')
        return '\n'.join(lines)

    def _emit_block(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        block_id = block.address.replace('0x', '')
        lines = [f'  block_{block_id}:']
        for insn_addr in block.instructions:
            insn = cfg.instructions.get(insn_addr)
            if insn:
                lines.append(self._emit_instruction(insn))
        lines.append(self._emit_block_exit(block, cfg))
        return '\n'.join(lines)

    def _emit_instruction(self, insn: Instruction) -> str:
        lines = []
        if any(a.type == 'trace_point' for a in insn.annotations):
            lines.append(f'    __trace({insn.address}ULL);')
        lines.append(f'    /* {insn.address}: {insn.mnemonic} {insn.operands} */')

        ext_calls    = [a for a in insn.annotations if a.type == 'external_call']
        syscall_anns = [a for a in insn.annotations if a.type == 'syscall']

        if ext_calls and insn.mnemonic == 'call':
            lines.append(self._emit_external_call(ext_calls[0]))
        elif syscall_anns and insn.mnemonic == 'syscall':
            lines.append(self._emit_syscall(syscall_anns[0]))
        else:
            lines.append(f'    {self._translate_instruction(insn)}')
        return '\n'.join(lines)

    def _emit_external_call(self, ann) -> str:
        func_name = ann.function_name
        call_info = _LIBC_CALL_MAP.get(func_name)
        if call_info is None:
            return (
                f'    /* EXTERNAL CALL sin prototipo: {func_name}() */\n'
                f'    rax = (uint64_t)(uintptr_t){func_name}(SIM_PTR(rdi), rsi, rdx, rcx, r8, r9);'
            )
        ret_type, args = call_info
        args_str = ', '.join(args)
        if ret_type == 'void':
            return f'    {func_name}({args_str});'
        return f'    rax = (uint64_t)(uintptr_t){func_name}({args_str});'

    def _emit_syscall(self, ann) -> str:
        syscall_name = ann.syscall_name or 'unknown'
        libc_func = _SYSCALL_LIBC_MAP.get(syscall_name)
        if libc_func and libc_func in _LIBC_CALL_MAP:
            fake_ann = ExternalCallAnnotation(added_by='translator', function_name=libc_func)
            return self._emit_external_call(fake_ann)
        num = ann.syscall_number if ann.syscall_number >= 0 else 'rax'
        return (
            f'    /* SYSCALL portable: {syscall_name} (num={ann.syscall_number}) */\n'
            f'    rax = (uint64_t)syscall((long){num}, '
            f'(long)rdi, (long)rsi, (long)rdx, (long)rcx, (long)r8, (long)r9);'
        )

    def _translate_instruction(self, insn: Instruction) -> str:
        m   = insn.mnemonic
        ops = insn.operands

        if m == 'nop':
            return '/* nop */'
        if m == 'push':
            reg = ops.strip()
            return f'rsp -= 8; SIM_WRITE64(rsp, {reg});'
        if m == 'pop':
            reg = ops.strip()
            w = _reg_write(reg, 'SIM_READ64(rsp)')
            if w:
                return f'{w} rsp += 8;'
        if m in ('ret', 'retn'):
            return 'return;'
        if m == 'leave':
            return 'rsp = rbp; rbp = SIM_READ64(rsp); rsp += 8;'
        if m == 'mov':
            dst, src = _split_operands(ops)
            if dst and src:
                c_src = _reg_to_c(src)
                if c_src is not None and _reg_to_c(dst) is not None:
                    return _reg_write(dst, c_src)
                mem = _mem_to_c(dst, 'write', src) or _mem_to_c(src, 'read', dst)
                if mem:
                    return mem
        if m in ('movsx', 'movsxd'):
            dst, src = _split_operands(ops)
            c_s = _reg_to_c(src) if src else None
            if dst and c_s is not None:
                return _reg_write(dst, f'(uint64_t)(int64_t)(int32_t){c_s}')
        if m == 'movzx':
            dst, src = _split_operands(ops)
            c_s = _reg_to_c(src) if src else None
            if dst and c_s is not None:
                return _reg_write(dst, f'(uint64_t){c_s}')
        if m == 'lea':
            dst, src = _split_operands(ops)
            if dst and src:
                addr = _mem_addr_expr(src)
                if addr:
                    return _reg_write(dst, f'(uint64_t)({addr})')
        if m == 'add':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'{c_d} + {c_s}')
        if m == 'sub':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'{c_d} - {c_s}')
        if m == 'inc':
            reg = ops.strip()
            c_o = _reg_to_c(reg)
            if c_o is not None:
                return _reg_write(reg, f'{c_o} + 1')
        if m == 'dec':
            reg = ops.strip()
            c_o = _reg_to_c(reg)
            if c_o is not None:
                return _reg_write(reg, f'{c_o} - 1')
        if m == 'imul':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'(uint64_t)((int64_t){c_d} * (int64_t){c_s})')
        if m == 'neg':
            reg = ops.strip()
            c_o = _reg_to_c(reg)
            if c_o is not None:
                return _reg_write(reg, f'(uint64_t)(-(int64_t){c_o})')
        if m == 'xor':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                if dst == src:
                    return f'{_reg_base(dst)} = 0;  /* xor reg,reg */'
                return _reg_write(dst, f'{c_d} ^ {c_s}')
        if m == 'and':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'{c_d} & {c_s}')
        if m == 'or':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'{c_d} | {c_s}')
        if m == 'not':
            reg = ops.strip()
            c_o = _reg_to_c(reg)
            if c_o is not None:
                return _reg_write(reg, f'~{c_o}')
        if m in ('shl', 'sal'):
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'{c_d} << ({c_s} & 63)')
        if m == 'shr':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'{c_d} >> ({c_s} & 63)')
        if m == 'sar':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'(uint64_t)((int64_t){c_d} >> ({c_s} & 63))')
        if m == 'cmp':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d and c_s:
                return (f'{{ uint64_t __t = {c_d} - {c_s}; '
                        f'ZF=(__t==0); SF=(uint8_t)(__t>>63); CF=({c_d}<{c_s}); }}')
        if m == 'test':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d and c_s:
                return (f'{{ uint64_t __t = {c_d} & {c_s}; '
                        f'ZF=(__t==0); SF=(uint8_t)(__t>>63); CF=0; }}')
        _setcc = {
            'sete': 'ZF', 'setz': 'ZF', 'setne': '!ZF', 'setnz': '!ZF',
            'setl': '(SF!=OF)', 'setg': '(!ZF&&(SF==OF))',
            'setge': '(SF==OF)', 'setle': '(ZF||(SF!=OF))',
            'seta': '(!CF&&!ZF)', 'setb': 'CF',
        }
        if m in _setcc:
            reg = ops.strip()
            if _reg_to_c(reg) is not None:
                return _reg_write(reg, f'(uint8_t)({_setcc[m]})')
        if m == 'call':
            target = _resolve_direct_target(ops)
            if target:
                if target in self._defined_funcs:
                    return f'func_{target.replace("0x", "")}();'
                return f'/* CALL {ops} — función no definida en este CFG */'
            return f'/* INDIRECT CALL: {ops} — omitido */\n    fprintf(stderr, "indirect call\\n");'

        return (
            f'/* UNSUPPORTED: {m} {ops} */\n'
            f'    fprintf(stderr, "UNSUPPORTED: {m} {ops}\\n");\n'
            f'    abort();'
        )

    def _emit_block_exit(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        if not block.successors:
            return ''
        if len(block.successors) == 1:
            succ = block.successors[0]
            if succ in cfg.basic_blocks:
                return f'  goto block_{succ.replace("0x", "")};'
            return ''
        if len(block.successors) == 2:
            t = block.successors[0].replace('0x', '')
            f_ = block.successors[1].replace('0x', '')
            return f'  if (ZF) goto block_{t};\n  goto block_{f_};'
        return (
            '  /* UNSUPPORTED: salto indirecto */\n'
            '  fprintf(stderr, "indirect jump\\n");\n'
            '  abort();'
        )

    def _emit_entry_point(self, cfg: EnrichedCFG) -> str:
        entry    = cfg.binary_info.entry_point
        entry_id = entry.replace('0x', '')
        ef       = cfg.functions.get(entry)
        fname    = ef.name if ef else f'func_{entry_id}'
        return (
            f'/* Punto de entrada — rsp apunta al stack simulado, no al stack real */\n'
            f'int main(int argc, char *argv[]) {{\n'
            f'    rsp  = (uint64_t)(uintptr_t)(__sim_stack + SIM_STACK_SIZE - 8);\n'
            f'    rsp &= ~(uint64_t)0xFULL;\n'
            f'    rdi = (uint64_t)(uint32_t)argc;\n'
            f'    rsi = (uint64_t)(uintptr_t)argv;\n'
            f'    func_{entry_id}();  /* {fname} @ {entry} */\n'
            f'    __trace_dump("flashback_trace.bin");\n'
            f'    return (int)(uint32_t)rax;\n'
            f'}}'
        )


# ---------------------------------------------------------------------------
# Utilidades privadas
# ---------------------------------------------------------------------------

def _split_operands(ops: str) -> tuple[str | None, str | None]:
    parts = ops.split(',', 1)
    return (parts[0].strip(), parts[1].strip()) if len(parts) == 2 else (None, None)


def _reg_to_c(operand: str) -> str | None:
    """Rvalue expression for reading a register or immediate. Cast but not an lvalue."""
    o = operand.strip()
    if o in _REGISTERS_64:
        return o
    if o in _REG_32_TO_64:
        return f'(uint32_t){_REG_32_TO_64[o]}'
    if o in _REG_16_TO_64:
        return f'(uint16_t){_REG_16_TO_64[o]}'
    if o in _REG_8L_TO_64:
        return f'(uint8_t){_REG_8L_TO_64[o]}'
    if o in _REG_8H_TO_64:
        return f'(uint8_t)({_REG_8H_TO_64[o]} >> 8)'
    if o.startswith('0x'):
        return f'((uint64_t){o}ULL)'
    if o.lstrip('-').isdigit():
        v = int(o)
        return f'((int64_t){v}LL)' if v < 0 else f'((uint64_t){v}ULL)'
    return None


def _reg_base(operand: str) -> str | None:
    """Returns the underlying 64-bit register name for any register alias."""
    o = operand.strip()
    if o in _REGISTERS_64:
        return o
    for table in (_REG_32_TO_64, _REG_16_TO_64, _REG_8L_TO_64, _REG_8H_TO_64):
        if o in table:
            return table[o]
    return None


def _reg_write(dst: str, src_expr: str) -> str | None:
    """
    Generates a valid C assignment statement writing src_expr into dst.

    Handles x86-64 partial-register semantics:
      - 32-bit writes zero-extend to 64 bits (Intel manual Vol.1 §3.4.1.1)
      - 16/8-bit writes merge into the base register (upper bits preserved)
    """
    d = dst.strip()
    if d in _REGISTERS_64:
        return f'{d} = {src_expr};'
    if d in _REG_32_TO_64:
        base = _REG_32_TO_64[d]
        return f'{base} = (uint64_t)(uint32_t)({src_expr});'
    if d in _REG_16_TO_64:
        base = _REG_16_TO_64[d]
        return f'{base} = ({base} & ~(uint64_t)0xFFFFULL) | (uint64_t)(uint16_t)({src_expr});'
    if d in _REG_8L_TO_64:
        base = _REG_8L_TO_64[d]
        return f'{base} = ({base} & ~(uint64_t)0xFFULL) | (uint64_t)(uint8_t)({src_expr});'
    if d in _REG_8H_TO_64:
        base = _REG_8H_TO_64[d]
        return f'{base} = ({base} & ~(uint64_t)0xFF00ULL) | ((uint64_t)(uint8_t)({src_expr}) << 8);'
    return None


def _mem_addr_expr(mem: str) -> str | None:
    s = mem.strip()
    for p in ('qword ptr ', 'dword ptr ', 'word ptr ', 'byte ptr '):
        if s.startswith(p):
            s = s[len(p):]
            break
    return s[1:-1].strip() if s.startswith('[') and s.endswith(']') else None


def _mem_to_c(operand: str, direction: str, other: str) -> str | None:
    s = operand.strip()
    size = 64
    for p, b in [('qword ptr ', 64), ('dword ptr ', 32), ('word ptr ', 16), ('byte ptr ', 8)]:
        if s.startswith(p):
            s = s[len(p):]
            size = b
            break
    if not (s.startswith('[') and s.endswith(']')):
        return None
    addr = s[1:-1].strip()
    if direction == 'read':
        if _reg_to_c(other) is not None:
            return _reg_write(other, f'(uint64_t)SIM_READ{size}({addr})')
        return None
    src = _reg_to_c(other)
    return f'SIM_WRITE{size}({addr}, {src});' if src else None


def _resolve_direct_target(operands: str) -> str | None:
    o = operands.strip()
    try:
        if o.startswith('0x'):
            return hex(int(o, 16))
        if o.lstrip('-').isdigit():
            return hex(int(o))
    except ValueError:
        pass
    return None
