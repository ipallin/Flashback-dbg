# Flashback — Arquitectura y Referencia Técnica

> Documento generado automáticamente para el repositorio `Flashback-dbg`.  
> Propósito: proporcionar una visión completa del código, sus piezas, y cómo encajan entre sí.

---

## Tabla de contenidos

1. [¿Qué es Flashback?](#1-qué-es-flashback)
2. [Estructura del repositorio](#2-estructura-del-repositorio)
3. [Pipeline de procesamiento](#3-pipeline-de-procesamiento)
4. [Módulo `core/` — Lógica agnóstica a la arquitectura](#4-módulo-core--lógica-agnóstica-a-la-arquitectura)
   - [models.py — Estructuras de datos centrales](#41-modelspy--estructuras-de-datos-centrales)
   - [cfg_builder.py — Construcción del grafo](#42-cfg_builderpy--construcción-del-grafo)
   - [translator.py — Generación de C](#43-translatorpy--generación-de-c)
   - [exporter.py — Serialización JSON](#44-exporterpy--serialización-json)
5. [Módulo `arch/` — Implementaciones por arquitectura](#5-módulo-arch--implementaciones-por-arquitectura)
   - [base.py — Interfaces abstractas](#51-basepy--interfaces-abstractas)
   - [x86_64/disassembler.py](#52-x86_64disassemblerpy)
   - [x86_64/enricher.py](#53-x86_64enricherpy)
   - [x86_64/register_map.py](#54-x86_64register_mappy)
   - [x86_64/calling_convention.py](#55-x86_64calling_conventionpy)
   - [x86_64/instruction_sem.py](#56-x86_64instruction_sempy)
   - [x86_64/syscall_table.py](#57-x86_64syscall_tablepy)
6. [Módulo `ui/` — Interfaces de usuario](#6-módulo-ui--interfaces-de-usuario)
7. [Suite de tests](#7-suite-de-tests)
8. [Datos de referencia](#8-datos-de-referencia)
9. [Patrones de diseño utilizados](#9-patrones-de-diseño-utilizados)
10. [La representación central: EnrichedCFG](#10-la-representación-central-enrichedcfg)
11. [Trazabilidad bidireccional](#11-trazabilidad-bidireccional)
12. [Código C generado — Cómo funciona](#12-código-c-generado--cómo-funciona)
13. [Jerarquía de herencia](#13-jerarquía-de-herencia)
14. [Configuración y herramientas de desarrollo](#14-configuración-y-herramientas-de-desarrollo)
15. [Limitaciones conocidas (v0.1)](#15-limitaciones-conocidas-v01)

---

## 1. ¿Qué es Flashback?

Flashback es un decompilador de binarios ELF x86-64 orientado a la **corrección funcional** y a la **trazabilidad bidireccional**. A diferencia de Ghidra o Hex-Rays, cuyo objetivo es la legibilidad del pseudo-código, Flashback genera **código C real que compila y ejecuta correctamente**, manteniendo una correspondencia línea a línea con el ensamblador original.

**Objetivos clave:**

| Objetivo | Cómo se logra |
|---|---|
| Código C compilable y ejecutable | Simulación de stack + mapeo de instrucciones a C |
| Trazabilidad estática (C ↔ ASM) | Comentarios `/* 0xADDR: mnemónico operandos */` en cada línea |
| Trazabilidad dinámica (ejecución) | Macro `__trace(addr)` insertada según política de granularidad |
| Portabilidad del C generado | Stack simulado, syscalls mapeados a libc, sin asm inline |
| Extensibilidad a otras ISAs | Separación `core/` (agnóstico) vs. `arch/<isa>/` (específico) |

---

## 2. Estructura del repositorio

```
Flashback-dbg/
│
├── flashback/                  ← Paquete principal (instalable con pip)
│   ├── __init__.py
│   ├── core/                   ← Lógica independiente de la ISA
│   │   ├── models.py           ← Todas las estructuras de datos
│   │   ├── cfg_builder.py      ← Construcción del CFG desde instrucciones crudas
│   │   ├── translator.py       ← Generación de código C desde el CFG enriquecido
│   │   └── exporter.py         ← Serialización/deserialización JSON
│   │
│   ├── arch/                   ← Implementaciones específicas por arquitectura
│   │   ├── base.py             ← Clases abstractas (interfaces)
│   │   ├── x86_64/             ← Implementación x86-64 (completa)
│   │   │   ├── disassembler.py ← LIEF + Capstone: parsea ELF, desensambla
│   │   │   ├── enricher.py     ← Anota el CFG con semántica
│   │   │   ├── register_map.py ← Registros → expresiones C
│   │   │   ├── calling_convention.py ← System V AMD64 ABI
│   │   │   ├── instruction_sem.py    ← Clasificación de instrucciones
│   │   │   └── syscall_table.py      ← Tabla de syscalls Linux x86-64
│   │   └── arm64/              ← Stubs para expansión futura
│   │
│   ├── ui/
│   │   ├── cli.py              ← CLI (argparse, producción actual)
│   │   └── tui/                ← TUI interactiva (roadmap)
│   │
│   └── data/                   ← Archivos de datos de referencia
│       ├── libc_prototypes.json
│       └── syscalls_x86_64.json
│
├── tests/
│   ├── test_functional.py      ← Tests unitarios del Translator (PF01-PF06)
│   ├── test_integration.py     ← Tests end-to-end del pipeline (PI01-PI04)
│   ├── test_traceability.py    ← Tests de trazabilidad (TR)
│   ├── binaries/               ← Binarios ELF de prueba
│   ├── sources/                ← Fuentes originales de los binarios de prueba
│   └── expected/               ← Salidas esperadas para validación
│
├── docs/
│   ├── 00_README.md            ← Descripción del esquema CFG
│   ├── 01_especificacion.md    ← Especificación formal del esquema CFG
│   ├── 02_cfg_schema.json      ← JSON Schema (draft-07) para validación
│   ├── 03_ejemplo_hello.json   ← CFG de ejemplo: hello_world.elf
│   ├── 04_cfg_model.py         ← Dataclasses originales (copiadas a core/models.py)
│   └── ARCHITECTURE.md         ← Este documento
│
├── flashback.py                ← Script de entrada
├── pyproject.toml              ← Metadatos del paquete y dependencias
├── requirements.txt
└── Makefile                    ← Targets de desarrollo
```

---

## 3. Pipeline de procesamiento

El flujo completo, desde el binario ELF hasta el código C ejecutable:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ENTRADA: hello_world.elf                                               │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  [1] Disassembler   │  arch/x86_64/disassembler.py
                    │  LIEF + Capstone    │
                    └──────────┬──────────┘
                               │  dict[int, RawInstruction] + BinaryMeta
                    ┌──────────▼──────────┐
                    │  [2] CFGBuilder     │  core/cfg_builder.py
                    │  Grafo de control   │
                    └──────────┬──────────┘
                               │  EnrichedCFG (pipeline_stage='initial')
                    ┌──────────▼──────────┐
                    │  [3] Enricher       │  arch/x86_64/enricher.py
                    │  Anotaciones        │
                    └──────────┬──────────┘
                               │  EnrichedCFG (pipeline_stage='enriched')
                    ┌──────────▼──────────┐
                    │  [4] Exporter       │  core/exporter.py  (opcional)
                    │  CFG → JSON         │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  [5] Translator     │  core/translator.py
                    │  CFG → Código C     │
                    └──────────┬──────────┘
                               │
┌─────────────────────────────────────────────────────────────────────────┐
│  SALIDA: hello_world.c  (compilable con gcc)                            │
└─────────────────────────────────────────────────────────────────────────┘
```

**Invocación típica:**
```bash
python flashback.py hello_world.elf -o hello_world.c --export-cfg cfg.json
gcc -O0 -g hello_world.c -o hello_world_reconstructed
./hello_world_reconstructed
```

---

## 4. Módulo `core/` — Lógica agnóstica a la arquitectura

### 4.1 `models.py` — Estructuras de datos centrales

Es el corazón del sistema. Define **todas** las estructuras de datos que fluyen entre etapas.

#### Jerarquía de anotaciones

Las anotaciones son metadatos polimórficos que se adjuntan a funciones, bloques, instrucciones y aristas. Se almacenan como listas y se deserializan mediante un registro.

```
Annotation (base)
  ├── ExternalCallAnnotation
  │     → function_name, library, prototype, argument_registers
  ├── SyscallAnnotation
  │     → syscall_number, syscall_name, argument_registers, return_register
  ├── FunctionalClassAnnotation
  │     → category: 'function_prologue' | 'function_epilogue' | 'loop_header' | ...
  ├── TraceRecommendationAnnotation
  │     → granularity: 'none' | 'block' | 'instruction' | 'selective'
  └── TracePointAnnotation
        → marks an instruction to emit __trace(addr)
```

El registro de anotaciones permite deserialización polimórfica:
```python
ANNOTATION_REGISTRY = {
    'external_call': ExternalCallAnnotation,
    'syscall': SyscallAnnotation,
    'functional_class': FunctionalClassAnnotation,
    'trace_recommendation': TraceRecommendationAnnotation,
    'trace_point': TracePointAnnotation,
}
```

#### Entidades principales

```
BinaryInfo
  → filename, sha256, entry_point, architecture, bits, endianness, is_pie, is_stripped

Metadata
  → generator_name, generator_version, timestamp, pipeline_stage, library_versions

Function
  → address (HexAddr), name, is_plt, is_external
  → entry_block (HexAddr), blocks[] (HexAddr)
  → called_from[], calls_to[]
  → annotations[]

BasicBlock
  → address, size, function (HexAddr)
  → instructions[] (HexAddr), successors[], predecessors[]
  → annotations[]

Instruction
  → address, mnemonic, operands, bytes, size
  → block (HexAddr)
  → registers_read[], registers_written[]
  → memory_accesses[] (MemoryAccess)
  → annotations[]

Edge
  → source (HexAddr), target (HexAddr)
  → type: 'fall_through' | 'unconditional_jump' | 'conditional_jump' |
           'call' | 'return' | 'syscall'
  → condition (string expresión de flags, e.g. "ZF == 1")
  → annotations[]

EnrichedCFG
  → metadata, binary_info
  → functions{}  : dict[HexAddr, Function]
  → basic_blocks{}: dict[HexAddr, BasicBlock]
  → instructions{}: dict[HexAddr, Instruction]
  → edges[]      : list[Edge]
```

#### Métodos importantes de `EnrichedCFG`

| Método | Descripción |
|---|---|
| `to_dict()` | Serializa a diccionario JSON-compatible |
| `save(path)` | Escribe JSON en disco |
| `from_dict(data)` | Deserializa desde diccionario |
| `load(path)` | Lee JSON desde disco |
| `validate()` | Verifica 7 invariantes de integridad referencial (I1–I7) |

#### Funciones auxiliares

- `hex_addr(int | str) → HexAddr` — Normaliza direcciones al formato `"0xNNNNNN"`
- `compute_sha256(path) → str` — Hash del binario para reproducibilidad
- `deserialize_annotation(dict) → Annotation` — Deserialización polimórfica

---

### 4.2 `cfg_builder.py` — Construcción del grafo

Recibe instrucciones crudas (`RawInstruction`) y metadatos del binario (`BinaryMeta`) y produce un `EnrichedCFG` en estado `'initial'` (sin anotaciones semánticas).

#### Tipos de entrada

```python
@dataclass
class RawInstruction:
    address: int
    mnemonic: str
    operands: str
    bytes_hex: str
    size: int
    registers_read: list[str]
    registers_written: list[str]

@dataclass
class BinaryMeta:
    path: str
    sha256: str
    entry_point: int
    architecture: str
    is_pie: bool
    is_stripped: bool
    func_symbols: dict[int, str]   # addr → nombre de función
    plt_symbols: dict[int, str]    # addr → nombre de función PLT
```

#### Algoritmo de 8 pasos

1. **Agregar funciones PLT** como stubs externos (`is_plt=True`, `is_external=True`)
2. **Identificar starts de bloques básicos:**
   - Entradas de funciones
   - Destinos de saltos/ramas
   - Direcciones de retorno (instrucción siguiente a `call`)
   - Fallthrough tras `ret` / `syscall`
3. **Construir bloques crudos** — secuencias contiguas de instrucciones hasta terminator o nuevo block start
4. **Asignar bloques a funciones** — heurística: bloque pertenece a la función cuya entrada precede más cercana
5. **Crear objetos `Function`** para funciones de usuario (no PLT)
6. **Crear objetos `BasicBlock` e `Instruction`**, poblar `cfg.instructions{}`
7. **Calcular sucesores y predecesores** de cada bloque
8. **Construir aristas** (`Edge`) con tipos:
   - `fall_through` — secuencia normal
   - `unconditional_jump` — `jmp`
   - `conditional_jump` — `je`, `jne`, `jl`... (dos aristas: taken y not-taken)
   - `call` — llamada a función
   - `return` — instrucción `ret`
   - `syscall` — instrucción `syscall`

---

### 4.3 `translator.py` — Generación de C

Recibe un `EnrichedCFG` en estado `'enriched'` y produce un fichero C completo como `str`.

#### Estructura del fichero C generado

```
1.  Comentario de cabecera (metadatos del binario, instrucciones de compilación)
2.  #include (stdint.h, stdio.h, stdlib.h, unistd.h, ...)
3.  Macros de portabilidad (SIM_READ8/16/32/64, SIM_WRITE8/16/32/64)
4.  Arrays de memoria simulada (__sim_stack[8MB], __sim_heap[8MB])
5.  Runtime de trazas (__trace_buffer[], __trace(), __trace_dump())
6.  Variables globales de registros (uint64_t rax, rbx, rcx, ..., rsp, rbp)
7.  Variables globales de flags (uint8_t ZF, CF, SF, OF, PF)
8.  Declaraciones forward de funciones
9.  Implementación de funciones (una por función de usuario)
10. main() — inicializa RSP, llama a la función entrada
```

#### Simulación del stack

En lugar de usar `alloca()` o asm inline, el stack es un array estático:

```c
#define SIM_STACK_SIZE (8 * 1024 * 1024)
static uint8_t __sim_stack[SIM_STACK_SIZE];

// RSP se inicializa al tope del stack simulado en main():
rsp = (uint64_t)(uintptr_t)(__sim_stack + SIM_STACK_SIZE);

// push rax  →  rsp -= 8; SIM_WRITE64(rsp, rax);
// pop rax   →  rax = SIM_READ64(rsp); rsp += 8;
```

Esto hace el C compilable en cualquier plataforma de 64 bits (x86-64, ARM64, RISC-V, etc.).

#### Mapeo de syscalls a libc

```c
// syscall (Linux write, número 1):
//   mov rax, 1 ; mov rdi, fd ; mov rsi, buf ; mov rdx, len ; syscall
// Se traduce a:
rax = (uint64_t)write((int)rdi, (void*)(uintptr_t)rsi, (size_t)rdx);
```

#### Instrucciones soportadas (40+)

| Categoría | Mnemonics |
|---|---|
| Aritmética | `add`, `sub`, `inc`, `dec`, `imul`, `neg` |
| Lógica | `xor`, `and`, `or`, `not` |
| Desplazamiento | `shl`/`sal`, `shr`, `sar` |
| Comparación | `cmp`, `test` (con actualización de flags) |
| Saltos condicionales | `je`, `jne`, `jl`, `jg`, `jle`, `jge`, `ja`, `jb`, `jae`, `jbe` |
| Movimiento de datos | `mov`, `movsx`, `movsxd`, `movzx`, `lea` |
| Stack | `push`, `pop`, `leave` |
| Control | `ret`, `call`, `jmp` |
| Set-condicional | `sete`, `setne`, `setl`, `setg`, `seta`, `setb`... |

Instrucciones no soportadas emiten:
```c
fprintf(stderr, "UNSUPPORTED: mnemonic operands\n"); abort();
```

---

### 4.4 `exporter.py` — Serialización JSON

Thin wrapper sobre `EnrichedCFG.save()` / `from_dict()` que añade validación de esquema JSON.

| Método | Descripción |
|---|---|
| `save(cfg, path)` | Escribe CFG a JSON con pretty-print |
| `load(path, validate=True)` | Lee CFG de JSON, opcionalmente valida contra `docs/02_cfg_schema.json` |
| `_validate_schema(data, path)` | Usa `jsonschema` para validar contra el esquema draft-07 |

---

## 5. Módulo `arch/` — Implementaciones por arquitectura

### 5.1 `base.py` — Interfaces abstractas

Define tres clases abstractas que cada implementación ISA debe satisfacer:

```python
class Disassembler(ABC):
    def load(binary_path) -> tuple[dict[int, RawInstruction], BinaryMeta]: ...
    def disassemble(binary_path) -> EnrichedCFG: ...  # convenience: load + build

class Enricher(ABC):
    def enrich(cfg, granularity='selective') -> EnrichedCFG: ...

class RegisterMap(ABC):
    def to_c(reg: str) -> str | None: ...
```

---

### 5.2 `x86_64/disassembler.py`

Parsea el binario ELF con **LIEF** y desensambla con **Capstone**.

**Flujo interno de `load()`:**
1. Validar que el fichero existe y es ELF x86-64
2. LIEF: extraer tabla de símbolos, tabla PLT, entry point, flags (PIE, stripped)
3. Capstone (`CS_ARCH_X86 + CS_MODE_64`): desensamblar todas las secciones ejecutables
4. Filtrar funciones del runtime C (`_start`, `__libc_csu_init`, etc.)
5. Devolver `dict[int, RawInstruction]` + `BinaryMeta`

---

### 5.3 `x86_64/enricher.py`

Añade anotaciones semánticas al CFG inicial. Su método `enrich()` ejecuta 5 sub-pasos:

#### 1. `_annotate_external_calls()`
- Itera instrucciones `call`
- Resuelve la dirección destino
- Si el destino está en PLT → busca prototipo en `libc_prototypes.json`
- Adjunta `ExternalCallAnnotation` con nombre, prototipo y registros de argumentos

```python
# Ejemplo de anotación generada:
ExternalCallAnnotation(
    added_by='enricher',
    function_name='printf',
    library='libc.so.6',
    prototype='int printf(const char*, ...)',
    argument_registers=['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
)
```

El traductor consume esta anotación para generar:
```c
/* 0x401060: call printf */
rax = (int64_t)printf((const char*)(uintptr_t)rdi, rsi, rdx, rcx, r8, r9);
```

#### 2. `_annotate_syscalls()`
- Itera instrucciones `syscall`
- Recupera el número de syscall desde el `mov rax, N` precedente
- Busca en `syscalls_x86_64.json`
- Adjunta `SyscallAnnotation`

#### 3. `_classify_blocks()`
- Asigna categoría a cada bloque:
  - `function_prologue` — empieza con `push rbp; mov rbp, rsp`
  - `function_epilogue` — termina con `ret`
  - `loop_header` — tiene arista de retroceso
  - `unreachable` — sin predecesores y no es entry point
  - `function_body` — resto

#### 4. `_annotate_trace_recommendations(granularity)`
- Decide qué bloques deben tener puntos de traza según la política elegida

#### 5. `_annotate_trace_points()`
- Para bloques con recomendación, adjunta `TracePointAnnotation` en las instrucciones apropiadas

---

### 5.4 `x86_64/register_map.py`

Mapea nombres de registros x86-64 a expresiones C portables:

| Registro | Expresión C | Semántica |
|---|---|---|
| `rax` | `rax` | 64 bits completos |
| `eax` | `(uint32_t)rax` | 32 bits bajos (zero-extends) |
| `ax` | `(uint16_t)rax` | 16 bits bajos |
| `al` | `(uint8_t)rax` | 8 bits bajos |
| `ah` | `(uint8_t)(rax >> 8)` | bits 8-15 |
| `0x1234` | `((uint64_t)0x1234ULL)` | Inmediato |

---

### 5.5 `x86_64/calling_convention.py`

Constantes del ABI System V AMD64:

```python
ARG_REGISTERS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
RETURN_REGISTER = 'rax'
CALLEE_SAVED = ['rbx', 'rbp', 'r12', 'r13', 'r14', 'r15']
CALLER_SAVED = ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']
```

Usado por el enricher para identificar los argumentos de llamadas externas.

---

### 5.6 `x86_64/instruction_sem.py`

Funciones de clasificación semántica de instrucciones:

| Función | Descripción |
|---|---|
| `is_prologue_block(mnemonics, operands)` | Detecta `push rbp; mov rbp, rsp` |
| `is_epilogue_block(mnemonics)` | Detecta bloque terminado en `ret`/`retn`/`retf` |
| `get_condition_string(mnemonic)` | `"je"` → `"ZF == 1"`, `"jl"` → `"SF != OF"`, etc. |

---

### 5.7 `x86_64/syscall_table.py`

Carga perezosa de la tabla de syscalls Linux x86-64 desde `data/syscalls_x86_64.json`.

| Función | Descripción |
|---|---|
| `lookup(number: int)` | `1` → `{'name': 'write', 'args': ['rdi','rsi','rdx'], 'ret': 'rax'}` |
| `name_to_number(name: str)` | `'write'` → `1` |

---

## 6. Módulo `ui/` — Interfaces de usuario

### `cli.py` — Interfaz de línea de comandos

Entry point de producción. Orquesta todo el pipeline.

**Opciones CLI:**

| Flag | Default | Descripción |
|---|---|---|
| `binary` (posicional) | — | Binario ELF de entrada |
| `-o / --output` | `<binary>.c` | Fichero C de salida |
| `--export-cfg FILE` | — | Exportar CFG enriquecido a JSON |
| `--functions F1,F2` | todas | Traducir solo funciones especificadas |
| `--granularity` | `selective` | Política de trazabilidad |
| `-v / --verbose` | `False` | Habilitar logging DEBUG |
| `--version` | — | Mostrar versión |

**Flujo de `run(args)`:**
```python
1. X86_64Disassembler().load(binary)     → raw_insns, meta
2. CFGBuilder().build(raw_insns, meta)   → cfg (initial)
3. X86_64Enricher().enrich(cfg)         → cfg (enriched)
4. Exporter.save(cfg, path)             # si --export-cfg
5. Translator().translate(cfg)          → c_code (str)
6. open(output).write(c_code)
```

---

## 7. Suite de tests

### `test_functional.py` — Tests unitarios del Translator

Prefijo `PF` (Pruebas Funcionales). Validan la salida C sin necesitar binarios reales (usan CFGs sintéticos).

| Test | Qué verifica |
|---|---|
| `TestPF01_Estructura` | Presencia de `#include`, declaraciones de registros, `main()`, labels |
| `TestPF02_Portabilidad` | `__sim_stack`, inicialización de RSP, macros `SIM_READ/WRITE` |
| `TestPF03-PF06` | Traducción correcta de instrucciones individuales |

### `test_integration.py` — Tests end-to-end

Prefijo `PI` (Pruebas Integración). Usan `hello_world.elf` real.

| Test | Qué verifica |
|---|---|
| `TestPI01_Desensamblado` | CFG tiene funciones, bloques, instrucciones; `main` presente |
| `TestPI02_Enriquecimiento` | Llamadas externas anotadas; todos los bloques con `functional_class` |
| `TestPI03_Traducción` | Código C generado tiene estructura esperada |
| `TestPI04_ExportaciónJSON` | CFG serializa/deserializa correctamente; pasa validación de esquema |

### `test_traceability.py` — Tests de trazabilidad

Prefijo `TR`.

| Test | Qué verifica |
|---|---|
| `TestTrazabilidadEstatica` | Cada instrucción tiene comentario `/* 0xADDR: mnemonic */` |
| `TestTrazabilidadDinamica` | Instrucciones con `trace_point` generan `__trace(addr)` |
| `TestGranularidad` | `none`/`block`/`instruction`/`selective` producen distintos números de trace points |

---

## 8. Datos de referencia

### `data/libc_prototypes.json`

~100 funciones libc con sus firmas, registros de argumentos y clasificación:

```json
{
  "printf": {
    "proto": "int printf(const char *format, ...)",
    "args": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "classification": "IO"
  },
  "malloc": {
    "proto": "void *malloc(size_t size)",
    "args": ["rdi"],
    "classification": "MEM"
  }
}
```

### `data/syscalls_x86_64.json`

300+ syscalls Linux x86-64:

```json
{
  "0": {"name": "read",   "args": ["rdi", "rsi", "rdx"], "ret": "rax", "classification": "IO"},
  "1": {"name": "write",  "args": ["rdi", "rsi", "rdx"], "ret": "rax", "classification": "IO"},
  "39": {"name": "getpid","args": [],                     "ret": "rax", "classification": "PROC"}
}
```

---

## 9. Patrones de diseño utilizados

### 1. Abstract Base Classes para separación ISA

```
arch/base.py
  Disassembler (ABC) ←── X86_64Disassembler
  Enricher (ABC)     ←── X86_64Enricher
  RegisterMap (ABC)  ←── X86_64RegisterMap
```

El módulo `core/` depende únicamente de los ABCs, nunca de implementaciones concretas. Añadir ARM64 requiere solo implementar `arch/arm64/` sin tocar `core/`.

### 2. Registro de anotaciones (Annotation Registry)

Permite añadir nuevos tipos de anotación sin cambios en el esquema ni en la lógica de serialización:

```python
ANNOTATION_REGISTRY: dict[str, type[Annotation]] = { ... }

def deserialize_annotation(data: dict) -> Annotation:
    cls = ANNOTATION_REGISTRY[data['type']]
    return cls(**data)
```

### 3. Carga perezosa (Lazy Loading)

Los datos de referencia se cargan una sola vez y se cachean en variables de módulo:

```python
_LIBC_PROTOTYPES: dict | None = None

def _load_prototypes() -> dict:
    global _LIBC_PROTOTYPES
    if _LIBC_PROTOTYPES is None:
        _LIBC_PROTOTYPES = json.loads(...)
    return _LIBC_PROTOTYPES
```

### 4. Diccionarios planos indexados por dirección

Todas las entidades usan `HexAddr` como clave → lookup O(1) desde cualquier punto del pipeline:

```python
cfg.functions['0x401000']           # → Function
cfg.basic_blocks['0x401010']        # → BasicBlock
cfg.instructions['0x401015']        # → Instruction
```

### 5. Serialización nativa JSON

No se usa pickle. `EnrichedCFG` se serializa a un diccionario limpio (`to_dict()`) y se valida contra un JSON Schema formal (`docs/02_cfg_schema.json`). Esto permite tooling en cualquier lenguaje.

### 6. Portabilidad via macros

El C generado abstrae toda arquitectura detrás de macros:
```c
#define SIM_READ64(addr)        (*(uint64_t*)(uintptr_t)(addr))
#define SIM_WRITE64(addr, val)  (*(uint64_t*)(uintptr_t)(addr) = (uint64_t)(val))
```

---

## 10. La representación central: EnrichedCFG

El `EnrichedCFG` es el **único objeto** que se pasa entre etapas del pipeline. Su estado cambia progresivamente:

| Etapa | `pipeline_stage` | Anotaciones |
|---|---|---|
| Después de `CFGBuilder` | `'initial'` | Vacías |
| Después de `Enricher` | `'enriched'` | Pobladas |

**Invariantes validadas por `validate()` (I1–I7):**

1. Cada bloque referenciado en `Function.blocks[]` existe en `cfg.basic_blocks{}`
2. Cada instrucción referenciada en `BasicBlock.instructions[]` existe en `cfg.instructions{}`
3. Cada sucesor de un bloque existe en `cfg.basic_blocks{}`
4. Cada predecesor de un bloque existe en `cfg.basic_blocks{}`
5. Si A es sucesor de B, entonces B es predecesor de A (consistencia)
6. Cada arista en `cfg.edges[]` tiene source y target existentes
7. El entry_block de cada función existe en `cfg.basic_blocks{}`

---

## 11. Trazabilidad bidireccional

### Trazabilidad estática (C → ASM)

Cada instrucción genera un comentario en el C con su dirección original:

```c
/* 0x401060: mov rax, 0x1 */
rax = ((uint64_t)0x1ULL);
/* 0x401067: mov rdi, 0x1 */
rdi = ((uint64_t)0x1ULL);
/* 0x40106e: syscall */
rax = (uint64_t)write((int)rdi, (void*)(uintptr_t)rsi, (size_t)rdx);
```

Dado cualquier línea del C generado, puedes encontrar la instrucción ASM exacta que la originó.

### Trazabilidad dinámica (ejecución)

Los puntos de traza emiten la dirección en tiempo de ejecución:

```c
__trace(0x401060ULL);   /* block entry */
/* 0x401060: mov rax, 0x1 */
rax = ((uint64_t)0x1ULL);
```

Al final de la ejecución, `__trace_dump("trace.bin")` escribe el buffer de trazas a disco. Esto permite reconstruir el camino de ejecución exacto y compararlo con una ejecución del binario original con `gdb`/`strace`.

### Políticas de granularidad (`--granularity`)

| Valor | Puntos de traza |
|---|---|
| `none` | Ninguno |
| `block` | Una por entrada de bloque básico |
| `instruction` | Una por instrucción (verbose) |
| `selective` (default) | Entradas de bloque + llamadas externas + syscalls + loop headers |

---

## 12. Código C generado — Cómo funciona

### Estructura de una función traducida

```c
// Declaración forward
void func_main(void);

// Implementación
void func_main(void) {
  // Bloque básico 0x401130 (function_prologue)
  block_0x401130:
    __trace(0x401130ULL);
    /* 0x401130: push rbp */
    rsp -= 8; SIM_WRITE64(rsp, rbp);
    /* 0x401131: mov rbp, rsp */
    rbp = rsp;
    /* 0x401134: sub rsp, 0x20 */
    rsp = rsp - ((uint64_t)0x20ULL);
    CF = (rsp > rsp + ((uint64_t)0x20ULL)); /* sub flags */
    ZF = (rsp == 0); SF = ((int64_t)rsp < 0); OF = 0;

  // Bloque básico 0x401138 (function_body)
  block_0x401138:
    /* 0x401138: lea rdi, [rip+0xeb5] */
    rdi = (uint64_t)(uintptr_t)(".../section_data");
    /* 0x40113f: call printf */
    __trace(0x40113fULL);
    rax = (int64_t)printf((const char*)(uintptr_t)rdi, rsi, rdx, rcx, r8, r9);

  // Bloque básico 0x401144 (function_epilogue)
  block_0x401144:
    /* 0x401144: xor eax, eax */
    rax = (uint32_t)((uint32_t)rax ^ (uint32_t)rax);
    ZF = ((uint32_t)rax == 0); SF = 0; OF = 0; CF = 0;
    /* 0x401146: leave */
    rsp = rbp;
    rbp = SIM_READ64(rsp); rsp += 8;
    /* 0x401147: ret */
    return;
}
```

### `main()` generado

```c
int main(int argc, char **argv) {
    // Inicializar stack simulado
    rsp = (uint64_t)(uintptr_t)(__sim_stack + SIM_STACK_SIZE);
    rsp &= ~((uint64_t)0xF);  // 16-byte alignment (ABI)
    
    // Registrar dump de trazas al salir
    atexit(__trace_dump_atexit);
    
    // Llamar a la función de entrada
    func_main();
    
    return (int)rax;
}
```

---

## 13. Jerarquía de herencia

```
object
├── Annotation
│   ├── ExternalCallAnnotation
│   ├── SyscallAnnotation
│   ├── FunctionalClassAnnotation
│   ├── TraceRecommendationAnnotation
│   └── TracePointAnnotation
│
├── Disassembler (ABC)
│   └── X86_64Disassembler
│       └── (ARM64Disassembler — futuro)
│
├── Enricher (ABC)
│   └── X86_64Enricher
│       └── (ARM64Enricher — futuro)
│
└── RegisterMap (ABC)
    └── X86_64RegisterMap
        └── (ARM64RegisterMap — futuro)

Dataclasses (no heredan entre sí):
  RawInstruction, BinaryMeta, MemoryAccess,
  Function, BasicBlock, Instruction, Edge,
  BinaryInfo, Metadata, EnrichedCFG
```

---

## 14. Configuración y herramientas de desarrollo

### Dependencias (`requirements.txt` / `pyproject.toml`)

| Librería | Versión mínima | Uso |
|---|---|---|
| `capstone` | 5.0 | Desensamblado multi-arquitectura |
| `lief` | 0.14 | Parseo de ELF (símbolos, PLT, secciones) |
| `networkx` | 3.0 | Estructura de datos de grafo para el CFG |
| `pyelftools` | 0.31 | Parseo ELF adicional (backup a LIEF) |
| `jsonschema` | 4.0 | Validación de JSON Schema draft-07 |

### Dependencias de desarrollo

| Librería | Uso |
|---|---|
| `pytest >= 8.0` | Framework de tests |
| `pytest-cov >= 5.0` | Cobertura de código |
| `flake8 >= 7.0` | Linting |
| `flake8-bugbear` | Reglas adicionales de calidad |

### Targets de Makefile

```bash
make install    # pip install -e ".[dev]"
make test       # pytest
make test-cov   # pytest con reporte de cobertura
make lint       # flake8 flashback/ tests/
make check      # lint + test (pre-commit)
make clean      # limpiar cachés y artefactos
make run BIN=./hello_world.elf  # prueba rápida del pipeline
```

### Instalación como comando global

```bash
pip install -e .
flashback hello_world.elf -o hello_world.c
```

---

## 15. Limitaciones conocidas (v0.1)

| Limitación | Motivo |
|---|---|
| Solo ELF x86-64 | Scope del TFE; ARM64 en roadmap |
| Sin resolución de saltos indirectos (`jmp rax`) | Requiere análisis de flujo de datos inter-bloque |
| Sin recuperación de tipos de alto nivel (structs, clases) | Fuera de scope; foco en correctitud funcional |
| Sin soporte de instrucciones SIMD/AVX | Poco frecuentes en código de sistema |
| Sin detección de código auto-modificable | No aplicable al scope del TFE |
| Heurísticas de CFB function discovery | Funciona para código compilado normal; no para obfuscación |
| Stack frame recovery parcial | Stack simulado funciona pero no recupera variables locales con nombres |

---

*Documento generado el 2026-04-28 para el repositorio Flashback-dbg (TFE — UNIR Ciberseguridad).*
