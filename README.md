# Flashback

**Trabajo De Fin de Grado - Grado en ciberseguridad UNIR 2025-2026**

Flashback transforma binarios desensamblados en código C de bajo nivel **compilable, ejecutable y depurable**. A diferencia de los descompiladores convencionales, que priorizan la legibilidad del código generado, Flashback prioriza la **corrección funcional, la trazabilidad bidireccional con el ensamblador original y la capacidad de análisis dinámico**.

---

## ¿Por qué Flashback?

Las herramientas existentes de decompilación y traducción binaria dejan tres huecos sin cubrir:

| Enfoque existente | Qué hace bien | Qué falla |
|---|---|---|
| **Descompiladores** (Ghidra, Hex-Rays, DREAM, SAILR) | Código legible, elimina gotos | Rara vez compilable ni ejecutable |
| **Binary lifters** (McSema, Rev.ng, RetDec) | Código funcional vía LLVM IR | Verboso, artefactos de emulación, pierde trazabilidad |
| **Decompilación verificada** (FoxDec) | Corrección formal demostrada | Alcance muy restringido (sin saltos indirectos, sin SIMD, sin PIE) |

Flashback ocupa el espacio intermedio: genera código C que **funciona**, que el analista puede **depurar con gdb** y que mantiene **correspondencia directa con cada instrucción del binario original**.

---

## Arquitectura

### Pipeline directa: sin LLVM IR de por medio

```
                  ┌──────────────────────────────────────────────┐
                  │              Pipeline Flashback              │
                  │                                              │
  ┌─────────┐    │  ┌──────────┐   ┌──────────┐   ┌──────────┐ │    ┌─────────┐
  │ Binario │───▶│  │ Desensam.│──▶│   CFG    │──▶│Traductor │ │───▶│Código C │
  │  ELF    │    │  │          │   │Enriquec. │   │   a C    │ │    │trazable │
  └─────────┘    │  └──────────┘   └──────────┘   └──────────┘ │    └─────────┘
                  │       ▲              ▲              ▲        │
                  │       │              │              │        │
                  │  arch/x86_64    arch/x86_64      core/      │
                  └──────────────────────────────────────────────┘
```

Los lifters convencionales atraviesan LLVM IR antes de generar C, introduciendo artefactos y perdiendo trazabilidad. Flashback traduce **directamente** desde un CFG enriquecido diseñado para este propósito.

### Separación core / arch

La decisión de diseño más importante del proyecto es la separación entre la lógica **agnóstica de arquitectura** y la lógica **específica de cada ISA**:

```
flashback/
├── core/                        # Agnóstico de arquitectura
│   ├── models.py                # EnrichedCFG, BasicBlock, Edge, ExternalCall, Syscall
│   ├── cfg_builder.py           # Construcción del grafo desde desensamblado abstracto
│   ├── translator.py            # Generación de código C desde CFG enriquecido
│   └── exporter.py              # Serialización del CFG a JSON
│
├── arch/                        # Específico de arquitectura
│   ├── base.py                  # Interfaces abstractas (Disassembler, Enricher, RegisterMap)
│   ├── x86_64/
│   │   ├── disassembler.py      # Desensamblado via Capstone + LIEF
│   │   ├── enricher.py          # Resolución de PLT/GOT, syscalls, convención System V
│   │   ├── register_map.py      # rax, rbx, rdi... → uint64_t + mapeo a posiciones de argumento
│   │   ├── syscall_table.py     # Número → nombre + argumentos (Linux x86-64)
│   │   ├── calling_convention.py # System V AMD64 ABI: rdi, rsi, rdx, rcx, r8, r9
│   │   └── instruction_sem.py   # Semántica de instrucciones: mov, add, cmp, jne...
│   └── arm64/                   # Stubs para extensión futura
│       └── __init__.py
│
├── ui/                          # Interfaces de usuario
│   ├── cli.py                   # CLI actual — punto de entrada principal
│   └── tui/                     # TUI futura (Textual) — ver Roadmap
│       └── __init__.py
│
├── data/
│   ├── libc_prototypes.json     # Prototipos conocidos de funciones libc/POSIX
│   └── syscalls_x86_64.json    # Tabla de syscalls Linux x86-64
│
├── flashback.py                 # Punto de entrada: detecta CLI o TUI
├── requirements.txt
└── tests/
    ├── binaries/                # Binarios de prueba precompilados
    ├── sources/                 # Código fuente original de cada binario de prueba
    ├── expected/                # Salidas esperadas para validación
    ├── test_functional.py       # Pruebas de corrección funcional (PF01–PF06)
    ├── test_integration.py      # Pruebas de integración de la pipeline (PI01–PI04)
    └── test_traceability.py     # Pruebas de trazabilidad bidireccional
```

**¿Qué es agnóstico y qué no?**

| Capa | Qué contiene | ¿Depende de la ISA? |
|---|---|---|
| Topología del CFG | Nodos, aristas, tipos de transición (condicional, fall-through, call, return) | No |
| Clasificación de interacciones | Categorías E/S, red, memoria, procesos, ficheros | No |
| Modelo de datos | BasicBlock, Edge, ExternalCall, Syscall | No |
| Traductor a C | Generación de cabecera, labels, gotos, comentarios de trazabilidad | Parcialmente (usa RegisterMap) |
| Registros concretos | rax, rdi, rsp... vs r0, r1, sp... | Sí |
| Convención de llamada | System V AMD64 vs AAPCS vs O32 | Sí |
| Tabla de syscalls | write=1 (x86-64) vs write=64 (aarch64) vs write=4004 (MIPS) | Sí |
| Semántica de instrucciones | mov, add, cmp, jne... vs ldr, str, b.eq... | Sí |

Esto significa que **añadir soporte para ARM64** requiere implementar los módulos en `arch/arm64/` sin tocar `core/`.

---

## El CFG enriquecido: la representación central

El CFG enriquecido es lo que diferencia a Flashback de una traducción instrucción-por-instrucción. Es un grafo dirigido donde cada bloque básico lleva anotaciones semánticas **diseñadas para que el traductor genere mejor código C**, no para clasificación de malware ni detección de similitud.

### ¿Qué anota el enriquecedor?

**Llamadas a funciones externas** con nombre, prototipo y argumentos resueltos:
```
Bloque 0x401028:
  call 0x401000 (PLT)  →  anotación: { name: "printf", 
                                         prototype: "int printf(const char*, ...)",
                                         args: [rdi, rsi],
                                         classification: "IO" }
```

**Syscalls** con número, nombre y argumentos:
```
Bloque 0x401050:
  mov rax, 1           →  anotación: { number: 1,
  syscall                              name: "write",
                                       args: [rdi, rsi, rdx],
                                       classification: "IO" }
```

**Clasificación funcional** de cada interacción:
- `IO`: printf, puts, read, write, scanf...
- `NET`: socket, connect, send, recv...
- `MEM`: malloc, free, mmap, brk...
- `PROC`: fork, exec, wait, exit...
- `FS`: open, close, stat, unlink...

### ¿Por qué importa?

Sin enriquecimiento, el traductor ve `call 0x401000` y genera una llamada opaca. Con enriquecimiento, genera:

```c
/* 0x401028: call printf@plt - IO */
printf((const char*)rdi, rsi);
```

Sin enriquecimiento, el traductor ve `syscall` y no sabe qué servicio se invoca. Con enriquecimiento, genera:

```c
/* 0x401052: syscall - write (IO) */
rax = syscall(SYS_write, rdi, rsi, rdx);
```

El enriquecimiento también permite generar automáticamente los `#include` correctos antes de empezar la traducción, porque ya se conocen todas las funciones externas usadas.

---

## Trazabilidad bidireccional

Cada línea del código C generado mantiene correspondencia con el ensamblador original:

```c
/* ============================================ */
/* Función: main (0x401020 - 0x401089)          */
/* Binario: challenge.elf                       */
/* SHA-256: a1b2c3d4...                         */
/* Generado por Flashback                        */
/* ============================================ */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

/* --- Registros x86-64 --- */
uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
uint64_t r8, r9, r10, r11, r12, r13, r14, r15;

/* --- Flags --- */
int ZF, CF, SF, OF;

/* --- Memoria simulada --- */
uint8_t mem[0x100000];

void main_func(void) {

    /* Bloque 0x401020 (main+0x0) - 4 instrucciones */
    block_401020:
        /* 0x401020: push rbp       */ mem[rsp-8] = rbp; rsp -= 8;
        /* 0x401021: mov rbp, rsp   */ rbp = rsp;
        /* 0x401024: sub rsp, 0x10  */ rsp -= 0x10;
        /* 0x401028: call puts@plt  */ /* IO - extern */
        rdi = 0x402000; /* "Hello, world" */
        puts((const char*)rdi);
        goto block_401036;

    /* Bloque 0x401036 (main+0x16) - 3 instrucciones */
    block_401036:
        /* 0x401036: xor eax, eax   */ rax = 0; ZF = 1; SF = 0; OF = 0;
        /* 0x401038: leave          */ rsp = rbp; rbp = mem[rsp]; rsp += 8;
        /* 0x401039: ret            */ return;
}
```

El analista puede:
1. Leer el C para entender el flujo.
2. Ver la instrucción original en cada comentario.
3. Buscar la dirección `0x401028` en Ghidra o gdb para cruzar información.
4. Compilar el C, ejecutarlo con gdb y poner breakpoints en los labels.

---

## Instalación

```bash
# Clonar el repositorio
git clone <repositorio>
cd flashback

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Verificar instalación
python flashback.py tests/binaries/hello_world.elf -o /dev/stdout
```

### Requisitos

- Python 3.10+
- Linux x86-64 (Ubuntu 22.04+ recomendado)
- gcc 11+ (para compilar y validar el C generado)

### Dependencias Python

- `capstone` ≥5.0 — Desensamblado multi-arquitectura
- `lief` ≥0.13 — Parsing de ELF/PE/Mach-O
- `networkx` ≥3.0 — Representación de grafos
- `textual` ≥0.50 — TUI interactiva *(roadmap, no requerida en v0.1)*

---

## Uso

### Traducción básica

```bash
python flashback.py firmware.elf -o firmware.c
```

### Traducción con exportación del CFG

```bash
python flashback.py malware.elf -o malware.c --export-cfg malware_cfg.json
```

### Solo funciones específicas

```bash
python flashback.py target.elf -o target.c --functions main,handle_request,parse_input
```

### Modo verbose

```bash
python flashback.py sample.elf -o sample.c --verbose
# [*] Cargando ELF: sample.elf (x86-64, little-endian)
# [*] Desensamblado: 12 funciones, 847 instrucciones
# [*] CFG construido: 94 bloques, 127 aristas
# [*] Enriquecimiento: 23 llamadas externas, 4 syscalls identificadas
# [*] Traducción: 94 bloques → 312 líneas de C
# [*] Salida escrita en sample.c
```

### Validación

```bash
# Compilar el C generado
gcc -Wall -o sample_reconstructed sample.c

# Comparar comportamiento
./sample_original < input.txt > out_original.txt
./sample_reconstructed < input.txt > out_reconstructed.txt
diff out_original.txt out_reconstructed.txt

# Comparar trazas de syscalls
strace -o trace_orig.txt ./sample_original < input.txt
strace -o trace_recon.txt ./sample_reconstructed < input.txt
diff trace_orig.txt trace_recon.txt
```

---

## Alcance y limitaciones

### Dentro del alcance

- Binarios ELF x86-64 (Linux)
- Binarios compilados sin ofuscación avanzada
- Funciones con flujo de control estáticamente resoluble
- Llamadas a libc/POSIX y syscalls directas
- Programas de complejidad moderada

### Fuera del alcance (versión actual)

- Otras arquitecturas (ARM64, MIPS — stubs preparados para extensión)
- Binarios con ofuscación, empaquetado o protección anti-RE
- Instrucciones SIMD/AVX
- Saltos indirectos no resolubles estáticamente
- Código automodificable
- Optimización del C generado
- Recuperación de tipos de alto nivel (structs, clases, objetos)

---

## Interfaces de usuario

### CLI (actual)

La interfaz actual es una línea de comandos pensada para integrarse en flujos de trabajo automatizados, scripts y pipelines de análisis. Es el modo por defecto.

```bash
python flashback.py sample.elf -o sample.c
```

### TUI (roadmap)

Una interfaz de terminal interactiva (TUI) está planificada como evolución natural del proyecto, orientada a analistas que prefieran un flujo de trabajo visual sin abandonar la terminal. La TUI se construirá con [Textual](https://textual.textualize.io/) y ofrecerá:

```
┌─ Flashback ──────────────────────────────────────────────────────────┐
│                                                                      │
│  ┌─ Funciones ──┐  ┌─ CFG Enriquecido ───────┐  ┌─ Código C ──────┐│
│  │              │  │                          │  │                  ││
│  │ ▶ main      │  │   ┌──────┐               │  │ block_401020:   ││
│  │   parse_req │  │   │401020│──┐             │  │   rbp = rsp;    ││
│  │   handle_io │  │   └──────┘  │             │  │   rsp -= 0x10;  ││
│  │   cleanup   │  │        ┌────▼───┐         │  │   puts(rdi);    ││
│  │             │  │        │ 401036 │         │  │   goto 401036;  ││
│  │             │  │        └────────┘         │  │                  ││
│  │             │  │                          │  │ block_401036:   ││
│  │             │  │  ● IO  ● MEM  ● NET     │  │   rax = 0;      ││
│  │             │  │                          │  │   return;        ││
│  └─────────────┘  └──────────────────────────┘  └──────────────────┘│
│                                                                      │
│  ┌─ Ensamblador original ────────────────────────────────────────────┐│
│  │ 0x401020: push rbp          0x401028: call puts@plt [IO]        ││
│  │ 0x401021: mov rbp, rsp      0x401036: xor eax, eax             ││
│  │ 0x401024: sub rsp, 0x10     0x401038: leave                    ││
│  └───────────────────────────────────────────────────────────────────┘│
│  [Tab] Cambiar panel  [Enter] Seleccionar  [E] Exportar  [Q] Salir  │
└──────────────────────────────────────────────────────────────────────┘
```

La idea es ofrecer tres paneles sincronizados: al seleccionar una función en el panel izquierdo, el CFG y el código C se actualizan; al hacer clic en un bloque del CFG, el código C y el ensamblador resaltan las líneas correspondientes. Esto convierte la trazabilidad bidireccional — que en la CLI se expresa mediante comentarios — en una navegación interactiva.

El lanzamiento se hará con:

```bash
# CLI (por defecto)
python flashback.py sample.elf -o sample.c

# TUI interactiva
python flashback.py sample.elf --tui
```

La TUI queda fuera del alcance de la versión actual del TFE pero la arquitectura está preparada para incorporarla: toda la lógica de la pipeline está en `core/` y `arch/`, mientras que `ui/` contiene las interfaces, de modo que añadir la TUI no requiere modificar la lógica de negocio.

---

## Roadmap

| Versión | Contenido | Estado |
|---|---|---|
| **v0.1** | Pipeline completa CLI: desensamblado → CFG → enriquecimiento → C trazable | En desarrollo (TFE) |
| **v0.2** | Exportación del CFG enriquecido a JSON + selección de funciones | Planificado (TFE) |
| **v0.3** | TUI interactiva con paneles sincronizados (Textual) | Roadmap |
| **v0.4** | Soporte ARM64 (`arch/arm64/`) | Roadmap |
| **v0.5** | Propagación de constantes mejorada + resolución parcial de saltos indirectos | Roadmap |
| **v1.0** | Integración como plugin de Ghidra/Binary Ninja | Futuro |

---

## Contexto académico

Este proyecto se desarrolla como **Trabajo Fin de Estudios** del Grado en Ciberseguridad de la Universidad Internacional de La Rioja (UNIR). Su contribución se posiciona en la intersección de tres líneas de investigación:

1. **Decompilación ejecutable** — frente a la decompilación legible de Ghidra/Hex-Rays/DREAM/SAILR.
2. **Enriquecimiento semántico orientado a traducción** — frente al enriquecimiento orientado a clasificación/similitud (ACFGs, Attributed CFGs, SOGs).
3. **Trazabilidad bidireccional integrada** — frente a la trazabilidad confinada en herramientas propietarias o perdida durante transformaciones de IR.

---

## Licencia

Proyecto académico. Pendiente de definir licencia de distribución.
