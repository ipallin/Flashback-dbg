# Especificación del esquema del CFG enriquecido

**Versión del esquema:** 1.0.0
**Estado:** inicial (semana 2 del cronograma)
**Autor:** [Igor Pallin]

## 1. Propósito

Este documento especifica el formato de intercambio del **CFG enriquecido**, la estructura de datos central que conecta las tres fases del pipeline:

```
Extractor ──(CFG inicial)──► Enriquecedor ──(CFG enriquecido)──► Traductor
```

El Extractor produce un fichero conforme a este esquema con los campos mínimos obligatorios. El Enriquecedor lee ese fichero y escribe otro fichero conforme al mismo esquema pero con las anotaciones semánticas añadidas. El Traductor lee el resultado final y genera código C guiándose por las anotaciones.

Una **propiedad clave** del diseño: el esquema es el mismo para CFG inicial y CFG enriquecido. La diferencia es que en el CFG inicial las listas de anotaciones (`annotations`) están vacías, y en el CFG enriquecido están pobladas. Esto permite usar las mismas herramientas de validación y carga en ambas fases.

## 2. Principios de diseño

**Estructura plana.** Todos los elementos direccionables (funciones, bloques, instrucciones) viven en diccionarios de nivel superior indexados por su dirección. Las relaciones jerárquicas se expresan mediante listas de direcciones. Esto hace el lookup O(1) y simplifica el Traductor.

**Direcciones como strings hex.** Siempre en formato `"0xNNNNNN"` con minúsculas. El parsing a entero es responsabilidad del código que carga el JSON.

**JSON puro.** Nada específico de Python (ni pickle, ni tipos custom). Cualquier lenguaje puede leer y escribir el formato.

**Extensibilidad por anotaciones.** Nuevos tipos de análisis no requieren cambiar el esquema base: se añaden como nuevos tipos en la lista `annotations` de cada nodo. El esquema valida que cada anotación tenga un `type` conocido, pero los datos específicos de cada tipo son libres.

**Versionado obligatorio.** Cada fichero indica la versión del esquema al que se ajusta. Los lectores deben rechazar versiones incompatibles.

## 3. Estructura de alto nivel

Un fichero conforme al esquema es un objeto JSON con exactamente estos campos de nivel superior:

```
{
  "schema_version": "1.0.0",
  "metadata": { ... },
  "binary_info": { ... },
  "functions": { ... },
  "basic_blocks": { ... },
  "instructions": { ... },
  "edges": [ ... ]
}
```

Ningún otro campo de nivel superior está permitido en la versión 1.0.0. Si una implementación necesita añadir información adicional, se hace dentro de `metadata.extensions`.

## 4. Descripción de cada sección

### 4.1 `schema_version`

String en formato semántico `MAJOR.MINOR.PATCH`.

```json
"schema_version": "1.0.0"
```

Regla de compatibilidad: un lector conforme a la versión `X.Y.Z` debe aceptar ficheros de versión `X.Y'.Z'` con `Y' <= Y`. Versiones mayores distintas son incompatibles y deben ser rechazadas.

### 4.2 `metadata`

Información de generación del fichero. No afecta al contenido semántico pero es esencial para trazabilidad y debugging.

```json
"metadata": {
  "generator": "tfe-reconstructor",
  "generator_version": "0.1.0",
  "generation_timestamp": "2026-05-15T14:32:10Z",
  "angr_version": "9.2.118",
  "capstone_version": "5.0.1",
  "pipeline_stage": "enriched",
  "extensions": {}
}
```

**Campos obligatorios:**

- `generator`: nombre de la herramienta que produjo el fichero.
- `generator_version`: versión de la herramienta.
- `generation_timestamp`: ISO 8601 en UTC.
- `pipeline_stage`: uno de `"initial"` (salida del Extractor) o `"enriched"` (salida del Enriquecedor).

**Campos opcionales:**

- `angr_version`, `capstone_version`, etc.: versiones de las librerías usadas.
- `extensions`: objeto libre para información específica de implementación (debe estar vacío si no se usa).

### 4.3 `binary_info`

Información del binario del que procede el CFG.

```json
"binary_info": {
  "filename": "hello",
  "path": "/home/igor/binarios_prueba/hello",
  "sha256": "9f4e3c...",
  "architecture": "amd64",
  "bits": 64,
  "endianness": "little",
  "entry_point": "0x401040",
  "format": "ELF",
  "is_pie": false,
  "is_stripped": false
}
```

**Campos obligatorios:**

- `filename`: nombre del fichero (sin ruta).
- `sha256`: hash del binario en hex, para verificar que el CFG corresponde al binario que esperamos.
- `architecture`: identificador de arquitectura. En la versión 1.0.0 solo `"amd64"` está soportado.
- `bits`: 64 (único valor soportado en v1.0.0).
- `endianness`: `"little"` (único valor soportado en v1.0.0).
- `entry_point`: dirección del punto de entrada del binario.
- `format`: `"ELF"` (único valor soportado en v1.0.0).

**Campos opcionales:**

- `path`: ruta absoluta original (útil para debug, no crítico).
- `is_pie`, `is_stripped`: propiedades del binario.

### 4.4 `functions`

Diccionario de funciones indexado por dirección de entrada.

```json
"functions": {
  "0x401130": {
    "address": "0x401130",
    "name": "suma",
    "is_plt": false,
    "is_external": false,
    "entry_block": "0x401130",
    "blocks": ["0x401130"],
    "called_from": ["0x401152"],
    "calls_to": [],
    "annotations": []
  },
  "0x401140": {
    "address": "0x401140",
    "name": "main",
    "is_plt": false,
    "is_external": false,
    "entry_block": "0x401140",
    "blocks": ["0x401140"],
    "called_from": [],
    "calls_to": ["0x401130", "0x401030"],
    "annotations": []
  }
}
```

**Campos obligatorios:**

- `address`: dirección de entrada (duplica la clave del diccionario, pero facilita el código).
- `name`: nombre simbólico de la función o `"sub_<addr>"` si no hay símbolo.
- `is_plt`: true si la función es un stub de la PLT (llamada dinámica a librería).
- `is_external`: true si la función no tiene código en el binario (solo símbolo importado).
- `entry_block`: dirección del bloque de entrada de la función.
- `blocks`: lista ordenada de direcciones de bloques pertenecientes a la función.
- `called_from`: lista de direcciones de instrucciones de `call` que apuntan a esta función.
- `calls_to`: lista de direcciones de funciones invocadas por ésta.
- `annotations`: lista de anotaciones semánticas (vacía en CFG inicial, poblada en CFG enriquecido).

### 4.5 `basic_blocks`

Diccionario de bloques básicos indexado por dirección de inicio.

```json
"basic_blocks": {
  "0x401130": {
    "address": "0x401130",
    "size": 11,
    "function": "0x401130",
    "instructions": ["0x401130", "0x401131", "0x401134", "0x401137", "0x40113a"],
    "successors": ["0x40113b"],
    "predecessors": [],
    "annotations": []
  }
}
```

**Campos obligatorios:**

- `address`: dirección de inicio del bloque.
- `size`: tamaño en bytes.
- `function`: dirección de la función que contiene el bloque.
- `instructions`: lista ordenada de direcciones de instrucciones del bloque.
- `successors`: direcciones de bloques a los que transfiere control. Para terminar análisis complejos el orden importa: para saltos condicionales, el primer sucesor es el del caso "taken" y el segundo el "fall-through".
- `predecessors`: direcciones de bloques desde los que se llega a éste. Redundante con `successors` pero se mantiene por comodidad del Traductor.
- `annotations`: anotaciones semánticas del bloque (ver sección 5).

**Propiedad estructural garantizada por el Extractor:** los bloques están normalizados. Cada bloque tiene exactamente una entrada (su primera instrucción) y exactamente una salida (su última instrucción). Esto corresponde a `CFGFast(normalize=True)` en angr.

### 4.6 `instructions`

Diccionario de instrucciones indexado por dirección.

```json
"instructions": {
  "0x401140": {
    "address": "0x401140",
    "mnemonic": "push",
    "operands": "rbp",
    "bytes": "55",
    "size": 1,
    "block": "0x401140",
    "registers_read": ["rsp", "rbp"],
    "registers_written": ["rsp"],
    "memory_accesses": [
      {"type": "write", "size": 8, "base_register": "rsp", "offset": -8}
    ],
    "annotations": []
  }
}
```

**Campos obligatorios:**

- `address`: dirección de la instrucción.
- `mnemonic`: mnemónico (minúsculas, por ejemplo `"push"`, `"mov"`, `"call"`).
- `operands`: string de operandos tal como lo emite capstone (por ejemplo `"rbp, rsp"`, `"qword ptr [rbp - 8], 5"`).
- `bytes`: bytes de la instrucción en hex sin prefijo (por ejemplo `"55"` para push rbp).
- `size`: tamaño en bytes.
- `block`: dirección del bloque que contiene la instrucción.
- `registers_read`, `registers_written`: listas de nombres de registros. Nombres en minúsculas tal como los da capstone (`"rax"`, `"rbp"`, `"rip"`).
- `memory_accesses`: lista de accesos a memoria de la instrucción.
- `annotations`: anotaciones semánticas específicas de la instrucción.

**Estructura de `memory_accesses`:**

```json
{
  "type": "read" | "write" | "read_write",
  "size": <int, bytes>,
  "base_register": <string | null>,
  "index_register": <string | null>,
  "scale": <int, 1 | 2 | 4 | 8>,
  "offset": <int, signed>
}
```

Representa accesos de la forma `[base + index*scale + offset]`. Si algún componente no aplica, su valor es `null` o `0` según corresponda (`base_register: null` si no hay base, `offset: 0` si no hay desplazamiento).

### 4.7 `edges`

Lista de aristas del CFG, con tipos tipificados. A diferencia de las secciones anteriores, las aristas no tienen dirección única, así que se representan como una lista.

```json
"edges": [
  {
    "source": "0x40113a",
    "target": "0x40113b",
    "type": "fall_through",
    "condition": null,
    "annotations": []
  },
  {
    "source": "0x401152",
    "target": "0x401130",
    "type": "call",
    "condition": null,
    "annotations": []
  },
  {
    "source": "0x401167",
    "target": "0x40116e",
    "type": "conditional_jump",
    "condition": "ZF == 1",
    "annotations": []
  }
]
```

**Campos obligatorios:**

- `source`: dirección de la instrucción origen (normalmente la última instrucción del bloque origen).
- `target`: dirección de destino. Para llamadas, la entrada de la función llamada.
- `type`: tipo de arista (ver enumeración abajo).
- `condition`: expresión de condición para saltos condicionales, `null` en otros casos.
- `annotations`: anotaciones sobre la arista.

**Tipos de arista permitidos:**

| Tipo | Descripción |
|---|---|
| `fall_through` | Caída natural a la siguiente instrucción sin salto explícito |
| `unconditional_jump` | `jmp` incondicional |
| `conditional_jump` | `je`, `jne`, `jl`, `jg`, etc. Requiere `condition` no-null |
| `call` | `call` a función conocida |
| `call_indirect` | `call` con destino indirecto (registro o memoria) |
| `return` | `ret` |
| `indirect_jump` | `jmp` con destino indirecto (no resuelto en v1.0.0) |
| `syscall` | Instrucción `syscall` |

## 5. Anotaciones semánticas

Las anotaciones son el mecanismo que distingue el CFG enriquecido del CFG inicial. Cada nodo del grafo (función, bloque, instrucción, arista) tiene una lista `annotations` que en el CFG inicial está vacía y en el CFG enriquecido contiene objetos de los tipos descritos aquí.

Toda anotación tiene esta estructura base:

```json
{
  "type": "<nombre_del_tipo>",
  "added_by": "<componente_que_añadió_la_anotación>",
  ... <campos específicos del tipo>
}
```

### 5.1 Tipos de anotación en v1.0.0

**`external_call`** (se coloca en instrucciones `call` que van a PLT, y en la instrucción misma, no en la arista).

```json
{
  "type": "external_call",
  "added_by": "enricher",
  "function_name": "printf",
  "library": "libc.so.6",
  "prototype": "int printf(const char *format, ...)",
  "argument_registers": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
}
```

**`syscall`** (se coloca en instrucciones `syscall`).

```json
{
  "type": "syscall",
  "added_by": "enricher",
  "syscall_number": 1,
  "syscall_name": "write",
  "argument_registers": ["rdi", "rsi", "rdx"],
  "return_register": "rax"
}
```

**`functional_class`** (se coloca en bloques básicos).

```json
{
  "type": "functional_class",
  "added_by": "enricher",
  "category": "function_prologue",
  "description": "Standard function prologue (push rbp; mov rbp, rsp)"
}
```

Valores permitidos de `category` en v1.0.0:

- `function_prologue`: prólogo de función (salvado de rbp, ajuste de rsp).
- `function_epilogue`: epílogo (restauración de rbp, ret).
- `function_body`: cuerpo general.
- `external_call_site`: bloque que contiene una llamada externa.
- `syscall_site`: bloque que contiene una syscall.
- `loop_header`: cabecera de bucle (detectado por back-edge).
- `return_block`: bloque que contiene el `ret`.
- `unreachable`: bloque marcado como inalcanzable por el análisis.

**`trace_recommendation`** (se coloca en bloques básicos — esta es la anotación clave que gobierna la generación de `__trace()`).

```json
{
  "type": "trace_recommendation",
  "added_by": "enricher",
  "granularity": "block",
  "rationale": "Block entry is sufficient for functional_body category"
}
```

Valores permitidos de `granularity`:

- `none`: no insertar trazabilidad runtime en este bloque.
- `block`: insertar una llamada `__trace()` al inicio del bloque (granularidad gruesa).
- `instruction`: insertar `__trace()` antes de cada instrucción (granularidad fina).
- `selective`: el traductor decide instrucción a instrucción según anotaciones de instrucción.

El Traductor consulta esta anotación para decidir su comportamiento. En modo "grueso" el Enriquecedor marca todos los bloques con `granularity: "block"`. En modo "fino" con `"instruction"`. En modo "selectivo" las decisiones se distribuyen: bloques de prólogo/epílogo pueden ir sin traza, llamadas externas y syscalls con traza fina, el resto con traza por bloque. **Esta es la contribución central del TFE.**

**`trace_point`** (se coloca en instrucciones concretas en modo selectivo).

```json
{
  "type": "trace_point",
  "added_by": "enricher",
  "reason": "external_call_site"
}
```

Campos permitidos en `reason`:

- `block_entry`: primera instrucción de un bloque con granularidad `"block"`.
- `external_call_site`: instrucción que hace llamada externa.
- `syscall_site`: instrucción syscall.
- `loop_backedge`: destino de un back-edge de bucle.
- `user_request`: el usuario pidió explícitamente traza aquí vía CLI.

### 5.2 Extensibilidad de anotaciones

Para añadir un nuevo tipo de anotación en versiones futuras (ej: `"dataflow_summary"` en v1.1.0), basta con:

1. Documentarlo en una nueva sección de este documento.
2. Incrementar el número de versión del esquema.
3. Asegurarse de que los lectores antiguos ignoran anotaciones desconocidas (comportamiento por defecto).

El Traductor debe ignorar tipos de anotación desconocidos en lugar de fallar. Esta es una regla de robustez importante.

## 6. Invariantes y validación

Un fichero conforme al esquema debe satisfacer estas invariantes. Cualquier fichero que las viole es inválido, aunque pase la validación sintáctica de JSON Schema.

**Invariante I1 (integridad referencial de funciones).** Para cada función F en `functions`:
- `F.entry_block` debe existir en `basic_blocks`.
- Cada dirección en `F.blocks` debe existir en `basic_blocks`.
- Cada dirección en `F.calls_to` debe existir en `functions`.

**Invariante I2 (integridad referencial de bloques).** Para cada bloque B en `basic_blocks`:
- `B.function` debe existir en `functions` y `B.address` debe estar en `functions[B.function].blocks`.
- Cada dirección en `B.instructions` debe existir en `instructions`.
- Cada dirección en `B.successors` y `B.predecessors` debe existir en `basic_blocks` o ser una función externa conocida.

**Invariante I3 (integridad referencial de instrucciones).** Para cada instrucción I en `instructions`:
- `I.block` debe existir en `basic_blocks` y `I.address` debe estar en `basic_blocks[I.block].instructions`.

**Invariante I4 (consistencia de aristas).** Para cada arista E en `edges`:
- `E.source` debe existir en `instructions`.
- `E.target` debe existir en `basic_blocks` o en `functions` (para llamadas externas).
- Si `E.type == "conditional_jump"` entonces `E.condition` no puede ser `null`.

**Invariante I5 (coherencia predecesores/sucesores).** Si `B1.successors` contiene `B2.address`, entonces `B2.predecessors` debe contener `B1.address`.

**Invariante I6 (bloques normalizados).** Cada instrucción excepto la primera de un bloque no debe tener aristas entrantes, y cada instrucción excepto la última no debe tener aristas salientes distintas de `fall_through` a la siguiente.

**Invariante I7 (unicidad de direcciones).** No pueden existir dos entradas en `functions`, `basic_blocks` o `instructions` con la misma dirección.

El validador (semana 2) comprueba I1 a I7 en cada carga de fichero. En caso de violación, aborta con un mensaje descriptivo.

## 7. Limitaciones conocidas de v1.0.0

Se documentan explícitamente para evitar confusiones:

- **Sin soporte de tipos de datos.** Las variables locales, argumentos y retornos no se anotan con tipos. Esto se pospone a trabajo futuro (recuperación de tipos).
- **Sin soporte de saltos indirectos resueltos.** `indirect_jump` y `call_indirect` se registran pero no se resuelven en v1.0.0.
- **Arquitectura fija.** Solo amd64 / x86-64 / ELF / little-endian.
- **Sin información de dataflow.** Los registros leídos/escritos son por instrucción individual; no hay análisis def-use a nivel de bloque o función.

## 8. Evolución prevista

Cambios razonables que pueden llegar en versiones futuras (no comprometen este trabajo):

- v1.1.0: anotaciones de dataflow y live variables.
- v1.2.0: soporte de saltos indirectos resueltos (tablas de switch).
- v1.3.0: anotaciones de tipos recuperados.
- v2.0.0: soporte de otras arquitecturas (ARM, RISC-V). Cambio mayor porque requiere revisar los nombres de registros y los tipos de acceso.
