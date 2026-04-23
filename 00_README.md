# Esquema del CFG enriquecido — v1.0.0

Este directorio contiene el contrato de datos del **CFG enriquecido**, la estructura central del pipeline del TFE. Es el entregable de la **semana 2** del cronograma.

## Qué es el CFG enriquecido

Es la estructura de datos intercambiada entre los tres componentes principales del prototipo:

```
Extractor ──(CFG inicial)──► Enriquecedor ──(CFG enriquecido)──► Traductor
```

- El **Extractor** lo produce a partir del binario ELF (anotaciones vacías).
- El **Enriquecedor** añade anotaciones semánticas.
- El **Traductor** lo consume para decidir qué emitir en el código C, incluyendo dónde insertar trazabilidad ejecutable.

El esquema es el mismo para ambas fases; lo que cambia son las anotaciones presentes.

## Ficheros de este directorio

| Fichero | Propósito | Audiencia |
|---|---|---|
| `01_especificacion.md` | Contrato human-readable. Define cada campo, los invariantes y las reglas de compatibilidad de versiones. | Tú, tu director, el tribunal |
| `02_cfg_schema.json` | JSON Schema draft-07. Validación sintáctica automática con `jsonschema`. | El código del proyecto |
| `03_ejemplo_hello.json` | CFG enriquecido de un hello world sencillo. Referencia visual. | Tú durante la implementación, y el tribunal en la defensa |
| `04_cfg_model.py` | Dataclasses Python con `load`/`save`/`validate`. | Copiar/pegar al repo del prototipo |

## Cómo usarlos durante la semana 2

1. Lee `01_especificacion.md` entero. Son unos 25 minutos.
2. Abre `03_ejemplo_hello.json` al lado y verifica que entiendes cada campo.
3. Copia `04_cfg_model.py` al repo del prototipo en `src/cfg/model.py` (o donde tengas la estructura de paquetes).
4. Copia `02_cfg_schema.json` al repo en `schemas/cfg_v1.0.0.json`.
5. Añade a los tests un smoke test que valide el fichero de ejemplo:
   ```python
   def test_esquema_ejemplo_valido():
       cfg = EnrichedCFG.load('schemas/ejemplos/hello.ecfg.json')
       cfg.validate()
   ```
6. Si decides modificar algo del esquema durante las semanas siguientes, **incrementa el número de versión** (patch → 1.0.1, minor → 1.1.0) y documenta el cambio en `01_especificacion.md` sección 8.

## Validación rápida

Para verificar que un fichero es conforme al esquema:

```bash
# Validación sintáctica con JSON Schema
python3 -c "
import json, jsonschema
schema = json.load(open('02_cfg_schema.json'))
data = json.load(open('<tu_fichero>.json'))
jsonschema.validate(data, schema)
print('OK')
"

# Validación semántica (invariantes I1-I7)
python3 04_cfg_model.py <tu_fichero>.json
```

Ambos tipos de validación son necesarios: JSON Schema valida que los tipos son correctos, las dataclasses validan que las referencias cruzadas son consistentes.

## Decisiones de diseño relevantes para la memoria

Las siguientes decisiones están documentadas en `01_especificacion.md` y conviene que aparezcan en la sección 4.5.1 "Decisiones de diseño" de la memoria:

- **Estructura plana indexada por dirección.** Lookup O(1) desde el Traductor, coste de legibilidad aceptable porque las herramientas de inspección del CFG resuelven la jerarquía al reconstruir.
- **Direcciones como strings hex.** Legibilidad al depurar, consistencia con las herramientas de análisis binario (objdump, IDA, Ghidra), parsing a entero trivial cuando se necesita.
- **Versionado del esquema + metadatos de generación.** Permite evolución del esquema sin romper ficheros antiguos, facilita el debugging al poder distinguir qué versión de la herramienta produjo cada fichero.
- **Anotaciones como mecanismo extensible.** Nuevos tipos de análisis no requieren cambios del esquema base, solo añadir entradas al `ANNOTATION_REGISTRY`. Lectores antiguos ignoran anotaciones desconocidas en lugar de fallar.
- **`trace_recommendation` como anotación de primera clase.** Es el mecanismo mediante el cual el CFG enriquecido gobierna las decisiones del Traductor sobre trazabilidad ejecutable. Esta es la contribución central del TFE a nivel de diseño.

## Qué NO cubre esta versión (v1.0.0)

Documentado también en la especificación, sección 7. Se declara explícitamente para acotar alcance:

- No hay soporte para tipos de datos recuperados (argumentos, variables, retornos).
- No se resuelven saltos indirectos (`indirect_jump`, `call_indirect` se registran pero no se resuelven).
- Solo arquitectura x86-64, formato ELF, little-endian.
- No hay análisis de dataflow (solo uso/definición a nivel de instrucción individual).

Estos puntos forman parte del trabajo futuro a plantear en el Capítulo 5 de la memoria y son la base del posible paper post-TFE.
