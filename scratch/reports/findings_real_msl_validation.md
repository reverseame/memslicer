# Hallazgos: Validación contra un volcado `.msl` real

**Fecha:** 27 de Agosto de 2026
**Contexto:** Todas las Fases 1-7 se habían verificado únicamente contra binarios sintéticos hechos a mano (`phase7_sample.msl`, blobs de test). Este documento recoge lo encontrado al probar por primera vez el pipeline completo contra un volcado real, capturado en vivo con `python -m memslicer` (backend Frida) sobre un proceso `notepad.exe` real (PID 18060): `phase7_validation/real_notepad_dump.msl` (89 MB, 344/465 regiones, 21.737/21.737 páginas 100%, 48 módulos, calidad GOOD).

---

## Confirmado que funciona

- **Captura real end-to-end**: `python -m memslicer <PID> --backend frida --os windows` produce un `.msl` válido y completo sobre un proceso Windows real.
- **`load_angr` con un volcado real**: resuelve el entry point real (dentro de `ntdll.dll`), carga las 21.737 páginas capturadas en `state.memory`, arranca sin excepciones.
- **Ejecución simbólica cruzando límites de módulo reales**: con direcciones ASLR genuinas (`0x7fff500c1104` → otra DLL → `0x7ff6237eb0f0` de vuelta en el `.exe` principal), sin errores de motor.
- **Fix de `GS`/`FS` (sesión de hoy)**: `GS` se siembra correctamente al valor real capturado (`0x8c778ad000`), no a `0x0` — validado tanto en el sintético como en el real.

---

## ~~Hallazgo~~ ARREGLADO: el hooking anti-análisis por símbolo no funcionaba sobre un volcado real

**Severidad: alta — invalidaba parcialmente la funcionalidad central de `--bypass-anti-analysis` en el caso de uso real del módulo.**

**Fix aplicado (vía 2 de las propuestas abajo — resolución por dirección, no registro de CLE completo):**
1. [`angr_loader.resolve_pe_export()`](../../src/memslicer/symbex/angr_loader.py): parsea la tabla de exports PE **directamente desde la memoria capturada** (DOS header → NT headers → Export Directory → AddressOfNames/Functions/Ordinals) para cualquier módulo de la lista `SliceImage.modules` que ya trae la captura real (base/tamaño/ruta por DLL). Como el módulo está cargado/rebasado en memoria, las RVA del PE mapean directo a `module.base + rva`, sin traducir offsets de fichero.
2. `load_angr()` ahora deja la lista de módulos en `state.globals["msl_modules"]`.
3. `apply_anti_analysis_bypass()`: si el hooking por símbolo CLE no engancha nada (el caso normal en un volcado real), cae a `resolve_pe_export()` sobre `kernel32.dll`/`ntdll.dll`/`kernelbase.dll` (con variantes de mayúsculas) y hookea por **dirección real** en vez de por nombre.

**Dos bugs encontrados y corregidos durante la implementación** (ambos habrían dejado el fix silenciosamente roto):
- **Endianness**: `state.memory.load()` de angr interpreta big-endian por defecto sin importar la arquitectura — sin `endness=state.arch.memory_endness` explícito, `e_lfanew` salía como `0xf8000000` en vez de `0xf8`, y todo lo demás se corrompía en cascada.
- **Prioridad de módulo**: la función se quedaba con el primer módulo de la lista que coincidiera con *cualquier* candidato (p. ej. `ntdll.dll`, que aparece antes que `kernel32.dll` en la captura) y se rendía si ese módulo concreto no tenía el export pedido — `IsDebuggerPresent` no está en `ntdll.dll`, así que nunca se encontraba pese a que sí estaba en `kernel32.dll`, más abajo en la lista. Ahora prueba **todos** los módulos candidatos, no solo el primero que coincide por nombre.
- Bonus: detección de *forwarders* PE (cuando un export es en realidad un reenvío a otra DLL, la RVA "resuelta" cae dentro de la propia tabla de exports y apunta a una cadena, no a código — se descarta y se prueba el siguiente candidato).

**Verificado sobre `real_notepad_dump.msl`:**
```
Hooked IsDebuggerPresent at 0x7fff51f304f0 via PE export table (no CLE symbol available)
Hooked CheckRemoteDebuggerPresent at 0x7fff51f11250 via PE export table (no CLE symbol available)
Hooked NtQueryInformationProcess at 0x7fff524ad8b0 via PE export table (no CLE symbol available)
```
Las tres direcciones caen dentro del rango real de `KERNEL32.DLL`/`ntdll.dll` en el volcado. El flujo E2E de la CLI (`--bypass-anti-analysis --steps 5`) y la regresión sintética de Fase 7 siguen funcionando igual (clave `00ff12a55a7e90421337c0defeed8899` sin cambios).

**Limitación que queda sin resolver:** el enmascarado PEB (parte 1 del bypass) sigue funcionando igual que antes; este fix solo cubre el hooking de API (parte 2). Tampoco se implementó la vía 1 (registrar un objeto CLE real por módulo) — sigue siendo una alternativa más completa pero mucho más cara si en el futuro se necesita resolución de símbolos genérica más allá de estas 3 APIs concretas.

---

<details>
<summary>Contexto original del hallazgo (antes del fix)</summary>

`load_angr` solo instancia un objeto CLE real para la **única región de memoria que contiene el PC capturado**. Las otras ~47 DLLs del proceso (incluida `kernel32.dll`, que exporta `IsDebuggerPresent`) quedan como bytes crudos en `state.memory`, sin tabla de símbolos/exports.

Verificado directamente sobre `real_notepad_dump.msl`:
```
all_objects count: 2        (el blob de la región del PC capturado + el placeholder cle##externs)
find_symbol('IsDebuggerPresent'): None
exported symbols found: 0
apply_anti_analysis_bypass() -> IsDebuggerPresent hooked anywhere? False
```

**Qué sigue funcionando:** el enmascarado de PEB (`mask_peb_anti_debug`, escritura directa en memoria) no depende de símbolos, así que sigue aplicándose.

**Qué NO funciona:** el hooking de `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` vía `project.hook_symbol(...)` — nunca se instala ningún hook porque ningún objeto CLE real expone esos símbolos.

Esto confirma con datos reproducibles lo que la Fase 6 ya admitía como caveat no verificado ("no validado como soporte Multi-CLE de producción") — deja de ser una advertencia teórica y pasa a ser un fallo medido y reproducible en el caso de uso principal del módulo (analizar un volcado forense real).

**Posibles vías de arreglo (no evaluadas en profundidad todavía):**
1. Registrar un objeto CLE real por cada módulo presente en el `.msl` (usando la lista de módulos que la propia captura ya registra), no solo la región del PC.
2. Alternativa más barata: en vez de depender de `find_symbol`/`hook_symbol` por nombre, resolver la dirección real de la API objetivo a partir de la lista de módulos/exports del `.msl` (si la captura la incluye) y hookear por dirección directamente.

</details>

---

## Confirmado que funciona (ronda 2, sobre el volcado real)

- **40 pasos de ejecución simbólica consecutivos sin ningún error**, saltando entre al menos 4 rangos de módulo reales distintos (`ntdll`, el `.exe` principal, y otras dos DLLs). Ninguna recuperación de `unmapped_handler.py` fue necesaria porque todas las páginas capturadas (de cualquier módulo) se almacenan en `state.memory` igualmente — el problema del hallazgo anterior es solo de resolución de *símbolos*, no de acceso a memoria/ejecución.
- **`--call-function` contra una dirección real dentro de `notepad.exe`** (no `ntdll`): arma correctamente el `call_state`, inyecta el búfer simbólico, ejecuta 5 pasos cruzando de vuelta a `ntdll` sin errores.

## ~~Hallazgo~~ ARREGLADO: `--avoid`/`--avoid-module` era un no-op silencioso en modo `--steps`

**Severidad: media — comportamiento engañoso, no solo indocumentado.**

Reproducido con datos reales: `--avoid 0x7ff6237eb0f0 --steps 10` imprimía `[+] Avoiding explicit address(es): ['0x7ff6237eb0f0']`, pero el paso 6 del trace aterrizaba **exactamente en esa dirección**. El bucle de `elif steps > 0:` nunca consultaba `avoid_addrs`/`avoid_module_addrs` — esa poda solo estaba implementada dentro del bucle de `--find`/`--find-rax-success`.

**Fix aplicado:** extraída la lógica de poda a [`_prune_avoided()`](../../src/memslicer/cli_symbex.py) y aplicada en ambos bucles (`--find`/`--find-rax-success` y `--steps`). Verificado con el mismo caso real: ahora el estado se poda antes de aterrizar en la dirección evitada (`active states: 0` en vez de continuar a través de ella).

---

## Confirmado que funciona (ronda 3): robustez profunda del motor

- **`--avoid-module ntdll.dll --find-rax-success` sobre el volcado real**: avisa correctamente "Module 'ntdll.dll' not found in loaded binary objects" (consistente con el hallazgo de arriba — no hay objeto CLE para `ntdll.dll`), y luego **explora 141 bloques reales consecutivos cruzando al menos 8 módulos Windows distintos (ntdll, notepad.exe, y varias DLLs más en rangos `0x7fff52...`, `0x7fff4fde...`, `0x7fff4fe4...`, `0x7fff3abe...`) sin un solo error de motor ni acceso a memoria no mapeada**. Es la prueba de estrés más profunda hecha hasta ahora y el motor la aguanta limpiamente.

## ~~Matiz~~ DOCUMENTADO: `--find-rax-success` no tiene sentido semántico fuera de binarios tipo "comprobación de licencia"

El comando anterior terminó en "REACHED TARGET ... SOLVED LICENSE KEY" con una clave que es literalmente ruido (`0000000000000000007e23f67f000020`, mayormente bytes no imprimibles). Esto es esperable, no un fallo: `--find-rax-success` da por bueno el primer estado real donde `RAX==1` sea satisfacible tras un `ret` — y en código Windows genérico (no un binario de comprobación de clave), *casi cualquier* función puede retornar 1 de forma trivial, así que "encuentra éxito" casi de inmediato sin que signifique nada.

**Fix aplicado:** documentado el alcance real en el `--help` de `-r/--find-rax-success`, y añadido un aviso en tiempo de ejecución (impreso al activar el flag) recomendando `--find ADDR` cuando se tiene una dirección objetivo real. No se cambió el comportamiento — el flag sigue haciendo exactamente lo que dice, solo se dejó de fingir que es una heurística de propósito general.

---

## Confirmado que funciona (ronda 4): syscalls reales no tabuladas

Forzado el PC al stub real `0x7fff500c1110` (`mov eax, 0x1007; test byte ptr [0x7ffe0308],1; jne; syscall`) dentro de `ntdll.dll`. `0x1007` no está en `WINDOWS_NT_X64_TABLE` (solo tiene un puñado de syscalls hardcodeadas). Resultado, paso a paso:
```
tras step 1 (mov eax,0x1007): pc=...1122 (la propia instrucción syscall) rax=0x1007
tras step 2 (ejecuta syscall): pc=...1124 (ret siguiente)              rax=0x0   <- GenericSyscallStub actuó
tras step 3 (ret real):        pc=0x7fff515d212e (vuelve al caller real) rax=0x0
```
`GenericSyscallStub` intercepta correctamente una syscall real **no tabulada**, la clasifica como `APPROXIMATE_FALLBACK`, pone `RAX=STATUS_SUCCESS (0)` y avanza el PC — sin caerse, sin necesitar que la syscall esté en la tabla. Robusto también en este frente.

---

## Pendiente de seguir probando

- Probar con un segundo proceso real distinto (con más hilos / GUI más compleja, o un binario de consola) para ver si la captura y carga siguen siendo robustas fuera de notepad.
- Evaluar en profundidad las dos vías de arreglo propuestas para el hallazgo grande abierto (multi-CLE / hooking por símbolo no funcional en volcados reales) — sigue sin resolver.
