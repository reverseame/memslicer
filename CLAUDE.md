# CLAUDE.md

Guía para trabajar en este repo, derivada de una sesión larga de debugging real sobre
`memslicer.symbex` (Fases 1-7) y `memslicer.emu`/`memslicer.behavior`. Todo lo de aquí costó tiempo
real de depuración para descubrir — no son cosas que se puedan re-derivar leyendo el código rápido.

## La regla de oro de esta sesión: no confíes en "no lanza excepción"

En una sola sesión aparecieron **5+ bugs reales** en `memslicer.symbex`, todos invisibles hasta que
alguien forzó una ejecución real contra datos reales y miró los valores byte a byte. Ninguno lo
detectó la suite de tests existente. El motivo común: **`except Exception: pass`/`except Exception:
return False` demasiado amplios**, sin logging, que convierten un fallo real en un resultado
silenciosamente incorrecto en vez de un crash visible.

**Antes de dar por buena cualquier función que toque `angr`/`unicorn`/parsing de memoria real:**
- Verifica con un `.msl` real capturado en vivo (`python -m memslicer <PID> --backend frida`), no
  solo con binarios sintéticos hechos a mano. Los binarios sintéticos no detectaron ninguno de los
  bugs de esta sesión — todos salieron al probar contra `phase7_validation/real_notepad_dump.msl`.
- Comprueba el *valor* resultante (`state.solver.eval(...)`, direcciones resueltas, etc.), no solo
  que la llamada "no falló".
- Si añades un `except`, plantéate si de verdad quieres silenciarlo o si necesita como mínimo
  `logger.debug`/`logger.warning` — un fallo real que se traga en silencio es peor que un crash.
- Corre la **suite completa** de tests antes de dar algo por cerrado, no solo el fichero que
  tocaste — los bugs de `anti_analysis.py` de esta sesión llevaban tiempo sin detectarse
  precisamente porque nadie corría la suite entera tras la última reescritura.

## Gotchas concretos de angr/unicorn descubiertos esta sesión

1. **`state.memory.load(addr, size)` interpreta big-endian por defecto**, sin importar la
   arquitectura objetivo. En x86/AMD64 (little-endian) hace falta pasar
   `endness=state.arch.memory_endness` explícitamente en cualquier lectura de un entero
   multi-byte, o el valor sale con los bytes invertidos. Esto rompió el parseo de cabeceras PE
   (`e_lfanew` salía como `0xf8000000` en vez de `0xf8`) hasta que se corrigió.

2. **`state.regs` en angr solo expone `gs`/`fs`** (contienen la base completa de 64/32 bits
   directamente) — **no existen** `gs_base`, `gs_const`, `gs_offset`, `fs_base`, etc. como
   atributos, ni en X86 ni en AMD64. Código que intente sembrar esos nombres debe normalizar sobre
   `gs`/`fs`, o el valor capturado se pierde en silencio.

3. **`load_angr()` solo registra como objeto CLE real la ÚNICA región que contiene el PC
   capturado.** El resto de módulos de un volcado real (DLLs, el `.exe` principal si el PC está en
   `ntdll`, etc.) quedan como bytes crudos en `state.memory`, sin tabla de símbolos. Por eso
   `find_symbol`/`hook_symbol` no resuelve nada de otros módulos en un volcado real multi-módulo —
   hace falta resolver por dirección (parseando la tabla de exports PE desde memoria capturada,
   ver `angr_loader.resolve_pe_export()`) en vez de por nombre de símbolo CLE.

4. **Parsear la tabla de exports de un PE ya cargado en memoria es más simple que desde disco**:
   las RVA del PE mapean directo a `module_base + rva`, sin traducir offset-de-fichero — pero hay
   que detectar *forwarders* (cuando la RVA "resuelta" cae dentro del propio rango de la tabla de
   exports, apunta a una cadena tipo `"KERNELBASE.NtQueryInformationProcess"`, no a código).

5. Al buscar un export/símbolo entre varios módulos candidatos (p. ej. `kernel32.dll` **y**
   `ntdll.dll` como candidatos válidos para una misma API), **prueba todos los módulos que
   coincidan por nombre, no te quedes con el primero de la lista** — una función puede existir en
   uno y no en otro, y quedarte con el primero que "coincide por nombre" puede no ser el que
   realmente la exporta.

6. `claripy` puede usarse en un fichero sin estar importado si el import real está detrás de un
   `try/except` genérico — revísalo si algo que usa `claripy.BVV(...)` falla en silencio.

## Principio de diseño para mecanismos de auto-recuperación/auto-hook

El bug raíz de la Fase 7 (`unmapped_handler.py` hookeando con un stub genérico cualquier dirección
de código revisitada) vino de aplicar una recuperación pensada para páginas **genuinamente nuevas y
sintéticas** también a código **ya cargado y válido** que simplemente se revisitaba (bucles, saltos
hacia atrás). Regla general: cualquier lógica de auto-mapeo/auto-hook debe distinguir explícitamente
"esto lo creé yo como relleno sintético" de "esto es dato real que se está accediendo otra vez" —
nunca aplicar la recuperación solo porque "la dirección no está hookeada todavía".

## Dónde está cada cosa

- `phase7_validation/` — arnés de validación sintético (binario hecho a mano, sin dependencias
  externas). `testSymbex/` — capturas reales + `target.c`/`target_dump.msl`, que incluye una función
  (`trigger_unmapped_stack_workload`) construida a propósito para disparar `UC_ERR_WRITE_UNMAPPED`
  en el emulador concreto.
- `scratch/reports/` — informes de fase (1-6) y hallazgos de validación real
  (`findings_real_msl_validation.md`). **Trata las afirmaciones de "COMPLETADO"/"APTO PARA
  PRODUCCIÓN" de los informes de fase 1-4 con escepticismo** — se escribieron contra un estado del
  código que ya no es el actual, y varias de esas afirmaciones no se sostenían al re-verificarlas.
- `docs/malware_analysis_guide.md` — evaluación honesta de para qué sirve (y para qué no) este
  módulo en análisis de malware, con flujo de trabajo concreto.
- El emulador concreto (`memslicer.emu`, Unicorn+Capstone) y el trazador de comportamiento
  (`memslicer.behavior`) **no tienen ningún mecanismo de recuperación ante memoria no mapeada** —
  a diferencia de `memslicer.symbex`, que sí lo tiene (`unmapped_handler.py`). Un
  `UC_ERR_*_UNMAPPED` hoy simplemente termina la traza.

## Estilo de colaboración esperado en este repo

- Reporta hallazgos primero, no arregles nada hasta que se confirme — el flujo habitual es
  encontrar → documentar → el usuario decide si se arregla ahora.
- Tras cualquier fix, verifica con: (1) el caso de reproducción exacto, (2) el flujo E2E sintético
  de referencia (`phase7_validation/phase7_sample.msl` con `--find-rax-success`, debe seguir
  resolviendo `00ff12a55a7e90421337c0defeed8899`), (3) la suite completa de pytest.
- No commitees nada salvo que se pida explícitamente — el usuario prefiere revisar y commitear él
  mismo.
