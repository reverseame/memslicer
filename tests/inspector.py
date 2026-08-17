"""Inspector universal de procedencia de restricciones para angr / MemSlicer.

Incluye formateo inteligente de direcciones hexadecimales, mapeo de punteros
y clasificación visual de regiones de memoria.
"""

from __future__ import annotations

from typing import Any


def format_address(val: int | None) -> str:
    """Formatea un valor entero de registro o dirección como notación Hexadecimal canónica."""
    if val is None:
        return "N/A"
    if isinstance(val, int):
        if val > 0xFFFFFFFF:
            return f"0x{val & 0xFFFFFFFFFFFFFFFF:016x}"
        return f"0x{val & 0xFFFFFFFF:08x}"
    return str(val)


def classify_memory_region(addr: int) -> str:
    """Clasifica la zona de memoria aproximada según el rango de dirección virtual."""
    if addr >= 0x7FF000000000 or addr >= 0x7FFF0000:
        return "Pila / Stack"
    elif addr >= 0xFF00000000000000 or addr >= 0x8000000000000000:
        return "Memoria Virtual Simbólica"
    elif addr >= 0x140000000 or addr >= 0x400000:
        return "Sección de Ejecutable / Binario"
    return "Heap / Memoria Dinámica"


def universal_provenance_inspector(state: Any, verbose: bool = True) -> dict[str, Any]:
    """Analiza las restricciones (constraints) de un SimState e identifica automáticamente
    el origen de cada variable simbólica con formateo limpio y mapeo de punteros.
    """
    findings: dict[str, Any] = {
        "STDIN": [],
        "Archivos": {},
        "Sockets de Red": {},
        "Registros CPU": {},
        "Memoria RAM": {},
        "Argumentos CLI": [],
        "Variables Entorno": [],
        "Mapeo Punteros": {},
    }

    if not hasattr(state, "solver") or not hasattr(state.solver, "constraints"):
        if verbose:
            print("[-] El estado proporcionado no tiene restricciones válidas.")
        return findings

    mem_bytes: dict[int, int] = {}

    for constraint in state.solver.constraints:
        variables = getattr(constraint, "variables", set())
        for var in variables:
            # 1. Registros de CPU (ej: reg_rcx_0_64)
            if var.startswith("reg_"):
                parts = var.split("_")
                if len(parts) >= 2:
                    reg_name = parts[1]
                    try:
                        reg_val = state.solver.eval(getattr(state.regs, reg_name, None))
                        findings["Registros CPU"][reg_name] = reg_val
                    except Exception:
                        findings["Registros CPU"][reg_name] = "Simbólico"

            # 2. Direcciones de Memoria RAM (ej: mem_8000000000000000_1_8)
            elif var.startswith("mem_"):
                parts = var.split("_")
                if len(parts) >= 2:
                    try:
                        addr = int(parts[1], 16)
                        byte_val = state.solver.eval(state.memory.load(addr, 1))
                        if isinstance(byte_val, int):
                            mem_bytes[addr] = byte_val
                    except Exception:
                        pass

            # 3. Entrada Estándar STDIN
            elif "stdin" in var or var.startswith("file_0_"):
                try:
                    if hasattr(state, "posix") and hasattr(state.posix, "dumps"):
                        val = state.posix.dumps(0)
                        if val and val not in findings["STDIN"]:
                            findings["STDIN"].append(val)
                except Exception:
                    pass

            # 4. Sockets de Red
            elif "socket" in var or "net" in var:
                parts = var.split("_")
                fd_name = parts[1] if len(parts) > 1 else var
                try:
                    val = state.solver.eval(constraint, cast_to=bytes)
                    findings["Sockets de Red"][fd_name] = val
                except Exception:
                    findings["Sockets de Red"][fd_name] = "Tráfico Simbólico"

            # 5. Archivos en Disco
            elif var.startswith("file_"):
                parts = var.split("_")
                file_name = parts[1] if len(parts) > 1 else var
                try:
                    val = state.solver.eval(constraint, cast_to=bytes)
                    findings["Archivos"][file_name] = val
                except Exception:
                    findings["Archivos"][file_name] = "Contenido Simbólico"

            # 6. Argumentos CLI
            elif var.startswith("arg_") or "argv" in var:
                try:
                    val = state.solver.eval(constraint, cast_to=bytes)
                    if val not in findings["Argumentos CLI"]:
                        findings["Argumentos CLI"].append(val)
                except Exception:
                    pass

    # Reconstrucción de cadena de memoria y vincular con registros (Mapeo de Punteros)
    if mem_bytes:
        sorted_addrs = sorted(mem_bytes.keys())
        start_addr = sorted_addrs[0]
        end_addr = sorted_addrs[-1]
        raw_bytes = bytes([mem_bytes[a] for a in sorted_addrs])
        decoded_text = raw_bytes.decode("latin-1", errors="ignore")

        findings["Memoria RAM"] = {
            "start_address": format_address(start_addr),
            "end_address": format_address(end_addr),
            "region": classify_memory_region(start_addr),
            "raw_hex": raw_bytes.hex(),
            "decoded_text": decoded_text,
            "bytes_count": len(raw_bytes),
        }

        # Detectar si algún registro de CPU apuntaba a esta dirección de memoria
        for reg_name, reg_val in findings["Registros CPU"].items():
            if isinstance(reg_val, int) and reg_val == start_addr:
                findings["Mapeo Punteros"][reg_name] = (
                    f"{reg_name.upper()} ({format_address(reg_val)}) ---> Apunta al buffer: '{decoded_text}'"
                )

    if verbose:
        _print_findings_report(findings)

    return findings


def _print_findings_report(findings: dict[str, Any]) -> None:
    print("\n" + "=" * 65)
    print(" [*] CLASIFICACION AUTOMATICA DE FUENTES Y RESTRICCIONES")
    print("=" * 65)

    has_data = False

    # 1. Mostrar Mapeo de Punteros Directos si existen
    if findings["Mapeo Punteros"]:
        has_data = True
        print("\n [+] VINCULACION DE PUNTEROS Y CONTENIDO:")
        for link_msg in findings["Mapeo Punteros"].values():
            print(f"     - {link_msg}")

    # 2. Mostrar Memoria RAM formateada
    if findings["Memoria RAM"]:
        has_data = True
        ram = findings["Memoria RAM"]
        print("\n [+] FUENTE DETECTADA: Memoria RAM")
        print(
            f"     - Rango Memoria    : {ram['start_address']} - {ram['end_address']}"
        )
        print(f"     - Zona de Memoria  : {ram['region']}")
        print(f"     - Texto Resuelto   : '{ram['decoded_text']}'")
        print(f"     - Bytes (Hex)      : {ram['raw_hex']}")

    # 3. Mostrar Registros de CPU formateados a Hexadecimal
    if findings["Registros CPU"]:
        has_data = True
        print("\n [+] FUENTE DETECTADA: Registros CPU")
        for k, v in findings["Registros CPU"].items():
            formatted_val = format_address(v) if isinstance(v, int) else v
            print(f"     - Registro {k:<5} = {formatted_val}")

    # 4. Mostrar otros canales (Archivos, STDIN, Sockets, CLI)
    for categoria in ["STDIN", "Archivos", "Sockets de Red", "Argumentos CLI"]:
        datos = findings[categoria]
        if datos:
            has_data = True
            print(f"\n [+] FUENTE DETECTADA: {categoria}")
            if isinstance(datos, dict):
                for k, v in datos.items():
                    print(f"     - {k} = {v}")
            elif isinstance(datos, list):
                for item in datos:
                    print(f"     - Valor: {item!r}")

    if not has_data:
        print("\n [-] No se detectaron fuentes o restricciones simbolicas activas.")

    print("=" * 65 + "\n")
