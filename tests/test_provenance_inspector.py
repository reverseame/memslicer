"""Pruebas unitarias verbosas para el inspector universal de procedencia de restricciones (Tests/inspector.py)."""
import sys
import os
from unittest.mock import MagicMock
import pytest

pytest.importorskip("angr")

sys.path.insert(0, os.path.dirname(__file__))
from inspector import universal_provenance_inspector


def create_mock_constraint(var_name):
    """Auxiliar para crear un mock de restricción con nombres de variable simbólica."""
    mock_c = MagicMock()
    mock_c.variables = {var_name}
    return mock_c


def test_empty_state_handling():
    """Verifica que el inspector maneje adecuadamente estados sin restricciones."""
    print("\n" + "-" * 60)
    print(" [TEST 1] Estado Vacio / Sin Restricciones")
    print("-" * 60)
    mock_state = MagicMock()
    mock_state.solver.constraints = []

    res = universal_provenance_inspector(mock_state, verbose=True)
    assert res["STDIN"] == []
    assert res["Memoria RAM"] == {}
    assert res["Registros CPU"] == {}
    print("  [PASS] VERIFICACION COMPLETADA: Manejo correcto de estado vacio.")


def test_memory_provenance_detection():
    """Verifica la detección de restricciones en memoria RAM y reconstrucción de texto."""
    print("\n" + "-" * 60)
    print(" [TEST 2] Deteccion de Procedencia en Memoria RAM")
    print("-" * 60)
    mock_state = MagicMock()

    # Variables de memoria simulando 'PASS'
    c1 = create_mock_constraint("mem_8000000000000000_1_8")
    c2 = create_mock_constraint("mem_8000000000000001_2_8")
    c3 = create_mock_constraint("mem_8000000000000002_3_8")
    c4 = create_mock_constraint("mem_8000000000000003_4_8")

    mock_state.solver.constraints = [c1, c2, c3, c4]

    # Simular evaluación de memoria en el solver: 'P', 'A', 'S', 'S'
    def mock_eval_mem(load_expr):
        addrs_map = {
            0x8000000000000000: 80,
            0x8000000000000001: 65,
            0x8000000000000002: 83,
            0x8000000000000003: 83,
        }
        return addrs_map.get(load_expr, 0)

    def mock_load(addr, size):
        return addr

    mock_state.memory.load = mock_load
    mock_state.solver.eval = mock_eval_mem

    res = universal_provenance_inspector(mock_state, verbose=True)

    assert "Memoria RAM" in res
    ram = res["Memoria RAM"]
    assert ram["decoded_text"] == "PASS"
    assert ram["start_address"] == "0x8000000000000000"
    assert ram["end_address"] == "0x8000000000000003"
    assert ram["bytes_count"] == 4
    print("  [PASS] VERIFICACION COMPLETADA: Cadena 'PASS' reconstruida desde RAM.")


def test_register_provenance_detection():
    """Verifica la detección de restricciones originadas en registros de la CPU."""
    print("\n" + "-" * 60)
    print(" [TEST 3] Deteccion de Procedencia en Registros de CPU")
    print("-" * 60)
    mock_state = MagicMock()
    c1 = create_mock_constraint("reg_rcx_0_64")
    c2 = create_mock_constraint("reg_rax_1_64")

    mock_state.solver.constraints = [c1, c2]

    mock_state.regs.rcx = 0x8000000000000000
    mock_state.regs.rax = 0x1337

    def mock_eval_reg(reg_expr):
        return reg_expr

    mock_state.solver.eval = mock_eval_reg

    res = universal_provenance_inspector(mock_state, verbose=True)

    assert "rcx" in res["Registros CPU"]
    assert res["Registros CPU"]["rcx"] == 0x8000000000000000
    assert "rax" in res["Registros CPU"]
    assert res["Registros CPU"]["rax"] == 0x1337
    print("  [PASS] VERIFICACION COMPLETADA: Registros RCX y RAX detectados.")


def test_stdin_provenance_detection():
    """Verifica la detección de restricciones originadas en la entrada estándar (STDIN)."""
    print("\n" + "-" * 60)
    print(" [TEST 4] Deteccion de Procedencia en STDIN (Entrada Estandar)")
    print("-" * 60)
    mock_state = MagicMock()
    c = create_mock_constraint("file_stdin_0_8")
    mock_state.solver.constraints = [c]
    mock_state.posix.dumps.return_value = b"user_input_key"

    res = universal_provenance_inspector(mock_state, verbose=True)

    assert b"user_input_key" in res["STDIN"]
    print("  [PASS] VERIFICACION COMPLETADA: Entrada STDIN 'user_input_key' capturada.")


def test_file_provenance_detection():
    """Verifica la detección de restricciones originadas en lectura de archivos en disco."""
    print("\n" + "-" * 60)
    print(" [TEST 5] Deteccion de Procedencia en Archivos en Disco")
    print("-" * 60)
    mock_state = MagicMock()
    c = create_mock_constraint("file_license.txt_0_8")
    mock_state.solver.constraints = [c]

    def mock_eval_file(constraint, cast_to=None):
        return b"VALID_LICENSE_DATA"

    mock_state.solver.eval = mock_eval_file

    res = universal_provenance_inspector(mock_state, verbose=True)

    assert "license.txt" in res["Archivos"]
    assert res["Archivos"]["license.txt"] == b"VALID_LICENSE_DATA"
    print("  [PASS] VERIFICACION COMPLETADA: Archivo 'license.txt' detectado.")


def test_network_socket_provenance_detection():
    """Verifica la detección de restricciones originadas en tráfico de sockets de red."""
    print("\n" + "-" * 60)
    print(" [TEST 6] Deteccion de Procedencia en Sockets de Red")
    print("-" * 60)
    mock_state = MagicMock()
    c = create_mock_constraint("file_socket_4_0_8")
    mock_state.solver.constraints = [c]

    def mock_eval_socket(constraint, cast_to=None):
        return b"REMOTE_C2_COMMAND"

    mock_state.solver.eval = mock_eval_socket

    res = universal_provenance_inspector(mock_state, verbose=True)

    assert "socket" in res["Sockets de Red"]
    assert res["Sockets de Red"]["socket"] == b"REMOTE_C2_COMMAND"
    print("  [PASS] VERIFICACION COMPLETADA: Trafico de Red detectado.")


def test_cli_argument_provenance_detection():
    """Verifica la detección de restricciones originadas en argumentos de línea de comandos."""
    print("\n" + "-" * 60)
    print(" [TEST 7] Deteccion de Procedencia en Argumentos CLI (argv)")
    print("-" * 60)
    mock_state = MagicMock()
    c = create_mock_constraint("arg_1_0_8")
    mock_state.solver.constraints = [c]

    def mock_eval_arg(constraint, cast_to=None):
        return b"--secret-flag"

    mock_state.solver.eval = mock_eval_arg

    res = universal_provenance_inspector(mock_state, verbose=True)

    assert b"--secret-flag" in res["Argumentos CLI"]
    print("  [PASS] VERIFICACION COMPLETADA: Argumento '--secret-flag' detectado.")


def run_all_tests():
    print("==================================================================")
    print(" [*] INICIANDO PRUEBAS UNITARIAS VERBOSAS (INSPECTOR DE PROCEDENCIA)")
    print("==================================================================")
    test_empty_state_handling()
    test_memory_provenance_detection()
    test_register_provenance_detection()
    test_stdin_provenance_detection()
    test_file_provenance_detection()
    test_network_socket_provenance_detection()
    test_cli_argument_provenance_detection()
    print("\n==================================================================")
    print(" [!] [EXITO TOTAL] TODAS LAS PRUEBAS UNITARIAS VERBOSAS PASARON")
    print("==================================================================")


if __name__ == "__main__":
    run_all_tests()
