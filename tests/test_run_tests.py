"""Tests del runner de tests.

Un runner que informa mal hace perder más tiempo que no tener runner: el caso
real de este repo es que `skipped=6` no decía **qué** se saltaba, así que
`test_bleak_transport.py` estuvo sin ejecutarse días en la VM de Windows —su
clase entera depende de `bleak`— y cuando por fin se ejecutó en el host Linux
falló a la primera.

Estos tests comprueban que el informe dice lo que dice que dice, y que el
**código de salida** no depende de parsear nada.
"""

from __future__ import annotations

import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))


def _cargar_runner():
    ruta = ROOT / "tools" / "run_tests.py"
    spec = importlib.util.spec_from_file_location("run_tests_mod", ruta)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


run_tests = _cargar_runner()


class _FakeSkip:
    """Sustituto de un test saltado: sólo necesita `.id()`."""

    def __init__(self, caso: str) -> None:
        self._caso = caso

    def id(self) -> str:
        return self._caso


class _ResultadoFalso:
    def __init__(self, saltados) -> None:
        self.skipped = saltados


def _capturar(saltados) -> str:
    err = io.StringIO()
    with redirect_stderr(err):
        run_tests._informe_saltados(_ResultadoFalso(saltados))
    return err.getvalue()


class TestInformeDeSaltados(unittest.TestCase):
    def test_sin_saltados_no_imprime_nada(self):
        """Sin huecos, nada que decir. Un informe vacío cada vez sería ruido."""
        self.assertEqual(_capturar([]), "")

    def test_lista_cuantos_saltados_hay(self):
        salida = _capturar([
            (_FakeSkip("test_a.TestX.uno"), "bleak no está instalado"),
            (_FakeSkip("test_a.TestX.dos"), "bleak no está instalado"),
        ])
        self.assertIn("2 test(s)", salida)

    def test_dice_el_motivo_del_salto(self):
        """El motivo es lo que dice qué hacer: instalar bleak, o no hay
        hardware."""
        salida = _capturar([(_FakeSkip("test_a.TestX.uno"), "bleak no está instalado")])
        self.assertIn("bleak no está instalado", salida)

    def test_agrupa_por_clase(self):
        """Los 6 de una clase se ven como 6, no como 6 líneas sueltas."""
        salida = _capturar([
            (_FakeSkip("test_b.TestClase.uno"), "motivo"),
            (_FakeSkip("test_b.TestClase.dos"), "motivo"),
            (_FakeSkip("test_b.TestClase.tres"), "motivo"),
        ])
        self.assertIn("TestClase  (3 test/s)", salida)

    def test_muestra_algunos_nombres_si_hay_muchos(self):
        """Más de 4 se resumen, para no volcar 60 líneas."""
        casos = [(_FakeSkip(f"test_c.TestX.t{i}"), "m") for i in range(9)]
        salida = _capturar(casos)
        self.assertIn("t0", salida)
        self.assertIn("y 5 más", salida)

    def test_va_a_stderr_y_no_a_stdout(self):
        """`unittest` escribe en stderr. Si el informe fuera a stdout saldría
        antes del `OK` resumen, y se leería como que va antes que los tests."""
        err, out = io.StringIO(), io.StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            run_tests._informe_saltados(
                _ResultadoFalso([(_FakeSkip("test_a.TestX.uno"), "m")])
            )
        self.assertIn("SKIPPED", err.getvalue())
        self.assertEqual(out.getvalue(), "")


class TestCodigoDeSalida(unittest.TestCase):
    """El runner no parsea salida: usa el código de salida del proceso."""

    def test_descubre_la_suite_sin_error_de_import(self):
        """Si algún test no importa, `discover()` collects el error y el runner
        tiene que fallo, no seguir como si nada."""
        suite = run_tests.discover()
        self.assertGreater(suite.countTestCases(), 400)

    def test_el_total_es_consistente_con_el_informe(self):
        """`discover()` y el recuento por fichero tienen que coincidir, o el
        informe de saltados habla de una suite y se ejecuta otra."""
        import unittest as _unittest

        total = run_tests.discover().countTestCases()
        manual = 0
        loader = _unittest.TestLoader()
        for f in sorted((ROOT / "tests").glob("test_*.py")):
            manual += loader.discover(
                str(ROOT / "tests"), pattern=f.name,
                top_level_dir=str(ROOT / "tests"),
            ).countTestCases()
        self.assertEqual(total, manual)


if __name__ == "__main__":
    unittest.main(verbosity=2)