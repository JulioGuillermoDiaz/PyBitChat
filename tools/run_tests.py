r"""Ejecuta toda la suite y sale con código de error si algo falla.

Existe por un motivo concreto: durante un tiempo se sirvió con un bucle de
PowerShell que comprobaba el resultado con `-match '(?m)^OK\s*$'`, y
**`-match` en PowerShell no distingue mayúsculas**. Los tests que pasaban
imprimen una línea en minúscula `... ok`, así que el patrón casaba con cualquiera
que tuviera un solo test verde. Un fichero con cuatro fallos se contaba como
OK.

Este script no parsea la salida: **usa el código de salida del proceso**, que es
lo único que no se puede interpretar mal.

Uso:
    python tools/run_tests.py            # todo
    python tools/run_tests.py -v         # con salida por test
    python tools/run_tests.py transport conformance

El docstring va en crudo a propósito: contiene una secuencia de escape inválida
(`\s`) que, en una cadena normal, el intérprete ya marca como advertencia.
"""

from __future__ import annotations

import subprocess  # noqa: F401  (documentado para extender el runner)
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
TESTS = RAIZ / "tests"

# Para poder correr un subconjunto por nombre hace falta que `tests/` esté en el
# path: si no, `loadTestsFromNames` no encuentra `test_transport` y falla con un
# error de importación que no dice nada útil.
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))
if str(RAIZ / "src") not in sys.path:
    sys.path.insert(0, str(RAIZ / "src"))


def discover() -> unittest.TestSuite:
    """Carga todos los ficheros `test_*.py` del directorio de tests."""
    loader = unittest.TestLoader()
    suite = loader.discover(str(TESTS), pattern="test_*.py", top_level_dir=str(TESTS))
    if loader.errors:
        for error in loader.errors:
            print(error, file=sys.stderr)
        raise SystemExit("fallo al cargar los tests: hay errores de import")
    return suite


def main() -> int:
    verbosidad = 2 if "-v" in sys.argv else 1
    pedir = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not pedir:
        verbosidad = 1

    loader = unittest.TestLoader()
    if pedir:
        suite = unittest.TestSuite()
        for nombre in pedir:
            suite.addTests(loader.loadTestsFromNames([f"test_{nombre}"]))
    else:
        suite = discover()

    runner = unittest.TextTestRunner(verbosity=verbosidad, buffer=False)
    resultado = runner.run(suite)
    return 0 if resultado.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())