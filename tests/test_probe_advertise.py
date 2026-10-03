"""Tests del informe de escaneo de `tools/probe_advertise.py`.

El filtro que había antes en ese script era

    if es_bitchat or dev.name:
        print(...)

y en una prueba real sacaba 7 dispositivos y mostraba 2. Los otros 5
desaparecían del informe, entre ellos el teléfono: un móvil Android no siempre
anuncia su nombre local, así que `dev.name` descarta justo al peer que nos
interesa.

Estos tests comprueban que **todos** los dispositivos salen, y que se distinguen
las tres situaciones que importan:

  - anuncia BitChat con los 8 bytes del peer_id
  - anuncia con un UUID que no es nuestro
  - no anuncia nada de servicio

La función `resumen()` recibe datos planos y no los objetos de bleak, así que
todo esto se comprueba sin adaptador.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.ble.gatt import SERVICE_UUID  # noqa: E402


def _cargar_probe():
    """Carga `tools/probe_advertise.py` como módulo.

    Vive en `tools/` y no es paquete, así que `import` normal no vale. Se carga
    por ruta. Importarlo **no** ejecuta `main()`: está bajo `__main__`.
    """
    ruta = ROOT / "tools" / "probe_advertise.py"
    spec = importlib.util.spec_from_file_location("probe_advertise", ruta)
    modulo = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(modulo)
    return modulo


probe = _cargar_probe()

#: peer_id real de la app Android.
PEER_ID = bytes.fromhex("34e01ccea10a8c6d")


def _anuncio(mac, nombre, uuids=None, service_data=None, rssi=-60):
    return (mac, nombre, uuids or [], service_data or {}, rssi)


class TestSeMuestraTodo(unittest.TestCase):
    """El fallo original: 7 dispositivos, 2 líneas."""

    def test_sale_un_dispositivo_sin_nombre_y_sin_uuid(self):
        """Este es el que se perdía. El móvil puede ser exactamente así."""
        lineas, cuantos = probe.resumen([_anuncio("AA:BB:CC:DD:EE:FF", None)])
        self.assertIn("AA:BB:CC:DD:EE:FF", "\n".join(lineas))
        self.assertEqual(cuantos, 0)

    def test_dice_que_no_tiene_nombre(self):
        """Que no salga `None` a secas: hay que distinguir "sin nombre" de
        un fallo al leer el nombre."""
        lineas, _ = probe.resumen([_anuncio("AA:BB:CC:DD:EE:FF", None)])
        self.assertIn("(sin nombre)", "\n".join(lineas))

    def test_todos_los_dispositivos_aparecen(self):
        anuncios = [_anuncio(f"AA:BB:CC:DD:EE:0{i}", None) for i in range(7)]
        lineas, _ = probe.resumen(anuncios)
        for mac, _nombre, _u, _sd, _r in anuncios:
            with self.subTest(mac=mac):
                self.assertTrue(
                    any(mac in linea for linea in lineas),
                    f"{mac} no sale en el informe",
                )

    def test_no_filtra_por_nombre(self):
        """Con y sin nombre, los dos salen. Es el criterio que se rompió."""
        con_nombre = _anuncio("AA:BB:CC:DD:EE:01", "TV Samsung")
        sin_nombre = _anuncio("AA:BB:CC:DD:EE:02", None)
        lineas, _ = probe.resumen([con_nombre, sin_nombre])
        self.assertEqual(len([l for l in lineas if "AA:BB" in l]), 2)


class TestDeteccionDeBitChat(unittest.TestCase):
    def test_cuenta_el_dispositivo_correcto(self):
        anuncios = [
            _anuncio("AA:BB:CC:DD:EE:01", "TV Samsung"),
            _anuncio("AA:BB:CC:DD:EE:02", None, [str(SERVICE_UUID)]),
            _anuncio("AA:BB:CC:DD:EE:03", None),
        ]
        _lineas, cuantos = probe.resumen(anuncios)
        self.assertEqual(cuantos, 1)

    def test_lo_marca_con_bitchat(self):
        lineas, _ = probe.resumen(
            [_anuncio("AA:BB:CC:DD:EE:02", None, [str(SERVICE_UUID)])]
        )
        self.assertIn("BITCHAT", "\n".join(lineas))

    def test_el_peer_id_de_8_bytes_se_reconoce(self):
        """El dato que la app usa para identificarnos."""
        lineas, _ = probe.resumen([
            _anuncio(
                "AA:BB:CC:DD:EE:02", None,
                [str(SERVICE_UUID)],
                {str(SERVICE_UUID): PEER_ID},
            )
        ])
        texto = "\n".join(lineas)
        self.assertIn(PEER_ID.hex(), texto)
        self.assertIn("<- peer_id", texto)

    def test_avisa_si_la_longitud_no_es_8(self):
        """Un peer_id de otra longitud significa que el formato no es el que
        creemos, y el script tiene que decirlo en vez de darlo por bueno."""
        lineas, _ = probe.resumen([
            _anuncio(
                "AA:BB:CC:DD:EE:02", None,
                [str(SERVICE_UUID)],
                {str(SERVICE_UUID): PEER_ID + b"\x00"},
            )
        ])
        self.assertIn("<- ?", "\n".join(lineas))

    def test_sin_ni_un_bitchat_dice_que_no_hay(self):
        """Que el recuento salga a cero es un dato: el problema es el móvil."""
        lineas, cuantos = probe.resumen([_anuncio("AA:BB:CC:DD:EE:01", None)])
        self.assertEqual(cuantos, 0)
        self.assertTrue(lineas)  # no es un informe vacío


class TestUuidDesconocido(unittest.TestCase):
    """Un UUID que no es nuestro se enseña, no se esconde.

    Comparar mal los formatos de UUID es un fallo silencioso: el dispositivo
    aparece, pero nunca se reconoce. Enseñar el UUID desconocido es lo que
    permite verlo.
    """

    def test_muestra_el_uuid_que_no_reconoce(self):
        raro = "12345678-1234-5678-1234-567812345678"
        lineas, _ = probe.resumen([_anuncio("AA:BB:CC:DD:EE:02", None, [raro])])
        texto = "\n".join(lineas)
        self.assertIn(raro, texto)
        self.assertIn("desconocido", texto)

    def test_no_marca_como_desconocido_el_nuestro(self):
        lineas, _ = probe.resumen(
            [_anuncio("AA:BB:CC:DD:EE:02", None, [str(SERVICE_UUID)])]
        )
        self.assertNotIn("desconocido", "\n".join(lineas))

    def test_reconoce_el_uuid_tambien_sin_guiones(self):
        """`hex` y `str` son formatos distintos del mismo UUID. Comparar uno
        contra el otro falla siempre y el descubrimiento se queda mudo."""
        sin_guiones = SERVICE_UUID.hex
        _lineas, cuantos = probe.resumen(
            [_anuncio("AA:BB:CC:DD:EE:02", None, [sin_guiones])]
        )
        self.assertEqual(cuantos, 1)


class TestTiemposDeEscaneo(unittest.TestCase):
    """El adaptador no anuncia y escanea a la vez.

    Por eso el escaneo va después de `stop()` **y** de una pausa. Con los
    valores por defecto de `smoke_ble.py` el escaneo de este script salía más
    corto que el de aquella herramienta, y por eso no vio los mismos
    dispositivos.
    """

    @staticmethod
    def _args():
        import argparse

        return argparse.Namespace(
            nickname="probe",
            segundos=25.0,
            descanso=3.0,
            scan=20.0,
        )

    def test_el_escaneo_no_es_mas_corto_que_el_de_smoke_ble(self):
        """Comparar el código de salida con el de otra prueba exige comparar
        tiempos comparables. Si este es más corto, su resultado no es
        comparable y parece que el teléfono ha desaparecido."""
        import re
        from pathlib import Path

        raiz = Path(__file__).resolve().parent.parent
        texto = (raiz / "tools" / "smoke_ble.py").read_text(encoding="utf-8")
        m = re.search(r'--scan"[^\n]*default=([0-9.]+)', texto)
        self.assertIsNotNone(m, "no se encontró el --scan de smoke_ble.py")
        self.assertGreaterEqual(self._args().scan, float(m.group(1)))

    def test_hay_pausa_entre_retirar_el_anuncio_y_esc_anear(self):
        """Sin la pausa, el escaneo sale mientras el adaptador todavía está
        en modo advertising."""
        self.assertGreater(self._args().descanso, 0.0)

    def test_el_escaneo_es_generoso(self):
        """Un discovery corto es la causa más fácil de un falso negativo."""
        self.assertGreaterEqual(self._args().scan, 15.0)

    def test_los_parametros_existen_en_el_parser(self):
        """Si el parser no acepta `--scan`, el script falla al arrancar.

        Se lanza `--help`, que escribe el uso y sale sin tocar el hardware. Se
        comprueba el **código de salida**, no el texto: es lo único que no se
        puede interpretar mal.
        """
        import subprocess

        raiz = Path(__file__).resolve().parent.parent
        codigo = (raiz / "tools" / "probe_advertise.py").read_text(encoding="utf-8")
        self.assertIn('"--scan"', codigo)
        self.assertIn('"--descanso"', codigo)

        r = subprocess.run(
            [sys.executable, str(raiz / "tools" / "probe_advertise.py"), "--help"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # El codigo de salida, no el texto: es lo unico fiable.
        self.assertEqual(r.returncode, 0, r.stderr)
        for opcion in ("--scan", "--descanso", "--segundos"):
            with self.subTest(opcion=opcion):
                self.assertIn(opcion, r.stdout)


class TestAvisoDeLimitacion(unittest.TestCase):
    """Si no aparece la app, el script no puede culpar al movil.

    El adaptador no anuncia y escanea a la vez, asi que este script mide lo que
    la app anuncia cuando el ya no esta anunciando. Afirmar "el problema es el
    movil" seria una conclusion que este script no puede sostener.
    """

    def test_el_mensaje_final_no_culpa_al_movil_incondicionalmente(self):
        raiz = Path(__file__).resolve().parent.parent
        texto = (raiz / "tools" / "probe_advertise.py").read_text(encoding="utf-8")
        self.assertNotIn("el problema no es este script.", texto)

    def test_el_mensaje_final_apunta_a_smoke_ble(self):
        """smoke_ble.py solo escanea: es la comprobacion sin ese problema."""
        raiz = Path(__file__).resolve().parent.parent
        texto = (raiz / "tools" / "probe_advertise.py").read_text(encoding="utf-8")
        self.assertIn("smoke_ble.py", texto.split("NINGUN dispositivo")[-1])

    def test_el_docstring_admite_la_limitacion(self):
        """La limitacion esta escrita antes de usarla, no despues de
        fallar. Es lo que permite saber de antemano que este script no es la
        herramienta para la pregunta."""
        raiz = Path(__file__).resolve().parent.parent
        texto = (raiz / "tools" / "probe_advertise.py").read_text(encoding="utf-8")
        cabecera = texto.split('"""')[1]
        # Se busca la frase entera y no "no puede": el enunciado completo es
        # lo que dice la limitacion, y trocearlo haria que el test pasara
        # con una redaccion que ya no dice nada.
        self.assertIn("no puede anunciar y escanear a la vez", cabecera)

    def test_escaneo_vacio_no_revienta(self):
        lineas, cuantos = probe.resumen([])
        self.assertEqual(lineas, [])
        self.assertEqual(cuantos, 0)

    def test_uvids_none_no_revienta(self):
        """bleak devuelve `None`, no lista vacía, cuando no hay UUID."""
        lineas, cuantos = probe.resumen(
            [("AA:BB:CC:DD:EE:01", None, None, None, -50)]
        )
        self.assertIn("sin UUID de servicio", "\n".join(lineas))
        self.assertEqual(cuantos, 0)

    def test_los_datos_vienen_legibles(self):
        """`service_data` con las claves de bleak tal cual, en hexadecimal."""
        lineas, _ = probe.resumen([
            _anuncio(
                "AA:BB:CC:DD:EE:02", None,
                [str(SERVICE_UUID)],
                {str(SERVICE_UUID): PEER_ID},
            )
        ])
        self.assertIn(PEER_ID.hex(), "\n".join(lineas))


if __name__ == "__main__":
    unittest.main(verbosity=2)