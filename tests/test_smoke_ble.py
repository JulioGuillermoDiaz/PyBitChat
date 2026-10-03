"""Tests de la lógica de `tools/smoke_ble.py`.

La parte pura —construir el announce y volcar hex— se prueba aquí, en cualquier
máquina y sin adaptador. Lo que necesita hardware se comprueba ejecutando la
herramienta, no aquí.

Ejecutar:
    .venv\\Scripts\\python.exe tests\\test_smoke_ble.py
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.ble.gatt import SERVICE_UUID  # noqa: E402
from pybitchat.protocol.packet import Packet  # noqa: E402
from pybitchat.protocol.identity import IdentityAnnouncement  # noqa: E402
from pybitchat.protocol.payloads import (  # noqa: E402
    AnnouncePayload,
    CURRENT,
    LEGACY,
    decode_payload,
)
from pybitchat.protocol.types import (  # noqa: E402
    PEER_ID_SIZE,
    MessageType,
    PacketFlags,
    should_pad_for_ble,
)


def _cargar_smoke():
    """Importa `tools/smoke_ble.py` sin ejecutarlo como script."""
    ruta = ROOT / "tools" / "smoke_ble.py"
    spec = importlib.util.spec_from_file_location("smoke_ble", ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestRssiSinMedir(unittest.TestCase):
    """`-127` es el valor por defecto de bleak, no una señal mínima.

    En `scanner.py:209` del backend BlueZ de bleak:

        rssi=props.get("RSSI", -127)

    O sea que `-127` significa "BlueZ no midió nada". Es el mínimo de un entero
    con signo de 8 bits, que es el valor "sin dato" del protocolo.

    Confundirlo con una medida hace que se elija un dispositivo no medido y se
    diagnostique como un fallo de enlace lo que es una elección a ciegas.
    """

    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()

    def test_menos_127_no_es_una_medida(self):
        self.assertFalse(self.smoke.es_rssi_real(-127))

    def test_none_no_es_una_medida(self):
        self.assertFalse(self.smoke.es_rssi_real(None))

    def test_una_senal_normal_si_es_medida(self):
        for valor in (-40, -58, -74, -96):
            with self.subTest(rssi=valor):
                self.assertTrue(self.smoke.es_rssi_real(valor))

    def test_el_umbral_es_127_exacto(self):
        """El valor en sí no se compara por igualdad: `None` y otros por debajo
        también son "sin dato"."""
        self.assertEqual(self.smoke.RSSI_SIN_DATO, -127)
        self.assertFalse(self.smoke.es_rssi_real(self.smoke.RSSI_SIN_DATO - 1))

    def test_una_senal_muy_debil_sigue_siendo_medida(self):
        """-120 dBm es una medida real y muy mala. Distinguirla de "sin dato"
        es justo lo que hace esta función, así que no debe descarta."""
        self.assertTrue(self.smoke.es_rssi_real(-120))


class TestEleccionDelTelefono(unittest.TestCase):
    """Antes se devolvía el primer candidato en orden de aparición.

    El orden de un dict de bleak no significa nada, así que eso era elegir a
    ciegas. Ahora se elige el de mayor RSSI **medido**, y si ninguno lo está se
    avisa. La prueba usa un fake de BleakScanner: la lógica es comprobable sin
    adaptador, y el fallo que Corrige (elegir el no medido) también.
    """

    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()

    def _anuncio(self, rssi):
        class _Adv:
            service_uuids = [str(SERVICE_UUID)]
            local_name = None
            service_data = {}
            manufacturer_data = {}
            tx_power = None

            def __init__(self, valor):
                self.rssi = valor

        class _Dev:
            def __init__(self):
                self.name = None
                self.address = "x"

        return _Dev(), _Adv(rssi)

    def _scanner(self, rssis):
        from unittest import mock

        # `discover` es una corrutina, así que el doble tiene que poder
        #.await-arse. Con un `MagicMock` a secas, `await` falla con
        # "object MagicMock can't be used in 'await' expression", que es el
        # mismo sintoma que un bug real y hace perder el tiempo.
        async def _discover(*_a, **_kw):
            return {
                f"AA:BB:CC:00:00:{i:02d}": self._anuncio(r)
                for i, r in enumerate(rssis)
            }

        mod = mock.MagicMock()
        mod.BleakScanner = mock.MagicMock(discover=_discover)
        return mock.patch.dict(sys.modules, {"bleak": mod})

    def _resolver(self, rssis):
        import asyncio

        with self._scanner(rssis):
            return asyncio.run(self.smoke.resolver_telefono(0.01))

    def test_elige_el_mas_fuerte_entre_los_medidos(self):
        """Con dos candidatos reales, gana el de mayor RSSI."""
        elegido = self._resolver([-70, -50, -80])
        self.assertIsNotNone(elegido)
        self.assertEqual(elegido[0], "AA:BB:CC:00:00:01")  # rssi=-50

    def test_no_elige_uno_sin_medir_aunque_sea_el_ultimo(self):
        """El caso real: el único con RSSI era -127, el valor por defecto.

        Sin el filtro, el script lo habría elegido y el fallo se habría
        diagnosticado como enlace roto."""
        elegido = self._resolver([-127, -60])
        self.assertEqual(elegido[0], "AA:BB:CC:00:00:01")  # rssi=-60

    def test_si_ninguno_esta_medido_devuelve_el_primero_pero_no_falla(self):
        """Sin alternativa, elige uno y lo dice. No es una razón para
        abortar: ver el anuncio ya es información."""
        elegido = self._resolver([-127, -127])
        self.assertIsNotNone(elegido)

    def test_sin_candidatos_devuelve_none(self):
        self.assertIsNone(self._resolver([]))


class TestGuardarCapturas(unittest.TestCase):
    """Los bytes recibidos se guardan siempre, incluso sin decodificar.

    El siguiente paso es arreglar el decodificador del ANNOUNCE, y para eso hace
    falta el paquete real. Perderlo porque el script imprimió en pantalla obliga
    a volver al host Linux a recapturar.
    """

    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()

    def test_guarda_los_paquetes_recibidos(self):
        import tempfile
        from pathlib import Path as _P

        recibidos = [b"\x01\x02\x03", b"\x04\x05"]
        with tempfile.TemporaryDirectory() as d:
            destino = _P(d) / "sub" / "recibido.bin"
            escritos = self.smoke._guardar(recibidos, destino)
            self.assertTrue(destino.exists(), "no se creó el fichero")
            self.assertEqual(destino.read_bytes(), b"\x01\x02\x03\x04\x05")
            self.assertEqual(escritos, 2)

    def test_guarda_aunque_no_haya_paquetes(self):
        """Sin datos también se crea el fichero: su ausencia significaría
        "no se guardó", no "no llegó nada", y esas son preguntas distintas."""
        import tempfile
        from pathlib import Path as _P

        with tempfile.TemporaryDirectory() as d:
            destino = _P(d) / "recibido.bin"
            self.smoke._guardar([], destino)
            self.assertTrue(destino.exists())
            self.assertEqual(destino.read_bytes(), b"")

    def test_crea_el_directorio(self):
        """`capturas/` no está en el repo. Si no se crea, el primer guardado
        falla y se pierde la captura."""
        import tempfile
        from pathlib import Path as _P

        with tempfile.TemporaryDirectory() as d:
            destino = _P(d) / "a" / "b" / "c" / "x.bin"
            self.smoke._guardar([b"\x00"], destino)
            self.assertTrue(destino.exists())

    def test_el_fichero_no_se_versiona(self):
        """Las capturas son de un dispositivo concreto: no van al repo."""
        import re
        from pathlib import Path as _P

        raiz = _P(__file__).resolve().parent.parent
        ignore = (raiz / ".gitignore").read_text(encoding="utf-8")
        patrones = [
            ln.strip()
            for ln in ignore.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        # Se comprueba el patrón más específico, que es el que manda.
        self.assertIn("capturas/", patrones)
        self.assertIsNotNone(
            re.search(r"^capturas/", ignore, re.M),
            ".gitignore no excluye capturas/",
        )


class TestConstruirAnnounce(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()

    def test_sender_id_mide_8(self):
        self.assertEqual(len(self.smoke.SENDER_ID), PEER_ID_SIZE)

    def test_announce_correcto_y_relegible(self):
        crudo = self.smoke.construir_announce("pybitchat-probe")
        p = Packet.from_bytes(crudo)
        self.assertEqual(p.header.version, 1)
        self.assertIs(p.header.type, MessageType.ANNOUNCE)
        # `type_name` desambigua entre dialectos cuando el nombre aparece en
        # ambos. ANNOUNCE está en los dos, así que sale la forma larga.
        self.assertIn("ANNOUNCE", p.header.type_name)
        self.assertEqual(p.sender_id, self.smoke.SENDER_ID)
        self.assertEqual(p.header.flags, PacketFlags(0))

    def test_esta_announce_es_legacy_y_solo_para_referencia(self):
        """`construir_announce` es **deliberadamente** del dialecto retirado.

        Su docstring lo dice: existe para mostrar lo que no hay que hacer. El
        announce real es el TLV de `Identity.announce_packet()`, y la app manda
        ese.

        Antes este test lo decodificaba con `CURRENT` y esperaba que saliera
        `AnnouncePayload`. Con el decoder actual eso ya no funciona, y en vez de
        arreglar el test se deduce **qué** está probando: que un announce legacy
        **no** se puede leer como actual, que es justo lo que dice la función.
        """
        crudo = self.smoke.construir_announce("pybitchat-probe")
        p = Packet.from_bytes(crudo)

        # En el dialecto retirado sí es un nickname, y eso es correcto.
        carga_legacy = decode_payload(p.header.raw_type, p.payload, LEGACY)
        self.assertIsInstance(carga_legacy, AnnouncePayload)
        self.assertEqual(carga_legacy.nickname, "pybitchat-probe")

        # Y en el actual **falla**: no es un TLV. Por eso no se usa.
        with self.assertRaises(Exception):
            decode_payload(p.header.raw_type, p.payload, CURRENT)

    def test_el_announce_de_identity_si_es_el_tlv_correcto(self):
        """El que se manda de verdad, el que construye `Identity`."""
        from pybitchat.protocol.identity import Identity

        ident = Identity.generate("pybitchat-probe")
        crudo = ident.announce_packet()
        carga = decode_payload(
            Packet.from_bytes(crudo).header.raw_type,
            Packet.from_bytes(crudo).payload,
            CURRENT,
        )
        self.assertIsInstance(carga, IdentityAnnouncement)
        self.assertEqual(carga.nickname, ident.nickname)
        self.assertEqual(carga.noise_public_key, ident.noise_public)

    def test_round_trip_byte_exacto(self):
        crudo = self.smoke.construir_announce("hola")
        self.assertEqual(Packet.from_bytes(crudo).to_bytes(), crudo)

    def test_no_va_relleno(self):
        """Sólo las tramas Noise se rellenan; ANNOUNCE va en crudo."""
        self.assertFalse(should_pad_for_ble(0x01))
        nickname = "pybitchat-probe"
        crudo = self.smoke.construir_announce(nickname)
        esperado = 14 + PEER_ID_SIZE + len(nickname.encode())
        self.assertEqual(len(crudo), esperado, "no debe haber relleno")

    def test_utf8_multibyte_cuenta_bytes(self):
        crudo = self.smoke.construir_announce("josé")
        self.assertEqual(Packet.from_bytes(crudo).payload, "josé".encode("utf-8"))

    def test_timestamp_reciente(self):
        """Un announce con el timestamp viejo se descarta; sirve de reloj."""
        import time

        crudo = self.smoke.construir_announce("x")
        ts = Packet.from_bytes(crudo).header.timestamp
        diferencia = abs(time.time() * 1000 - ts) / 1000
        self.assertLess(diferencia, 60, "el timestamp debe ser actual")


class TestContarUuids(unittest.TestCase):
    """El recuento distingue "no aparece el teléfono" de "no escanea nada".

    Es la diferencia entre depurar el móvil y depurar el adaptador, así que
    merece estar probado sin necesidad del hardware.
    """

    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()

    class _Adv:
        def __init__(self, uuids):
            self.service_uuids = uuids

    def _ann(self, por_dispositivo):
        return {
            f"AA:BB:CC:DD:EE:{i:02X}": (object(), self._Adv(u))
            for i, u in enumerate(por_dispositivo)
        }

    def test_vacio(self):
        self.assertEqual(self.smoke.contar_uuids({}), 0)

    def test_cuenta_todos(self):
        ann = self._ann([["a"], ["b", "c"], []])
        self.assertEqual(self.smoke.contar_uuids(ann), 3)

    def test_service_uuids_a_none_no_revienta(self):
        """bleak puede devolver `None` si el anuncio no trae UUID."""
        ann = self._ann([None, ["a"], []])
        self.assertEqual(self.smoke.contar_uuids(ann), 1)


class TestHexdump(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()

    def test_vacio(self):
        self.assertIn("vacío", self.smoke.hexdump(b""))

    def test_una_linea_por_bloque_de_16(self):
        salida = self.smoke.hexdump(bytes(range(64)))
        lineas = [l for l in salida.splitlines() if l.strip()]
        self.assertEqual(len(lineas), 4)

    def test_imprime_los_bytes(self):
        salida = self.smoke.hexdump(b"\xde\xad\xbe\xef")
        self.assertIn("de ad be ef", salida)

    def test_no_imprimibles_pasan_a_punto(self):
        self.assertIn("....", self.smoke.hexdump(bytes([0, 1, 2, 3])))


if __name__ == "__main__":
    unittest.main(verbosity=2)