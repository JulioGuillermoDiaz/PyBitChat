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

from pybitchat.protocol.packet import Packet  # noqa: E402
from pybitchat.protocol.payloads import AnnouncePayload, CURRENT, decode_payload  # noqa: E402
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

    def test_payload_es_el_nickname_sin_prefijo_de_longitud(self):
        """`AnnouncePayload` es sólo UTF-8: la longitud la da `payload_len`."""
        crudo = self.smoke.construir_announce("pybitchat-probe")
        carga = decode_payload(Packet.from_bytes(crudo).header.raw_type,
                               Packet.from_bytes(crudo).payload, CURRENT)
        self.assertIsInstance(carga, AnnouncePayload)
        self.assertEqual(carga.nickname, "pybitchat-probe")

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