"""Tests del transporte BLE.

Lo majoritymente que se puede comprobar sin adaptador: que el módulo importe,
que cumpla el contrato de `Transport`, y que los números que dependen del
hardware estén donde deben.

Los que sí necesitan hardware se saltan solos. Es preferible un test saltado
que uno que dé verde sin comprobar nada: un skipped deja constancia de lo que
no se ha verificado.

Ejecutar:
    .venv\\Scripts\\python.exe tests\\test_bleak_transport.py
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.ble import gatt  # noqa: E402
from pybitchat.mesh.transport import PEER_ID_SIZE, Transport  # noqa: E402

#: bleak es opcional: el resto del proyecto debe funcionar sin él.
TIENE_BLEAK = importlib.util.find_spec("bleak") is not None


class TestGattSinBleak(unittest.TestCase):
    """Los UUID no dependen de bleak y deben estar siempre disponibles."""

    def test_el_paquete_ble_no_arrastra_bleak(self):
        """Importar `pybitchat.ble` no debe requerir hardware ni bleak."""
        import pybitchat.ble as ble

        self.assertTrue(hasattr(ble, "__path__"))

    def test_bleak_no_se_reexporta(self):
        import pybitchat.ble as ble

        self.assertFalse(
            hasattr(ble, "bleak_transport"),
            "reexportarlo obligaría a instalar bleak para usar los UUID",
        )


@unittest.skipUnless(TIENE_BLEAK, "bleak no está instalado")
class TestTransporteBleak(unittest.TestCase):
    def setUp(self):
        from pybitchat.ble import bleak_transport

        self.mod = bleak_transport

    def test_implementa_transport(self):
        self.assertTrue(issubclass(self.mod.BleakTransport, Transport))

    def test_mtu_minimo_cubre_el_bloque_de_relleno(self):
        """512 de relleno + 3 de cabecera ATT = 515. Medido: 517."""
        from pybitchat.protocol.types import FRAGMENT_SIZE_THRESHOLD

        self.assertEqual(self.mod.MTU_MINIMO, FRAGMENT_SIZE_THRESHOLD + 3)

    def test_usa_los_mismos_uuid_que_verificados_contra_hardware(self):
        self.assertEqual(str(self.mod.SERVICE_UUID), gatt.SERVICE_UUID.hex)
        self.assertEqual(str(self.mod.CHARACTERISTIC_UUID), gatt.CHARACTERISTIC_UUID.hex)

    def test_enviar_a_un_par_desconocido_falla_con_mensaje_util(self):
        """Sin identidad de BitChat no hay a quién enviar, y hay que decirlo."""
        import asyncio

        t = self.mod.BleakTransport()
        with self.assertRaises(Exception) as ctx:
            asyncio.run(t.send(b"\x01" * PEER_ID_SIZE, b"x"))
        self.assertIn("identidad", str(ctx.exception).lower())

    def test_peer_id_de_medida_correcta(self):
        import asyncio

        t = self.mod.BleakTransport()
        with self.assertRaises(Exception):
            asyncio.run(t.send(b"\x01" * 4, b"x"))

    def test_arrancar_dos_veces_falla(self):
        import asyncio

        async def escenario():
            t = self.mod.BleakTransport()
            await t.start(lambda pid, data: None)
            try:
                with self.assertRaises(Exception):
                    await t.start(lambda pid, data: None)
            finally:
                await t.stop()

        asyncio.run(escenario())


if __name__ == "__main__":
    unittest.main(verbosity=2)