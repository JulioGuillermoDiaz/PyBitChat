"""Tests del transporte BLE.

Lo que se puede comprobar sin adaptador: que el módulo importe, que cumpla el
contrato de `Transport`, y que los números que dependen del hardware estén donde
deben.

**Estos tests sólo se ejecutan donde hay `bleak` instalado.** En la VM de
Windows se saltan enteros, así que un fallo aquí puede llevar días sin verse:
comprobarlos en el host Linux, no sólo en la máquina donde se escriben.

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
        """Los UUID del transporte son los mismos que los de `gatt`.

        La comparación es **como UUID**, no como texto. `str(uuid)` da 36
        caracteres con guiones y `uuid.hex` da 32 sin ellos, así que comparar
        cualquiera de los dos contra el otro falla siempre.

        No es teórico: es el mismo error que dejó el descubrimiento muto en
        `gatt.es_nuestro_servicio()`, y ya se corrigió allí una vez. Que
        reapareciera en un test es la prueba de que el patrón sigue siendo
        fácil de escribir mal.
        """
        import uuid as _uuid

        self.assertEqual(
            _uuid.UUID(str(self.mod.SERVICE_UUID)), _uuid.UUID(str(gatt.SERVICE_UUID))
        )
        self.assertEqual(
            _uuid.UUID(str(self.mod.CHARACTERISTIC_UUID)),
            _uuid.UUID(str(gatt.CHARACTERISTIC_UUID)),
        )

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


class TestFormatosDeUuid(unittest.TestCase):
    """Los dos formatos de un UUID no son iguales como texto.

    **Este test no necesita `bleak`, así que no va en la clase condicional.**
    Vive aquí a propósito: la clase de arriba entera se salta en la VM de
    Windows, y un test que sólo depende de `gatt` no tiene por qué desaparecer
    con ella. Un skipped que no es necesario esconde trabajo sin hacer.

    `str(uuid)` da 36 caracteres con guiones y `uuid.hex` da 32 sin ellos, así
    que comparar cualquiera de los dos contra el otro falla siempre. Es el error
    que dejó el descubrimiento mudo en `gatt.es_nuestro_servicio()`.
    """

    def test_los_formatos_difieren(self):
        self.assertNotEqual(str(gatt.SERVICE_UUID), gatt.SERVICE_UUID.hex)
        self.assertEqual(len(str(gatt.SERVICE_UUID)), 36)
        self.assertEqual(len(gatt.SERVICE_UUID.hex), 32)

    def test_normalizar_los_hace_iguales(self):
        import uuid as _uuid

        self.assertEqual(
            _uuid.UUID(str(gatt.SERVICE_UUID)), _uuid.UUID(gatt.SERVICE_UUID.hex)
        )

    def test_es_nuestro_servicio_acepta_los_dos_formatos(self):
        """La función que se corrigió por este mismo bug."""
        self.assertTrue(gatt.es_nuestro_servicio(str(gatt.SERVICE_UUID)))
        self.assertTrue(gatt.es_nuestro_servicio(gatt.SERVICE_UUID.hex))

    def test_es_nuestro_servicio_rechaza_uno_distinto(self):
        otro = "12345678-1234-5678-1234-567812345678"
        self.assertFalse(gatt.es_nuestro_servicio(otro))


if __name__ == "__main__":
    unittest.main(verbosity=2)