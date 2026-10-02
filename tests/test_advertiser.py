"""Tests del anuncio BLE.

Lo verificable sin adaptador es la **forma** del anuncio, que es lo que
determina si la app nos reconoce. Lo demás necesita hardware y se prueba
ejecutando `tools/smoke_ble.py --peripheral`.

La regla que estos tests protegen: la app identifica a los peers por el
`peer_id` del scan response, no por la MAC. Si alguien "simplifica" el anuncio y
deja sólo el UUID, estos tests lo detectan.

Ejecutar:
    .venv\\Scripts\\python.exe tests\\test_advertiser.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.ble.advertiser import (  # noqa: E402
    IFACE_ADVERTISEMENT,
    IFACE_MANAGER,
    opciones_anuncio,
)
from pybitchat.ble.gatt import SERVICE_UUID  # noqa: E402

#: peer_id real capturado de la app Android.
PEER_ID_REAL = bytes.fromhex("34e01ccea10a8c6d")


class TestFormaDelAnuncio(unittest.TestCase):
    """El anuncio tiene que llevar el peer_id, no sólo el UUID."""

    def test_el_uuid_va_en_el_anuncio(self):
        o = opciones_anuncio(PEER_ID_REAL)
        self.assertEqual(o["ServiceUUIDs"], [str(SERVICE_UUID)])

    def test_es_de_tipo_peripheral(self):
        """`broadcast` no es un peripheral: no aceptarían conexiones."""
        self.assertEqual(opciones_anuncio(PEER_ID_REAL)["Type"], "peripheral")

    def test_el_peer_id_va_como_service_data(self):
        """Esto es lo que permite a la app deduplicarnos si rota la MAC."""
        o = opciones_anuncio(PEER_ID_REAL, scan_response=False)
        self.assertEqual(o["ServiceData"], {str(SERVICE_UUID): PEER_ID_REAL})

    def test_scan_response_lleva_el_peer_id(self):
        o = opciones_anuncio(PEER_ID_REAL, scan_response=True)
        self.assertEqual(
            o["ScanResponseServiceData"], {str(SERVICE_UUID): PEER_ID_REAL}
        )

    def test_el_scan_response_tambien_declara_el_uuid(self):
        """Algunos escáneres leen el UUID sólo del scan response."""
        o = opciones_anuncio(PEER_ID_REAL, scan_response=True)
        self.assertEqual(o["ScanResponseServiceUUIDs"], [str(SERVICE_UUID)])

    def test_no_declara_tx_power_ni_nombre(self):
        """La app los omite: se declara lo mismo, sin inventar campos."""
        o = opciones_anuncio(PEER_ID_REAL)
        self.assertNotIn("Includes", o)
        self.assertNotIn("LocalName", o)

    def test_el_peer_id_mide_8(self):
        with self.assertRaises(ValueError):
            opciones_anuncio(b"\x00" * 7)
        with self.assertRaises(ValueError):
            opciones_anuncio(b"\x00" * 9)

    def test_los_datos_son_bytes_no_hex(self):
        """Un dict de bytes, no de cadenas: D-Bus no acepta texto aquí."""
        o = opciones_anuncio(PEER_ID_REAL, scan_response=False)
        valor = o["ServiceData"][str(SERVICE_UUID)]
        self.assertIsInstance(valor, (bytes, bytearray))
        self.assertEqual(len(valor), 8)


class TestRutasDeCaida(unittest.TestCase):
    """`ScanResponse*` es experimental en BlueZ: puede no existir."""

    def test_las_dos_variantes_son_distintas(self):
        con = opciones_anuncio(PEER_ID_REAL, scan_response=True)
        sin = opciones_anuncio(PEER_ID_REAL, scan_response=False)
        self.assertIn("ScanResponseServiceData", con)
        self.assertIn("ServiceData", sin)
        # Exactamente uno, nunca los dos.
        self.assertNotIn("ServiceData", con)
        self.assertNotIn("ScanResponseServiceData", sin)

    def test_ambas_llevan_el_peer_id(self):
        """Sea cual sea la ruta, el peer_id va en alguna parte."""
        for scan in (True, False):
            with self.subTest(scan_response=scan):
                o = opciones_anuncio(PEER_ID_REAL, scan_response=scan)
                todos = [
                    v
                    for k, v in o.items()
                    if "ServiceData" in k
                ]
                self.assertEqual(len(todos), 1)
                self.assertEqual(list(todos[0].values()), [PEER_ID_REAL])


class TestNombresDeInterfaz(unittest.TestCase):
    """Los nombres de interfaz no son negociables con BlueZ."""

    def test_gestor_de_anuncios(self):
        self.assertEqual(IFACE_MANAGER, "org.bluez.LEAdvertisingManager1")

    def test_interfaz_del_anuncio(self):
        self.assertEqual(IFACE_ADVERTISEMENT, "org.bluez.LEAdvertisement1")


if __name__ == "__main__":
    unittest.main(verbosity=2)