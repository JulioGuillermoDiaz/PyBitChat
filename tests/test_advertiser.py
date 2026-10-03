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
    NOMBRE_SERVICIO,
    RUTA_ANUNCIO,
    RUTA_SERVICIO,
    _variant_cls,
    opciones_anuncio,
)
from pybitchat.ble.gatt import SERVICE_UUID  # noqa: E402

#: peer_id real capturado de la app Android.
PEER_ID_REAL = bytes.fromhex("34e01ccea10a8c6d")


def _es_variant(v):
    return hasattr(v, "signature") and hasattr(v, "value")


def sin_variant(v):
    """Quita **todos** los envoltorios `Variant` y devuelve el valor pelado.

    `opciones_anuncio()` devuelve `Variant` porque BlueZ lo exige, y los lleva
    en dos niveles: el dict de opciones y el dict interior de `ServiceData`.
    Estos tests comparan el **contenido**, que es lo que importa para la forma
    del anuncio; que las firmas sean las correctas se comprueba en
    `TestVariantesDbus`.
    """
    if _es_variant(v):
        return sin_variant(v.value)
    if isinstance(v, dict):
        return {k: sin_variant(x) for k, x in v.items()}
    if isinstance(v, list):
        return [sin_variant(x) for x in v]
    return v


class TestFormaDelAnuncio(unittest.TestCase):
    """El anuncio tiene que llevar el peer_id, no sólo el UUID."""

    def test_el_uuid_va_en_el_anuncio(self):
        o = opciones_anuncio(PEER_ID_REAL)
        self.assertEqual(sin_variant(o["ServiceUUIDs"]), [str(SERVICE_UUID)])

    def test_es_de_tipo_peripheral(self):
        """`broadcast` no es un peripheral: no aceptarían conexiones."""
        self.assertEqual(sin_variant(opciones_anuncio(PEER_ID_REAL)["Type"]), "peripheral")

    def test_el_peer_id_va_como_service_data(self):
        """Esto es lo que permite a la app deduplicarnos si rota la MAC."""
        o = opciones_anuncio(PEER_ID_REAL, scan_response=False)
        self.assertEqual(
            sin_variant(o["ServiceData"]), {str(SERVICE_UUID): PEER_ID_REAL}
        )

    def test_scan_response_lleva_el_peer_id(self):
        o = opciones_anuncio(PEER_ID_REAL, scan_response=True)
        self.assertEqual(
            sin_variant(o["ScanResponseServiceData"]),
            {str(SERVICE_UUID): PEER_ID_REAL},
        )

    def test_el_scan_response_tambien_declara_el_uuid(self):
        """Algunos escáneres leen el UUID sólo del scan response."""
        o = opciones_anuncio(PEER_ID_REAL, scan_response=True)
        self.assertEqual(
            sin_variant(o["ScanResponseServiceUUIDs"]), [str(SERVICE_UUID)]
        )

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
        interior = sin_variant(o["ServiceData"])
        valor = interior[str(SERVICE_UUID)]
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
                todos = [sin_variant(v) for k, v in o.items() if "ServiceData" in k]
                self.assertEqual(len(todos), 1)
                self.assertEqual(list(todos[0].values()), [PEER_ID_REAL])


class TestVariantesDbus(unittest.TestCase):
    """Cada valor del dict de BlueZ tiene que ser un `Variant`.

    La firma es `RegisterAdvertisement(o, a{sv})` y `a{sv}` significa
    **dict de cadena a Variant**. Pasar un dict normal falla con

        TypeError: Cannot convert str to dbus_fast.signature.Variant

    Los tests de *firma* corren en cualquier máquina porque `opciones_anuncio`
    usa un sustituto cuando `dbus_fast` no está instalado. Los que pasan el dict
    al validador real necesitan la librería y se saltan fuera de Linux.
    """

    def test_los_valores_son_variantes(self):
        o = opciones_anuncio(PEER_ID_REAL, scan_response=False)
        for clave, valor in o.items():
            with self.subTest(clave=clave):
                self.assertIsInstance(valor, _variant_cls())
                self.assertIsInstance(valor.signature, str)

    def test_el_peer_id_va_como_ay_no_como_texto(self):
        """8 bytes binarios: como cadena serían otro dato."""
        o = opciones_anuncio(PEER_ID_REAL, scan_response=False)
        valor = list(o["ServiceData"].value.values())[0]
        self.assertEqual(valor.signature, "ay")
        self.assertEqual(valor.value, PEER_ID_REAL)

    def test_las_cadenas_van_como_s(self):
        o = opciones_anuncio(PEER_ID_REAL, scan_response=False)
        self.assertEqual(o["Type"].signature, "s")
        self.assertEqual(o["Type"].value, "peripheral")

    def test_las_listas_de_uuid_van_como_as(self):
        o = opciones_anuncio(PEER_ID_REAL, scan_response=False)
        self.assertEqual(o["ServiceUUIDs"].signature, "as")
        self.assertEqual(o["ServiceUUIDs"].value, [str(SERVICE_UUID)])

    def test_el_dict_interior_tambien_lleva_variantes(self):
        """El dict de `ServiceData` es `a{sv}`: sus valores también."""
        for scan in (True, False):
            with self.subTest(scan_response=scan):
                o = opciones_anuncio(PEER_ID_REAL, scan_response=scan)
                clave = "ScanResponseServiceData" if scan else "ServiceData"
                self.assertEqual(o[clave].signature, "a{sv}")
                for valor in o[clave].value.values():
                    self.assertIsInstance(valor, _variant_cls())


class TestValidacionConDbusFast(unittest.TestCase):
    """Los tests que necesitan el validador real de `dbus_fast`.

    Sólo se ejecutan en la máquina donde corre BlueZ. Comprueban lo que de
    verdad importa: que el dict que mandamos no es rechazado **antes** de salir,
    que es donde fallaba.
    """

    def setUp(self):
        try:
            import dbus_fast
        except ImportError:
            self.skipTest("dbus_fast no está instalado (sólo en Linux)")
        self.variant = dbus_fast.Variant

    def test_el_dict_completo_es_valido(self):
        """No debe lanzar: es la comprobación que hace dbus_fast al enviar."""
        self.variant("a{sv}", opciones_anuncio(PEER_ID_REAL, scan_response=False))

    def test_el_dict_con_scan_response_es_valido(self):
        self.variant("a{sv}", opciones_anuncio(PEER_ID_REAL, scan_response=True))

    def test_ambos_diccionarios_interiores_son_validos(self):
        for scan in (True, False):
            with self.subTest(scan_response=scan):
                o = opciones_anuncio(PEER_ID_REAL, scan_response=scan)
                clave = "ScanResponseServiceData" if scan else "ServiceData"
                self.variant("a{sv}", o[clave].value)

    def test_un_dict_plano_fallaria(self):
        """La forma que había antes, comprobada para que no vuelva."""
        plano = {
            "Type": "peripheral",
            "ServiceData": {str(SERVICE_UUID): PEER_ID_REAL},
        }
        with self.assertRaises(Exception):
            self.variant("a{sv}", plano)


class TestRutaDeObjeto(unittest.TestCase):
    """El bug de la ruta: nombre de bus con puntos donde va una ruta.

    Cada elemento de una ruta de objeto D-Bus tiene que cumplir `[A-Za-z0-9_]`,
    así que un punto dentro de un elemento es inválido. Se usa el nombre de bus
    como ruta y BlueZ responde `InvalidObjectPathError`.

    Esto **sí** es comprobable sin adaptador: la validación es aritmética sobre
    la cadena, y es la clase de fallo que sólo aparecía al ejecutar.
    """

    #: Elementos válidos según la especificación D-Bus.
    ELEMENTO = __import__("re").compile(r"^[A-Za-z0-9_]+$")

    def test_la_ruta_usa_barras(self):
        self.assertEqual(RUTA_SERVICIO, "/org/bluez/pybitchat")
        self.assertIn("/", RUTA_SERVICIO[1:])

    def test_la_ruta_no_tiene_puntos(self):
        """Este es exactamente el fallo: un punto en un elemento de la ruta."""
        self.assertNotIn(".", RUTA_SERVICIO)

    def test_cada_elemento_cumple_el_patron(self):
        self.assertTrue(RUTA_SERVICIO.startswith("/"))
        for elemento in RUTA_SERVICIO[1:].split("/"):
            with self.subTest(elemento=elemento):
                self.assertRegex(elemento, self.ELEMENTO)

    def test_el_nombre_de_bus_si_lleva_puntos(self):
        """Ahí los puntos son obligatorios: es un nombre, no una ruta."""
        self.assertIn(".", NOMBRE_SERVICIO)
        self.assertNotIn(" ", NOMBRE_SERVICIO)

    def test_la_ruta_del_anuncio_bajo_la_del_servicio(self):
        """BlueZ llama a Release() en la ruta que le registramos, así que el
        objeto tiene que estar exportado en la ruta que le pasamos."""
        self.assertTrue(RUTA_ANUNCIO.startswith(RUTA_SERVICIO + "/"))
        self.assertNotIn(".", RUTA_ANUNCIO)

    def test_la_ruta_del_anuncio_es_valida(self):
        self.assertTrue(RUTA_ANUNCIO.startswith("/"))
        for elemento in RUTA_ANUNCIO[1:].split("/"):
            with self.subTest(elemento=elemento):
                self.assertRegex(elemento, self.ELEMENTO)


class TestNombresDeInterfaz(unittest.TestCase):
    """Los nombres de interfaz no son negociables con BlueZ."""

    def test_gestor_de_anuncios(self):
        self.assertEqual(IFACE_MANAGER, "org.bluez.LEAdvertisingManager1")

    def test_interfaz_del_anuncio(self):
        self.assertEqual(IFACE_ADVERTISEMENT, "org.bluez.LEAdvertisement1")


if __name__ == "__main__":
    unittest.main(verbosity=2)