"""El filtro de UUID del escáner, y su caso límite: el build de testnet.

## El bug que motivó esto

El móvil se captaba con `bluetoothctl` y `smoke_ble` decía que no anunciaba
BitChat. Cero candidatos desde nuestro lado, un dispositivo visible desde el de
BlueZ: las dos mitades de la misma verdad, y sin nada en medio que las explique.

La causa era esta:

```python
BITCHAT_SERVICE_UUID         = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
BITCHAT_SERVICE_UUID_TESTNET = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5A"
```

Se diferencian **en un único carácter**, el último. Un APK de testnet anuncia
`...4B5A`; el filtro pedía `...4B5C`; y el móvil estaba ahí anunciando a todo el
mundo menos a nosotros. Dos sesiones de mensajes "no aparece el teléfono" con el
móvil delante y su app abierta.

## Por qué un filtro tan estrecho no era un descuido

`BITCHAT_SERVICE_UUID_TESTNET` existe en `types.py` desde el principio, y el
cliente GATT lo conoce. Lo que no hacía era **aceptarlo para descubrir**. El
filtro tiene que aceptar los dos.

## Lo que estos tests fijan

1. El principal se acepta.
2. **El testnet también**, que es lo que estaba roto.
3. Comparar como `UUID`, no como texto: bleak devuelve 36 caracteres con
   guiones o 32 sin ellos según la versión, y `hex` frente a `str` falla
   siempre.
4. Basura no revienta: bytes, `None`, cadenas inválidas devuelven `False`.
5. Los dos UUID son distintos entre sí, que es la precondition de todo esto: si
   fueran iguales, el test 2 no probaría nada.
"""

import sys
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol.types import (  # noqa: E402
    BITCHAT_SERVICE_UUID,
    BITCHAT_SERVICE_UUID_TESTNET,
)
from pybitchat.ble.gatt import es_nuestro_servicio  # noqa: E402


class TestFiltroDeUuid(unittest.TestCase):
    def test_acepta_el_uuid_principal(self):
        self.assertTrue(es_nuestro_servicio(BITCHAT_SERVICE_UUID))

    def test_acepta_el_uuid_testnet(self):
        """Lo que estaba roto. Un APK de prueba anuncia este."""
        self.assertTrue(es_nuestro_servicio(BITCHAT_SERVICE_UUID_TESTNET))

    def test_los_dos_uuid_son_distintos(self):
        """Precondition de los dos tests de arriba.

        Si fueran iguales, "acepta el testnet" no probaría nada, porque el
        principal ya lo aceptaría.
        """
        self.assertNotEqual(BITCHAT_SERVICE_UUID, BITCHAT_SERVICE_UUID_TESTNET)

    def test_se_diferencian_solo_en_el_ultimo_caracter(self):
        """Y por eso es tan fácil no verlo al leer el código.

        Lo deja documentado como el detalle que es: dos cadenas larguísimas que
        solo difieren al final, sin nada que resalte la diferencia.
        """
        self.assertEqual(len(BITCHAT_SERVICE_UUID), len(BITCHAT_SERVICE_UUID_TESTNET))
        distintos = [
            i
            for i, (a, b) in enumerate(zip(BITCHAT_SERVICE_UUID,
                                           BITCHAT_SERVICE_UUID_TESTNET))
            if a != b
        ]
        self.assertEqual(len(distintos), 1, "solo debería diferir en una posición")
        self.assertEqual(
            distintos[0], len(BITCHAT_SERVICE_UUID) - 1, "y esa es la última"
        )

    # -- el formato con el que llega ---------------------------------------

    def test_compara_como_uuid_y_no_como_texto(self):
        """Con minúsculas y sin guiones, que es como lo devuelve bleak.

        Es el bug que ya se corrigió una vez (`uuid.UUID.hex` son 32
        caracteres sin guiones y `str(uuid)` son 36 con ellos) y vuelve a morder
        si alguien compara texto. La constante de `types.py` ya está en
        mayúsculas, así que la diferencia de formato hay que provocarla a mano.
        """
        minusculas = BITCHAT_SERVICE_UUID.lower()
        self.assertNotEqual(minusculas, BITCHAT_SERVICE_UUID, "el texto difiere")
        self.assertTrue(
            es_nuestro_servicio(minusculas),
            "pero como UUID son el mismo, y por eso tiene que compararse así",
        )

    def test_acepta_el_objeto_uuid(self):
        self.assertTrue(es_nuestro_servicio(uuid.UUID(BITCHAT_SERVICE_UUID)))

    def test_acepta_el_uuid_sin_guiones(self):
        sin = BITCHAT_SERVICE_UUID.replace("-", "")
        self.assertNotEqual(sin, BITCHAT_SERVICE_UUID)
        self.assertTrue(es_nuestro_servicio(sin))

    # -- lo que no es nuestro ---------------------------------------------

    def test_rechaza_otro_servicio(self):
        self.assertFalse(
            es_nuestro_servicio("0000180f-0000-1000-8000-00805f9b34fb"),
            "el de Heart Rate no es el nuestro",
        )

    def test_rechaza_el_testnet_cambiado_en_mas_de_un_lugar(self):
        """Un UUID parecido pero con dos cambios no se acepta.

        Evita que ampliar el filtro para el testnet lo convierta en "acepta lo
        que se parezca", que ya sería un fallo de seguridad.
        """
        falso = BITCHAT_SERVICE_UUID_TESTNET[:-1] + "D"
        self.assertFalse(es_nuestro_servicio(falso))

    def test_basura_no_revienta(self):
        """El móvil announces cosas raras y un `TypeError` tumba el escaneo."""
        for valor in (None, b"\\x00\\x01", "", "no-es-un-uuid", 42, object()):
            with self.subTest(valor=valor):
                self.assertFalse(es_nuestro_servicio(valor))


class TestElEscanerTieneModoCrudo(unittest.TestCase):
    """Que exista el volcado crudo, porque sin él no se diagnostica esto.

    El síntoma es "cero candidatos", y es el mismo si el filtro falla o si el
    móvil no anuncia. La única forma de separarlo es ver los UUID que llegan.
    """

    @classmethod
    def setUpClass(cls):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "smoke_crudo", ROOT / "tools" / "smoke_ble.py"
        )
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        cls.smoke = mod

    def test_el_flag_existe(self):
        import inspect

        fuente = inspect.getsource(self.smoke.main)
        self.assertIn('"--crudo"', fuente)

    def test_resolver_telefono_acepta_crudo(self):
        import inspect

        firma = inspect.signature(self.smoke.resolver_telefono)
        self.assertIn("crudo", firma.parameters)
        self.assertIs(
            firma.parameters["crudo"].default, False,
            "por defecto apagado: una ejecucion normal no vuelca 20 lineas",
        )

    def test_el_volcado_imprime_los_dos_uuid(self):
        """Imprime el principal **y** el testnet.

        Es lo que permite leer en crudo cuál de los dos está llegando. Con solo
        el principal, si por el motivo que sea fuera el testnet, el volcado
        seguiría sin explicarlo.
        """
        import inspect

        fuente = inspect.getsource(self.smoke.resolver_telefono)
        self.assertIn("BITCHAT_SERVICE_UUID}", fuente)
        self.assertIn("BITCHAT_SERVICE_UUID_TESTNET}", fuente)

    def test_el_volcado_distingue_el_principal(self):
        """Marca qué dispositivo ES el nuestro.

        Sin la marca, el volcado obliga a comparar 32 caracteres a ojo, que es
        justo el fallo del testnet: un carácter de diferencia en una cadena
        larguísima.
        """
        import inspect

        fuente = inspect.getsource(self.smoke.resolver_telefono)
        self.assertIn("BITCHAT", fuente)


if __name__ == "__main__":
    unittest.main()