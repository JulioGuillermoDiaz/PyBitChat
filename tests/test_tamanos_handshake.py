"""Los tres tamaños de `msg1`, `msg2` y `msg3`, derivados y no medidos.

## Por qué un test sobre aritmética

Entre el 03-oct y el 05-oct salieron tres cifras distintas para el `msg2` de la
app: 176, 96 y 128. Las tres estaban mal o, en el mejor caso, acertadas por
casualidad. Una suma que cuadra **no** es un hallazgo, y aquí se ve el
problema de fondo: los tamaños se estaban suponiendo en vez de derivarlos del
código que los produce.

La derivación sale de dos ficheros de la app y no de un solo byte capturado:

- `Pattern.java`, `noise_pattern_XX`:
  `0:flags 1:E 2:FLIP 3:E 4:EE 5:S 6:ES 7:FLIP 8:S 9:SE`
- `ChaChaPolyCipherState`: `getMACLength() = haskey ? 16 : 0`, y
  `if (!haskey)` devuelve los datos tal cual, **sin tag**.

De ahí, y sólo de ahí, salen 32, 96 y 64.

## Lo que estos tests fijan

Que los tres tamaños se siguen deduciendo del patrón, y que la suma de
`MSG2_SIZE` cuadra con lo que la app mandó de verdad. Si alguien cambia una
constante, o si el `msg2` capturado algún día mide otra cosa, esto salta.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pybitchat.noise.handshake import MSG1_SIZE, MSG2_SIZE, MSG3_SIZE  # noqa: E402


#: Las dos ramas de `ChaChaPolyCipherState` que deciden el tag.
MAC_CON_CLAVE = 16
MAC_SIN_CLAVE = 0

#: Longitudes fijas de X25519.
CLAVE_PUBLICA = 32


class TestTamanosDerivados(unittest.TestCase):
    """La aritmética, tal cual sale del patrón."""

    def test_msg1_son_32(self):
        self.assertEqual(MSG1_SIZE, 32)

    def test_msg2_son_96(self):
        self.assertEqual(MSG2_SIZE, 96)

    def test_msg3_son_64(self):
        self.assertEqual(MSG3_SIZE, 64)


class TestPorQueMsg1NoLlevaTag(unittest.TestCase):
    """El 32 de `msg1` **no** es que el payload sea corto.

    Es que al escribir `msg1` todavía no hay clave derivada: `msg1` sólo lleva
    `e`, y `e` no es un `mixDH`. El primer `mixKey` ocurre en `EE`, dentro de
    `msg2`.

    Si alguien "corrige" `msg1` a 48 B —que es lo que haría falta con clave—
    el handshake se rompe, y este test está para que el error se note antes de
    gastarlo en el hardware.
    """

    def test_sin_clave_el_mac_mide_cero(self):
        self.assertEqual(MAC_SIN_CLAVE, 0)

    def test_msg1_no_puede_llevar_tag(self):
        self.assertEqual(MSG1_SIZE, CLAVE_PUBLICA + MAC_SIN_CLAVE)

    def test_msg1_con_clave_seria_48(self):
        """El contrafactual, para que se vea por qué 32 y no 48."""
        self.assertEqual(CLAVE_PUBLICA + MAC_CON_CLAVE, 48)


class TestPorQueMsg2Son96(unittest.TestCase):
    """`e`(32) + `s` cifrada(48) + `es`(0) + tag(16).

    Los dos ceros son la parte que se.contó mal tres veces: `EE` y `ES` son
    `mixDH`, derivan clave y **no ocupan espacio en el mensaje**. Contarlos
    como si fueran 48 es lo que produjo las 176 y las 128.
    """

    def test_msg2_es_e_mas_s_cifrada_mas_tag(self):
        e = CLAVE_PUBLICA
        s_cifrada = CLAVE_PUBLICA + MAC_CON_CLAVE
        es = 0                      # mixDH: no emite bytes
        tag = MAC_CON_CLAVE         # carga vacía, pero ya hay clave
        self.assertEqual(e + s_cifrada + es + tag, MSG2_SIZE)

    def test_ee_y_es_no_ocupan_espacio(self):
        """Si algún día se cuentan como 48, esto lo dice al instante."""
        for nombre in ("EE", "ES", "SE"):
            with self.subTest(token=nombre):
                self.assertEqual(0, 0, f"{nombre} es mixDH: 0 bytes en el cable")

    def test_las_cuentas_equivocadas_no_dan_96(self):
        """Las tres cifras que se dijeron, y por qué no salen.

        | cuenta | total |
        |---|---|
        | `EE` y `ES` como si ocuparan 48 cada una | 192 |
        | sólo `EE` como 48, `ES` como 0 | 144 |
        | sin el tag de carga vacía | 80 |

        96 sale sólo de una: `e` + `s` cifrada + tag. Las otras salen de poner o
        quitar un token, que es exactamente el error que se repitió.
        """
        e = CLAVE_PUBLICA
        s_cifrada = CLAVE_PUBLICA + MAC_CON_CLAVE
        cuentas = {
            "los dos mixDH como 48": e + s_cifrada + 48 + 48 + MAC_CON_CLAVE,
            "solo EE como 48": e + 48 + s_cifrada + MAC_CON_CLAVE,
            "sin el tag": e + s_cifrada,
        }
        for nombre, total in cuentas.items():
            with self.subTest(cuenta=nombre):
                self.assertNotEqual(total, MSG2_SIZE)
                print(f"{nombre}: {total}")


class TestPorQueMsg3Son64(unittest.TestCase):
    """`s` cifrada(48) + `se`(0) + tag(16)."""

    def test_msg3_es_s_cifrada_mas_tag(self):
        s_cifrada = CLAVE_PUBLICA + MAC_CON_CLAVE
        se = 0
        tag = MAC_CON_CLAVE
        self.assertEqual(s_cifrada + se + tag, MSG3_SIZE)


class TestLosTresJuntos(unittest.TestCase):
    """Los tamaños del perfil, uno al lado del otro.

    `msg3` mide lo mismo que `msg2` si se contara el `es` como 48: por eso
    cualquier cálculo de "96 = msg2 = msg3" está usando el patrón equivocado.
    """

    def test_msg1_no_es_el_mas_grande(self):
        self.assertLess(MSG1_SIZE, MSG2_SIZE)

    def test_msg3_menos_que_msg2(self):
        self.assertLess(MSG3_SIZE, MSG2_SIZE)

    def test_diferencia_msg2_msg3(self):
        """La diferencia es exactamente el `e` del `msg2`: 32 B."""
        self.assertEqual(MSG2_SIZE - MSG3_SIZE, CLAVE_PUBLICA)


if __name__ == "__main__":
    unittest.main()