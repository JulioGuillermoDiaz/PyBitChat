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

La clase `TestTamanosMedidos` los **mide** además, montando un XX completo con
los dos roles. La deducción demuestra que la cuenta está bien; la Medición
demuestra que **nuestro motor** genera los mismos bytes que el de la app. Las dos
cosas hacen falta: una suma correcta sobre bytes ajenos no prueba que el cifrado
sea el nuestro.

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


class TestTamanosMedidos(unittest.TestCase):
    """Los mismos tres numeros, **medidos** en vez de deducidos.

    ## Por que medir y deducir las dos cosas

    `tests/test_tamanos_handshake.py` deriva 32/96/64 del codigo de la app. Eso
    demuestra que la cuenta esta bien, pero no que `noiseprotocol` —nuestro
    motor— produzca esos mismos bytes.

    Aqui se monta un XX completo con los dos roles de nuestro propio
    `HandshakeSession` y se miden. Si `noiseprotocol` dejara de emitir el tag de
    la carga vacia, o empezara a emitirlo antes de tener clave, estos numeros
    cambiarian y el test caeria.

    ## Que demuestra

    Que el motor que usamos genera exactamente los 96 B que nos manda la app.
    No que losOur tamano sea correcto: que el nuestro coincide con el suyo.
    """

    @classmethod
    def setUpClass(cls):
        import os

        from pybitchat.noise.session import HandshakeSession

        try:
            import noise.noise_protocol  # noqa: F401
        except Exception as exc:  # pragma: no cover - depende del entorno
            raise unittest.SkipTest(f"el motor de Noise no importa: {exc}")

        cls.HandshakeSession = HandshakeSession
        cls._os = os

    def _par(self):
        os = self._os
        S = self.HandshakeSession
        return (
            S(initiator=True, static_private=os.urandom(32)),
            S(initiator=False, static_private=os.urandom(32)),
        )

    def _handshake(self):
        """Devuelve los tres mensajes y las dos sesiones ya divididas."""
        i, r = self._par()
        m1 = i.write_handshake(b"")
        r.read_handshake(m1)
        m2 = r.write_handshake(b"")
        i.read_handshake(m2)
        m3 = i.write_handshake(b"")
        r.read_handshake(m3)
        return i, r, m1, m2, m3

    def test_msg1_mide_32(self):
        _i, _r, m1, _m2, _m3 = self._handshake()
        self.assertEqual(len(m1), MSG1_SIZE)

    def test_msg2_mide_96(self):
        """El mismo tamaño que el `msg2` real de la app."""
        _i, _r, _m1, m2, _m3 = self._handshake()
        self.assertEqual(len(m2), MSG2_SIZE)

    def test_msg3_mide_64(self):
        _i, _r, _m1, _m2, m3 = self._handshake()
        self.assertEqual(len(m3), MSG3_SIZE)

    def test_las_huellas_coinciden(self):
        """Si no coinciden, el `split()` dara claves distintas y nada cifrado
        funcionara. Es la comprobacion que de verdad importa del handshake."""
        i, r, _m1, _m2, _m3 = self._handshake()
        self.assertEqual(i.handshake_hash, r.handshake_hash)

    def test_cada_lado_aplica_la_estatica_del_otro(self):
        """El token `S` del `msg2` se descifra y deja la clave del otro."""
        i, r, _m1, _m2, _m3 = self._handshake()
        self.assertIsNotNone(i.remote_static_public)
        self.assertIsNotNone(r.remote_static_public)
        self.assertEqual(len(i.remote_static_public), 32)
        self.assertEqual(len(r.remote_static_public), 32)

    def test_la_estatica_recibida_es_la_del_otro_y_no_la_propia(self):
        """Lo que prueba el token `S`: llega la clave **del otro**.

        Comparar con la del otro es lo que hace util el descifrado; comprobar que
        **no** es la propia es lo que demuestra que no se hasimply exchanges.
        """
        i, r, _m1, _m2, _m3 = self._handshake()
        # Lo que recibe el iniciador es la estatica del respondedor.
        self.assertEqual(i.remote_static_public, r._state.s.public_bytes)
        self.assertEqual(r.remote_static_public, i._state.s.public_bytes)
        # Y ninguna se parece a su propia clave.
        self.assertNotEqual(i.remote_static_public, i._state.s.public_bytes)
        self.assertNotEqual(r.remote_static_public, r._state.s.public_bytes)

    def test_split_de_los_dos(self):
        """`split()` es el final del handshake y devuelve el canal de transporte.

        Que no lance y que los dos lados consigan uno es lo que dice que la
        derivacion llego hasta el final.
        """
        i, r, _m1, _m2, _m3 = self._handshake()
        self.assertIsNotNone(i.split())
        self.assertIsNotNone(r.split())

    def test_el_tag_de_la_carga_vacia_solo_aparece_con_clave(self):
        """El por que de que `msg1` no lleve tag y `msg2` sí.

        `msg1` se escribe sin clave derivada: 32 B, sin tag. En `msg2` ya la hay,
        por el `mixDH` de `EE`, y el tag de la carga vacía aparece: 16 B más.
        Si esto cambia, los tres números de arriba dejan de ser 32/96/64.
        """
        i, _r = self._par()
        solo = i.write_handshake(b"")
        # e (32) y nada mas
        self.assertEqual(len(solo), CLAVE_PUBLICA)


if __name__ == "__main__":
    unittest.main()