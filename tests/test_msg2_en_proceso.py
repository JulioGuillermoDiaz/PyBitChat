"""Por qué el `msg2` de la app **solo** se puede leer en el proceso que lo envió.

## Lo que pasó

El 2026-10-05, `tools/probe_msg2.py`.imprime sobre un `msg2` **real** de la app:

    leído sin error. carga útil: 64 B
    remote_static_public: None

Las dos cosas están mal a la vez, y una sola causa las explica: la sesión nunca
escribió el `msg1`.

## La causa

`noiseprotocol` no lleva un contador de mensajes: lleva una **lista de
patrones**, uno por mensaje, y cada `read_message`/`write_message` hace `pop(0)`
del primero (`noise/state.py:302` y `:362`). `PatternXX.tokens` es:

    [[e], [e, ee, s, es], [s, se]]

El `msg1` se lleva el primero. Así que para leer el `msg2` hay que haber escrito
el `msg1` antes, o el `pop(0)` se come `[e]` — un solo token— y los 64 bytes
restantes se quedan como "carga útil".

Y sin `mix_key` no hay clave, así que ese tramo **no se descifra**: sale tal
cual, sin error y con 64 bytes. De ahí el "leído sin error": no lee nada.

## Lo que este test fija

La firma del error. Si algún día alguien lee un `msg2` sin haber escrito su
`msg1`, tiene que sacar 64 bytes y `None`, y aquí se ve por qué.

## Lo que no se puede arreglar aquí

Aunque se escribiera un `msg1` nuevo, **no** descifraría el `msg2` real: hace
falta la clave efímera privada del `msg1` que la app recibió de verdad, y esa
solo existe en el proceso que lo mandó. Por eso la comprobación vive en
`smoke_ble.py`, que es quien tiene la sesión viva.
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pybitchat.noise.session import HandshakeSession  # noqa: E402

try:
    import noise.noise_protocol  # noqa: F401

    HAY_MOTOR = True
except Exception:  # pragma: no cover - depende del entorno
    HAY_MOTOR = False


@unittest.skipUnless(HAY_MOTOR, "el motor de Noise no importa")
class TestLeerMsg2SinMsg1Antes(unittest.TestCase):
    """La firma de la trampa: 64 bytes de carga y ninguna estática."""

    def _par(self):
        return (
            HandshakeSession(initiator=True, static_private=os.urandom(32)),
            HandshakeSession(initiator=False, static_private=os.urandom(32)),
        )

    def _msg2_realista(self):
        """Un `msg2` de 96 B, con la misma forma que el de la app."""
        i, r = self._par()
        m1 = i.write_handshake(b"")
        r.read_handshake(m1)
        return r.write_handshake(b"")

    def test_el_msg2_mide_96(self):
        """Punto de partida: el mensaje tiene la forma que esperamos."""
        self.assertEqual(len(self._msg2_realista()), 96)

    def test_sin_msg1_la_carga_es_el_resto_sin_descifrar(self):
        """64 = 96 - 32. Se come `[e]` y lo demas queda de carga."""
        msg2 = self._msg2_realista()
        suelta = HandshakeSession(initiator=True, static_private=os.urandom(32))
        carga = suelta.read_handshake(msg2, payload_size=0)
        self.assertEqual(len(carga), 64)

    def test_sin_msg1_no_hay_estatica_remota(self):
        msg2 = self._msg2_realista()
        suelta = HandshakeSession(initiator=True, static_private=os.urandom(32))
        suelta.read_handshake(msg2, payload_size=0)
        self.assertIsNone(suelta.remote_static_public)

    def test_sin_msg1_no_hay_error(self):
        """Lo peligroso: **no falla**. Por eso hay que mirar el tamaño.

        El descifrado no se intenta, así que el Poly1305 no puede fallar. Un
        informe que solo mira "leyó sin error" daría el visto bueno.
        """
        msg2 = self._msg2_realista()
        suelta = HandshakeSession(initiator=True, static_private=os.urandom(32))
        carga = suelta.read_handshake(msg2, payload_size=0)  # no debe lanzar
        self.assertNotEqual(len(carga), 0)

    def test_con_msg1_si_se_descifra(self):
        """El contraste: haciendo las cosas bien, carga 0 y estática puesta."""
        i = HandshakeSession(initiator=True, static_private=os.urandom(32))
        r = HandshakeSession(initiator=False, static_private=os.urandom(32))
        m1 = i.write_handshake(b"")
        r.read_handshake(m1)
        m2 = r.write_handshake(b"")
        carga = i.read_handshake(m2, payload_size=0)
        self.assertEqual(len(carga), 0)
        self.assertIsNotNone(i.remote_static_public)


class TestPatronDeNoiseprotocol(unittest.TestCase):
    """La lista de patrones es la que manda, y hay que mirarla."""

    def test_el_patron_xx_tiene_tres_mensajes(self):
        try:
            from noise.patterns import PatternXX
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"el motor no importa: {exc}")
        self.assertEqual(len(PatternXX().tokens), 3)

    def test_el_primer_mensaje_es_solo_e(self):
        """Por eso leer el `msg2` sin escribir el `msg1` se come `[e]`."""
        try:
            from noise.patterns import PatternXX
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"el motor no importa: {exc}")
        self.assertEqual(PatternXX().tokens[0], ["e"])

    def test_el_segundo_mensaje_es_e_ee_s_es(self):
        try:
            from noise.patterns import PatternXX
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"el motor no importa: {exc}")
        self.assertEqual(PatternXX().tokens[1], ["e", "ee", "s", "es"])

    def test_el_tercer_mensaje_es_s_se(self):
        try:
            from noise.patterns import PatternXX
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"el motor no importa: {exc}")
        self.assertEqual(PatternXX().tokens[2], ["s", "se"])


if __name__ == "__main__":
    unittest.main()