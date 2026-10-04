"""`_leer_msg2`: los cuatro desenlaces, probados sin Bluetooth.

## Por qué hay que probarla con tanto detalle

Esta función es la que dice si la cadena de derivación coincide con la de la
app. Antes de esto, esa pregunta se hacía en `tools/probe_msg2.py`, que contestaba
siempre que no:

    leído sin error. carga útil: 64 B
    remote_static_public: None

Las dos líneas eran síntomas del mismo error: leía el `msg2` **sin haber escrito
el `msg1`**. El motor se come el patrón `[e]` en vez de `[e, ee, s, es]`, los
64 B de cola quedan sin descifrar, y como no hay clave el Poly1305 no se
comprueba — así que no puede fallar. "Leído sin error" no significaba nada.

Aquí la comprobación vive en `smoke_ble.py`, que tiene la sesión viva, y estos
tests la ejercitan con un `msg2` fabricado en local. Los cuatro desenlaces se
distinguen por la salida, que es lo que hay que leer en el terminal.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.noise.session import HandshakeSession  # noqa: E402

try:
    import noise.noise_protocol  # noqa: F401

    HAY_MOTOR = True
except Exception:  # pragma: no cover - depende del entorno
    HAY_MOTOR = False


def _cargar_smoke():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "smoke_leer_msg2", ROOT / "tools" / "smoke_ble.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class _Args:
    """Lo mínimo de `argparse.Namespace` que `_leer_msg2` usa."""

    def __init__(self, noise_public=None, peer_id=None):
        self.noise_public = noise_public
        self.peer_id = peer_id


@unittest.skipUnless(HAY_MOTOR, "el motor de Noise no importa")
class TestLeerMsg2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()

    def _par(self):
        """Dos sesiones y un `msg2` de 96 B, con la misma forma que el de la app."""
        i = HandshakeSession(initiator=True, static_private=os.urandom(32))
        r = HandshakeSession(initiator=False, static_private=os.urandom(32))
        m1 = i.write_handshake(b"")
        r.read_handshake(m1)
        return i, r, r.write_handshake(b"")

    def _salida(self, msg2, sesion, **kw):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.smoke._leer_msg2(msg2, sesion, _Args(**kw))
        return buf.getvalue()

    # -- el caso bueno ------------------------------------------------------

    def test_msg2_de_96_b(self):
        _i, _r, msg2 = self._par()
        self.assertEqual(len(msg2), 96)

    def test_sesion_viva_lee_el_msg2(self):
        """Con la sesión que escribió el `msg1`, la carga útil es 0."""
        i, _r, msg2 = self._par()
        salida = self._salida(msg2, i)
        self.assertIn("carga \u00fatil: 0 B", salida)

    def test_sesion_viva_pone_la_estatica(self):
        i, r, msg2 = self._par()
        salida = self._salida(msg2, i)
        self.assertIn(r._state.s.public_bytes.hex(), salida)

    def test_avisa_de_la_pausa_de_verificacion(self):
        """Es un punto de espera. Ya no es correcto decir que hay que esperar
        a otro sitio: `probe_msg2` ya no lo hace."""
        i, _r, msg2 = self._par()
        salida = self._salida(msg2, i)
        self.assertIn("--noise-public", salida)

    # -- el desenlace IGUAL -------------------------------------------------

    def test_con_la_clave_de_la_app_dice_igual(self):
        i, r, msg2 = self._par()
        ruido = r._state.s.public_bytes
        salida = self._salida(msg2, i, noise_public=ruido)
        self.assertIn("IGUAL", salida)

    def test_con_la_clave_de_la_app_deriva_el_peer_id(self):
        from pybitchat.protocol.identity import peer_id_from_noise_key

        i, r, msg2 = self._par()
        pid = peer_id_from_noise_key(r._state.s.public_bytes)
        salida = self._salida(msg2, i, noise_public=r._state.s.public_bytes,
                              peer_id=pid)
        self.assertIn(pid.hex(), salida)
        self.assertNotIn("DISTINTO", salida)

    # -- el desenlace DISTINTA ---------------------------------------------

    def test_con_otra_clave_dice_distinta(self):
        i, _r, msg2 = self._par()
        salida = self._salida(msg2, i, noise_public=os.urandom(32))
        self.assertIn("DISTINTA", salida)

    def test_con_otra_clave_no_dice_que_coincide(self):
        i, _r, msg2 = self._par()
        salida = self._salida(msg2, i, noise_public=os.urandom(32))
        self.assertNotIn("-> IGUAL", salida)

    def test_con_otra_clave_no_pide_escribir_el_msg3(self):
        i, _r, msg2 = self._par()
        salida = self._salida(msg2, i, noise_public=os.urandom(32))
        self.assertNotIn("criterio, sin adivinar", salida)

    # -- el desenlace 64 B: el bug de probe_msg2 ----------------------------

    def test_sesion_sin_msg1_avisa_de_64_b(self):
        """El caso que `probe_msg2` daba como si fuera bueno."""
        _i, _r, msg2 = self._par()
        suelta = HandshakeSession(initiator=True, static_private=os.urandom(32))
        salida = self._salida(msg2, suelta)
        self.assertIn("Deber\u00eda ser **0 B**", salida)

    def test_sesion_sin_msg1_lo_atribuye_al_que_llama(self):
        _i, _r, msg2 = self._par()
        suelta = HandshakeSession(initiator=True, static_private=os.urandom(32))
        salida = self._salida(msg2, suelta)
        self.assertIn("bug de quien llama", salida)

    def test_sesion_sin_msg1_no_dice_que_va_a_iley(self):
        _i, _r, msg2 = self._par()
        suelta = HandshakeSession(initiator=True, static_private=os.urandom(32))
        salida = self._salida(msg2, suelta)
        self.assertNotIn("criterio, sin adivinar", salida)

    # -- el desenlace error ------------------------------------------------

    def test_ciphertext_corrupto_avisa_de_poly1305(self):
        i, _r, msg2 = self._par()
        roto = bytearray(msg2)
        roto[40] ^= 0xFF          # dentro de la `s` cifrada
        salida = self._salida(bytes(roto), i)
        self.assertIn("ERROR al leer", salida)
        self.assertIn("Poly1305", salida)

    def test_ciphertext_corrupto_no_dice_igual(self):
        i, _r, msg2 = self._par()
        roto = bytearray(msg2)
        roto[40] ^= 0xFF
        salida = self._salida(bytes(roto), i)
        self.assertNotIn("-> IGUAL", salida)

    # -- sin sesion --------------------------------------------------------

    def test_sin_sesion_no_revienta(self):
        _i, _r, msg2 = self._par()
        salida = self._salida(msg2, None)
        self.assertIn("no hay sesi\u00f3n", salida)


class TestEscucharHandshakePasaLaSesion(unittest.TestCase):
    """`_escuchar_handshake` tiene que recibir la sesión para poder leer el `msg2`.

    Sin esto, la lectura viviría en un sitio al que no llega y volveríamos a
    tener un `probe_msg2` que contesta sin poder.
    """

    def test_la_firma_acepta_la_sesion(self):
        import inspect

        mod = _cargar_smoke()
        firma = inspect.signature(mod._escuchar_handshake)
        self.assertIn("sesion", firma.parameters)

    def test_llama_a_leer_msg2(self):
        import inspect

        mod = _cargar_smoke()
        self.assertIn("_leer_msg2", inspect.getsource(mod._escuchar_handshake))

    def test_leer_msg2_usa_la_sesion_del_argumento(self):
        """Que no coja la sesión de otro sitio: es el bug que ya versioning."""
        import inspect

        mod = _cargar_smoke()
        fuente = inspect.getsource(mod._leer_msg2)
        self.assertIn("sesion.read_handshake", fuente)


if __name__ == "__main__":
    unittest.main()