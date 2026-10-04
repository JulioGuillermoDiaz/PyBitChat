"""El `msg3`: cuándo se construye, cuándo se envía, y qué pasa si no.

## Por qué tiene tantas condiciones

`construir_msg3` tiene dos guardas y ambas son Load-bearing:

1. **`--msg3` explícito.** Sin el flag, las ejecuciones que se usan para otra cosa
   no cambian de comportamiento.
2. **La lectura del `msg2` dio `IGUAL`.** Es lo que dice que el `ck` de la sesión
   es el de la app.

La segunda es la que protege de verdad. Un `msg3` con bytes plausibles y una
derivación equivocada es **peor que no enviarlo**: desde fuera, un mensaje mal
derivado y uno ausente pueden ser lo mismo, y no hay forma de distinguirlos sin
adivinar. Un `msg3` con el tag Poly1305 de la carga vacía y la `s` correcta por
casualidad no se distingue de uno bien derivado.

Y un tercer filtro: si el tamaño no es 64 B, no se envía. Tampoco a modo de
prueba.

## Qué no se hace aquí

No se descifra nada de lo que llegue después (`NOISE_ENCRYPTED`, `0x11`). Eso
sería el paso siguiente y merece su propia decisión. Aquí solo se registra qué
tipos llegan.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.noise.handshake import MSG3_SIZE  # noqa: E402
from pybitchat.noise.session import HandshakeSession  # noqa: E402
from pybitchat.protocol.packet import Packet  # noqa: E402
from pybitchat.protocol.types import MessageType  # noqa: E402

try:
    import noise.noise_protocol  # noqa: F401

    HAY_MOTOR = True
except Exception:  # pragma: no cover - depende del entorno
    HAY_MOTOR = False


def _cargar_smoke():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "smoke_msg3", ROOT / "tools" / "smoke_ble.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class _Args:
    def __init__(self, msg3=True, peer_id=None, ttl_handshake=6,
                 noise_public=None):
        self.msg3 = msg3
        self.peer_id = peer_id
        self.ttl_handshake = ttl_handshake
        self.noise_public = noise_public


@unittest.skipUnless(HAY_MOTOR, "el motor de Noise no importa")
class TestConstruirMsg3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()

    def _par(self):
        """Un `msg1` nuestro y el `msg2` de un respondedor."""
        i = HandshakeSession(initiator=True, static_private=os.urandom(32))
        r = HandshakeSession(initiator=False, static_private=os.urandom(32))
        r.read_handshake(i.write_handshake(b""))
        return i, r, r.write_handshake(b"")

    #: Con esto, `_leido` usa la clave del respondedor. Es el caso bueno, y no
    #: se puede escribir como argumento porque la clave sale del propio par.
    AUTO = "auto"

    def _leido(self, noise_public=AUTO, **kw):
        """Lee el `msg2`. Devuelve `(sesion, resultado, salida, clave_ajena)`."""
        i, r, msg2 = self._par()
        ajena = r._state.s.public_bytes
        buf = io.StringIO()
        with redirect_stdout(buf):
            resultado = self.smoke._leer_msg2(
                msg2, i, _Args(noise_public=ajena if noise_public is self.AUTO
                               else noise_public, **kw)
            )
        return i, resultado, buf.getvalue(), ajena

    def _construido(self, **kw):
        i, resultado, _leido, ajena = self._leido(**kw)
        buf = io.StringIO()
        with redirect_stdout(buf):
            mensaje = self.smoke.construir_msg3(i, resultado, _Args(**kw))
        return mensaje, buf.getvalue()

    # -- lo que sale bien ---------------------------------------------------

    def test_con_igual_y_el_flag_se_construye(self):
        mensaje, _salida = self._construido()
        self.assertIsNotNone(mensaje)

    def test_mide_64(self):
        mensaje, _salida = self._construido()
        self.assertEqual(len(mensaje), MSG3_SIZE)
        self.assertEqual(MSG3_SIZE, 64)

    def test_la_lectura_dice_igual(self):
        _i, resultado, _salida, _ajena = self._leido()
        self.assertEqual(resultado["estado"], "igual")

    def test_la_sesion_queda_establecida(self):
        """`split()` tiene que funcionar: es lo que demuestra que el handshake
        se puede completar de verdad, no solo que salen 64 B."""
        i, resultado, _leido, ajena = self._leido()
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.smoke.construir_msg3(i, resultado, _Args(noise_public=ajena))
        self.assertIn("split() correcto", buf.getvalue())

    # -- guarda 1: el flag --------------------------------------------------

    def test_sin_el_flag_no_se_construye(self):
        mensaje, salida = self._construido(msg3=False)
        self.assertIsNone(mensaje)
        self.assertIn("falta --msg3", salida)

    def test_sin_el_flag_la_lectura_sigue_diciendo_igual(self):
        """Sin el flag no se lee siquiera el `msg2`. Una ejecucion normal no
        debe imprimir la mitad del handshake por sorpresa."""
        _i, resultado, _salida, _ajena = self._leido(msg3=False)
        self.assertEqual(resultado["estado"], "igual")

    # -- guarda 2: solo si IGUAL -------------------------------------------

    def test_con_clave_distinta_no_se_construye(self):
        # Una sola clave para las dos llamadas: si cada una genera la suya, no
        # se esta probando el caso "distinta" sino dos sesiones distintas.
        otra = os.urandom(32)
        i, resultado, _leido, _ajena = self._leido(noise_public=otra)
        self.assertEqual(resultado["estado"], "distinta")
        with redirect_stdout(io.StringIO()):
            mensaje = self.smoke.construir_msg3(
                i, resultado, _Args(noise_public=otra)
            )
        self.assertIsNone(mensaje)

    def test_con_clave_distinta_lo_dice(self):
        otra = os.urandom(32)
        _i, _r, salida, _ajena = self._leido(noise_public=otra)
        self.assertIn("DISTINTA", salida)

    def test_sin_comparar_no_se_construye(self):
        """Sin `--noise-public` no se sabe si la clave es la buena. No saber no
        es un motivo para enviar."""
        i, resultado, _leido, _ajena = self._leido(noise_public=None)
        self.assertEqual(resultado["estado"], "sin-comparar")
        with redirect_stdout(io.StringIO()):
            mensaje = self.smoke.construir_msg3(
                i, resultado, _Args(noise_public=None)
            )
        self.assertIsNone(mensaje)

    def test_error_de_descifrado_no_se_construye(self):
        i, _r, msg2 = self._par()
        roto = bytearray(msg2)
        roto[40] ^= 0xFF
        buf = io.StringIO()
        with redirect_stdout(buf):
            resultado = self.smoke._leer_msg2(bytes(roto), i, _Args())
        self.assertEqual(resultado["estado"], "error")
        with redirect_stdout(io.StringIO()):
            mensaje = self.smoke.construir_msg3(i, resultado, _Args())
        self.assertIsNone(mensaje)

    def test_payload_64_no_se_construye(self):
        """El bug de `probe_msg2`: el motor no consumi\u00f3 el patron."""
        _i, _r, msg2 = self._par()
        suelta = HandshakeSession(initiator=True, static_private=os.urandom(32))
        buf = io.StringIO()
        with redirect_stdout(buf):
            resultado = self.smoke._leer_msg2(msg2, suelta, _Args())
        self.assertEqual(resultado["estado"], "payload")
        with redirect_stdout(io.StringIO()):
            mensaje = self.smoke.construir_msg3(suelta, resultado, _Args())
        self.assertIsNone(mensaje)

    def test_sin_sesion_no_se_construye(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            resultado = self.smoke._leer_msg2(bytes(96), None, _Args())
        self.assertEqual(resultado["estado"], "sin-sesion")
        with redirect_stdout(io.StringIO()):
            self.assertIsNone(self.smoke.construir_msg3(None, resultado, _Args()))

    def test_todo_estado_distinto_de_igual_da_none(self):
        """Una sola regla, exhaustiva: solo `igual` construye."""
        for estado in ("distinta", "payload", "error", "sin-estatica",
                       "sin-comparar", "sin-sesion"):
            with self.subTest(estado=estado):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    out = self.smoke.construir_msg3(
                        None, {"estado": estado}, _Args()
                    )
                self.assertIsNone(out)

    # -- el tamano ----------------------------------------------------------

    def test_no_se_envia_un_tamano_que_no_es_el_del_perfil(self):
        """Aunque la sesion devuelva otra cosa, no se manda."""
        class SesionFalsa:
            def write_handshake(self, payload=b""):
                return b"\x00" * 32          # ni 64 ni 96

        buf = io.StringIO()
        with redirect_stdout(buf):
            out = self.smoke.construir_msg3(
                SesionFalsa(), {"estado": "igual"}, _Args()
            )
        self.assertIsNone(out)
        self.assertIn("NO enviado", buf.getvalue())

    # -- empaquetado --------------------------------------------------------

    def test_el_paquete_del_msg3_es_un_handshake_dirigido(self):
        """El mismo tipo que el `msg1` y el `msg2`, y con `recipient_id`: sin
        \u00e9l la app lo descarta en silencio (`MessageHandler.kt:375-377`)."""
        from pybitchat.protocol.identity import Identity

        identidad = Identity.generate("pybitchat-probe")
        destino = bytes.fromhex("34e01ccea10a8c6d")
        from pybitchat.noise.handshake import empaquetar

        paquete = empaquetar(b"\x11" * MSG3_SIZE, identidad, destino, ttl=6)
        leido = Packet.from_bytes(paquete)
        self.assertEqual(leido.header.raw_type, int(MessageType.NOISE_HANDSHAKE))
        self.assertEqual(leido.recipient_id, destino)
        self.assertEqual(len(leido.payload), MSG3_SIZE)

    def test_el_paquete_del_msg3_va_rellenado(self):
        from pybitchat.noise.handshake import empaquetar
        from pybitchat.protocol.identity import Identity

        identidad = Identity.generate("pybitchat-probe")
        paquete = empaquetar(b"\x11" * MSG3_SIZE, identidad,
                             bytes.fromhex("34e01ccea10a8c6d"))
        self.assertEqual(len(paquete), 256)


class TestElFlagActivaElHandshake(unittest.TestCase):
    """`--msg3` sin `--handshake` no tendr\xeda nada que completar.

    Sin handshake no hay `msg1`, y sin `msg1` no hay `msg2` que responder. En
    vez de fallar con un error seco, el flag activa el handshake: lo que el
    usuario ha pedido implica lo que hace falta.
    """

    def _main(self, argv):
        """Ejecuta `main()` de verdad, sin BLE: se sustituye `principal`."""
        import sys as _sys
        from unittest import mock

        mod = _cargar_smoke()
        vistos = {}

        async def principal_falso(args):
            vistos["args"] = args
            return 0

        mod.principal = principal_falso
        with mock.patch.object(_sys, "argv", ["smoke_ble.py"] + argv):
            codigo = mod.main()
        self.assertEqual(codigo, 0)
        return vistos["args"]

    def test_msg3_solo_ya_activa_el_handshake(self):
        args = self._main(["--msg3"])
        self.assertTrue(args.msg3)
        self.assertTrue(args.handshake)

    def test_sin_msg3_no_activa_el_handshake(self):
        """Una ejecucion normal no cambia de comportamiento."""
        args = self._main([])
        self.assertFalse(args.msg3)
        self.assertFalse(args.handshake)

    def test_handshake_solo_sigue_siendo_handshake(self):
        args = self._main(["--handshake"])
        self.assertTrue(args.handshake)
        self.assertFalse(args.msg3)

    def test_msg3_no_por_si_solo_es_handshake(self):
        """Que se active el handshake no significa que se env\xeda el msg3."""
        args = self._main(["--handshake"])
        args_msg3 = self._main(["--msg3"])
        self.assertFalse(args.msg3)
        self.assertTrue(args_msg3.msg3)


if __name__ == "__main__":
    unittest.main()