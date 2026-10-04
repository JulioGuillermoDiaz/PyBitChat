"""Tests del empaque del handshake Noise.

La criptografía ya está verificada con 39 vectores en `test_noise_vectors.py`.
Estos tests comprueban lo que **no** es criptografía: que el mensaje y el
paquete tienen la forma que espera la app, y que se cumplen las condiciones que
el código de ella impone.

Las condiciones salen de leer su fuente, y cada una lleva el `file:line`:

| Condición | De dónde |
|---|---|
| `msg1` son 32 B, sin carga | `NoiseSession.kt:293, 301` |
| Sin firma en el handshake | `MessageHandler.kt:392` |
| `recipient_id` obligatorio | `MessageHandler.kt:375-377` |
| TTL = `MESSAGE_TTL_HOPS` | `MessageHandler.kt:393` |
| Relleno por defecto activo | `BinaryProtocol.kt:227` |

La del destinatario es la que más importa y la más fácil de no ver: sin ella
el paquete se **descarta en silencio**, así que un fallo aquí se manifiesta como
"la app nunca contesta", que no señala la causa.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.noise.handshake import (  # noqa: E402
    MSG1_SIZE,
    TTL_HANDSHAKE,
    completar_handshake,
    construir_msg1,
    empaquetar,
    iniciar_handshake,
)
from pybitchat.noise.session import HandshakeSession  # noqa: E402
from pybitchat.protocol.identity import peer_id_from_noise_key  # noqa: E402
from pybitchat.noise.session import NoiseError  # noqa: E402
from pybitchat.protocol.identity import Identity  # noqa: E402
from pybitchat.protocol.packet import Packet, ProtocolError  # noqa: E402
from pybitchat.protocol.types import MessageType, PacketFlags  # noqa: E402

#: Datos reales de la app Android, del announce de 80 B del 2026-10-03.
PEER_APP = bytes.fromhex("34e01ccea10a8c6d")
NOISE_APP = bytes.fromhex(
    "973585b6502836ff5767934bdb4c62458c48b87e94c02d470797e93d21052f6b"
)


class TestMsg1(unittest.TestCase):
    """`msg1` es `-- e, es`: 32 bytes exactos y sin carga."""

    @classmethod
    def setUpClass(cls):
        cls.ident = Identity.generate("pybitchat-probe")

    def test_msg1_mide_32(self):
        """`NoiseSession.kt:293` reserva `XX_MESSAGE_1_SIZE` y avisa si no
        cuadra. No es una longitud aproximada: dos claves públicas de 32 B."""
        mensaje, _ = construir_msg1(self.ident)
        self.assertEqual(len(mensaje), MSG1_SIZE)
        self.assertEqual(len(mensaje), 32)

    def test_msg1_cambia_en_cada_sesion(self):
        """Lleva una clave efímera nueva. Dos sesiones contra el mismo peer
        deben dar mensajes distintos, o el segundo sería un replay."""
        a, _ = construir_msg1(self.ident)
        b, _ = construir_msg1(self.ident)
        self.assertNotEqual(a, b)

    def test_msg1_no_depende_de_la_clave_del_otro(self):
        """En Noise XX el iniciador no necesita la clave estática del receptor
        para el primer mensaje. Passarlo o no, `msg1` es el mismo tamaño.

        Importante porque `msg1` **no** lleva `recipient_id`: ése va en el
        paquete, no en el mensaje de Noise.
        """
        con_clave, _ = construir_msg1(
            self.ident, remote_static_public=NOISE_APP
        )
        sin_clave, _ = construir_msg1(self.ident)
        self.assertEqual(len(con_clave), len(sin_clave))
        self.assertEqual(len(con_clave), MSG1_SIZE)

    def test_perfil_no_soportado_se_rechaza(self):
        """Un perfil que no es XX daría otro `msg1`, y no lo sabríamos hasta
        que la app no contestara."""
        with self.assertRaises(NoiseError):
            construir_msg1(self.ident, protocol_name=b"Noise_XX_448_ChaChaPoly_SHA512")


class TestEmpaquetado(unittest.TestCase):
    """El paquete que ve la app por el characteristic."""

    @classmethod
    def setUpClass(cls):
        cls.ident = Identity.generate("pybitchat-probe")
        cls.mensaje, cls.sesion = construir_msg1(cls.ident)
        cls.paquete = empaquetar(cls.mensaje, cls.ident, PEER_APP)

    def test_el_tipo_es_noise_handshake(self):
        """`0x10`. En el dialecto **legacy** ese valor es
        `NOISE_HANDSHAKE_RESP`, que es una respuesta y no una petición."""
        p = Packet.from_bytes(self.paquete)
        self.assertEqual(p.header.raw_type, int(MessageType.NOISE_HANDSHAKE))
        self.assertEqual(p.header.raw_type, 0x10)

    def test_el_payload_es_el_msg1_entero(self):
        """Los 32 B van enteros, sin recortar ni anteponer nada."""
        p = Packet.from_bytes(self.paquete)
        self.assertEqual(len(p.payload), MSG1_SIZE)
        self.assertEqual(p.payload, self.mensaje)

    def test_no_lleva_firma(self):
        """`MessageHandler.kt:392` pone `signature = null` en el handshake.

        Con firma, el payload se leería desplazado 64 B y la respuesta sería
        basura silenciosa.
        """
        p = Packet.from_bytes(self.paquete)
        self.assertIsNone(p.signature)
        self.assertFalse(p.header.flags & PacketFlags.HAS_SIGNATURE)

    def test_el_ttl_es_el_de_la_app(self):
        self.assertEqual(Packet.from_bytes(self.paquete).header.ttl, TTL_HANDSHAKE)

    def test_el_emisor_es_nuestro_peer_id(self):
        p = Packet.from_bytes(self.paquete)
        self.assertEqual(p.sender_id, self.ident.peer_id)

    def test_el_relleno_es_pkcs7(self):
        """`BinaryProtocol.kt:227` tiene `padding: Boolean = true`, y
        `NOISE_HANDSHAKE` es trama Noise, que es donde la política marca
        relleno. El paquete llega a 256 B."""
        self.assertEqual(len(self.paquete), 256)
        relleno = self.paquete[-1]
        self.assertEqual(relleno, 256 - self._sin_relleno())
        self.assertEqual(set(self.paquete[self._sin_relleno():]), {relleno})

    def _sin_relleno(self) -> int:
        return len(empaquetar(self.mensaje, self.ident, PEER_APP, con_releno=False))

    def test_sin_relleno_tambien_se_puede_construir(self):
        """Para comparar contra capturas. 62 B: 14 cabecera + 8 sender +
        8 recipient + 32 payload."""
        corto = empaquetar(self.mensaje, self.ident, PEER_APP, con_releno=False)
        self.assertEqual(len(corto), 62)

    def test_sin_relleno_el_payload_sigue_siendolo(self):
        """El relleno no debe alterar lo que ve la app."""
        p = Packet.from_bytes(
            empaquetar(self.mensaje, self.ident, PEER_APP, con_releno=False)
        )
        self.assertEqual(p.payload, self.mensaje)
        self.assertEqual(p.recipient_id, PEER_APP)

    def test_un_mensaje_vacio_se_rechaza(self):
        """Un paquete de 0 B de payload no es un handshake, y `Packet` lo
        aceptaría. Se rechaza aquí para no enviar basura."""
        with self.assertRaises(ValueError):
            empaquetar(b"", self.ident, PEER_APP)


class TestElDestinatarioEsObligatorio(unittest.TestCase):
    """El requisito que más caro sale si se ignora.

    `MessageHandler.kt:374-377`:

        val recipientID = packet.recipientID?.toHexString()
        if (recipientID != myPeerID) {
            return
        }

    Sin `recipient_id` el paquete se descarta **en silencio**: sin error, sin
    log, sin respuesta. Desde fuera es indistinguible de "la app me ignoró".
    """

    @classmethod
    def setUpClass(cls):
        cls.ident = Identity.generate("pybitchat-probe")
        cls.mensaje, _ = construir_msg1(cls.ident)

    def test_lleva_el_peer_id_de_la_app_como_recipient(self):
        p = Packet.from_bytes(empaquetar(self.mensaje, self.ident, PEER_APP))
        self.assertEqual(p.recipient_id, PEER_APP)
        self.assertEqual(p.recipient_id_hex, PEER_APP.hex())

    def test_el_flag_has_recipient_esta_activo(self):
        """Sin el flag, el parser ni siquiera lee los 8 bytes y el resto del
        paquete se descuadra."""
        p = Packet.from_bytes(empaquetar(self.mensaje, self.ident, PEER_APP))
        self.assertTrue(p.header.flags & PacketFlags.HAS_RECIPIENT)

    def test_un_recipient_mas_largo_se_rechaza(self):
        """Truncar la identidad de un par es dirección incorrecta.

        `Packet._normalise_peer_id` rellena con ceros lo que sobra **corto**, pero
        un id largo se rechaza: convertirlo en otro par distinto sería peor que
        fallar. Por eso el handshake no acepta un `peer_id` de 9 B.
        """
        with self.assertRaises(ProtocolError):
            empaquetar(self.mensaje, self.ident, b"\x01" * 9)

    def test_un_recipient_corto_se_rellena(self):
        """Lo que sí hace la app (`BinaryProtocol.kt:311-315`): ceros a la
        derecha. Un id de 4 B no puede significar otra cosa que 4 B y ceros."""
        p = Packet.from_bytes(empaquetar(self.mensaje, self.ident, b"\x01" * 4))
        self.assertEqual(p.recipient_id, b"\x01\x01\x01\x01\x00\x00\x00\x00")

    def test_un_handshake_sin_destinatario_se_descartaria(self):
        """Demuestra el descarte, aunque `empaquetar` no lo permita construir.

        Se arma a mano un paquete sin `recipient_id` y se comprueba que la app
        no podría aceptarlo: `recipientID` sería `null` y `null != myPeerID`.
        """
        import time

        from pybitchat.protocol.packet import PacketHeader

        cabecera = PacketHeader(
            version=1,
            raw_type=int(MessageType.NOISE_HANDSHAKE),
            ttl=TTL_HANDSHAKE,
            timestamp=int(time.time() * 1000),
            flags=PacketFlags(0),
            payload_len=len(self.mensaje),
        )
        sin_destino = Packet(
            header=cabecera, sender_id=self.ident.peer_id, payload=self.mensaje
        ).to_bytes(include_padding=False)

        p = Packet.from_bytes(sin_destino)
        # Así es como lo lee MessageHandler.kt:374
        recipient = p.recipient_id.hex() if p.recipient_id is not None else None
        self.assertIsNone(recipient)
        # Y la comparación que hace la app, que es lo que lo descarta:
        self.assertNotEqual(recipient, PEER_APP.hex())


class TestAtajo(unittest.TestCase):
    def test_iniciar_devuelve_paquete_y_sesion(self):
        ident = Identity.generate("pybitchat-probe")
        paquete, sesion = iniciar_handshake(
            ident, peer_id_remoto=PEER_APP, noise_public_remoto=NOISE_APP
        )
        p = Packet.from_bytes(paquete)
        # El payload es un `msg1` de 32 B. **No** se compara con el de otra
        # llamada: cada sesión genera una efímera nueva, así que dos `msg1`
        # legítimos nunca coinciden.
        self.assertEqual(len(p.payload), MSG1_SIZE)
        self.assertEqual(p.recipient_id, PEER_APP)
        # La sesión está viva y puede seguir con `read_handshake`.
        self.assertFalse(sesion.complete)
        self.assertEqual(len(sesion.static_public), 32)

    def test_la_estatica_local_es_la_de_la_identidad(self):
        """La clave que se manda en `msg1` es la del TLV `0x02`. Si no
        coincidieran, la app calcularía un `peer_id` distinto del que
       Kendrá como remitente."""
        ident = Identity.generate("pybitchat-probe")
        _, sesion = construir_msg1(ident)
        self.assertEqual(sesion.static_public, ident.noise_public)

    def test_el_peer_id_del_remoto_no_va_en_el_payload(self):
        """El `peer_id` va en el **paquete**, no en el mensaje de Noise. Si
        fuera dentro del payload, la app leería 32 B desplazados."""
        ident = Identity.generate("pybitchat-probe")
        paquete, _ = iniciar_handshake(ident, peer_id_remoto=PEER_APP)
        p = Packet.from_bytes(paquete)
        self.assertNotIn(PEER_APP, p.payload)
        self.assertIn(PEER_APP, paquete)


class TestCompletarHandshake(unittest.TestCase):
    """El tercer mensaje de XX: el que cierra el patrón.

    Verificado el 2026-10-04: la app responde a nuestro `msg1` con 96 B, y
    `HandshakeSession` como *responder* produce también 96 B. Mismo tamaño = la
    configuración Noise es la misma: perfil, tag y orden de tokens.
    """

    @classmethod
    def setUpClass(cls):
        cls.ident = Identity.generate("pybitchat-probe")
        #: Clave privada fija de la "app" simulada. Se usa para que
        #: `HandshakeSession`derive su clave pública correctamente.
        #:
        #: Antes se manipulaba `s.public_bytes` a mano y el `msg2` no lo podía
        #: leer ni el iniciador: la clave pública es el resultado de
        #: `X25519BasepointMult`, y cambiarla a posteriori deja la sesión en un
        #: estado que no corresponde a ninguna clave real. Con la privada
        #: verdadera, las dos mitades encajan desde el principio.
        cls.app_priv = b"\x22" * 32
        #: `peer_id` derivado de la clave de la app simulada. **No** se escribe a
        #: mano: el test tiene que usar el mismo criterio que
        #: `completar_handshake`. Con una constante fija, el test comprobaría que
        #: el código hace lo que el test dice, en vez de lo que el código dice.
        cls.peer_app = peer_id_from_noise_key(
            HandshakeSession(
                initiator=False,
                static_private=cls.app_priv,
                remote_static_public=b"\x33" * 32,
            ).static_public
        )

    def _par(self):
        """Devuelve `(iniciador, app_responder, msg2)`.

        El llamante decide hasta dónde avanzar, porque cada test necesita un
        punto distinto de la conversación.
        """
        ident = self.ident
        ini = HandshakeSession(initiator=True, static_private=ident.noise_private)
        app = HandshakeSession(
            initiator=False,
            static_private=self.app_priv,
            remote_static_public=ident.noise_public,
        )
        msg1 = ini.write_handshake(b"")
        app.read_handshake(msg1)
        msg2 = app.write_handshake(b"")
        return ini, app, msg2

    def test_el_msg2_de_la_app_mide_lo_que_producimos(self):
        """El dato que cerró la duda: 96 B de un lado y de otro.

        Los 96 B del `msg2` real de la app se transcribieron del hexdump del
        2026-10-04. Que nuestra implementación produzca el mismo tamaño es lo
        que dice que el perfil, la etiqueta y el orden de tokens coinciden.
        """
        ini, _app, msg2 = self._par()
        self.assertEqual(len(msg2), 96)

    def test_completar_cierra_el_patron(self):
        ini, _app, msg2 = self._par()
        msg3_paquete, sesion = completar_handshake(
            ini, self.ident, msg2, self.peer_app, ttl=6
        )
        p = Packet.from_bytes(msg3_paquete)
        self.assertEqual(p.header.raw_type, int(MessageType.NOISE_HANDSHAKE))
        # msg3 va dirigido a la app, que es quien nos respondió.
        self.assertEqual(p.recipient_id, self.peer_app)
        self.assertTrue(sesion.complete)

    def test_verifica_la_clave_estatica_contra_el_peer_id(self):
        """Es la única comprobación criptográfica de identidad disponible.

        Sin ella, cualquier peer podría presentar una clave y hacerse pasar por
        otro: el `peer_id` que da `sha256(clave)[:8]` es lo único que no
        podemos comprobar por nosotros mismos.
        """
        ini, _app, msg2 = self._par()
        otro = bytes.fromhex("00112233445566ff")
        with self.assertRaises(NoiseError) as ctx:
            completar_handshake(ini, self.ident, msg2, otro)
        self.assertIn("peer_id", str(ctx.exception))

    def test_el_peer_id_correcto_pasa(self):
        """El mismo caso, pero con el peer_id que sí corresponde."""
        ini, _app, msg2 = self._par()
        _, sesion = completar_handshake(ini, self.ident, msg2, self.peer_app)
        self.assertTrue(sesion.complete)

    def test_el_peer_id_se_deriva_de_la_clave_estatica_del_msg2(self):
        """Lo que hace la comprobación, medido: el `peer_id` del otro sale de
        su clave Noise, y no de lo que el paquete diga."""
        ini, app, msg2 = self._par()
        _, sesion = completar_handshake(ini, self.ident, msg2, self.peer_app)
        # Lo que la sesión dedujo del msg2 debe ser la clave de la app, y su
        # `peer_id` el mismo que calculamos aparte.
        self.assertEqual(sesion.remote_static_public, app.static_public)
        self.assertEqual(peer_id_from_noise_key(sesion.remote_static_public),
                         self.peer_app)

    def test_ambos_lados_coinciden_en_el_handshake_hash(self):
        """Si los hashes difieren, las claves derivadas no son las mismas y el
        transporte fallaría más tarde, con un error que no señala el origen."""
        ini, app, msg2 = self._par()
        msg3 = app.write_handshake(b"")
        ini.read_handshake(msg2)
        ini.read_handshake(msg3)
        self.assertEqual(ini.handshake_hash, app.handshake_hash)

    def test_un_msg2_corrupto_se_rechaza(self):
        """Bytes alterados: la etiqueta Poly1305 tiene que detectarlo."""
        ini, _app, msg2 = self._par()
        roto = bytearray(msg2)
        roto[-1] ^= 0xFF
        with self.assertRaises(NoiseError):
            completar_handshake(ini, self.ident, bytes(roto), self.peer_app)

    def test_msg3_tambien_lleva_recipient(self):
        """La respuesta va dirigida, igual que el msg1. Si no, la app la
        descarta igual que el primero (`MessageHandler.kt:375`)."""
        ini, _app, msg2 = self._par()
        paquete, _ = completar_handshake(ini, self.ident, msg2, self.peer_app)
        p = Packet.from_bytes(paquete)
        self.assertEqual(p.recipient_id, self.peer_app)
        self.assertTrue(p.header.flags & PacketFlags.HAS_RECIPIENT)


class TestParserDeHex(unittest.TestCase):
    """Un error ilegible cuesta más que el fallo que causa.

    El caso real: un `~` de más al pegar una clave de 32 bytes daba

        invalid <lambda> value: '9735...6b~'

    que no dice cuántos bytes se esperaban ni dónde está el problema. Y el fallo
    real casi siempre es de copiar y pegar, así que el mensaje tiene que ayudar
    a corregirlo.
    """

    @classmethod
    def setUpClass(cls):
        import importlib.util

        ruta = ROOT / "tools" / "smoke_ble.py"
        # Nombre de módulo **distinto** del de `TestSmokeBle`. Cargar dos veces
        # el mismo fichero bajo nombres distintos no da dos módulos
        # independientes: el segundo import reutiliza el primero, y se acaba
        # probando la versión vieja con el error
        # "_hex() takes 2 positional arguments".
        spec = importlib.util.spec_from_file_location("smoke_ble_parsers", ruta)
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        # `staticmethod` obligatorio: una función normal asignada en un `TestCase` se
        # convierte en método enlazado y se come el primer argumento. El síntoma
        # es el mismo de ayer, en otro sitio: `_hex() takes 2 positional
        # arguments but 3 were given` habiendo pasado dos.
        cls.hex = staticmethod(mod._hex)

    def test_convierte_hex_valido(self):
        self.assertEqual(self.hex("34e01ccea10a8c6d", 8), PEER_APP)

    def test_acepta_el_prefijo_0x(self):
        """Copiando de un visor que lo pone, aparece. No debería fallar."""
        self.assertEqual(self.hex("0x" + NOISE_APP.hex(), 32), NOISE_APP)

    def test_acepta_mayusculas(self):
        self.assertEqual(self.hex(NOISE_APP.hex().upper(), 32), NOISE_APP)

    def test_el_guion_bajo_falla_diciendo_que_caracter_es(self):
        import argparse

        malo = NOISE_APP.hex() + "~"
        with self.assertRaises(argparse.ArgumentTypeError) as ctx:
            self.hex(malo, 32)
        mensaje = str(ctx.exception)
        self.assertIn("~", mensaje)
        self.assertIn("64", mensaje)  # 32 bytes en hex

    def test_la_longitud_equivocada_dice_cuantos_faltan(self):
        """El error que se repite: cortar o pegar de más.

        Una clave de 20 bytes pasada donde se esperan 8.
        """
        import argparse

        corto = NOISE_APP.hex()[:40]  # 20 bytes
        with self.assertRaises(argparse.ArgumentTypeError) as ctx:
            self.hex(corto, 8)
        mensaje = str(ctx.exception)
        self.assertIn("8", mensaje)   # los esperados
        self.assertIn("20", mensaje)  # los que llegaron

    def test_una_longitud_impar_se_distingue_de_una_corta(self):
        """`34e01ccea` son 5 bytes: falta un dígito, no sobran bytes.

        Son dos errores distintos y el mensaje debe distinguirlos, porque
        pegar de menos es mucho más frecuente que pegar de más.
        """
        import argparse

        with self.assertRaises(argparse.ArgumentTypeError) as ctx:
            self.hex("34e01ccea", 8)
        self.assertIn("impar", str(ctx.exception))

    def test_no_admite_espacios_en_medio(self):
        """Un hex con espacios a mitad **no** debe aceptarse en silencio.

        `bytes.fromhex` los tolera, así que sin comprobarlo, un pegado con
        separadores de bloque pasaría y luego el handshake fallaría mucho más
        tarde, con un error que no señala el origen.
        """
        import argparse

        con = NOISE_APP.hex()[:16] + " " + NOISE_APP.hex()[16:]
        with self.assertRaises(argparse.ArgumentTypeError) as ctx:
            self.hex(con, 32)
        self.assertIn("' '", str(ctx.exception))


class TestSmokeBle(unittest.TestCase):
    """`_preparar` decide qué se envía. Un fallo aquí es silencioso.

    Si el handshake se manda sin `recipient_id`, o con el `peer_id` equivocado,
    la app lo descarta sin decir nada (`MessageHandler.kt:375`). El síntoma es
    "no contesta", que no señala la causa. Estos tests comprueban que el camino
    de handshake construye el paquete con el destinatario.
    """

    @classmethod
    def setUpClass(cls):
        import importlib.util

        ruta = ROOT / "tools" / "smoke_ble.py"
        spec = importlib.util.spec_from_file_location("smoke_hs", ruta)
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        cls.smoke = mod
        cls.ident = Identity.generate("pybitchat-probe")

    def _args(self, **kw):
        import argparse

        base = dict(
            nickname="pybitchat-probe",
            identity=None,
            paquete=None,
            segundos=1.0,
            scan=1.0,
            timeout=5.0,
            guardar=ROOT / "capturas" / "recibido.bin",
            handshake=False,
            peer_id=None,
            noise_public=None,
            ttl_handshake=TTL_HANDSHAKE,
        )
        base.update(kw)
        return argparse.Namespace(**base)

    def test_sin_handshake_envia_el_announce(self):
        """El modo por defecto no cambia: sigue siendo el announce."""
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            paquete, _ = self.smoke._preparar(
                self._args(), self.ident, "AA:BB:CC:DD:EE:FF"
            )
        self.assertEqual(Packet.from_bytes(paquete).header.raw_type,
                         int(MessageType.ANNOUNCE))

    def test_con_handshake_envia_msg1_al_destinatario(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            paquete, _ = self.smoke._preparar(
                self._args(handshake=True, peer_id=PEER_APP), self.ident, "X"
            )
        p = Packet.from_bytes(paquete)
        self.assertEqual(p.header.raw_type, int(MessageType.NOISE_HANDSHAKE))
        self.assertEqual(p.recipient_id, PEER_APP)
        self.assertEqual(len(p.payload), MSG1_SIZE)

    def test_sin_peer_id_avisa_que_el_destinatario_puede_fallar(self):
        """Sin `--peer-id` se usa el nuestro, que la app no tiene. El mensaje
        tiene que decirlo: en otro caso el silencio de la app no se explica."""
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            self.smoke._preparar(
                self._args(handshake=True), self.ident, "X"
            )
        salida = buf.getvalue()
        self.assertIn("AVISO", salida)
        self.assertIn("MessageHandler.kt:375", salida)

    def test_con_handshake_devuelve_la_sesion(self):
        """Sin sesión no hay quien procese el `msg2`.

        El fallo real: `_preparar` creaba la sesión y devolvía `None`, y
        `completar_handshake` reventaba con

            AttributeError: 'NoneType' object has no attribute 'read_handshake'

        que no señala que el problema está dos funciones más arriba, en el
        retorno. El mensaje señalaba el síntoma, no la causa.
        """
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            _paquete, sesion = self.smoke._preparar(
                self._args(handshake=True, peer_id=PEER_APP), self.ident, "X"
            )
        self.assertIsNotNone(sesion)
        # Y tiene que ser utilizable: es la que va a leer el msg2.
        self.assertTrue(hasattr(sesion, "read_handshake"))
        self.assertFalse(sesion.complete)

    def test_sin_handshake_no_hay_sesion(self):
        """El announce no usa Noise, así que no hay sesión que devolver."""
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            _paquete, sesion = self.smoke._preparar(self._args(), self.ident, "X")
        self.assertIsNone(sesion)

    def test_el_ttl_del_handshake_es_configurable(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            paquete, _ = self.smoke._preparar(
                self._args(handshake=True, peer_id=PEER_APP, ttl_handshake=1),
                self.ident, "X",
            )
        self.assertEqual(Packet.from_bytes(paquete).header.ttl, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)