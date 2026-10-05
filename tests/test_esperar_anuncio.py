"""`_esperar_anuncio_app`: de dónde sale el destinatario del `msg1`.

## Por qué existe esta función

El `msg1` va dirigido a `recipient_id`, y `MessageHandler.handleNoiseHandshake`
lo compara con **su** `myPeerID`:

```kotlin
val recipientID = packet.recipientID?.toHexString()
if (recipientID != myPeerID) { return }
```

Si no cuadra, el paquete desaparece: sin `msg2`, sin excepción, sin traza. El
2026-10-06 el destino por defecto era **nuestro propio `peer_id`**, así que el
handshake se mandaba a uno mismo y la app lo tiraba callada. Costó una
ejecución entera, y el aviso que había en pantalla no lo evitó.

La solución no es acordarse de `--peer-id`. Es que la app **anuncia su propia
identidad**, firmada, y que su `peer_id` es derivable de la clave que anuncia:

    peer_id == sha256(clave Noise del announce)[:8]     (NoisePeerIdentity)

O sea que el dato es **comprobable**, no una afirmación del otro.

## Lo que estos tests fijan

1. Del announce firmado sale un `peer_id`, y coincide con el `sender_id`.
2. Un announce cuyo `sender_id` **no** cuadra con su clave se descarta. Esto es
   lo que separa "aprender la identidad" de "creérsela": con BLE, un `sender_id`
   sin comprobar es un dato que el otro pone sobre sí mismo.
3. Sin announce, devuelve `None` en el plazo, y no se queda esperando.
4. Los TLV que no son announces no los confunde.
"""

import asyncio
import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol.identity import (  # noqa: E402
    Identity,
    IdentityAnnouncement,
    peer_id_from_noise_key,
)
from pybitchat.protocol.packet import MESSAGE_TTL_HOPS  # noqa: E402


def _cargar_smoke():
    spec = importlib.util.spec_from_file_location(
        "smoke_espera", ROOT / "tools" / "smoke_ble.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestAprenderElPeerIdDeLaApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()
        # Una identidad que hace de "la app": la que va a anunciar.
        cls.app = Identity.generate("anewells74")

    def _announce_de_la_app(self):
        """Un announce de verdad, firmado, como el que manda la app."""
        return self.app.announce_packet(ttl=MESSAGE_TTL_HOPS, firmar=True)

    # -- el camino bueno ---------------------------------------------------

    def test_saca_el_peer_id_del_announce(self):
        recibidos = [self._announce_de_la_app()]
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = asyncio.run(
                self.smoke._esperar_anuncio_app(recibidos, 0.05)
            )
        self.assertIsNotNone(out, "el announce de la app debe bastar")
        peer_id, noise_public = out
        self.assertEqual(peer_id, self.app.peer_id)
        self.assertEqual(len(peer_id), 8)

    def test_saca_tambien_la_clave_noise(self):
        """Que salga con el `peer_id` evita depender de `--noise-public`."""
        recibidos = [self._announce_de_la_app()]
        with redirect_stdout(io.StringIO()):
            _peer, noise_public = asyncio.run(
                self.smoke._esperar_anuncio_app(recibidos, 0.05)
            )
        self.assertEqual(noise_public, self.app.noise_public)

    def test_el_peer_id_es_el_derivado_de_la_clave(self):
        """La comprobación de verdad: `derivePeerID`, no el campo del paquete."""
        recibidos = [self._announce_de_la_app()]
        with redirect_stdout(io.StringIO()):
            peer_id, noise_public = asyncio.run(
                self.smoke._esperar_anuncio_app(recibidos, 0.05)
            )
        self.assertEqual(peer_id, peer_id_from_noise_key(noise_public))

    def test_acepta_el_announce_tambien_sin_firma(self):
        """La firma no es lo que se comprueba aquí; el `sender_id` sí.

        Se acepta sin firma a propósito, y por eso el nombre de la función
        engaña un poco. Lo que se verifica es la **coherencia** entre el
        `sender_id` y la clave, que es la mitad de
        `AnnouncementIdentityValidator`. Si además viene firmado, mejor; pero la
        app podría cambiar de versión y no vamos a dejar de poder hacer
        handshake por eso.
        """
        recibidos = [self.app.announce_packet(ttl=MESSAGE_TTL_HOPS, firmar=False)]
        with redirect_stdout(io.StringIO()):
            out = asyncio.run(self.smoke._esperar_anuncio_app(recibidos, 0.05))
        self.assertIsNotNone(out)
        self.assertEqual(out[0], self.app.peer_id)

    # -- lo que no debe entrar --------------------------------------------

    def test_un_sender_id_falso_se_descarta(self):
        """El caso de seguridad. `sender_id` que no cuadra con la clave: fuera.

        Sin esta comprobación, el `peer_id` del handshake saldría de un campo
        que el otro afirma sobre sí mismo. Con BLE, eso no es una identidad, es
        una cadena de texto. Y un `msg1` dirigido a lo que diga el otro es
        exactamente lo que hay que no hacer.
        """
        # Announce legítimo de la app, con el `sender_id` cambiado por uno ajeno.
        # La firma deja de cuadrar, pero eso es lo segundo que hay que mirar: lo
        # primero es que el `sender_id` ya no se deriva de la clave del payload.
        crudo = bytearray(self._announce_de_la_app())
        crudo[14:22] = bytes.fromhex("0011223344556677")
        with redirect_stdout(io.StringIO()):
            out = asyncio.run(self.smoke._esperar_anuncio_app([bytes(crudo)], 0.05))
        self.assertIsNone(out, "un sender_id que no cuadra no puede ser destino")

    def test_un_announce_con_clave_ajena_se_descarta(self):
        """La otra mitad: la clave correcta con otro `sender_id`."""
        ident = Identity.generate("otro")
        carga = IdentityAnnouncement(
            nickname="x",
            noise_public_key=ident.noise_public,
            signing_public_key=ident.signing_public,
        ).to_bytes()
        # Se construye a mano un paquete cuyo payload es de `ident` pero cuyo
        # sender_id no lo deriva. Sin esto el test no distinguiría nada.
        from pybitchat.protocol.packet import Packet, PacketHeader
        from pybitchat.protocol.types import MessageType

        p = Packet(
            header=PacketHeader(
                version=1, raw_type=int(MessageType.ANNOUNCE),
                ttl=MESSAGE_TTL_HOPS, timestamp=1_000, flags=0,
                payload_len=len(carga),
            ),
            sender_id=bytes.fromhex("deadbeefdeadbeef"),
            payload=carga,
        )
        with redirect_stdout(io.StringIO()):
            out = asyncio.run(
                self.smoke._esperar_anuncio_app([p.to_bytes(include_padding=False)], 0.05)
            )
        self.assertIsNone(out)

    def test_un_handshake_no_se_toma_por_un_announce(self):
        """Filtra por tipo, no por «parece un paquete»."""
        from pybitchat.noise.handshake import iniciar_handshake
        from pybitchat.protocol.identity import peer_id_from_noise_key

        nuestro = Identity.generate("pybitchat-probe")
        paquete, _sesion = iniciar_handshake(
            nuestro, peer_id_remoto=bytes.fromhex("34e01ccea10a8c6d")
        )
        with redirect_stdout(io.StringIO()):
            out = asyncio.run(self.smoke._esperar_anuncio_app([paquete], 0.05))
        self.assertIsNone(out, "un NOISE_HANDSHAKE no dice quién es la app")
        del peer_id_from_noise_key

    def test_ruido_antes_del_announce(self):
        """Bytes que no parsean no rompen la espera."""
        recibidos = [b"\x00" * 7, b"basura", b"\xff" * 3]
        recibidos.append(self._announce_de_la_app())
        with redirect_stdout(io.StringIO()):
            out = asyncio.run(self.smoke._esperar_anuncio_app(recibidos, 0.05))
        self.assertIsNotNone(out)

    # -- el plazo ----------------------------------------------------------

    def test_sin_announce_devuelve_none(self):
        """Y no se queda esperando para siempre."""
        with redirect_stdout(io.StringIO()):
            out = asyncio.run(self.smoke._esperar_anuncio_app([], 0.05))
        self.assertIsNone(out)

    def test_espera_a_lo_que_llegue_despues(self):
        """Poll, no un único intento: el announce puede tardar.

        Es lo que pasa de verdad: la app anuncia 200 ms después de conectar
        (`delay(200)` en `onDeviceConnected`), y otra vez al suscribirse las
        notificaciones. Llegar antes es lo normal, no la excepción.
        """
        recibidos = []

        async def escenario():
            tarea = asyncio.create_task(
                self.smoke._esperar_anuncio_app(recibidos, 3.0)
            )
            await asyncio.sleep(0.15)
            recibidos.append(self._announce_de_la_app())
            return await tarea

        with redirect_stdout(io.StringIO()):
            out = asyncio.run(escenario())
        self.assertIsNotNone(out, "tiene que ver el announce aunque llegue tarde")
        self.assertEqual(out[0], self.app.peer_id)


class TestElAprendizajeNoEsUnAccidente(unittest.TestCase):
    """Que la función siga siendo la que decide, no un `--peer-id` olvidado.

    El fallo del 2026-10-06 no fue escribir mal un flag: fue que el valor por
    defecto era silenciosamente incorrecto. Estos tests son sobre la
    *estructura*, que es donde ese tipo de fallo se esconde.
    """

    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()

    def test_el_peer_id_se_asigna_en_args(self):
        """Se guarda en `args.peer_id`, que es lo que ya leen `_preparar` y
        `_enviar_msg3`.

        Es lo que hace que el cambio sea pequeño: en vez de pasar un parámetro
        nuevo por tres funciones, se rellena el que ya existía. Y hace que
        `--peer-id` siga mandando sin ningún caso especial.
        """
        import inspect

        fuente = inspect.getsource(self.smoke._sesion)
        self.assertIn("args.peer_id, args.noise_public = hallado", fuente)

    def test_learn_it_overrides_the_flag(self):
        """`--peer-id` gana sobre lo aprendido, y el orden lo dice."""
        import inspect

        fuente = inspect.getsource(self.smoke._sesion)
        i_condicion = fuente.index("if args.handshake and args.peer_id is None:")
        i_asignacion = fuente.index("args.peer_id, args.noise_public = hallado")
        self.assertLess(
            i_condicion, i_asignacion,
            "el aprendizaje solo puede pasar si no hay --peer-id",
        )

    def test_el_fallo_dice_como_resolverlo(self):
        """Si no se puede aprender, el mensaje dice que se pase a mano."""
        import inspect

        fuente = inspect.getsource(self.smoke._sesion)
        self.assertIn("--peer-id <16 hex>", fuente)


if __name__ == "__main__":
    unittest.main()
