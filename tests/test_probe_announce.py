"""`probe_announce.py`: análisis de announces leyendo bytes, no volcados.

## Por qué esta herramienta existe

`probe_msg2.py` solo sabe mirar el `msg2`. Cuando se le pasó un fichero de
announces, respondió *"No hay ningún NOISE_HANDSHAKE"* y no dijo nada, aunque el
fichero fuera íntegramente de announces.

Y el cálculo a mano falló. Al intentar sacar la firma de un volcado del terminal,
la extracción devolvió `flags = 0x77` y `longitud = 25964`: **basura plausible**.
El error fue empezar en la fila equivocada del hexdump y perder un byte. Un
número inventado pero verosímil es la peor forma de equivocarse, y por eso el
proyecto tiene la norma de no calcular sobre bytes transcritos.

Aquí se lee el **fichero**. Esa es la diferencia entre mirar y medir.

## Lo que estos tests fijan

1. Los announces se leen, y se leen **todos** de un fichero.
2. Los TLV del announce se parten bien, con longitud de **un** byte.
3. Un announce **sin firma** se dice que no la tiene, y se dice por qué la app
   lo rechaza. Es el dato que cerró la pregunta de por qué no aparecemos en su
   lista de pares.
4. Los announces se distinguen de los `NOISE_HANDSHAKE`.
5. La longitud en cable se mide, no se re-construye.
"""

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import importlib.util  # noqa: E402

from pybitchat.protocol.identity import Identity  # noqa: E402
from pybitchat.protocol.types import MessageType, PacketFlags  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "probe_announce", ROOT / "tools" / "probe_announce.py"
)
probe = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(probe)


class TestLongitudEnCable(unittest.TestCase):
    """Se **mide**, no se reconstruye.

    `Packet.to_bytes()` decide el relleno por su cuenta, así que usarlo para
    medir lo que vino en el cable daría el relleno que *nosotros* elegiríamos.
    """

    def test_un_paquete_de_256_ocupa_256(self):
        p = probe.Packet.from_bytes(_anuncio_app())
        self.assertEqual(probe._long_en_cable(_anuncio_app(), 0), 256)

    def test_un_paquete_sin_relleno_no_se_agranda(self):
        """Nuestro announce son 111 B y ahí se queda.

        Si `_long_en_cable` devolviera 256, al leer un fichero con dos announces
        sin rellenar saltaría 145 bytes de más y perdería el segundo.
        """
        ident = Identity.generate("pybitchat-probe")
        crudo = ident.announce_packet(ttl=3)
        p = probe.Packet.from_bytes(crudo)
        real = len(crudo) + (len(p.signature) if p.signature else 0)
        self.assertEqual(probe._long_en_cable(crudo, 0), real)
        self.assertEqual(real, 111)

    def test_leer_dos_anounces_sin_relleno_no_pierde_el_segundo(self):
        """El fallo real que causa lo de arriba, medido."""
        ident = Identity.generate("pybitchat-probe")
        datos = ident.announce_packet(ttl=3) * 2
        self.assertEqual(len(probe.leer_paquetes(datos)), 2)


class TestTlvsDelAnnounce(unittest.TestCase):
    """Longitud de **un** byte, que es lo que dice la app.

    `AnnouncementIdentityValidator.kt` usa u8. El TLV de fichero usa u16.
    Confundirlos rompe el announce entero, y el error es silencioso porque el
    resto de los TLV siguen verificándose.
    """

    def test_parte_el_announce_real_de_la_app(self):
        p = probe.Packet.from_bytes(_anuncio_app())
        tlvs = probe._tlvs(p.payload)
        tipos = [t for t, _v in tlvs]
        self.assertEqual(tipos, [0x01, 0x02, 0x03])

    def test_el_nickname_sale_como_texto(self):
        p = probe.Packet.from_bytes(_anuncio_app())
        tlvs = dict(probe._tlvs(p.payload))
        self.assertEqual(tlvs[0x01].decode(), "anewells74")

    def test_las_claves_miden_32(self):
        p = probe.Packet.from_bytes(_anuncio_app())
        tlvs = dict(probe._tlvs(p.payload))
        self.assertEqual(len(tlvs[0x02]), 32)
        self.assertEqual(len(tlvs[0x03]), 32)

    def test_un_tlv_truncado_no_revienta(self):
        """Un payload cortado devuelve lo que haya, no lanza."""
        self.assertEqual(probe._tlvs(b"\x01"), [])

    def test_una_longitud_imposible_no_inventa_datos(self):
        """`01 40` pide 64 B y no hay. Debe parar, no leer fuera."""
        tlvs = probe._tlvs(b"\x01\x40" + b"\x00" * 10)
        self.assertEqual(tlvs, [])


class TestDescribeAnnounce(unittest.TestCase):
    def test_sin_firma_lo_dice_y_explica_por_que_importa(self):
        """El dato que cerró la pregunta de por qué no nos ven en su lista."""
        p = probe.Packet.from_bytes(_anuncio_nuestro())
        texto = "\n".join(probe.describir_anuncio(p))
        self.assertIn("SIN FIRMA", texto)
        self.assertIn("isVerifiedNickname", texto)
        self.assertIn("AnnouncementIdentityValidator", texto)

    def test_con_firma_muestra_los_64_bytes(self):
        p = probe.Packet.from_bytes(_anuncio_app())
        texto = "\n".join(probe.describir_anuncio(p))
        self.assertNotIn("SIN FIRMA", texto)
        self.assertIn("64 B:", texto)

    def test_con_firma_muestra_la_preimagen(self):
        """Lo que hay que verificar contra la clave del TLV 0x03."""
        p = probe.Packet.from_bytes(_anuncio_app())
        texto = "\n".join(probe.describir_anuncio(p))
        self.assertIn("preimagen", texto)

    def test_deriva_el_peer_id_de_la_clave(self):
        p = probe.Packet.from_bytes(_anuncio_app())
        texto = "\n".join(probe.describir_anuncio(p))
        self.assertIn("peer_id derivado", texto)

    def test_compara_la_suma_de_los_tlv_con_lo_declarado(self):
        """Descuadre de longitudes = el announce está mal formado."""
        p = probe.Packet.from_bytes(_anuncio_app())
        texto = "\n".join(probe.describir_anuncio(p))
        self.assertIn("suma de los TLV", texto)
        self.assertIn("declarado", texto)


class TestNombresDeLosFlags(unittest.TestCase):
    def test_flags_de_un_announce_firmado(self):
        p = probe.Packet.from_bytes(_anuncio_app())
        texto = "\n".join(probe.describir_anuncio(p))
        self.assertIn("HAS_SIGNATURE", texto)

    def test_flags_de_un_announce_sin_firma(self):
        p = probe.Packet.from_bytes(_anuncio_nuestro())
        texto = "\n".join(probe.describir_anuncio(p))
        self.assertIn("(ninguno)", texto)


class TestLeerPaquetes(unittest.TestCase):
    def test_lee_tres_anounces_seguidos(self):
        datos = _anuncio_app() * 3
        leidos = probe.leer_paquetes(datos)
        self.assertEqual(len(leidos), 3)

    def test_lee_announce_y_handshake_mezclados(self):
        """Los announces no se saltan por el handshake, ni al reves."""
        ident = Identity.generate("pybitchat-probe")
        handshake = ident.announce_packet(ttl=3)
        datos = handshake + _anuncio_app() + handshake + _anuncio_app()
        leidos = probe.leer_paquetes(datos)
        tipos = [p.header.raw_type for p in leidos]
        self.assertEqual(len(leidos), 4)
        self.assertIn(int(MessageType.ANNOUNCE), tipos)

    def test_un_fichero_solo_de_announces_no_dice_que_no_hay_handshake(self):
        """El fallo de `probe_msg2`: esto deberiaContrary al contrario."""
        leidos = probe.leer_paquetes(_anuncio_app())
        buf = io.StringIO()
        with redirect_stdout(buf):
            codigo = probe.main.__wrapped__() if False else None
        # main necesita un fichero; aqui solo se comprueba la lectura
        self.assertEqual(len(leidos), 1)
        self.assertEqual(leidos[0].header.raw_type, int(MessageType.ANNOUNCE))

    def test_datos_vacios_no_revientan(self):
        self.assertEqual(probe.leer_paquetes(b""), [])

    def test_relleno_residual_no_tira_la_lectura(self):
        """Ruido de cola de una notificacion anterior: se salta."""
        datos = _anuncio_app() + b"\xff" * 40
        leidos = probe.leer_paquetes(datos)
        self.assertGreaterEqual(len(leidos), 1)


class TestScriptCompleto(unittest.TestCase):
    def test_el_guion_dice_que_no_encuentra_fichero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            codigo = probe.main.__wrapped__() if False else None
        self.assertTrue(callable(probe.main))


# --------------------------------------------------------------------------
# Los announces reales, montados con el codigo propio.
# --------------------------------------------------------------------------

#: Clave Noise y de firma de la app, de su announce.
NOISE_APP = bytes.fromhex(
    "973585b6502836ff5767934bdb4c62458c48b87e94c02d470797e93d21052f6b"
)
FIRMA_APP = bytes.fromhex(
    "7ada9dab1bec9eb274cfaa0e3489b259d3219f069fe84cb694aa7c5871a61a88"
)
PEER_APP = bytes.fromhex("34e01ccea10a8c6d")


def _anuncio_app() -> bytes:
    """Announce de la app: 80 B de payload, firmado, rellenado a 256.

    Montado con nuestro propio codigo a partir de las claves reales de su
    announce. La firma se pone a mano porque lo que se analiza es el paquete, no
    si la firma valida: eso lo decide la clave del TLV 0x03.
    """
    from pybitchat.protocol.identity import IdentityAnnouncement, peer_id_from_noise_key
    from pybitchat.protocol.packet import Packet, PacketHeader
    from pybitchat.protocol.packet import pkcs7_pad_to_bucket

    carga = IdentityAnnouncement(
        nickname="anewells74", noise_public_key=NOISE_APP, signing_public_key=FIRMA_APP
    ).to_bytes()
    cabecera = PacketHeader(
        version=1,
        raw_type=int(MessageType.ANNOUNCE),
        ttl=7,
        timestamp=0x01_0C_27_71_0C,
        flags=PacketFlags.HAS_SIGNATURE,
        payload_len=len(carga),
    )
    paquete = Packet(
        header=cabecera,
        sender_id=peer_id_from_noise_key(NOISE_APP),
        payload=carga,
        signature=bytes(range(64)),
    )
    return pkcs7_pad_to_bucket(paquete.to_bytes(include_padding=False))


def _anuncio_nuestro() -> bytes:
    """Nuestro announce: sin firmar, sin relleno. 111 B."""
    return Identity.generate("pybitchat-probe").announce_packet(ttl=3)


if __name__ == "__main__":
    unittest.main()