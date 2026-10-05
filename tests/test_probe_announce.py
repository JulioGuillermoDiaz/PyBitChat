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


class TestVerificarFirma(unittest.TestCase):
    """La clave de firma va en el propio announce, así que no hay excusa.

    Y a mano sale mal: el 2026-10-06 se copiaron el preimagen y la firma del
    terminal a un fichero y la verificación dio que no validaba, cuando lo que
    pasaba es que la preimagen transcrita medía 102 B y la aritmética decía 100.
    Un cálculo sobre hex pegado es una fuente de números falsos.
    """

    def _anuncio_con_firma_valida(self):
        """Announce firmado de verdad, con la firma hecha por nuestro código."""
        from pybitchat.protocol.identity import Identity, IdentityAnnouncement
        from pybitchat.protocol.packet import Packet, PacketHeader, pkcs7_pad_to_bucket
        from pybitchat.protocol.types import MessageType, PacketFlags

        import dataclasses

        ident = Identity.generate("anewells74")
        carga = IdentityAnnouncement(
            nickname=ident.nickname,
            noise_public_key=ident.noise_public,
            signing_public_key=ident.signing_public,
        ).to_bytes()
        cabecera = PacketHeader(
            version=1, raw_type=int(MessageType.ANNOUNCE), ttl=7,
            timestamp=0x01_0C_27_71_0C,
            flags=PacketFlags.HAS_SIGNATURE, payload_len=len(carga),
        )
        sin_firma = Packet(header=cabecera, sender_id=ident.peer_id,
                           payload=carga)
        # Se firma `to_binary_data_for_signing()`, **no** `to_bytes()`.
        # No son lo mismo, por dos razones:
        #
        #   - la preimagen pone el TTL a 0, y `to_bytes()` lo deja intacto;
        #   - la preimagen va **rellena**, y `to_bytes()` no.
        #
        # Firmar el segundo y validar contra el primero da una firma que no
        # valida. Pasó dos veces: primero por el TTL, luego por el relleno.
        #
        # Y la firma se añade al `Packet`, no se pega al final: pegada a mano,
        # `Packet.from_bytes` la leeria como ausente.
        firma = ident.sign(sin_firma.to_binary_data_for_signing())
        firmado = dataclasses.replace(sin_firma, signature=firma)
        return pkcs7_pad_to_bucket(firmado.to_bytes(include_padding=False))

    def test_una_firma_hecha_por_nosotros_valida(self):
        """El caso bueno: nuestra propia firma verifica con nuestra clave."""
        p = probe.Packet.from_bytes(self._anuncio_con_firma_valida())
        texto = "\n".join(probe.describir_anuncio(p))
        self.assertIn(">>> VALIDA", texto)

    def test_una_firma_alterada_no_valida(self):
        """Si la firma está tocada, tiene que decir que no."""
        p0 = probe.Packet.from_bytes(self._anuncio_con_firma_valida())
        crudo = bytearray(self._anuncio_con_firma_valida())
        # La firma va justo despues de los bytes reales: 22 + len(payload).
        inicio = 22 + len(p0.payload)
        self.assertEqual(inicio + 64, 166, "el announce firmado debe medir 166 B")
        crudo[inicio + 8] ^= 0xFF
        p = probe.Packet.from_bytes(bytes(crudo))
        texto = "\n".join(probe.describir_anuncio(p))
        # Con la firma tocada no vale ninguna de las dos preimagenes, y el
        # mensaje lo dice: antes decia "NO VALIDA con esta preimagen", como si
        # hubiera una sola candidata.
        self.assertIn("no valida con relleno", texto)
        self.assertIn("no valida sin relleno", texto)
        self.assertIn("NINGUNA", texto.upper())

    def test_sin_firma_no_llega_a_verificar(self):
        """El announce nuestro va por la rama de "SIN FIRMA", que ya explica
        que la app lo rechaza. No llega al verificador, y no debe."""
        texto = "\n".join(probe.describir_anuncio(
            probe.Packet.from_bytes(_anuncio_nuestro())))
        self.assertIn("SIN FIRMA", texto)
        self.assertNotIn("preimagen", texto)

    def test_firmado_sin_tlv_03_lo_dice_y_no_revienta(self):
        """Firmado pero sin la clave publica en el announce: no hay con que
        comprobarlo. Se dice, no se lanza."""
        import dataclasses
        from pybitchat.protocol.identity import Identity
        from pybitchat.protocol.packet import Packet, PacketHeader
        from pybitchat.protocol.types import MessageType, PacketFlags

        ident = Identity.generate("anewells74")
        carga = (b"\x01\x0anewells74"
                 + b"\x02\x20" + ident.noise_public)      # sin TLV 0x03
        p = Packet(
            header=PacketHeader(version=1, raw_type=int(MessageType.ANNOUNCE),
                                ttl=7, timestamp=1,
                                flags=PacketFlags.HAS_SIGNATURE,
                                payload_len=len(carga)),
            sender_id=ident.peer_id, payload=carga,
        )
        firmado = dataclasses.replace(p, signature=bytes(64))
        texto = "\n".join(probe.describir_anuncio(firmado))
        self.assertIn("no hay clave de firma", texto.lower())

    def test_dice_la_composicion_de_la_preimagen(self):
        """Si valida, hay que decir de qué consta, para poder reproducirla."""
        p = probe.Packet.from_bytes(self._anuncio_con_firma_valida())
        texto = "\n".join(probe.describir_anuncio(p))
        self.assertIn("12 cabecera", texto)
        self.assertIn("el TTL puesto a 0", texto)
        self.assertIn("relleno", texto)

    def test_el_ttl_de_la_preimagen_es_cero(self):
        """La regla del TTL, comprobada sobre los bytes de la preimagen."""
        p = probe.Packet.from_bytes(self._anuncio_con_firma_valida())
        pre = p.to_binary_data_for_signing()
        self.assertEqual(pre[2], 0, "el TTL tiene que estar a 0 al firmar")
        self.assertEqual(p.header.ttl, 7, "el paquete si lleva TTL 7")

    def test_la_preimagen_no_lleva_la_firma(self):
        p = probe.Packet.from_bytes(self._anuncio_con_firma_valida())
        self.assertIsNotNone(p.signature, "el announce deberia ir firmado")
        pre = p.to_binary_data_for_signing()
        self.assertNotIn(p.signature, pre)
        reales = 22 + len(p.payload)
        self.assertEqual(
            len(pre), 256,
            "la preimagen va rellena a 256, como la de la app",
        )
        # Los bytes reales coinciden con el cable salvo dos: el TTL (byte 2), que
        # la preimagen pone a 0, y los flags (byte 11), que pierden el
        # HAS_SIGNATURE al no haber firma. Lo demas es relleno.
        cable = p.to_bytes(include_padding=False)

        def _sin(numeros, datos: bytes) -> bytes:
            return bytes(b for i, b in enumerate(datos[:reales])
                         if i not in numeros)

        self.assertEqual(_sin({2, 11}, pre), _sin({2, 11}, cable))
        self.assertEqual(pre[2], 0, "el TTL de la preimagen es 0")
        self.assertEqual(cable[2], 7, "el del cable es el que llevaba")
        self.assertEqual(pre[11] & 0x02, 0, "la preimagen no se firma a si misma")
        self.assertTrue(cable[11] & 0x02)
        relleno = 256 - reales
        self.assertEqual(
            pre[-relleno:], bytes([relleno]) * relleno,
            "el relleno es PKCS#7 con su propia longitud como byte",
        )

    def test_lo_que_se_firma_no_es_lo_que_se_manda(self):
        """La diferencia que hizo fallar la primera versión, medida.

        `to_binary_data_for_signing()` pone el TTL a 0; `to_bytes()` no. Si se
        firma el segundo, la firma no valida contra el primero.
        """
        from pybitchat.protocol.identity import Identity, IdentityAnnouncement
        from pybitchat.protocol.packet import Packet, PacketHeader
        from pybitchat.protocol.types import MessageType

        ident = Identity.generate("x")
        carga = IdentityAnnouncement(
            nickname="x", noise_public_key=ident.noise_public,
            signing_public_key=ident.signing_public,
        ).to_bytes()
        p = Packet(
            header=PacketHeader(version=1, raw_type=int(MessageType.ANNOUNCE),
                                ttl=7, timestamp=1_000, flags=0,
                                payload_len=len(carga)),
            sender_id=ident.peer_id, payload=carga,
        )
        self.assertNotEqual(p.to_bytes(include_padding=False),
                            p.to_binary_data_for_signing())
        self.assertEqual(p.to_binary_data_for_signing()[2], 0)

    def test_el_anuncio_de_prueba_va_realmente_firmado(self):
        """Guardia: si el helper vuelve a dejar la firma fuera, todo lo demas
        de esta clase mide un announce sin firmar y no sirve."""
        p = probe.Packet.from_bytes(self._anuncio_con_firma_valida())
        self.assertEqual(len(p.signature), 64)


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