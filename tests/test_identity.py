"""Tests de identidad y del anuncio TLV.

El caso de referencia no es un vector inventado: es el **ANNOUNCE real que la
app Android envió** durante la prueba de enlace del 2026-10-02, extraído del
hexdump del characteristic de GATT. Eso convierte "lo implementé según el
código" en "descodifica lo que la app manda de verdad".

Ejecutar:
    .venv\\Scripts\\python.exe tests\\test_identity.py
"""

from __future__ import annotations

import pathlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol.identity import (  # noqa: E402
    KEY_LEN,
    PEER_ID_LEN,
    SIGNATURE_LEN,
    Capability,
    Identity,
    IdentityAnnouncement,
    TlvType,
    UnknownTlv,
    decode_capabilities,
    encode_capabilities,
    peer_id_from_noise_key,
)
from pybitchat.protocol.packet import ProtocolError  # noqa: E402

# --------------------------------------------------------------------------
# Vector real: el ANNOUNCE de la app Android
# --------------------------------------------------------------------------
#
# Capturado del characteristic de GATT el 2026-10-02, con la app Android
# conectada al portatil. **Dos de los tres campos son reales; el tercero está
# reconstruido y se dice cuál.**
#
# El volcado hex se cortó a 96 B, y el TLV 0x03 empieza en el offset 46 del
# payload, así que de sus 32 bytes sólo se capturaron 26. No se inventan bytes:
# la clave de firma de abajo es un valor de relleno, y el test lo comprueba
# contra un segundo announce idéntico.

#: Nickname real de la app: "anewells74"
NICKNAME_REAL = "anewells74"

#: Clave pública Noise real, 32 bytes, completa.
CLAVE_NOISE_REAL = bytes.fromhex(
    "973585b6502836ff5767934bdb4c62458c48b87e94c02d470797e93d21052f6b"
)

#: Valor de RELLENO, NO real. Los 26 bytes que sí se leyeron del volcado, más 6
#: inventados para poder construir un announce de 80 B completo. Longitud
#: comprobada: 26 + 6 = 32.
CLAVE_FIRMA_SINTETICA = bytes.fromhex("7ada9dab1bec9eb274cf") + bytes.fromhex(
    "aa0e3489b259d3219f069fe84cb694aa"
) + b"\x00" * 6

#: Los 74 bytes que sí se capturaron, con el último TLV cortado.
ANNOUNCE_COMPLETO_TRUNCADO = (
    bytes((0x01, len(NICKNAME_REAL)))
    + NICKNAME_REAL.encode()
    + bytes((0x02, 32))
    + CLAVE_NOISE_REAL
    + bytes((0x03, 32))
    + CLAVE_FIRMA_SINTETICA[:26]
)

#: Anuncio completo de 80 B: campos reales salvo la clave de firma.
ANNOUNCE_COMPLETO = (
    bytes((0x01, len(NICKNAME_REAL)))
    + NICKNAME_REAL.encode()
    + bytes((0x02, 32))
    + CLAVE_NOISE_REAL
    + bytes((0x03, 32))
    + CLAVE_FIRMA_SINTETICA
)


class TestAnuncioReal(unittest.TestCase):
    """Tráfico real de la app, no un vector inventado."""

    def test_el_payload_real_mide_80_bytes(self):
        """`payload_len = 0x0050` en el paquete capturado."""
        self.assertEqual(len(ANNOUNCE_COMPLETO), 80)
        self.assertEqual(len(ANNOUNCE_COMPLETO), 0x0050)

    def test_decodifica_el_nickname_real(self):
        a = IdentityAnnouncement.parse(ANNOUNCE_COMPLETO)
        self.assertEqual(a.nickname, NICKNAME_REAL)
        self.assertEqual(a.nickname, "anewells74")

    def test_decodifica_la_clave_noise_real(self):
        a = IdentityAnnouncement.parse(ANNOUNCE_COMPLETO)
        self.assertEqual(a.noise_public_key, CLAVE_NOISE_REAL)
        self.assertEqual(len(a.noise_public_key), KEY_LEN)

    def test_la_clave_noise_real_es_inventada_por_nosotros(self):
        """Guarda contra Exchange la identidad de la app en tests futuros.

        X25519 es eficiente: cualquier clave privada genera su pública. Si esto
        se cumple, el vector no es real y hay que buscar otro.
        """
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        for privada in (bytes(32), b"\x01" * 32, bytes(range(32))):
            with self.subTest(privada=privada.hex()[:16]):
                derivada = (
                    X25519PrivateKey.from_private_bytes(privada)
                    .public_key()
                    .public_bytes_raw()
                )
                self.assertNotEqual(derivada, CLAVE_NOISE_REAL)

    def test_round_trip_byte_exacto(self):
        """Re-codificar da los mismos bytes: importa para reenviar."""
        a = IdentityAnnouncement.parse(ANNOUNCE_COMPLETO)
        self.assertEqual(a.to_bytes(), ANNOUNCE_COMPLETO)

    def test_sin_capacidades(self):
        """Este announce real no traía TLV 0x05. No es obligatorio."""
        a = IdentityAnnouncement.parse(ANNOUNCE_COMPLETO)
        self.assertIsNone(a.capabilities)

    def test_la_longitud_del_tlv_es_de_un_byte(self):
        """Lo distingue del TLV de BitchatFilePacket, que usa u16."""
        crudo = ANNOUNCE_COMPLETO
        self.assertEqual(crudo[1], 10, "longitud del nickname en 1 byte")
        self.assertEqual(crudo[12], 0x02, "el byte 12 es el tag siguiente")
        self.assertEqual(crudo[13], 32, "longitud de la clave en 1 byte")


class TestAnuncioTruncadoReal(unittest.TestCase):
    """Lo que realmente nos dio el volcado: el último TLV cortado."""

    def test_lo_que_capturamos_si_eran_74_bytes(self):
        self.assertEqual(len(ANNOUNCE_COMPLETO_TRUNCADO), 74)

    def test_el_truncado_se_rechaza(self):
        """Longitud que no cabe -> se rechaza el anuncio entero.

        Es el comportamiento de `IdentityAnnouncement.kt:108`. Un decodificador
        que rellenara con ceros aceptaría una identidad falsa.
        """
        with self.assertRaises(ProtocolError) as ctx:
            IdentityAnnouncement.parse(ANNOUNCE_COMPLETO_TRUNCADO)
        self.assertIn("sólo quedan", str(ctx.exception))

    def test_nickname_y_clave_noise_si_son_legibles_del_truncado(self):
        """Los TLV anteriores al corte se pueden leer a mano."""
        i = 0
        vistos = {}
        while i + 2 <= len(ANNOUNCE_COMPLETO_TRUNCADO):
            t = ANNOUNCE_COMPLETO_TRUNCADO[i]
            L = ANNOUNCE_COMPLETO_TRUNCADO[i + 1]
            if i + 2 + L > len(ANNOUNCE_COMPLETO_TRUNCADO):
                break
            vistos[t] = ANNOUNCE_COMPLETO_TRUNCADO[i + 2 : i + 2 + L]
            i += 2 + L
        self.assertEqual(vistos[0x01].decode(), NICKNAME_REAL)
        self.assertEqual(vistos[0x02], CLAVE_NOISE_REAL)
        self.assertNotIn(0x03, vistos, "el TLV cortado no llega a leerse")


class TestAnuncioInvalido(unittest.TestCase):
    """Las tres claves y el nickname son obligatorios."""

    def _sin(self, tipo: int) -> bytes:
        """Reconstruye el anuncio real quitando un TLV."""
        salida = bytearray()
        off = 0
        while off + 2 <= len(ANNOUNCE_COMPLETO):
            t = ANNOUNCE_COMPLETO[off]
            largo = ANNOUNCE_COMPLETO[off + 1]
            valor = ANNOUNCE_COMPLETO[off + 2 : off + 2 + largo]
            off += 2 + largo
            if t != tipo:
                salida += bytes((t, largo)) + valor
        return bytes(salida)

    def test_sin_nickname_falla(self):
        with self.assertRaises(ProtocolError) as ctx:
            IdentityAnnouncement.parse(self._sin(TlvType.NICKNAME))
        self.assertIn("nickname", str(ctx.exception))

    def test_sin_clave_noise_falla(self):
        with self.assertRaises(ProtocolError) as ctx:
            IdentityAnnouncement.parse(self._sin(TlvType.NOISE_PUBLIC_KEY))
        self.assertIn("noise", str(ctx.exception))

    def test_sin_clave_de_firma_falla(self):
        with self.assertRaises(ProtocolError) as ctx:
            IdentityAnnouncement.parse(self._sin(TlvType.SIGNING_PUBLIC_KEY))
        self.assertIn("signing", str(ctx.exception))

    def test_nickname_vacio_falla(self):
        crudo = bytes((TlvType.NICKNAME, 0))
        resto = self._sin(TlvType.NICKNAME)
        with self.assertRaises(ProtocolError):
            IdentityAnnouncement.parse(crudo + resto)

    def test_longitud_que_se_pasa_rechaza_el_anuncio_entero(self):
        """No se recorta: es el comportamiento de `:108`."""
        roto = bytes((0x01, 0xFF)) + b"corta"
        with self.assertRaises(ProtocolError):
            IdentityAnnouncement.parse(roto)

    def test_byte_suelto_final_se_ignora(self):
        """El bucle `while offset + 2 <= size` de la app no lo ve.

        Se replica por fidelidad, aunque sea una holgura del otro extremo: un
        byte suelto no es un TLV y descartarlo es lo que hace la referencia.
        """
        a = IdentityAnnouncement.parse(ANNOUNCE_COMPLETO + b"\x99")
        self.assertEqual(a.nickname, NICKNAME_REAL)


class TestTlvDesconocidos(unittest.TestCase):
    def test_se_conservan_y_se_reenvian(self):
        """Un cliente más nuevo puede añadir TLVs; no deben borrarse."""
        extra = UnknownTlv(0x7F, b"\xde\xad")
        a = IdentityAnnouncement.parse(ANNOUNCE_COMPLETO + extra.to_bytes())
        self.assertEqual(len(a.unknown_tlvs), 1)
        self.assertEqual(a.unknown_tlvs[0].type, 0x7F)
        self.assertEqual(a.unknown_tlvs[0].value, b"\xde\xad")
        # Y al re-codificar vuelven a aparecer.
        self.assertEqual(a.to_bytes(), ANNOUNCE_COMPLETO + extra.to_bytes())

    def test_gossip_no_es_desconocido_para_el_analizador(self):
        """El TLV 0x04 existe en la app, así que no debe ir a desconocidos."""
        a = IdentityAnnouncement.parse(ANNOUNCE_COMPLETO)
        a.unknown_tlvs.append(UnknownTlv(TlvType.GOSSIP, b"\x01"))
        vuelta = IdentityAnnouncement.parse(a.to_bytes())
        self.assertEqual([t.type for t in vuelta.unknown_tlvs], [TlvType.GOSSIP])


class TestCapacidades(unittest.TestCase):
    def test_private_media_es_el_bit_8(self):
        """`LOCAL_SUPPORTED` en la app es exactamente PRIVATE_MEDIA."""
        self.assertEqual(Capability.LOCAL_SUPPORTED, Capability.PRIVATE_MEDIA)
        self.assertEqual(Capability.LOCAL_SUPPORTED, 1 << 8)

    def test_little_endian(self):
        self.assertEqual(encode_capabilities(1 << 8), b"\x00\x01")
        self.assertEqual(encode_capabilities(1), b"\x01")
        self.assertEqual(encode_capabilities(0), b"\x00", "mínimo un byte")

    def test_round_trip(self):
        for v in (0, 1, 1 << 8, (1 << 8) | (1 << 10), (1 << 63)):
            with self.subTest(valor=v):
                self.assertEqual(decode_capabilities(encode_capabilities(v)), v)

    def test_se_leen_solo_los_64_bits_bajos(self):
        """Los bytes de más se ignoran, como en iOS."""
        crudo = b"\xff" * 12
        self.assertEqual(decode_capabilities(crudo), (1 << 64) - 1)

    def test_capacidades_vacias_no_es_lo_mismo_que_ausentes(self):
        """Un TLV de longitud 0 y ningún TLV son cosas distintas."""
        con_ninguna = IdentityAnnouncement(
            NICKNAME_REAL, CLAVE_NOISE_REAL, CLAVE_FIRMA_SINTETICA, capabilities=0
        )
        self.assertEqual(
            con_ninguna.to_bytes(), ANNOUNCE_COMPLETO + bytes((TlvType.CAPABILITIES, 1, 0))
        )


class TestGenerarAnnounce(unittest.TestCase):
    """Lo que emitimos nosotros."""

    def test_genera_identidad_valida(self):
        ident = Identity.generate("pybitchat-probe")
        anuncio = ident.announcement()
        vuelta = IdentityAnnouncement.parse(anuncio.to_bytes())
        self.assertEqual(vuelta.nickname, "pybitchat-probe")
        self.assertEqual(vuelta.noise_public_key, ident.noise_public)
        self.assertEqual(vuelta.signing_public_key, ident.signing_public)
        self.assertEqual(vuelta.capabilities, Capability.LOCAL_SUPPORTED)

    def test_las_claves_publicas_cambian_cada_vez(self):
        a = Identity.generate("x")
        b = Identity.generate("x")
        self.assertNotEqual(a.noise_public, b.noise_public)
        self.assertNotEqual(a.signing_public, b.signing_public)

    def test_las_claves_privadas_no_se_publican(self):
        """El anuncio lleva las públicas; las privadas se quedan fuera."""
        ident = Identity.generate("secreto")
        anuncio = ident.announcement().to_bytes()
        self.assertNotIn(ident.noise_private, anuncio)
        self.assertNotIn(ident.signing_private, anuncio)

    def test_nickname_muy_largo_se_rechaza(self):
        """El longitud del TLV es de un byte: 255 es el tope."""
        Identity.generate("n" * 255)
        with self.assertRaises(ValueError):
            Identity.generate("n" * 256)

    def test_nickname_multibyte_cuenta_bytes(self):
        ident = Identity.generate("josé")
        vuelta = IdentityAnnouncement.parse(ident.announcement().to_bytes())
        self.assertEqual(vuelta.nickname, "josé")

    def test_restaura_identidad_guardada(self):
        original = Identity.generate("persistente")
        copia = Identity.importar(original.exportar())
        self.assertEqual(copia.nickname, original.nickname)
        self.assertEqual(copia.noise_public, original.noise_public)
        self.assertEqual(copia.signing_public, original.signing_public)

    def test_la_identidad_sobrevive_a_exportar_e_importar(self):
        """Sin esto, al reiniciar el proceso nadie volvería a encontrarnos."""
        ident = Identity.generate("estable")
        otra_vez = Identity.importar(ident.exportar())
        self.assertEqual(ident.sign(b"datos"), otra_vez.sign(b"datos"))


class TestFirma(unittest.TestCase):
    def setUp(self):
        self.ident = Identity.generate("signer")

    def test_firma_y_verifica(self):
        firma = self.ident.sign(b"contenido")
        self.assertEqual(len(firma), SIGNATURE_LEN)
        self.assertTrue(self.ident.verify(b"contenido", firma))

    def test_contenido_distinto_no_verifica(self):
        firma = self.ident.sign(b"contenido")
        self.assertFalse(self.ident.verify(b"otro", firma))

    def test_firma_de_otro_no_verifica(self):
        otro = Identity.generate("otro")
        self.assertFalse(self.ident.verify(b"x", otro.sign(b"x")))

    def test_firma_corrupta_no_verifica(self):
        firma = bytearray(self.ident.sign(b"x"))
        firma[0] ^= 0xFF
        self.assertFalse(self.ident.verify(b"x", bytes(firma)))

    def test_firma_de_longitud_equivocada_no_verifica(self):
        self.assertFalse(self.ident.verify(b"x", b"\x00" * 10))


class TestFidelidadDelAnuncio(unittest.TestCase):
    """El orden de los TLVs y la forma del announce propio."""

    def test_el_anuncio_propio_empieza_por_el_nickname(self):
        ident = Identity.generate("orden")
        crudo = ident.announcement().to_bytes()
        self.assertEqual(crudo[0], TlvType.NICKNAME)

    def test_capabilities_va_tras_las_claves(self):
        ident = Identity.generate("orden")  # nickname de 5 bytes
        crudo = ident.announcement().to_bytes()
        # (1+1+5) nickname + (1+1+32) noise + (1+1+32) firma = 75
        self.assertEqual(crudo[75], TlvType.CAPABILITIES)

    def test_tamano_del_anuncio_propio(self):
        ident = Identity.generate("ab")  # nickname de 2 bytes
        # 4 + 34 + 34 + (1+1+2) = 76
        self.assertEqual(len(ident.announcement().to_bytes()), 76)


class TestDerivacionDelPeerId(unittest.TestCase):
    """El `sender_id` se deriva de la clave Noise; no se elige."""

    #: sender_id que la app Android puso en su announce real.
    SENDER_ID_REAL = bytes.fromhex("34e01ccea10a8c6d")

    def test_deriva_de_la_clave_noise(self):
        """Verificado contra tráfico real, no contra el código."""
        self.assertEqual(
            peer_id_from_noise_key(CLAVE_NOISE_REAL), self.SENDER_ID_REAL
        )

    def test_es_sha256_primeros_8(self):
        import hashlib

        esperado = hashlib.sha256(CLAVE_NOISE_REAL).digest()[:8]
        self.assertEqual(peer_id_from_noise_key(CLAVE_NOISE_REAL), esperado)

    def test_mide_8_bytes(self):
        self.assertEqual(len(peer_id_from_noise_key(CLAVE_NOISE_REAL)), PEER_ID_LEN)
        self.assertEqual(PEER_ID_LEN, 8)

    def test_es_determinista(self):
        """La misma clave da siempre el mismo id: es una función, no un azar."""
        a = peer_id_from_noise_key(CLAVE_NOISE_REAL)
        b = peer_id_from_noise_key(CLAVE_NOISE_REAL)
        self.assertEqual(a, b)

    def test_claves_distintas_dan_ids_distintos(self):
        otra = Identity.generate("otro").noise_public
        self.assertNotEqual(
            peer_id_from_noise_key(CLAVE_NOISE_REAL), peer_id_from_noise_key(otra)
        )

    def test_no_depende_del_nickname(self):
        """El nickname no participa: cambiarlo no cambia el id."""
        a = Identity.generate("uno", noise_private=b"\x01" * 32)
        b = Identity.generate("dos", noise_private=b"\x01" * 32)
        self.assertEqual(a.peer_id, b.peer_id)

    def test_clave_de_longitud_equivocada_se_rechaza(self):
        for mala in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.subTest(longitud=len(mala)):
                with self.assertRaises(ValueError):
                    peer_id_from_noise_key(mala)


class TestAnnounceCompleto(unittest.TestCase):
    """El paquete que emitimos de verdad."""

    def setUp(self):
        import tempfile

        self.ident = Identity.generate("pybitchat-probe")

    def test_el_sender_id_corresponde_a_la_clave_anunciada(self):
        """La coherencia que permite a un par detectar una suplantación."""
        from pybitchat.protocol.packet import Packet

        p = Packet.from_bytes(self.ident.announce_packet())
        anuncio = IdentityAnnouncement.parse(p.payload)
        self.assertEqual(p.sender_id, peer_id_from_noise_key(anuncio.noise_public_key))

    def test_es_un_announce_del_dialecto_actual(self):
        from pybitchat.protocol.packet import Packet

        p = Packet.from_bytes(self.ident.announce_packet())
        self.assertEqual(p.header.raw_type, 0x01)
        anuncio = IdentityAnnouncement.parse(p.payload)
        self.assertEqual(anuncio.nickname, "pybitchat-probe")
        self.assertEqual(anuncio.capabilities, Capability.LOCAL_SUPPORTED)

    def test_mede_111_bytes(self):
        """2+15 + 2+32 + 2+32 + 2+2 = 111."""
        self.assertEqual(len(self.ident.announce_packet()), 111)

    def test_timestamp_actual(self):
        import time

        from pybitchat.protocol.packet import Packet

        p = Packet.from_bytes(self.ident.announce_packet())
        self.assertLess(abs(time.time() * 1000 - p.header.timestamp) / 1000, 60)


class TestPersistencia(unittest.TestCase):
    """La identidad debe sobrevivir al reinicio, o somos un par distinto."""

    def setUp(self):
        import tempfile

        self.dir = tempfile.TemporaryDirectory()
        self.ruta = pathlib.Path(self.dir.name) / "identity.json"

    def tearDown(self):
        self.dir.cleanup()

    def test_se_guarda_y_se_recupera(self):
        a = Identity.cargar_o_crear("persistente", ruta=self.ruta)
        b = Identity.cargar_o_crear("otro", ruta=self.ruta)
        self.assertEqual(a.peer_id, b.peer_id, "el peer_id debe ser el mismo")
        self.assertEqual(b.nickname, "persistente", "el nombre no se cambia solo")

    def test_el_nickname_se_ignora_si_ya_hay_identidad(self):
        Identity.cargar_o_crear("primero", ruta=self.ruta)
        b = Identity.cargar_o_crear("segundo", ruta=self.ruta)
        self.assertEqual(b.nickname, "primero")

    def test_fichero_corrupto_no_impide_arrancar(self):
        self.ruta.write_text("{ no es json", encoding="utf-8")
        ident = Identity.cargar_o_crear("recuperado", ruta=self.ruta)
        self.assertEqual(ident.nickname, "recuperado")
        self.assertEqual(len(ident.peer_id), PEER_ID_LEN)

    def test_no_se_guarda_en_el_repo(self):
        """El fichero de identidad no debe acabar en un commit."""
        self.assertFalse(str(Identity.RUTA_POR_DEFECTO).startswith(str(ROOT)))
        self.assertIn("pybitchat", str(Identity.RUTA_POR_DEFECTO))


if __name__ == "__main__":
    unittest.main(verbosity=2)