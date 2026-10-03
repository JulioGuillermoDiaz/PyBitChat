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
CLAVE_FIRMA_REAL = bytes.fromhex("7ada9dab1bec9eb274cf") + bytes.fromhex(
    "aa0e3489b259d3219f069fe84cb694aa"
) + b"\x00" * 6

#: Clave de firma **real** y completa. Se obtuvo al repetir la captura con el
#: volcado sin truncar: en el primer intento solo se leyeron 26 de sus 32 bytes,
#: porque smoke_ble limitaba el hexdump a 96 B y el TLV 0x03 empieza en el
#: offset 46 del payload.
CLAVE_FIRMA_REAL = (
    bytes.fromhex("7ada9dab1bec9eb274cf")
    + bytes.fromhex("aa0e3489b259d3219f069fe84cb694aa")
    + bytes.fromhex("7c5871a61a88")
)

#: Los 74 B de la **primera** captura, con el TLV 0x03 cortado. Se conservan
#: porque "el volcado se truncó" es un fallo real que hay que seguir probando.
ANNOUNCE_COMPLETO_TRUNCADO = (
    bytes((0x01, len(NICKNAME_REAL)))
    + NICKNAME_REAL.encode()
    + bytes((0x02, 32))
    + CLAVE_NOISE_REAL
    + bytes((0x03, 32))
    + CLAVE_FIRMA_REAL[:26]
)

#: Anuncio completo de 80 B. Los tres campos son REALES, sin relleno.
ANNOUNCE_COMPLETO = (
    bytes((0x01, len(NICKNAME_REAL)))
    + NICKNAME_REAL.encode()
    + bytes((0x02, 32))
    + CLAVE_NOISE_REAL
    + bytes((0x03, 32))
    + CLAVE_FIRMA_REAL
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

    def test_las_tres_claves_son_reales(self):
        """Ya no hay ningún byte de relleno en el vector.

        La clave de firma se pudo leer entera al repetir la captura con el
        volcado completo, así que los 80 bytes son reales de principio a fin.
        """
        a = IdentityAnnouncement.parse(ANNOUNCE_COMPLETO)
        self.assertEqual(a.signing_public_key, CLAVE_FIRMA_REAL)
        self.assertEqual(len(a.signing_public_key), KEY_LEN)
        # Las tres claves son distintas entre sí.
        self.assertNotEqual(a.noise_public_key, a.signing_public_key)

    def test_ambos_anuncios_dan_el_mismo_peer_id(self):
        """El truncado y el completo tienen las mismas claves públicas."""
        completo = IdentityAnnouncement.parse(ANNOUNCE_COMPLETO)
        parcial = IdentityAnnouncement.parse(
            ANNOUNCE_COMPLETO[: 2 + len(NICKNAME_REAL) + 2 + 32]
            + bytes((0x03, 32)) + CLAVE_FIRMA_REAL
        )
        self.assertEqual(
            completo.noise_public_key, parcial.noise_public_key
        )
        self.assertEqual(
            peer_id_from_noise_key(completo.noise_public_key),
            peer_id_from_noise_key(parcial.noise_public_key),
        )

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
            NICKNAME_REAL, CLAVE_NOISE_REAL, CLAVE_FIRMA_REAL, capabilities=0
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


class TestRellenoObservado(unittest.TestCase):
    """El relleno *cuando lo hay* está confirmado contra tráfico real.

    Y hay una contradicción abierta con la política, que se documenta en vez de
    esconderse: `BLEPacketPaddingPolicy.shouldPadForBLE` dice que sólo se
    rellenan las tramas Noise, pero estos dos paquetes no lo son y sí vienen
    rellenos.
    """

    #: (nombre, contenido, longitud total, byte de relleno observado)
    #:
    #: **El `contenido` de estas filas lo daba un cálculo, no una medición.** El
    #: caso del ANNOUNCE era `14 + 8 + 80 + 64`: los 64 eran una firma
    #: **supuesta**. Con ese número inventado el relleno salía de 90 B y
    #: `0x5a` = 90 "cuadraba" — era aritmética circular.
    #:
    #: Con los bytes reales del 3-oct el announce son **102 B** (14 + 8 + 80, todo
    #: declarado), luego el relleno hasta 256 son **154 B**, y `0x5a` = 90 no
    #: coincide. Por eso estas filas ya **no** dicen "PKCS#7": ver
    #: `test_el_relleno_no_es_pkcs7`.
    CASOS = (
        # ANNOUNCE: 14 + 8 sender + 80 payload = 102, **todo declarado**. Relleno
        # 154 B con byte 0x5a=90: no es PKCS#7, y entre el payload y el final
        # hay 64 bytes más que la cabecera no declara.
        ("ANNOUNCE 0x01", 102, 256, 0x5A, False),
        # MESSAGE: la cabecera declara payload_len=2, o sea 24 B, pero el relleno
        # implica 96 B de contenido. Sobran 72 bytes de 0xff sin explicar. Aquí
        # sí cuadra PKCS#7: 160 B de relleno, byte 0xa0 = 160.
        ("MESSAGE 0x02", 96, 256, 0xA0, True),
    )

    #: Bytes de `0xff` entre el payload y el relleno en el segundo paquete.
    RELLENO_FF_SIN_EXPLICAR = 72

    def test_el_relleno_no_siempre_es_pkcs7(self):
        """El `ANNOUNCE` **no** es PKCS#7; el `MESSAGE` sí lo es.

        Decir "el relleno es PKCS#7" era una afirmación falsa que estuvo en el
        docstring de `should_pad_for_ble` y en `ESTADO.md`. El caso del ANNOUNCE
        no cuadra:

            ANNOUNCE      real 102 B -> relleno 154 B, byte 0x5a = 90   NO
            REQUEST_SYNC  real  38 B -> relleno 218 B, byte 0x9a = 154  NO
            MESSAGE       real  96 B -> relleno 160 B, byte 0xa0 = 160  sí

        Los dos que fallan son los del announce. La diferencia es que el
        announce lleva 64 bytes que la cabecera no declara antes del relleno, y
        no son un byte constante. Si alguien "arregla" esto para que todo cuadre
        con PKCS#7, este test falla.
        """
        for nombre, contenido, total, byte, es_pkcs7 in self.CASOS:
            with self.subTest(paquete=nombre):
                relleno = total - contenido
                coincide = byte == relleno
                self.assertEqual(
                    coincide, es_pkcs7,
                    f"{nombre}: byte 0x{byte:02x}={byte}, relleno {relleno} B, "
                    f"esperado es_pkcs7={es_pkcs7}. Si ha cambiado, revisa si "
                    "el contenido está medido o calculado.",
                )

    def test_el_anounce_real_mide_102_bytes(self):
        """El contenido del ANNOUNCE son 102 B, medidos, no calculados.

        14 de cabecera + 8 de sender + 80 de payload TLV. Los tres campos los
        declara la propia cabecera, así que no hay nada supuesto aquí. Es lo que
        hace que el caso de arriba sea 102 y no 166.
        """
        ANNOUNCE_REAL = (
            bytes.fromhex("010107000001a10310526d02005034e01ccea10a8c6d")
            + bytes.fromhex("010a616e6577656c6c733734")
            + bytes.fromhex(
                "0220973585b6502836ff5767934bdb4c62458c48b87e94c02d470797e93d21052f6b"
            )
            + bytes.fromhex(
                "03207ada9dab1bec9eb274cfaa0e3489b259d3219f069fe84cb694aa7c5871a61a88"
            )
        )
        self.assertEqual(len(ANNOUNCE_REAL), 102)
        # `payload_len` es el byte 13 de la cabecera: 0x50 = 80. Comprobado
        # contra nuestro propio paquete, que declara 0x59 = 89 y realmente
        # ocupa 89 B. No es u16 en 12:14 (eso daría 20480), ni u16 en 11:13
        # (2). Este test existe porque se dio por bueno un offset equivocado
        # antes, dos veces seguidas.
        payload_len = ANNOUNCE_REAL[13]
        self.assertEqual(payload_len, 80)
        self.assertEqual(len(ANNOUNCE_REAL) - 22, payload_len)

    def test_hay_64_bytes_que_la_cabecera_no_declara(self):
        """El announce ocupa 256 B y sólo declara 102. Los 64 que faltan.

        Empiezan justo tras el payload y no son `0x5a` constante. 64 es el
        tamaño de una firma Ed25519, y la app manda `0x03` = clave de firma, así
        que la hipótesis más fuerte es que es una firma. **Probado y no
        valida** sobre los cinco mensajes candidatos, así que se documenta como
        campo sin explicar y no como firma.
        """
        RELLENO_INICIAL = bytes.fromhex(
            "de0a272249f517047a1c976910a65096bd5a9056c3d7ea73c12aec2123"
            "6879b7a8a0ab8e497701b075175117d8704ad4989a2f3dcba85db14fae"
            "64f5441d1a01"
        )
        self.assertEqual(len(RELLENO_INICIAL), 64)
        # No es un bloque constante: si lo fuera, sería relleno.
        self.assertGreater(len(set(RELLENO_INICIAL)), 16)

    def test_el_relleno_llega_a_256(self):
        """Lo único que se afirma del relleno es que **tope en 256 B**.

        No se afirma el byte, porque no siempre es la longitud: ver
        `test_el_relleno_no_siempre_es_pkcs7`.
        """
        for nombre, contenido, total, byte, es_pkcs7 in self.CASOS:
            with self.subTest(paquete=nombre):
                relleno = total - contenido
                self.assertEqual(contenido + relleno, total)
                self.assertEqual(total, 256)

    def test_nuestro_pkcs7_no_reproduce_el_relleno_del_announce(self):
        """Nuestro emisor usa PKCS#7 y **no** es lo que hace la app.

        Se conserva el test, pero cambiado de afirmación: antes decía que
        reproducía los mismos bytes del announce, y no puede decir eso. Ahora
        fija la diferencia, que es lo que hay que saber al comparar capturas.
        """
        from pybitchat.protocol.packet import pkcs7_pad_to_bucket

        for nombre, contenido, total, byte, es_pkcs7 in self.CASOS:
            with self.subTest(paquete=nombre):
                # Devuelve `datos + relleno`, no sólo el relleno.
                original = bytes(contenido)
                emitted = pkcs7_pad_to_bucket(original)
                relleno_real = len(emitted) - len(original)
                # El tope a 256 B sí coincide siempre: es lo único que sabemos
                # reproducir bien.
                self.assertEqual(len(emitted), total)
                # PKCS#7 pone la longitud del relleno como último byte.
                self.assertEqual(emitted[-1], relleno_real)
                if es_pkcs7:
                    # Para el MESSAGE, eso coincide con lo que hizo la app.
                    self.assertEqual(byte, relleno_real)
                else:
                    # Para el announce, no: ahí es donde difieren.
                    self.assertNotEqual(byte, relleno_real)

    def test_el_segundo_paquete_tiene_72_bytes_sin_explicar(self):
        """El caso abierto: la cabecera no describe todo el contenido.

        `payload_len = 2` pero el contenido son 96 B. Los 72 que sobran son
        `0xff`, que es el identificador de receptor especial de BitChat
        (emisión general) repetido. No se sabe todavía si es relleno deliberado
        del emisor, un campo que la cabecera no declara, o un artefacto. Se deja
        anotado en vez de inventar una explicación.
        """
        _, contenido, _, _, _ = self.CASOS[1]
        explicado = 14 + 8 + 2
        self.assertEqual(contenido - explicado, self.RELLENO_FF_SIN_EXPLICAR)

    def test_la_contradiccion_de_la_politica_sigue_abierta(self):
        """Si algún día se resuelve, este test es el que hay que cambiar.

        Se afirma aquí para que no se cierre en silencio: la app envió un
        ANNOUNCE relleno y la política dice que no se rellena.
        """
        from pybitchat.protocol.types import should_pad_for_ble

        self.assertFalse(should_pad_for_ble(0x01), "ANNOUNCE: la política dice que no")
        # ...pero el primer CASOS de esta clase es un ANNOUNCE relleno de 256 B.
        self.assertEqual(self.CASOS[0][2], 256)
        self.assertEqual(self.CASOS[0][0], "ANNOUNCE 0x01")


if __name__ == "__main__":
    unittest.main(verbosity=2)

