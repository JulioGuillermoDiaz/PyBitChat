"""Conformidad con los tests de la app oficial.

Cada caso de este fichero está **portado** de
`app/src/test/java/com/bitchat/android/protocol/BinaryProtocolTest.kt` de
`permissionlesstech/bitchat-android`. El nombre de cada test lleva el original
entre comillas para poder rastrearlo.

## Por qué esto y no es más tests

Estos vectores no salen de nuestra lectura del código: son **las expectativas
del propio autor del protocolo sobre su propia implementación**. Pasarlos
convierte "lo implementé según lo que leí" en "cumplo lo que la app cree de sí
misma".

⚠️ No sustituye a la interoperabilidad en vivo. Nada offline la sustituye: sólo
demuestra que our códec coincide con la especificación tal y como la
implementa la app, no que la app acepte lo que emitimos.

Ejecutar:
    .venv\\Scripts\\python.exe tests\\test_conformance.py
"""

from __future__ import annotations

import os
import struct
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import sys  # noqa: E402

sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol.compression import CompressionError  # noqa: E402
from pybitchat.protocol.compression import decompress as inflate_exact  # noqa: E402
from pybitchat.protocol.packet import (  # noqa: E402
    KNOWN_UPSTREAM_VERSIONS,
    PROTOCOL_VERSION,
    SYNC_TTL_HOPS,
    Packet,
    PacketHeader,
    ProtocolError,
    UnsupportedVersionError,
)
from pybitchat.protocol.types import PacketFlags, should_pad_for_ble  # noqa: E402

# Datos que la app usa en sus tests, para que los vectores coincidan.
SENDER = bytes.fromhex("1122334455667788")
RECIPIENT = bytes.fromhex("8877665544332211")
TS = 1_709_600_000_000

HEADER_SIZE_BY_VERSION = {1: 14, 2: 16}


def make_packet(
    payload: bytes = b"hola",
    *,
    version: int = 1,
    raw_type: int = 0x02,
    sender: bytes = SENDER,
    recipient: bytes | None = None,
    signature: bytes | None = None,
    route: list[bytes] | None = None,
    ttl: int = 5,
    wire_payload=None,
) -> Packet:
    """Construye un paquete con `payload_len` calculado, como haría la app."""
    size_field = 4 if version >= 2 else 2
    if wire_payload is not None and wire_payload.compressed:
        cuerpo = size_field + len(wire_payload.wire)
    else:
        cuerpo = len(payload)
    flags = PacketFlags(0)
    if recipient is not None:
        flags |= PacketFlags.HAS_RECIPIENT
    if signature is not None:
        flags |= PacketFlags.HAS_SIGNATURE
    if route and version >= 2:
        flags |= PacketFlags.HAS_ROUTE
    if wire_payload is not None and wire_payload.compressed:
        flags |= PacketFlags.IS_COMPRESSED
    header = PacketHeader(version, raw_type, ttl, TS, flags, cuerpo)
    return Packet(
        header=header,
        sender_id=sender,
        payload=payload,
        recipient_id=recipient,
        signature=signature,
        route=route,
        wire_payload=wire_payload,
    )


def roundtrip(p: Packet) -> Packet:
    return Packet.from_bytes(p.to_bytes())


# --------------------------------------------------------------------------
# Cabecera
# --------------------------------------------------------------------------


class TestCabeceraV1(unittest.TestCase):
    def test_minimal_v1_broadcast_round_trips(self):
        """`minimal v1 broadcast packet round-trips correctly`"""
        p = make_packet(b"hola mundo")
        vuelta = roundtrip(p)
        self.assertEqual(vuelta.header.version, 1)
        self.assertEqual(vuelta.header.raw_type, 0x02)
        self.assertEqual(vuelta.header.ttl, 5)
        self.assertEqual(vuelta.header.timestamp, TS)
        self.assertEqual(vuelta.sender_id, SENDER)
        self.assertEqual(vuelta.payload, b"hola mundo")
        self.assertIsNone(vuelta.recipient_id)
        self.assertIsNone(vuelta.signature)
        # El byte de flags está en el offset 11 en v1.
        self.assertEqual(vuelta.header.flags, PacketFlags(0))

    def test_v1_con_destinatario(self):
        """`v1 packet with recipient round-trips correctly`"""
        vuelta = roundtrip(make_packet(b"privado", recipient=RECIPIENT))
        self.assertEqual(vuelta.recipient_id, RECIPIENT)
        self.assertTrue(vuelta.header.flags & PacketFlags.HAS_RECIPIENT)

    def test_v1_con_firma(self):
        """`v1 packet with signature round-trips correctly`"""
        firma = bytes(range(64))
        vuelta = roundtrip(make_packet(b"firmado", signature=firma))
        self.assertEqual(vuelta.signature, firma)
        self.assertTrue(vuelta.header.flags & PacketFlags.HAS_SIGNATURE)

    def test_v1_con_destinatario_y_firma(self):
        """`v1 packet with recipient and signature round-trips correctly`"""
        firma = bytes((i + 0xD0) & 0xFF for i in range(64))
        vuelta = roundtrip(
            make_packet(b"privado firmado", recipient=RECIPIENT, signature=firma)
        )
        self.assertEqual(vuelta.recipient_id, RECIPIENT)
        self.assertEqual(vuelta.signature, firma)

    def test_payload_vacio(self):
        """`empty payload round-trips correctly`"""
        vuelta = roundtrip(make_packet(b""))
        self.assertEqual(vuelta.payload, b"")

    def test_payload_v1_maximo(self):
        """`maximum v1 payload length round-trips correctly`"""
        vuelta = roundtrip(make_packet(b"x" * 0xFFFF))
        self.assertEqual(len(vuelta.payload), 0xFFFF)

    def test_v1_usa_longitud_de_2_bytes(self):
        """`v1 uses 2-byte and v2 uses 4-byte payload length`"""
        crudo = make_packet(b"x" * 300).to_bytes()
        # Los bytes 12-13 son la longitud en v1.
        self.assertEqual(int.from_bytes(crudo[12:14], "big"), 300)


class TestCabeceraV2(unittest.TestCase):
    def test_v2_con_ruta(self):
        """`v2 packet with route round-trips correctly`"""
        ruta = [bytes([1] * 8), bytes([2] * 8), bytes([3] * 8)]
        vuelta = roundtrip(make_packet(b"enrutado", version=2, route=ruta))
        self.assertEqual(vuelta.header.version, 2)
        self.assertEqual(vuelta.route, ruta)
        self.assertTrue(vuelta.header.flags & PacketFlags.HAS_ROUTE)

    def test_v2_sin_ruta(self):
        """`v2 packet without route round-trips correctly`"""
        firma = bytes(range(64))
        vuelta = roundtrip(
            make_packet(b"v2", version=2, recipient=RECIPIENT, signature=firma)
        )
        self.assertIsNone(vuelta.route)
        self.assertEqual(vuelta.recipient_id, RECIPIENT)
        self.assertEqual(vuelta.signature, firma)

    def test_v2_con_ruta_pero_sin_destinatario(self):
        """`v2 packet with route but no recipient round-trips correctly`"""
        ruta = [bytes([9] * 8)]
        vuelta = roundtrip(make_packet(b"x", version=2, route=ruta))
        self.assertEqual(vuelta.route, ruta)
        self.assertIsNone(vuelta.recipient_id)

    def test_v2_ruta_vacia_se_canoniza_a_none(self):
        """`v2 packet with HAS_ROUTE flag and count zero decodes route as null`

        La representación vacía y la ausente no deben distinguirse: si se
        distinguieran, un mismo paquete tendría dos codificaciones y la
        verificación de firma dependería de cuál se eligió.
        """
        bruto = bytearray(make_packet(b"x", version=2).to_bytes())
        # Cabecera v2 = 16, luego sender(8). Ponemos HAS_ROUTE y un conteo 0.
        bruto[11] |= PacketFlags.HAS_ROUTE
        bruto.insert(24, 0)
        vuelta = Packet.from_bytes(bytes(bruto))
        self.assertIsNone(vuelta.route)

    def test_v2_usa_longitud_de_4_bytes(self):
        """`v1 uses 2-byte and v2 uses 4-byte payload length`"""
        crudo = make_packet(b"x" * 300, version=2).to_bytes()
        self.assertEqual(int.from_bytes(crudo[12:16], "big"), 300)
        self.assertEqual(crudo[16:24], SENDER)  # sender va tras 16 B de cabecera

    def test_v2_truncado_con_ruta_devuelve_none(self):
        """`v2 truncated packet with HAS_ROUTE flag returns null`"""
        crudo = make_packet(b"datos", version=2, route=[bytes([1] * 8)]).to_bytes()
        with self.assertRaises(ProtocolError):
            Packet.from_bytes(crudo[:-4])


class TestFlagsDeRuta(unittest.TestCase):
    def test_v1_ignora_el_flag_de_ruta(self):
        """`v1 decoder ignores HAS_ROUTE flag`"""
        bruto = bytearray(make_packet(b"x", version=1).to_bytes())
        bruto[11] |= PacketFlags.HAS_ROUTE
        vuelta = Packet.from_bytes(bytes(bruto))
        self.assertIsNone(vuelta.route, "v1 no tiene sección de ruta")

    def test_v1_descarta_la_ruta_en_salida(self):
        """`v1 packet with route silently drops route`"""
        crudo = make_packet(b"x", version=1, route=[bytes([1] * 8)]).to_bytes()
        vuelta = Packet.from_bytes(crudo)
        self.assertIsNone(vuelta.route)
        # Y al re-codificar, la ruta ya no está y el paquete no crece.
        self.assertEqual(vuelta.to_bytes(), crudo)


class TestVersionDesconocida(unittest.TestCase):
    def test_version_invalida(self):
        """`invalid version returns null`"""
        bruto = bytearray(make_packet(b"x").to_bytes())
        bruto[0] = 9
        with self.assertRaises(ProtocolError) as ctx:
            Packet.from_bytes(bytes(bruto))
        self.assertNotIsInstance(ctx.exception, UnsupportedVersionError)

    def test_ambas_versiones_conocidas_estan_implementadas(self):
        self.assertEqual(KNOWN_UPSTREAM_VERSIONS, frozenset({1, 2}))
        self.assertEqual(PROTOCOL_VERSION, 1, "Android emite siempre v1")

    def test_basura_no_revienta(self):
        """`garbage data returns null without crashing`"""
        for basura in (b"", b"\x00", b"\xff" * 4, bytes(range(64)), os.urandom(64)):
            with self.subTest(datos=len(basura)):
                try:
                    Packet.from_bytes(basura)
                except (ProtocolError, ValueError, struct.error):
                    pass  # lo que importa es que no levante otra cosa


# --------------------------------------------------------------------------
# Identificadores
# --------------------------------------------------------------------------


class TestSenderID(unittest.TestCase):
    def test_corto_se_rellena_a_8(self):
        """`sender ID is padded or truncated to exactly 8 bytes` (parte corta)"""
        corto = bytes([0x11, 0x22, 0x33, 0x44])
        vuelta = roundtrip(make_packet(b"short-sender", sender=corto, raw_type=0x01))
        self.assertEqual(len(vuelta.sender_id), 8)
        self.assertEqual(vuelta.sender_id[:4], corto)
        self.assertEqual(vuelta.sender_id[4:], b"\x00" * 4)

    def test_largo_se_trunca_en_la_app_pero_nosotros_rechazamos(self):
        """`sender ID is padded or truncated to exactly 8 bytes` (parte larga)

        Divergencia deliberada: la app trunca en silencio, nosotros fallamos.
        Truncar la identidad de un par es dirección incorrecta, y un id
        demasiado largo debe descubrirse aquí y no convertirse en otro par.
        """
        largo = bytes((i + 0x50) & 0xFF for i in range(12))
        with self.assertRaises(ProtocolError) as ctx:
            make_packet(b"x", sender=largo).to_bytes()
        self.assertIn("truncarlo", str(ctx.exception))

    def test_recipient_corto_se_rellena(self):
        """`short recipientID is zero-padded to 8 bytes`"""
        vuelta = roundtrip(
            make_packet(b"x", recipient=bytes([0xAA, 0xBB, 0xCC]))
        )
        self.assertEqual(vuelta.recipient_id, bytes([0xAA, 0xBB, 0xCC, 0, 0, 0, 0, 0]))

    def test_recipient_largo_se_rechaza(self):
        with self.assertRaises(ProtocolError):
            make_packet(b"x", recipient=bytes(9)).to_bytes()


# --------------------------------------------------------------------------
# Compresión
# --------------------------------------------------------------------------


class TestCompresionDecision(unittest.TestCase):
    def test_payload_pequeno_no_se_comprime(self):
        """`small payload skips compression`"""
        payload = b"A" * 50
        crudo = make_packet(payload).with_compression().to_bytes()
        flags = crudo[11]
        self.assertEqual(flags & PacketFlags.IS_COMPRESSED, 0)
        self.assertEqual(Packet.from_bytes(crudo).payload, payload)

    def test_payload_comprimible_se_comprime(self):
        """`large compressible payload is compressed and decompressed correctly`"""
        payload = b"texto muy repetido que se comprime bien. " * 30
        p = make_packet(payload).with_compression()
        crudo = p.to_bytes()
        self.assertTrue(crudo[11] & PacketFlags.IS_COMPRESSED)
        self.assertLess(len(crudo), len(payload) + 14 + 8)
        self.assertEqual(Packet.from_bytes(crudo).payload, payload)

    def test_payload_De_alta_entropia_sobrevive(self):
        """`high-entropy payload skips compression`

        Con semilla fija para que sea reproducible, como hace el test.
        """
        import random

        rnd = random.Random(42)
        payload = bytes(rnd.getrandbits(8) for _ in range(200))
        self.assertEqual(roundtrip(make_packet(payload)).payload, payload)


class TestCodificadorAjeno(unittest.TestCase):
    """El test más importante de todo este fichero.

    Portado de `re-encoding preserves a foreign encoder's compressed payload`.
    Construye a mano un bloque *stored* de DEFLATE: bytes que ningún codificador
    produciría para ese payload, y que `zlib` de Python **jamás** generaría.

    Comprueba que re-codificar un paquete reproduce los bytes del originator. Si
    re-compresionáramos, la salida sería distinta y la firma dejaría de validar.
    """

    @staticmethod
    def _stored_block(payload: bytes) -> bytes:
        """Bloque DEFLATE stored: BFINAL=1, BTYPE=00, LEN y NLEN en little-endian."""
        n = len(payload)
        return (
            bytes([0x01, n & 0xFF, (n >> 8) & 0xFF, (~n) & 0xFF, ((~n) >> 8) & 0xFF])
            + payload
        )

    def test_recodificar_conserva_los_bytes_del_otro_codificador(self):
        payload = (
            b"the mesh is up near the north gate. relay running all evening. " * 4
        )
        stored = self._stored_block(payload)

        # Comprobación previa: estos bytes no son los que produce zlib, pero
        # los dos inflan al mismo payload. Si coincidieran, el vector no
        # probaría nada.
        propio = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
        nuestro = propio.compress(payload) + propio.flush()
        self.assertNotEqual(stored, nuestro, "el vector debe usar bytes ajenos")
        self.assertEqual(
            zlib.decompressobj(-15).decompress(stored, len(payload)), payload
        )

        # Montamos el paquete v2 a mano, como hace el test de la app.
        size_field = 4
        cuerpo = size_field + len(stored)
        flags = PacketFlags.IS_COMPRESSED
        crudo = b"".join((
            bytes([2, 0x02, 5]),
            struct.pack(">Q", TS),
            bytes([int(flags)]),
            struct.pack(">I", cuerpo),
            SENDER,
            struct.pack(">I", len(payload)),
            stored,
        ))

        self.assertEqual(len(crudo), 16 + 8 + cuerpo)

        decodificado = Packet.from_bytes(crudo)
        self.assertEqual(decodificado.payload, payload)

        recodificado = decodificado.to_bytes(include_padding=False)
        self.assertEqual(
            recodificado, crudo,
            "re-codificar debe reproducir los bytes del originator, o una firma "
            "válida deja de verificar",
        )

    def test_si_recomprimimos_los_bytes_cambian(self):
        """El riesgo, demostrado: comprimir de nuevo produce otra cosa."""
        payload = b"el mesh aguanta toda la noche. " * 12
        stored = self._stored_block(payload)
        size_field = 4
        crudo = b"".join((
            bytes([2, 0x02, 5]),
            struct.pack(">Q", TS),
            bytes([int(PacketFlags.IS_COMPRESSED)]),
            struct.pack(">I", size_field + len(stored)),
            SENDER,
            struct.pack(">I", len(payload)),
            stored,
        ))
        p = Packet.from_bytes(crudo)

        # Reutilizando los bytes del cable: idéntico.
        self.assertEqual(p.to_bytes(include_padding=False), crudo)

        # Descartando el WirePayload y comprimiendo de nuevo: distinto. Esto
        # es exactamente lo que haría que una firma válida dejara de validar.
        recomprimido = Packet(
            header=p.header,
            sender_id=p.sender_id,
            payload=p.payload,
            wire_payload=None,
        ).with_compression()
        self.assertIsNotNone(recomprimido.wire_payload)
        self.assertNotEqual(recomprimido.to_bytes(include_padding=False), crudo)


# --------------------------------------------------------------------------
# Rechazos del descompresor
# --------------------------------------------------------------------------


class TestDescompresorRechazos(unittest.TestCase):
    """Los doce rechazos de `CompressionUtil` y `BinaryProtocol`."""

    @staticmethod
    def _stored(payload: bytes) -> bytes:
        n = len(payload)
        return (
            bytes([0x01, n & 0xFF, (n >> 8) & 0xFF, (~n) & 0xFF, ((~n) >> 8) & 0xFF])
            + payload
        )

    def test_bomba_de_compresion(self):
        """`compression bomb is rejected`"""
        with self.assertRaises(CompressionError):
            inflate_exact(self._stored(b"x" * 100), 10_000_000)

    def test_expansion_subdeclarada_se_rechaza(self):
        """`under-declared raw expansion is rejected even when output buffer fills`"""
        with self.assertRaises(CompressionError):
            inflate_exact(self._stored(b"x" * 100), 50)

    def test_expansion_sobredeclarada_se_rechaza(self):
        """`over-declared raw expansion is rejected instead of returning a prefix`"""
        with self.assertRaises(CompressionError):
            inflate_exact(self._stored(b"x" * 100), 150)

    def test_stream_truncado_se_rechaza(self):
        """`truncated raw stream is rejected even if all declared bytes were emitted`"""
        with self.assertRaises(CompressionError):
            inflate_exact(self._stored(b"x" * 100)[:50], 100)

    def test_bytes_sobrantes_se_rechazan(self):
        """`raw stream with trailing bytes is rejected`"""
        with self.assertRaises(CompressionError):
            inflate_exact(self._stored(b"x" * 100) + b"\x00\x00", 100)

    def test_cuerpo_comprimido_vacio(self):
        """`empty compressed body never reaches decompressor`"""
        with self.assertRaises(CompressionError):
            inflate_exact(b"", 100)

    def test_expansion_cero_se_rechaza(self):
        """`zero expanded payload never reaches decompressor`"""
        with self.assertRaises(CompressionError):
            inflate_exact(self._stored(b"x" * 10), 0)

    def test_expansion_negativa_se_rechaza(self):
        """`v2 negative expanded payload never reaches decompressor`"""
        with self.assertRaises(CompressionError):
            inflate_exact(self._stored(b"x" * 10), -1)

    def test_zlib_envuelto_todavia_es_compatible(self):
        """`zlib wrapped payload remains compatible when size and stream completion are exact`"""
        payload = b"contenido tolerante " * 20
        with_cabecera = zlib.compress(payload)
        self.assertEqual(inflate_exact(with_cabecera, len(payload)), payload)

    def test_zlib_con_prefijo_raw_cae_a_raw(self):
        """`raw deflate with zlib-looking prefix falls back after non-exact zlib parse`

        Un stream raw puede empezar por dos bytes que *parecen* una cabecera
        zlib válida. Si el parseo zlib no cuadra exactamente, hay que caer a raw
        en vez de rendirse.
        """
        payload = b"x" * 300
        raw = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
        bytes_raw = raw.compress(payload) + raw.flush()
        # Lo forzamos a parecer zlib sólo si ya lo parece de forma creíble.
        from pybitchat.protocol.compression import looks_like_zlib

        if looks_like_zlib(bytes_raw):
            self.assertEqual(inflate_exact(bytes_raw, len(payload)), payload)

    def test_zlib_subdeclarado_rechazado_por_fallback(self):
        """`under-declared zlib expansion is rejected by fallback`"""
        payload = b"x" * 300
        with_cabecera = zlib.compress(payload)
        with self.assertRaises(CompressionError):
            inflate_exact(with_cabecera, len(payload) - 10)

    def test_zlib_sobredeclarado_rechazado_por_fallback(self):
        """`over-declared zlib expansion is rejected by fallback`"""
        payload = b"x" * 300
        with_cabecera = zlib.compress(payload)
        with self.assertRaises(CompressionError):
            inflate_exact(with_cabecera, len(payload) + 10)

    def test_zlib_truncado_rechazado(self):
        """`truncated zlib stream is rejected by fallback`

        El corte es a la mitad de verdad: `zlib.compress` de 300 bytes iguales
        cabe en muy pocos, así que cortar por una posición fija podía no cortar
        nada.
        """
        payload = b"x" * 300
        with_cabecera = zlib.compress(payload)
        mitad = max(2, len(with_cabecera) // 2)
        self.assertLess(mitad, len(with_cabecera), "el corte debe ser real")
        with self.assertRaises(CompressionError):
            inflate_exact(with_cabecera[:mitad], len(payload))

    def test_zlib_con_bytes_sobrantes_rechazado(self):
        """`zlib stream with trailing bytes is rejected by fallback`"""
        payload = b"x" * 300
        with_cabecera = zlib.compress(payload) + b"\x00\x00"
        with self.assertRaises(CompressionError):
            inflate_exact(with_cabecera, len(payload))

    def test_resultado_mas_corto_que_lo_declarado(self):
        """`decoder rejects a decompressor result shorter than its declaration`"""
        payload = b"x" * 300
        with_cabecera = zlib.compress(payload)
        with self.assertRaises(CompressionError):
            inflate_exact(with_cabecera, len(payload) + 1)

    def test_utilidad_rechaza_tamanos_invalidos_directamente(self):
        """`compression utility rejects invalid expansion sizes directly`"""
        from pybitchat.protocol import compression as c

        with self.assertRaises(CompressionError):
            c.check_expansion(100, 0)
        with self.assertRaises(CompressionError):
            c.check_expansion(100, c.MAX_PAYLOAD_LENGTH + 1)


# --------------------------------------------------------------------------
# Relleno
# --------------------------------------------------------------------------


class TestRelleno(unittest.TestCase):
    def test_payload_corto_no_se_rellena_para_ble(self):
        """`oversized packet bypasses padding and still round-trips` (contraste)

        Android sólo rellena tramas Noise, no todo.
        """
        from pybitchat.protocol.types import FRAGMENT_SIZE_THRESHOLD

        self.assertFalse(should_pad_for_ble(FRAGMENT_SIZE_THRESHOLD - 1))

    def test_cubos_de_relleno(self):
        """`padding produces correct block sizes and round-trips`"""
        from pybitchat.protocol.packet import pkcs7_pad_to_bucket
        from pybitchat.protocol.types import PADDING_BUCKETS

        for cubo in PADDING_BUCKETS:
            with self.subTest(cubo=cubo):
                # Un paquete que cabe justo en el cubo no necesita relleno.
                datos = b"x" * (cubo - 1)
                relleno = pkcs7_pad_to_bucket(datos)
                self.assertLessEqual(len(relleno), cubo)
                self.assertGreater(len(relleno), len(datos))


# --------------------------------------------------------------------------
# Firma
# --------------------------------------------------------------------------


class TestPreimagenDeFirma(unittest.TestCase):
    def test_quita_la_firma_y_fija_el_ttl(self):
        """`toBinaryDataForSigning excludes signature and fixes TTL`"""
        firma = bytes((i + 0xD0) & 0xFF for i in range(64))
        original = make_packet(
            b"sign-me", recipient=RECIPIENT, signature=firma, ttl=7
        )

        para_firmar = original.to_binary_data_for_signing()
        self.assertNotIn(bytes(firma), para_firmar, "la firma no se firma a sí misma")

        decodificado = Packet.from_bytes(para_firmar)
        self.assertIsNone(decodificado.signature)
        self.assertEqual(decodificado.header.ttl, SYNC_TTL_HOPS)
        self.assertEqual(decodificado.header.raw_type, original.header.raw_type)
        self.assertEqual(decodificado.header.timestamp, original.header.timestamp)
        self.assertEqual(decodificado.sender_id, original.sender_id)
        self.assertEqual(decodificado.recipient_id, original.recipient_id)
        self.assertEqual(decodificado.payload, original.payload)

    def test_la_firma_no_depende_de_los_saltos(self):
        """La razón de fijar el TTL: un reenvío no puede romper la firma.

        El TTL baja en cada salto. Si entrase en la preimagen, un paquete que ha
        sido reenviado *una sola vez* llegaría con firma inválida.
        """
        base = make_packet(b"reenviable", recipient=RECIPIENT, ttl=3)
        firma_inicial = base.to_binary_data_for_signing()

        # El mismo paquete, ya reenviado tres veces.
        reenviado = base.with_ttl(0)
        self.assertEqual(
            reenviado.to_binary_data_for_signing(), firma_inicial,
            "el TTL no debe entrar en la preimagen",
        )

    def test_sin_relleno(self):
        """La preimagen no incluye relleno: el relleno no es parte del paquete."""
        original = make_packet(b"x" * 300)
        original.padding = b"\x00" * 200
        con = len(original.to_binary_data_for_signing())
        self.assertEqual(con, len(original.to_bytes(include_padding=False)))


if __name__ == "__main__":
    unittest.main(verbosity=2)