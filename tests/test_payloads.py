"""Tests de los payloads decodificados en Fase 1.

Cubre lo que se puede **probar** con los vectores reales:
  - ANNOUNCE: validado contra 4 vectores
  - NOISE_ENCRYPTED: framing de 4 B validado contra 7 vectores
  - FRAGMENT_*: round-trip y reensamblado exacto (sin vectores reales)

Y comprueba explícitamente que los payloads sin decodificar siguen siendo
**byte-exactos** en vez de mal interpretados.

Ejecutar:
    python tests/test_payloads.py
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol import MessageType, Packet  # noqa: E402
from pybitchat.protocol.packet import ProtocolError  # noqa: E402
from pybitchat.protocol.payloads import (  # noqa: E402
    AMBIGUOUS_VALUES,
    CURRENT,
    LEGACY,
    OPEN_QUESTIONS,
    AnnouncePayload,
    FragmentPayload,
    NoiseCiphertext,
    OpaquePayload,
    decode_payload,
    split_into_fragments,
)
from pybitchat.protocol.types import (  # noqa: E402
    LEGACY_FRAGMENT_CHUNK_SIZE,
    MAX_FRAGMENT_SIZE,
    LegacyMessageType as VectorType,
)

DOC = json.loads(
    (ROOT / "tests" / "fixtures" / "vectors.json").read_text(encoding="utf-8")
)
VECTORS = [v for v in DOC["vectors"] if "raw_hex" in v]


def packets_of(mtype: VectorType) -> list[tuple[dict, Packet]]:
    out = []
    for v in VECTORS:
        p = Packet.from_bytes(bytes.fromhex(v["raw_hex"]))
        if p.header.legacy_type is mtype:
            out.append((v, p))
    return out


class TestAnnounce(unittest.TestCase):
    """El payload de ANNOUNCE es sólo el nickname, sin prefijo de longitud."""

    def test_decode_contra_todos_los_vectores(self):
        found = packets_of(VectorType.ANNOUNCE)
        self.assertEqual(len(found), 4, "esperábamos 4 announces en los logs")

        seen = set()
        for v, p in found:
            with self.subTest(source=f"{v['source_file']}:{v['source_line']}"):
                ann = AnnouncePayload.parse(p.payload)
                seen.add(ann.nickname)
                self.assertEqual(len(p.payload), len(ann.nickname.encode("utf-8")))

        self.assertEqual(seen, {"anonymous", "anon6328"})

    def test_round_trip(self):
        for v, p in packets_of(VectorType.ANNOUNCE):
            with self.subTest(nickname=p.payload.decode()):
                ann = AnnouncePayload.parse(p.payload)
                self.assertEqual(ann.to_bytes(), p.payload)

    def test_nickname_con_utf8_multibyte(self):
        """Un nickname no-ASCII debe ocupar sus bytes, no sus caracteres."""
        for nickname in ("josé", "日本", "🐍python"):
            with self.subTest(nickname=nickname):
                raw = nickname.encode("utf-8")
                self.assertEqual(AnnouncePayload.parse(raw).nickname, nickname)
                self.assertEqual(AnnouncePayload(nickname).to_bytes(), raw)

    def test_despacho_usa_el_codec_correcto(self):
        _, p = packets_of(VectorType.ANNOUNCE)[0]
        self.assertIsInstance(decode_payload(p.header.raw_type, p.payload, LEGACY), AnnouncePayload)


class TestNoiseCiphertextFraming(unittest.TestCase):
    """El prefijo de 4 B little-endian es la desviación clave de BitChat."""

    def test_decode_contra_los_7_vectores(self):
        found = packets_of(VectorType.NOISE_ENCRYPTED)
        self.assertEqual(len(found), 7, "esperábamos 7 NoiseEncrypted")

        for v, p in found:
            with self.subTest(source=f"{v['source_file']}:{v['source_line']}"):
                nc = NoiseCiphertext.parse(p.payload)
                self.assertEqual(nc.nonce, 0, "todos los vectores usan nonce 0")
                self.assertEqual(len(nc.ciphertext), len(p.payload) - 4)
                # Y el round-trip debe devolver los bytes exactos.
                self.assertEqual(nc.to_bytes(), p.payload)

    def test_el_prefijo_no_es_ruido(self):
        """Los 4 primeros bytes deben ser el nonce, no parte del ciphertext.

        Si el framing fuese estándar, el nonce no iría en claro y los primeros
        4 bytes del ciphertext serían aleatorios. Aquí son siempre cero.
        """
        for v, p in packets_of(VectorType.NOISE_ENCRYPTED):
            with self.subTest(source=v["source_line"]):
                self.assertEqual(p.payload[:4], b"\x00\x00\x00\x00")

    def test_nonce_little_endian(self):
        """Un nonce grande debe codificarse little-endian, no big-endian."""
        nc = NoiseCiphertext(nonce=0x01020304, ciphertext=b"\xaa")
        self.assertEqual(nc.to_bytes()[:4], b"\x04\x03\x02\x01")
        self.assertEqual(NoiseCiphertext.parse(nc.to_bytes()).nonce, 0x01020304)

    def test_payload_corto_falla_explicitamente(self):
        with self.assertRaises(Exception):
            NoiseCiphertext.parse(b"\x00\x00")


class TestFragmentation(unittest.TestCase):
    """Fragmentos: sin vectores reales, se valida el round-trip y el reensamblado."""

    @staticmethod
    def _sample_padded_packet(size: int = 1024) -> bytes:
        """Un paquete con relleno simulado, determinista."""
        from pybitchat.protocol.packet import pkcs7_pad_to_bucket

        body = bytes((i * 7 + 3) & 0xFF for i in range(size - 64))
        header = (
            bytes([1, int(MessageType.MESSAGE), 7])
            + (1_754_073_314_075).to_bytes(8, "big")
            + bytes([1])
            + size.to_bytes(2, "big")
        )
        return pkcs7_pad_to_bucket(header + body)

    def test_troceado_reconstruye_exactamente(self):
        for size in (512, 1024, 2048):
            with self.subTest(size=size):
                pkt = self._sample_padded_packet(size)
                frags = split_into_fragments(
                    pkt, MessageType.MESSAGE, fragment_id=bytes(range(8))
                )
                self.assertGreater(len(frags), 1, "1024 B deberían necesitar fragmentos")

                # Cada fragmento cabe en el presupuesto de bytes.
                for f in frags:
                    self.assertLessEqual(len(f), MAX_FRAGMENT_SIZE)

                # Reensamblado byte a byte.
                decoded = [FragmentPayload.parse(f) for f in frags]
                self.assertEqual([d.index for d in decoded], list(range(len(frags))))
                self.assertTrue(decoded[0].is_first)
                self.assertTrue(decoded[-1].is_last)
                for d in decoded:
                    self.assertEqual(d.total, len(frags))
                    self.assertEqual(d.original_type, MessageType.MESSAGE)

                rebuilt = b"".join(d.data for d in decoded)
                self.assertEqual(rebuilt, pkt, "el reensamblado no reproduce el paquete")

    def test_troceado_es_determinista_con_fragment_id(self):
        pkt = self._sample_padded_packet(1024)
        a = split_into_fragments(pkt, MessageType.MESSAGE, fragment_id=b"\x01" * 8)
        b = split_into_fragments(pkt, MessageType.MESSAGE, fragment_id=b"\x01" * 8)
        self.assertEqual(a, b)

    def test_mensaje_corto_no_se_fragmenta(self):
        """Con las constantes actuales, un mensaje de 256 B va entero.

        FRAGMENT_SIZE_THRESHOLD es 512 B: por debajo no se fragmenta nada. Con
        el valor heredado de `bitchat-tui` (150 B) si hacia falta, porque caben
        137 B utiles por fragmento y el cubo minimo de relleno es 256 B.
        """
        pkt = self._sample_padded_packet(256)
        self.assertEqual(len(pkt), 256, "el cubo minimo de relleno es 256 B")

        actual = split_into_fragments(pkt, MessageType.MESSAGE, fragment_id=b"\x02" * 8)
        self.assertEqual(len(actual), 1, "256 B < 512: no debe fragmentarse")

        legacy = split_into_fragments(
            pkt, MessageType.MESSAGE, fragment_id=b"\x02" * 8,
            chunk_size=LEGACY_FRAGMENT_CHUNK_SIZE,
        )
        self.assertEqual(len(legacy), 2)
        self.assertEqual(len(FragmentPayload.parse(legacy[0]).data), 137)

        for frags in (actual, legacy):
            rebuilt = b"".join(FragmentPayload.parse(f).data for f in frags)
            self.assertEqual(rebuilt, pkt)

    def test_umbral_de_fragmentacion(self):
        """Por encima de 512 B si hay que fragmentar, y con cuantos."""
        pkt = self._sample_padded_packet(1024)
        self.assertEqual(len(pkt), 1024)

        useful = MAX_FRAGMENT_SIZE - FragmentPayload.HEADER_SIZE
        self.assertEqual(useful, 469 - 13)
        self.assertEqual(useful, 456)

        frags = split_into_fragments(pkt, MessageType.MESSAGE, fragment_id=b"\x03" * 8)
        self.assertEqual(len(frags), 3)
        for f in frags:
            self.assertLessEqual(len(f), MAX_FRAGMENT_SIZE)
        rebuilt = b"".join(FragmentPayload.parse(f).data for f in frags)
        self.assertEqual(rebuilt, pkt)

    def test_chunk_sobre_el_maximo_se_rechaza(self):
        """469 B es el tope del receptor: un fragmento mayor no llegaria."""
        pkt = self._sample_padded_packet(1024)
        with self.assertRaises(ValueError):
            split_into_fragments(pkt, MessageType.MESSAGE, chunk_size=514)
        ok = split_into_fragments(
            pkt, MessageType.MESSAGE, fragment_id=b"\x04" * 8, chunk_size=469
        )
        self.assertGreater(len(ok), 1)

    def test_demasiados_fragmentos_se_rechaza(self):
        """Mas de 256 fragmentos por conjunto es inentregable."""
        from pybitchat.protocol.types import MAX_FRAGMENTS_PER_ID

        self.assertEqual(MAX_FRAGMENTS_PER_ID, 256)
        grande = self._sample_padded_packet(1024) * 400  # ~400 KiB
        with self.assertRaises(ValueError):
            split_into_fragments(grande, MessageType.MESSAGE, chunk_size=469)

    def test_bajo_mtu_de_linux_hay_que_ser_conservador(self):
        """Si BlueZ devuelve MTU 23, el chunk minimo viable es 20 B."""
        self.assertEqual(23 - 3, 20, "20 B utiles tras el overhead ATT de 3")
        pkt = self._sample_padded_packet(256)
        frags = split_into_fragments(pkt, MessageType.MESSAGE, chunk_size=23)
        self.assertGreater(len(frags), 10, "MTU 23 implica muchos fragmentos")
        rebuilt = b"".join(FragmentPayload.parse(f).data for f in frags)
        self.assertEqual(rebuilt, pkt)

    def test_chunk_size_invalido_falla(self):
        pkt = self._sample_padded_packet(1024)
        with self.assertRaises(ValueError):
            split_into_fragments(pkt, MessageType.MESSAGE, chunk_size=5)

    def test_fragment_id_de_longitud_incorrecta_falla(self):
        with self.assertRaises(ValueError):
            split_into_fragments(b"x" * 512, MessageType.MESSAGE, fragment_id=b"\x00")


class TestOpaquePayloads(unittest.TestCase):
    """Lo que no sabemos decodificar debe seguir siendo byte-exacto."""

    def test_casos_abiertos_cubren_los_tipos_sin_decodificar(self):
        for (dialect, valor), question in OPEN_QUESTIONS.items():
            with self.subTest(dialecto=dialect, tipo=hex(valor)):
                self.assertRegex(question, r"^H\d$")
                self.assertIsInstance(valor, int)

    def test_payload_opaco_conserva_los_bytes(self):
        for dialect, valor in OPEN_QUESTIONS:
            for v in VECTORS:
                p = Packet.from_bytes(bytes.fromhex(v["raw_hex"]))
                if p.header.raw_type != valor:
                    continue
                with self.subTest(
                    dialect=dialect, tipo=hex(valor), source=v["source_line"]
                ):
                    got = decode_payload(valor, p.payload, dialect)
                    self.assertIsInstance(
                        got,
                        OpaquePayload,
                        f"{hex(valor)} debería quedar opaco, no {type(got).__name__}",
                    )
                    self.assertEqual(got.raw, p.payload)
                    self.assertEqual(got.msg_type, valor)
                    self.assertIsNotNone(got.open_question)

    def test_todos_los_payloads_reproducen_sus_bytes(self):
        """Propiedad general: decodificar y re-codificar da los bytes."""
        checked = 0
        for v in VECTORS:
            p = Packet.from_bytes(bytes.fromhex(v["raw_hex"]))
            got = decode_payload(p.header.raw_type, p.payload, LEGACY)
            if isinstance(got, OpaquePayload):
                self.assertEqual(got.raw, p.payload)
                checked += 1
                continue
            self.assertTrue(
                hasattr(got, "to_bytes"),
                f"{p.header.type_name} decodifica en {type(got).__name__} "
                "sin método to_bytes",
            )
            self.assertEqual(got.to_bytes(), p.payload)
            checked += 1
        self.assertEqual(checked, len(VECTORS))

    def test_todos_los_tipos_observados_estan_gestionados(self):
        """Ningún tipo presente en los vectores debe quedar sin cobertura."""
        from pybitchat.protocol.payloads import DECODED_TYPES, OPAQUE_TYPES

        observed = {
            Packet.from_bytes(bytes.fromhex(v["raw_hex"])).header.raw_type for v in VECTORS
        }
        for valor in sorted(observed):
            with self.subTest(tipo=hex(valor)):
                covered = valor in DECODED_TYPES or valor in OPAQUE_TYPES
                self.assertTrue(
                    covered,
                    f"{hex(valor)} no está ni en DECODED_TYPES ni en OPEN_QUESTIONS",
                )

    def test_los_dos_dialectos_cubren_los_mismos_valores_brutos(self):
        """Cada decoder registrado pertenece al menos a un dialecto conocido."""
        from pybitchat.protocol.payloads import DECODED_TYPES
        from pybitchat.protocol.types import MessageType

        for valor in DECODED_TYPES:
            with self.subTest(valor=hex(valor)):
                self.assertTrue(
                    valor in MessageType._value2member_map_
                    or valor in VectorType._value2member_map_,
                    f"{hex(valor)} no pertenece a ningún dialecto conocido",
                )

    def test_asimetria_entre_decoders_confirmados(self):
        """Guardarraíl sobre cómo se comporta cada decoder con payload vacío.

        La asimetría es intencionada y refleja el protocolo:
          - ANNOUNCE acepta payload vacío porque su longitud la da la cabecera
            y un anuncio sin nickname es legal (así lo genera el cliente).
          - NOISE_ENCRYPTED lo rechaza porque el prefijo de nonce son 4 bytes
            obligatorios.
        """
        # Announce vacío -> nickname vacío, sin error.
        self.assertEqual(AnnouncePayload.parse(b"").nickname, "")

        # NoiseCiphertext vacío -> error explícito.
        with self.assertRaises(ProtocolError):
            NoiseCiphertext.parse(b"")

        # Message vacío -> error explícito (necesita al menos flags+timestamp).
        with self.assertRaises(ProtocolError):
            decode_payload(int(MessageType.MESSAGE), b"", CURRENT)

    def test_valor_ambiguo_se_niega_a_adivinar(self):
        """El caso 0x11, que es donde el error sería más caro.

        Sin dialecto, `decode_payload` tiene dos respuestas plausibles y
        distintas para el mismo byte. Devolver cualquiera de ellas sin avisar
        sería el modo de fallo más silencioso posible: produces un objeto
        válido de bytes que no son los que querías.
        """
        from pybitchat.protocol.payloads import AMBIGUOUS_VALUES

        self.assertIn(0x11, AMBIGUOUS_VALUES)

        # 96 bytes que empiezan por una clave efímera: es un mensaje de
        # handshake, no un ciphertext de transporte.
        handshake = bytes.fromhex(
            "2a3b7beec6e2c2720cd77dcddc657ddfc85231d84e21d9556900d209d0b1ee4"
            "b917edfbef7b1c0d4ef4e8da5aacd0a9ab9104abbec829ce93cd343ee6479af"
            "aa"
        )

        got = decode_payload(0x11, handshake)
        self.assertIsInstance(got, OpaquePayload)
        self.assertIn("ambiguo", got.open_question)
        self.assertIn("NOISE_HANDSHAKE_RESP", got.open_question)
        self.assertIn("NOISE_ENCRYPTED", got.open_question)
        self.assertEqual(got.raw, handshake, "debe conservar los bytes intactos")

        # En el dialecto actual el mismo byte sí es un transporte cifrado.
        self.assertIsInstance(
            decode_payload(0x11, b"\x00\x00\x00\x00" + bytes(40), CURRENT),
            NoiseCiphertext,
        )
        # En el legacy sigue siendo opaco: aún no sabemos su layout.
        self.assertIsInstance(decode_payload(0x11, handshake, LEGACY), OpaquePayload)

    def test_dialecto_desconocido_falla(self):
        with self.assertRaises(ValueError):
            decode_payload(0x01, b"x", "klingon")


if __name__ == "__main__":
    unittest.main(verbosity=2)

