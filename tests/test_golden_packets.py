"""Tests golden contra los paquetes reales de la app oficial de iOS.

Las fixtures las genera `tools/extract_vectors.py` a partir de los ficheros
`.log` commiteados en `reference/bitchat-tui/`.

Se usan tres oráculos independientes:

  1. Round-trip byte a byte: parsear y re-serializar debe devolver
     exactamente los bytes originales, relleno incluido.
  2. Longitudes "tras quitar el relleno" de `packet_debug.log`, que validan
     la aritmética de la cabecera de 14 bytes y de los identificadores
     dirigidos por flags.
  3. Valores en claro conocidos (nickname, contenido, peer_id) extraídos a
     mano del volcado hex.

Ejecutar sin pytest:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol import (  # noqa: E402
    LegacyMessageType,
    HEADER_SIZE,
    MessageFlags,
    MessagePayload,
    MessageType,
    Packet,
    PacketFlags,
    ProtocolError,
)

FIXTURES = Path(__file__).parent / "fixtures" / "vectors.json"


def load_fixtures() -> dict:
    return json.loads(FIXTURES.read_text(encoding="utf-8"))


DOC = load_fixtures()
RAW_VECTORS = [v for v in DOC["vectors"] if "raw_hex" in v]
ORACLE = DOC["unpadding_oracle"]


class TestFixtureIntegrity(unittest.TestCase):
    """La extracción no debe perder datos silenciosamente."""

    def test_hay_vectores(self):
        self.assertGreaterEqual(len(RAW_VECTORS), 9, "esperaba al menos 9 paquetes")

    def test_longitudes_declaradas_cuadran(self):
        """`Raw notification data: N bytes` debe coincidir con el volcado."""
        for v in RAW_VECTORS:
            with self.subTest(source=f"{v['source_file']}:{v['source_line']}"):
                self.assertEqual(
                    v["declared_length"],
                    v["byte_count"],
                    "la longitud declarada y el volcado hex no coinciden",
                )

    def test_varios_emisores_y_anchos_de_id(self):
        """Se observan al menos dos emisores distintos, con id de 8 bytes."""
        senders = {
            Packet.from_bytes(bytes.fromhex(v["raw_hex"])).sender_id_hex
            for v in RAW_VECTORS
        }
        self.assertGreaterEqual(
            len(senders), 2, f"sólo se vio un emisor: {senders}"
        )
        for s in senders:
            self.assertEqual(len(s), 16, f"sender_id no es de 8 bytes: {s}")

    def test_testnet_y_mainnet_no_se_confunden(self):
        """Los UUID de testnet y mainnet difieren sólo en el último carácter."""
        from pybitchat.protocol import (
            BITCHAT_SERVICE_UUID,
            BITCHAT_SERVICE_UUID_TESTNET,
        )

        self.assertEqual(BITCHAT_SERVICE_UUID[-1], "C")
        self.assertEqual(BITCHAT_SERVICE_UUID_TESTNET[-1], "A")
        self.assertEqual(BITCHAT_SERVICE_UUID[:-1], BITCHAT_SERVICE_UUID_TESTNET[:-1])


class TestHeaderLayout(unittest.TestCase):
    """La cabecera de 14 bytes, validada contra los bytes reales."""

    def test_header_size_is_14(self):
        self.assertEqual(HEADER_SIZE, 14)

    def test_primeros_paquetes_consistentes(self):
        for v in RAW_VECTORS:
            with self.subTest(source=f"{v['source_file']}:{v['source_line']}"):
                p = Packet.from_bytes(bytes.fromhex(v["raw_hex"]))
                self.assertEqual(p.header.version, 1)
                self.assertGreater(p.header.payload_len, 0)
                self.assertIsInstance(p.header.raw_type, int)


class TestByteExactRoundTrip(unittest.TestCase):
    """Oráculo 1: parsear y re-serializar debe ser la identidad."""

    def test_round_trip_todos_los_paquetes(self):
        for v in RAW_VECTORS:
            with self.subTest(source=f"{v['source_file']}:{v['source_line']}"):
                original = bytes.fromhex(v["raw_hex"])
                p = Packet.from_bytes(original)
                self.assertEqual(
                    p.to_bytes(),
                    original,
                    "el round-trip no reprodujo los bytes originales",
                )

    def test_reparse_es_estable(self):
        """Un segundo ciclo no debe seguir moviendo el relleno."""
        for v in RAW_VECTORS:
            with self.subTest(source=f"{v['source_file']}:{v['source_line']}"):
                original = bytes.fromhex(v["raw_hex"])
                once = Packet.from_bytes(original).to_bytes()
                twice = Packet.from_bytes(once).to_bytes()
                self.assertEqual(once, twice)


class TestUnpaddingOracle(unittest.TestCase):
    """Oráculo 2: longitudes de `packet_debug.log` contra nuestro parser.

    Validación bidireccional:

      a) Cada paquete del que tenemos bytes debe tener una longitud sin
         relleno correspondiente en el oráculo.
      b) Cada entrada del oráculo debe corresponder a algún paquete del que
         tenemos bytes, EXCEPTO las que se listan en `HUECOS_CONOCIDOS`.

    Los huecos son reales y están documentados: el cliente Rust parseó 28
    paquetes pero sólo volcó 21 en `debug.log`. Los 7 que faltan son
    emisiones propias del cliente, cuyo volcado hex no se guardó. Hacen
    falta para cerrar el formato de los paquetes que el cliente envía.
    """

    #: Entradas del oráculo que no se pueden contrastar por falta de bytes.
    HUECOS_CONOCIDOS = 7

    def test_a_todo_paquete_con_bytes_le_corresponde_una_entrada(self):
        from collections import Counter

        oracle = Counter(
            (e["declared_length"], e["unpadded_length"])
            for e in ORACLE
            if "declared_length" in e and "unpadded_length" in e
        )
        ours = Counter()
        for v in RAW_VECTORS:
            p = Packet.from_bytes(bytes.fromhex(v["raw_hex"]))
            ours[(v["declared_length"], len(p.to_bytes(include_padding=False)))] += 1

        for key, count in ours.items():
            with self.subTest(key=key):
                self.assertIn(
                    key,
                    oracle,
                    f"nuestro parser produce {key}, ausente del oráculo",
                )
                self.assertLessEqual(
                    count,
                    oracle[key],
                    "tenemos más paquetes de este tipo que el oráculo",
                )

    def test_b_los_huecos_conocidos_no_crecen(self):
        matched = set()
        ours = set()
        for v in RAW_VECTORS:
            p = Packet.from_bytes(bytes.fromhex(v["raw_hex"]))
            ours.add((v["declared_length"], len(p.to_bytes(include_padding=False))))

        for e in ORACLE:
            if "declared_length" not in e or "unpadded_length" not in e:
                continue
            if (e["declared_length"], e["unpadded_length"]) in ours:
                matched.add((e["declared_length"], e["unpadded_length"]))

        uncovered = [
            e
            for e in ORACLE
            if "declared_length" in e
            and "unpadded_length" in e
            and (e["declared_length"], e["unpadded_length"]) not in ours
        ]
        with self.subTest(uncovered=uncovered):
            self.assertEqual(
                len(uncovered),
                self.HUECOS_CONOCIDOS,
                "el número de entradas del oráculo sin bytes ha cambiado: "
                "actualiza el análisis de huecos y el comentario del módulo",
            )
            # Todas las entradas sin cubrir son del mismo tipo, para que el
            # hueco siga siendo un único caso de análisis pendiente.
            kinds = {(e["declared_length"], e["unpadded_length"]) for e in uncovered}
            self.assertEqual(
                len(kinds), 1, f"los huecos se han diversificado: {sorted(kinds)}"
            )


class TestKnownPlaintext(unittest.TestCase):
    """Oráculo 3: valores en claro conocidos, leídos a mano del volcado."""

    def test_anonymous_announce(self):
        """`debug.log:2-4`: Announce de 256 B con nickname 'anonymous'."""
        found = [
            v
            for v in RAW_VECTORS
            if Packet.from_bytes(bytes.fromhex(v["raw_hex"])).header.legacy_type is LegacyMessageType.ANNOUNCE
            and v["source_line"] == 2
        ]
        self.assertEqual(len(found), 1)
        p = Packet.from_bytes(bytes.fromhex(found[0]["raw_hex"]))
        self.assertEqual(p.sender_id_hex, "234de4e300000000")
        self.assertEqual(p.recipient_id_hex, "ffffffffffffffff")
        self.assertEqual(p.header.payload_len, 9)
        self.assertEqual(p.payload, b"anonymous")
        self.assertTrue(p.header.flags & PacketFlags.HAS_RECIPIENT)
        self.assertFalse(p.header.flags & PacketFlags.HAS_SIGNATURE)
        # 14 + 8 + 8 + 9 = 39, que es lo que registró packet_debug.log.
        self.assertEqual(len(p.to_bytes(include_padding=False)), 39)

    def test_message_hi(self):
        """`debug.log:7-9`: Message de 256 B, nickname 'anon6328', contenido 'hi'."""
        found = [
            v
            for v in RAW_VECTORS
            if Packet.from_bytes(bytes.fromhex(v["raw_hex"])).header.legacy_type is LegacyMessageType.MESSAGE
            and v["source_line"] == 7
        ]
        self.assertEqual(len(found), 1)
        p = Packet.from_bytes(bytes.fromhex(found[0]["raw_hex"]))
        self.assertEqual(p.sender_id_hex, "8b7f0cb466d3f967")

        msg = MessagePayload.parse(p.payload)
        self.assertEqual(msg.flags, MessageFlags.HAS_SENDER_PEER_ID)
        self.assertEqual(msg.flags, 0x10)
        self.assertEqual(msg.sender, "anon6328")
        self.assertEqual(msg.content, "hi")
        self.assertEqual(msg.sender_peer_id, "8b7f0cb466d3f967")
        self.assertEqual(len(msg.message_id), 36)
        self.assertEqual(msg.message_id.count("-"), 4)

        # La suma de los campos debe ser exactamente payload_len.
        self.assertEqual(len(p.payload), 76)
        self.assertEqual(len(msg.to_bytes()), 76)

    def test_timestamps_son_epoch_ms(self):
        """Los timestamps deben caer en agosto de 2025, epoch Unix en ms."""
        import datetime

        for v in RAW_VECTORS:
            p = Packet.from_bytes(bytes.fromhex(v["raw_hex"]))
            when = datetime.datetime.fromtimestamp(
                p.header.timestamp / 1000, tz=datetime.timezone.utc
            )
            with self.subTest(source=f"{v['source_file']}:{v['source_line']}"):
                self.assertEqual(when.year, 2025, f"timestamp inesperado: {when}")
                self.assertEqual(when.month, 8)


class TestNoiseFramingObservation(unittest.TestCase):
    """El prefijo de nonce de 4 bytes: la desviación que rompe las librerías."""

    def test_noise_encrypted_empieza_con_cuatro_ceros(self):
        found = [
            v
            for v in RAW_VECTORS
            if Packet.from_bytes(bytes.fromhex(v["raw_hex"])).header.legacy_type is LegacyMessageType.NOISE_ENCRYPTED
        ]
        self.assertGreaterEqual(len(found), 2)

        for v in found:
            with self.subTest(source=f"{v['source_file']}:{v['source_line']}"):
                p = Packet.from_bytes(bytes.fromhex(v["raw_hex"]))
                self.assertGreaterEqual(len(p.payload), 4)
                self.assertEqual(
                    p.payload[:4],
                    b"\x00\x00\x00\x00",
                    "esperábamos un prefijo de nonce de 4 bytes a cero",
                )
                # Lo que sigue es ciphertext opaco, no texto legible.
                self.assertGreater(len(p.payload) - 4, 16)

    def test_payload_len_coincide_con_lo_que_registro_rust(self):
        """`debug.log:41` dice 276; la cabecera debe decir 276."""
        for v in RAW_VECTORS:
            reported = v.get("rust_reported_payload_len")
            if reported is None:
                continue
            p = Packet.from_bytes(bytes.fromhex(v["raw_hex"]))
            with self.subTest(source=f"{v['source_file']}:{v['source_line']}"):
                self.assertEqual(p.header.payload_len, reported)


class TestNegativeVectors(unittest.TestCase):
    """Paquetes que el cliente Rust sabía recibir pero no sabe manejar.

    Sirven como casos negativos: confirman que el payload tiene formas que
    aún no soportamos, y que debemos fallar explícitamente en vez de adivinar.
    """

    def test_existen_tipos_que_rust_ignora(self):
        ignorados = {
            b
            for v in RAW_VECTORS
            for b in v.get("rust_behaviour", [])
            if b.startswith("ignored: ")
        }
        self.assertTrue(
            ignorados,
            "esperábamos al menos un tipo de paquete que el cliente Rust ignora",
        )

    def test_payload_incompleto_falla_explicitamente(self):
        """Las flags pueden prometer campos que no estan.

        Cuando eso pasa hay que fallar, no leer basura como si fuera el
        siguiente campo: un error de longitud desplaza todo lo que viene
        detras y produce basura silenciosa.
        """
        # flags = 0x40 (canal) pero sin el campo de canal detras.
        truncado = (
            bytes([0x40])
            + (0).to_bytes(8, "big")
            + b"\x01i"        # id
            + b"\x01s"        # sender
            + b"\x00\x01c"    # content de 1 byte
        )
        with self.assertRaises(ProtocolError):
            MessagePayload.parse(truncado)

    def test_esas_mismas_flags_con_el_campo_si_valen(self):
        """El caso anterior no falla por el flag, sino por faltar el campo."""
        completo = (
            bytes([0x40])
            + (0).to_bytes(8, "big")
            + b"\x01i"
            + b"\x01s"
            + b"\x00\x01c"
            + b"\x01#"
        )
        msg = MessagePayload.parse(completo)
        self.assertEqual(msg.channel, "#")
        self.assertEqual(msg.message_id, "i")
        self.assertEqual(msg.sender, "s")
        self.assertEqual(msg.content, "c")

    def test_flags_que_piden_mas_bytes_de_los_que_hay(self):
        """Menciona 3 elementos pero solo trae 1: no se rellena con basura."""
        corto = (
            bytes([0x20])
            + (0).to_bytes(8, "big")
            + b"\x01i"
            + b"\x01s"
            + b"\x00\x01c"
            + b"\x03"       # dice 3 menciones
            + b"\x01x"      # ... pero solo hay 1
        )
        with self.assertRaises(ProtocolError):
            MessagePayload.parse(corto)


if __name__ == "__main__":
    unittest.main(verbosity=2)
