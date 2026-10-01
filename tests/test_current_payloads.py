"""Tests de los payloads del dialecto actual: MESSAGE, TLV y voz.

Todos los formatos verificados contra el codigo de
`permissionlesstech/bitchat-android`, leyendo tanto el `encode` como el `decode`
de cada clase.

Ejecutar:
    .venv\\Scripts\\python.exe tests\\test_current_payloads.py
"""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import sys  # noqa: E402

sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol.message import MessagePayload  # noqa: E402
from pybitchat.protocol.packet import ProtocolError  # noqa: E402
from pybitchat.protocol.tlv import (  # noqa: E402
    FileTransferPayload,
    RequestSyncPayload,
)
from pybitchat.protocol.voice import (  # noqa: E402
    CanceledPayload,
    EndPayload,
    FramesPayload,
    Kind,
    StartPayload,
    VoiceCodec,
    VoiceFramePayload,
)

TS = 1_754_073_314_075
#: UUID con la forma 8-4-4-4-12, 36 caracteres.
UUID_ID = "4394670B-A5C3-4B48-924E-CB96D1A27AF3"


class TestMessageCompleto(unittest.TestCase):
    """Los 8 flags de `MessagePayload`, en orden ascendente."""

    def test_uuid_de_ejemplo_mide_36(self):
        # El resto de tests asumen esta longitud al calcular tamanos.
        self.assertEqual(len(UUID_ID), 36)

    def test_caso_minimo(self):
        msg = MessagePayload(timestamp=TS, message_id=UUID_ID, sender="anon", content="hi")
        self.assertEqual(msg.flags, 0)
        # 1 flags + 8 ts + (1+36) id + (1+4) sender + (2+2) content = 55
        self.assertEqual(len(msg.to_bytes()), 55)

    def test_cada_flag_por_separado(self):
        base = {"timestamp": TS, "message_id": UUID_ID, "sender": "a", "content": "b"}
        casos = {
            "is_relay": dict(base, is_relay=True),
            "is_private": dict(base, is_private=True),
            "original_sender": dict(base, original_sender="orig"),
            "recipient_nickname": dict(base, recipient_nickname="dest"),
            "sender_peer_id": dict(base, sender_peer_id="8b7f0cb466d3f967"),
            "mentions": dict(base, mentions=["x", "yz"]),
            "channel": dict(base, channel="#canal"),
        }
        esperado = {
            "is_relay": 0x01,
            "is_private": 0x02,
            "original_sender": 0x04,
            "recipient_nickname": 0x08,
            "sender_peer_id": 0x10,
            "mentions": 0x20,
            "channel": 0x40,
        }
        for nombre, kwargs in casos.items():
            with self.subTest(campo=nombre):
                msg = MessagePayload(**kwargs)
                self.assertEqual(msg.flags, esperado[nombre])
                vuelta = MessagePayload.parse(msg.to_bytes())
                self.assertEqual(vuelta.flags, msg.flags)
                self.assertEqual(vuelta.to_bytes(), msg.to_bytes())

    def test_flags_booleanas_no_se_activan_solas(self):
        """`False is not None` es True en Python: no debe activar el bit."""
        msg = MessagePayload(timestamp=TS, message_id=UUID_ID, sender="a", content="b")
        self.assertFalse(msg.is_relay)
        self.assertFalse(msg.is_private)
        self.assertEqual(msg.flags, 0)

    def test_todos_los_flags_juntos(self):
        msg = MessagePayload(
            timestamp=TS,
            message_id=UUID_ID,
            sender="a",
            content="hola @b",
            is_relay=True,
            is_private=True,
            original_sender="o",
            recipient_nickname="d",
            sender_peer_id="8b7f0cb466d3f967",
            mentions=["@b"],
            channel="#canal",
        )
        self.assertEqual(msg.flags, 0x7F)
        vuelta = MessagePayload.parse(msg.to_bytes())
        self.assertEqual(vuelta.original_sender, "o")
        self.assertEqual(vuelta.recipient_nickname, "d")
        self.assertEqual(vuelta.sender_peer_id, "8b7f0cb466d3f967")
        self.assertEqual(vuelta.mentions, ["@b"])
        self.assertEqual(vuelta.channel, "#canal")
        self.assertTrue(vuelta.is_relay)
        self.assertTrue(vuelta.is_private)
        self.assertEqual(vuelta.to_bytes(), msg.to_bytes())

    def test_orden_de_campos_es_ascendente_por_flag(self):
        """El receptor lee en orden de flag: si se invirtiera, se rompe."""
        msg = MessagePayload(
            timestamp=TS,
            message_id=UUID_ID,
            sender="a",
            content="b",
            original_sender="o",
            recipient_nickname="d",
            sender_peer_id="peerxx",
            mentions=["mncn"],
            channel="#c",
        )
        raw = msg.to_bytes()
        valores = ("o", "d", "peerxx", "mncn", "#c")
        posiciones = [raw.index(v.encode()) for v in valores]
        self.assertEqual(posiciones, sorted(posiciones), "orden de flags incorrecto")

    def test_contenido_cifrado_sustituye_al_texto(self):
        cifrado = bytes(range(40))
        msg = MessagePayload(
            timestamp=TS, message_id=UUID_ID, sender="a", encrypted_content=cifrado
        )
        self.assertEqual(msg.flags, 0x80)
        vuelta = MessagePayload.parse(msg.to_bytes())
        self.assertTrue(vuelta.is_encrypted)
        self.assertEqual(vuelta.encrypted_content, cifrado)
        self.assertEqual(vuelta.content, "")

    def test_no_se_pueden_dar_content_y_cifrado(self):
        with self.assertRaises(ValueError):
            MessagePayload(
                timestamp=TS, message_id=UUID_ID, sender="a",
                content="x", encrypted_content=b"y",
            )

    def test_utf8_multibyte_cuenta_bytes(self):
        msg = MessagePayload(timestamp=TS, message_id=UUID_ID, sender="josé", content="日本")
        vuelta = MessagePayload.parse(msg.to_bytes())
        self.assertEqual(vuelta.sender, "josé")
        self.assertEqual(vuelta.content, "日本")

    def test_payload_corto_se_rechaza(self):
        with self.assertRaises(ProtocolError):
            MessagePayload.parse(b"\x00" * 12)

    def test_bytes_sobrantes_se_rechazan(self):
        msg = MessagePayload(timestamp=TS, message_id=UUID_ID, sender="a", content="b")
        with self.assertRaises(ProtocolError):
            MessagePayload.parse(msg.to_bytes() + b"\x00\x00")

    def test_limite_de_255_por_campo(self):
        """El limite se comprueba al serializar, no al construir."""
        with self.assertRaises(ValueError):
            MessagePayload(
                timestamp=TS, message_id="x" * 256, sender="a", content="b"
            ).to_bytes()

    def test_limite_de_65535_de_contenido(self):
        with self.assertRaises(ValueError):
            MessagePayload(
                timestamp=TS, message_id=UUID_ID, sender="a", content="x" * 65536
            ).to_bytes()

    def test_255_mentiones_es_el_maximo(self):
        msg = MessagePayload(
            timestamp=TS, message_id=UUID_ID, sender="a", content="b",
            mentions=["m"] * 256,
        )
        with self.assertRaises(ValueError):
            msg.to_bytes()
        # Justo en el limite si pasa.
        ok = MessagePayload(
            timestamp=TS, message_id=UUID_ID, sender="a", content="b",
            mentions=["m"] * 255,
        )
        self.assertEqual(MessagePayload.parse(ok.to_bytes()).mentions, ok.mentions)


class TestRequestSync(unittest.TestCase):
    """GCS: TLV de longitud u16 big-endian."""

    def test_round_trip(self):
        p = RequestSyncPayload(p=5, m=0xFFFF_FFFF, data=b"\xde\xad\xbe\xef")
        vuelta = RequestSyncPayload.parse(p.to_bytes())
        self.assertEqual(vuelta.p, 5)
        self.assertEqual(vuelta.m, 0xFFFF_FFFF)
        self.assertEqual(vuelta.data, b"\xde\xad\xbe\xef")

    def test_layout_exacto(self):
        raw = RequestSyncPayload(p=1, m=2, data=b"").to_bytes()
        # 4 (P) + 7 (M) + 3 (DATA vacio) = 14
        self.assertEqual(len(raw), 14)
        # TLV P: tipo 01, longitud 0001, valor 01
        self.assertEqual(raw[0:4], b"\x01\x00\x01\x01")
        # TLV M: tipo 02, longitud 0004, valor 00000002
        self.assertEqual(raw[4:11], b"\x02\x00\x04\x00\x00\x00\x02")
        # TLV DATA vacio: tipo 03, longitud 0000
        self.assertEqual(raw[11:14], b"\x03\x00\x00")

    def test_m_es_u32_big_endian(self):
        raw = RequestSyncPayload(p=0, m=0x01020304).to_bytes()
        self.assertIn(b"\x01\x02\x03\x04", raw)

    def test_tags_desconocidos_se_ignoran(self):
        raw = RequestSyncPayload(p=3, m=4).to_bytes() + b"\x7f\x00\x02\xaa\xbb"
        vuelta = RequestSyncPayload.parse(raw)
        self.assertEqual(vuelta.p, 3)
        self.assertEqual(vuelta.m, 4)

    def test_faltan_p_o_m_se_rechaza(self):
        with self.assertRaises(ProtocolError):
            RequestSyncPayload.parse(b"\x03\x00\x00")

    def test_p_con_longitud_incorrecta_se_rechaza(self):
        with self.assertRaises(ProtocolError):
            RequestSyncPayload.parse(b"\x01\x00\x02\x05\x06\x02\x00\x04\x00\x00\x00\x01")


class TestFileTransfer(unittest.TestCase):
    """El TLV de contenido usa u32; el resto, u16."""

    def test_round_trip(self):
        p = FileTransferPayload(
            filename="foto.jpg",
            file_size=1234,
            mime_type="image/jpeg",
            content=b"\x89PNG" + bytes(50),
        )
        vuelta = FileTransferPayload.parse(p.to_bytes())
        self.assertEqual(vuelta.filename, "foto.jpg")
        self.assertEqual(vuelta.file_size, 1234)
        self.assertEqual(vuelta.mime_type, "image/jpeg")
        self.assertEqual(vuelta.content, p.content)
        self.assertEqual(vuelta.to_bytes(), p.to_bytes())

    def test_longitud_de_contenido_es_u32(self):
        raw = FileTransferPayload(content=b"x" * 70000).to_bytes()
        # tipo 04 + longitud u32 = 0x00011170
        self.assertEqual(raw[0:5], b"\x04\x00\x01\x11\x70")
        self.assertEqual(raw[5:5 + 70000], b"x" * 70000)

    def test_longitud_de_nombre_es_u16(self):
        raw = FileTransferPayload(filename="a.txt").to_bytes()
        self.assertEqual(raw[0:3], b"\x01\x00\x05")
        self.assertEqual(raw[3:8], b"a.txt")

    def test_tamano_es_u64(self):
        raw = FileTransferPayload(file_size=2**40).to_bytes()
        self.assertEqual(raw[0:3], b"\x02\x00\x08")
        self.assertEqual(raw[3:11], (2**40).to_bytes(8, "big"))

    def test_contenido_partido_se_concatena(self):
        """Varios TLV CONTENT se unen en orden."""
        raw = b"\x04\x00\x00\x00\x03AAA" + b"\x04\x00\x00\x00\x03BBB"
        vuelta = FileTransferPayload.parse(raw)
        self.assertEqual(vuelta.content, b"AAABBB")

    def test_tags_desconocidos_se_saltan_no_se_rechazan(self):
        """Es lo que hace la app oficial: un par puede mandar TLVs nuevos."""
        raw = FileTransferPayload(filename="a.txt").to_bytes() + b"\x7e\x00\x02\xde\xad"
        vuelta = FileTransferPayload.parse(raw)
        self.assertEqual(vuelta.filename, "a.txt")
        self.assertEqual(vuelta.unknown_types, [0x7E])

    def test_cabecera_truncada_se_rechaza(self):
        with self.assertRaises(ProtocolError):
            FileTransferPayload.parse(b"\x01\x00")

    def test_longitud_que_se_pasa_del_final_se_rechaza(self):
        with self.assertRaises(ProtocolError):
            FileTransferPayload.parse(b"\x01\x00\xff" + b"corta")

    def test_tamano_que_no_son_8_bytes_se_rechaza(self):
        with self.assertRaises(ProtocolError):
            FileTransferPayload.parse(b"\x02\x00\x02\x00\x01")

    def test_campos_ausentes_quedan_en_none(self):
        vuelta = FileTransferPayload.parse(FileTransferPayload(filename="a").to_bytes())
        self.assertIsNone(vuelta.file_size)
        self.assertIsNone(vuelta.mime_type)
        self.assertEqual(vuelta.content, b"")


class TestVoiceFrame(unittest.TestCase):
    """`flags` se compara por igualdad exacta, no por mascara."""

    def test_header_de_11_bytes(self):
        p = VoiceFramePayload(bytes(range(8)), 0, CanceledPayload())
        self.assertEqual(len(p.to_bytes()), 11)

    def test_start_lleva_codec(self):
        p = VoiceFramePayload(b"\x01" * 8, 7, StartPayload(VoiceCodec.AAC_LC_16K_MONO))
        raw = p.to_bytes()
        self.assertEqual(len(raw), 12)
        self.assertEqual(raw[8:10], b"\x00\x07")
        self.assertEqual(raw[10], 0x01)
        self.assertEqual(raw[11], 0x01)
        vuelta = VoiceFramePayload.parse(raw)
        self.assertEqual(vuelta.payload.codec, VoiceCodec.AAC_LC_16K_MONO)

    def test_end_lleva_total_y_duracion(self):
        p = VoiceFramePayload(b"\x02" * 8, 3, EndPayload(42, 1_500))
        raw = p.to_bytes()
        self.assertEqual(len(raw), 11 + 6)
        vuelta = VoiceFramePayload.parse(raw)
        self.assertEqual(vuelta.payload.total_data_packets, 42)
        self.assertEqual(vuelta.payload.duration_ms, 1_500)

    def test_canceled_no_trae_datos(self):
        p = VoiceFramePayload(b"\x03" * 8, 1, CanceledPayload())
        self.assertEqual(len(p.to_bytes()), 11)
        vuelta = VoiceFramePayload.parse(p.to_bytes())
        self.assertIsInstance(vuelta.payload, CanceledPayload)

    def test_frames_repiten_longitud(self):
        p = VoiceFramePayload(b"\x04" * 8, 2, FramesPayload([b"\xaa" * 10, b"\xbb" * 5]))
        raw = p.to_bytes()
        self.assertEqual(raw[10], 0x00)
        vuelta = VoiceFramePayload.parse(raw)
        self.assertEqual([len(f) for f in vuelta.payload.frames], [10, 5])
        self.assertEqual(vuelta.payload.frames[0], b"\xaa" * 10)

    def test_flags_combinado_se_rechaza(self):
        """`0x03` no casa con ningun caso del `when` de Kotlin."""
        with self.assertRaises(ProtocolError):
            VoiceFramePayload.parse(bytes(8) + b"\x00\x01" + b"\x03")

    def test_maximo_8_tramas(self):
        with self.assertRaises(ValueError):
            VoiceFramePayload(b"\x05" * 8, 0, FramesPayload([b"x"] * 9)).to_bytes()

    def test_ocho_tramas_si_valen(self):
        p = VoiceFramePayload(b"\x05" * 8, 0, FramesPayload([b"x"] * 8))
        self.assertEqual(len(VoiceFramePayload.parse(p.to_bytes()).payload.frames), 8)

    def test_trama_de_longitud_cero_se_rechaza(self):
        with self.assertRaises(ProtocolError):
            VoiceFramePayload.parse(bytes(8) + b"\x00\x00" + b"\x00" + b"\x00\x00")

    def test_cabecera_mas_corta_que_11_falla(self):
        with self.assertRaises(ProtocolError):
            VoiceFramePayload.parse(bytes(10))

    def test_sequence_fuera_de_rango(self):
        with self.assertRaises(ValueError):
            VoiceFramePayload(b"\x06" * 8, 0x10000, CanceledPayload())

    def test_burst_id_de_longitud_correcta(self):
        with self.assertRaises(ValueError):
            VoiceFramePayload(b"\x07" * 4, 0, CanceledPayload())

    def test_kind_es_exacto(self):
        self.assertEqual(Kind(0x00), Kind.FRAMES)
        self.assertEqual(Kind(0x01), Kind.START)
        self.assertEqual(Kind(0x02), Kind.END)
        self.assertEqual(Kind(0x04), Kind.CANCELED)

    def test_orden_en_la_rafaga(self):
        """Start -> frames -> End, con la secuencia avanzando."""
        rafaga = [
            VoiceFramePayload(b"\x09" * 8, 0, StartPayload(VoiceCodec.AAC_LC_16K_MONO)),
            VoiceFramePayload(b"\x09" * 8, 1, FramesPayload([b"\x01\x02"])),
            VoiceFramePayload(b"\x09" * 8, 2, EndPayload(1, 120)),
        ]
        vuelta = [VoiceFramePayload.parse(p.to_bytes()) for p in rafaga]
        self.assertIsInstance(vuelta[0].payload, StartPayload)
        self.assertIsInstance(vuelta[1].payload, FramesPayload)
        self.assertIsInstance(vuelta[2].payload, EndPayload)
        self.assertEqual([v.sequence for v in vuelta], [0, 1, 2])
        self.assertEqual(len({v.burst_id for v in vuelta}), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)