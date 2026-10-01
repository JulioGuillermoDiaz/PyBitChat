"""Tests del despacho de `decode_payload` tras cerrar H6, H7 y H8.

Comprueba que los decoders nuevos están registrados, que `0x22` sigue siendo
ambiguo sin dialecto, y que ya no se conservan opacos los tipos resueltos.

Ejecutar:
    .venv\\Scripts\\python.exe tests\\test_dispatch.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol.message import MessagePayload  # noqa: E402
from pybitchat.protocol.payloads import (  # noqa: E402
    AMBIGUOUS_VALUES,
    CURRENT,
    DECODED_TYPES,
    LEGACY,
    OPEN_QUESTIONS,
    OPAQUE_BY_DIALECT,
    OPAQUE_TYPES,
    RESOLVED_QUESTIONS,
    FileTransferPayload,
    OpaquePayload,
    RequestSyncPayload,
    VoiceFramePayload,
    decode_payload,
)
from pybitchat.protocol.types import LegacyMessageType, MessageType  # noqa: E402


class TestTiposResueltos(unittest.TestCase):
    """H6, H7 y H8 pasan de opaco a decodificado."""

    def test_h6_h7_h8_ya_no_estan_abiertos(self):
        for tipo in (MessageType.REQUEST_SYNC, MessageType.FILE_TRANSFER,
                     MessageType.VOICE_FRAME):
            with self.subTest(tipo=tipo.name):
                self.assertNotIn((CURRENT, int(tipo)), OPEN_QUESTIONS)

    def test_h6_h7_h8_estan_registrados_como_resueltos(self):
        self.assertEqual(RESOLVED_QUESTIONS[(CURRENT, int(MessageType.REQUEST_SYNC))], "H6")
        self.assertEqual(RESOLVED_QUESTIONS[(CURRENT, int(MessageType.FILE_TRANSFER))], "H7")
        self.assertEqual(RESOLVED_QUESTIONS[(CURRENT, int(MessageType.VOICE_FRAME))], "H8")

    def test_ya_no_son_opacos(self):
        for tipo in (MessageType.REQUEST_SYNC, MessageType.FILE_TRANSFER,
                     MessageType.VOICE_FRAME):
            with self.subTest(tipo=tipo.name):
                self.assertIn(int(tipo), DECODED_TYPES)
                self.assertNotIn(int(tipo), OPAQUE_BY_DIALECT[CURRENT])

    def test_022_sigue_opaco_en_legacy_pero_no_en_current(self):
        """La vista plana mezcla dialectos: la vista por dialecto no."""
        self.assertIn(int(MessageType.FILE_TRANSFER), OPAQUE_TYPES)
        self.assertIn(int(MessageType.FILE_TRANSFER), OPAQUE_BY_DIALECT[LEGACY])
        self.assertNotIn(int(MessageType.FILE_TRANSFER), OPAQUE_BY_DIALECT[CURRENT])

    def test_request_sync_se_decodifica(self):
        crudo = RequestSyncPayload(p=3, m=1024, data=b"\xaa\xbb").to_bytes()
        vuelta = decode_payload(int(MessageType.REQUEST_SYNC), crudo, CURRENT)
        self.assertIsInstance(vuelta, RequestSyncPayload)
        self.assertEqual(vuelta.p, 3)
        self.assertEqual(vuelta.m, 1024)

    def test_file_transfer_se_decodifica(self):
        crudo = FileTransferPayload(
            filename="a.txt", file_size=5, mime_type="text/plain", content=b"hola"
        ).to_bytes()
        vuelta = decode_payload(int(MessageType.FILE_TRANSFER), crudo, CURRENT)
        self.assertIsInstance(vuelta, FileTransferPayload)
        self.assertEqual(vuelta.filename, "a.txt")
        self.assertEqual(vuelta.content, b"hola")

    def test_voice_frame_se_decodifica(self):
        from pybitchat.protocol.voice import CanceledPayload, VoiceFramePayload as VF

        crudo = VF(b"\x01" * 8, 0, CanceledPayload()).to_bytes()
        vuelta = decode_payload(int(MessageType.VOICE_FRAME), crudo, CURRENT)
        self.assertIsInstance(vuelta, VoiceFramePayload)
        self.assertEqual(vuelta.burst_id, b"\x01" * 8)

    def test_message_sigue_funcionando(self):
        crudo = MessagePayload(
            timestamp=1, message_id="i", sender="s", content="c", channel="#x"
        ).to_bytes()
        vuelta = decode_payload(int(MessageType.MESSAGE), crudo, CURRENT)
        self.assertIsInstance(vuelta, MessagePayload)
        self.assertEqual(vuelta.channel, "#x")


class TestAmbiguedad022(unittest.TestCase):
    """`0x22` es el caso delicado: renumerado de `PROTOCOL_ACK` a `FILE_TRANSFER`."""

    def test_sigue_siendo_ambiguo(self):
        self.assertIn(int(LegacyMessageType.PROTOCOL_ACK), AMBIGUOUS_VALUES)
        self.assertIn(int(MessageType.FILE_TRANSFER), AMBIGUOUS_VALUES)

    def test_sin_dialecto_se_conserva_opaco(self):
        crudo = FileTransferPayload(filename="a.txt").to_bytes()
        vuelta = decode_payload(int(MessageType.FILE_TRANSFER), crudo, None)
        self.assertIsInstance(vuelta, OpaquePayload)
        self.assertEqual(vuelta.raw, crudo, "el opaco debe ser byte-exacto")
        self.assertIn("ambiguo", vuelta.open_question)

    def test_con_dialecto_actual_si_decodifica(self):
        crudo = FileTransferPayload(filename="a.txt").to_bytes()
        vuelta = decode_payload(int(MessageType.FILE_TRANSFER), crudo, CURRENT)
        self.assertIsInstance(vuelta, FileTransferPayload)

    def test_dialecto_actual_no_puede_significar_protocol_ack(self):
        """`PROTOCOL_ACK` sigue sin decodificar **en legacy**.

        Es el caso que motivó indexar por dialecto: `0x22` está resuelto en el
        dialecto actual (H7) y sin decodificar en el legacy (H5). Con una clave
        de un solo int, una de las dos se habría perdido.
        """
        self.assertIn((LEGACY, int(LegacyMessageType.PROTOCOL_ACK)), OPEN_QUESTIONS)
        self.assertNotIn((CURRENT, int(MessageType.FILE_TRANSFER)), OPEN_QUESTIONS)
        self.assertIn((CURRENT, int(MessageType.FILE_TRANSFER)), RESOLVED_QUESTIONS)


class TestHuecosQueNoSeCierran(unittest.TestCase):
    """H3, H4 y H5 son tipos del dialecto retirado: no tienen equivalente vivo."""

    def test_h3_y_h4_no_existen_en_el_dialecto_actual(self):
        for nombre in ("NOISE_IDENTITY_ANNOUNCE", "HANDSHAKE_REQUEST"):
            with self.subTest(tipo=nombre):
                self.assertFalse(
                    any(m.name == nombre for m in MessageType),
                    f"{nombre} no existe en MessageType: no hay nada que decodificar",
                )

    def test_h3_y_h4_siguen_en_el_legacy(self):
        for nombre in ("NOISE_IDENTITY_ANNOUNCE", "HANDSHAKE_REQUEST"):
            with self.subTest(tipo=nombre):
                self.assertTrue(any(m.name == nombre for m in LegacyMessageType))
                self.assertIn(
                    (LEGACY, int(getattr(LegacyMessageType, nombre))),
                    OPEN_QUESTIONS,
                )

    def test_h2_sigue_abierto(self):
        """El handshake en sí está resuelto; sus dos envoltorios no."""
        self.assertIn((CURRENT, int(MessageType.NOISE_HANDSHAKE)), OPEN_QUESTIONS)
        self.assertIn((LEGACY, int(LegacyMessageType.NOISE_HANDSHAKE_INIT)), OPEN_QUESTIONS)
        self.assertIn((LEGACY, int(LegacyMessageType.NOISE_HANDSHAKE_RESP)), OPEN_QUESTIONS)

    def test_open_question_for_usa_el_dialecto(self):
        from pybitchat.protocol.payloads import open_question_for

        # 0x22: H5 en legacy, resuelto en current.
        self.assertEqual(open_question_for(0x22, LEGACY), "H5")
        self.assertIsNone(open_question_for(0x22, CURRENT))
        # Sin dialecto se busca en ambos, aunque el valor sea ambiguo.
        self.assertEqual(open_question_for(0x11, None), "H2")  # legacy RESP
        self.assertEqual(open_question_for(0x13, None), "H3")  # sólo legacy
        self.assertIsNone(open_question_for(0x21, None))  # H6, ya resuelto


class TestErrores(unittest.TestCase):
    def test_dialecto_invalido(self):
        with self.assertRaises(ValueError):
            decode_payload(int(MessageType.ANNOUNCE), b"x", "otro")

    def test_tipo_desconocido_se_conserva_opaco(self):
        vuelta = decode_payload(0x7E, b"\x01\x02", CURRENT)
        self.assertIsInstance(vuelta, OpaquePayload)
        self.assertEqual(vuelta.raw, b"\x01\x02")

    def test_payload_corrupto_propaga_el_error(self):
        """Un decoder confirmado que falla es un bug: no se esconde tras opaco."""
        with self.assertRaises(Exception):
            decode_payload(int(MessageType.REQUEST_SYNC), b"\x03\x00\x00", CURRENT)


if __name__ == "__main__":
    unittest.main(verbosity=2)