"""Payload de `MESSAGE` (0x02) del dialecto actual.

Layout cerrado leyendo `model/BitchatMessage.kt` de
`permissionlesstech/bitchat-android` por las dos caras, `toBinaryPayload()` y
`fromBinaryPayload()`:

    offset  tamaño  campo                      flag
    ------  ------  -------------------------  ----
    0       1       flags                      -
    1       8       timestamp (epoch ms)       -
    9       1       id_len                     -
    10      n       id (UTF-8)                 -
    ..      1       sender_len                 -
    ..      n       sender (UTF-8)             -
    ..      2       content_len                -
    ..      n       content (UTF-8)             -
    ..      1       original_sender_len        0x04
    ..      n       original_sender (UTF-8)    0x04
    ..      1       recipient_nickname_len     0x08
    ..      n       recipient_nickname         0x08
    ..      1       sender_peer_id_len         0x10
    ..      n       sender_peer_id             0x10
    ..      1       mentions_count            0x20
    ..      ..      mentions (len+bytes) × N   0x20
    ..      1       channel_len                0x40
    ..      n       channel (UTF-8)            0x40

Detalles que no son evidentes:

- **Todos los enteros son big-endian.** El `ByteBuffer` se crea con
  `order(ByteOrder.BIG_ENDIAN)` explícito (`:190`).
- **El orden de los campos opcionales es el orden ascendente de sus flags**
  (0x04, 0x08, 0x10, 0x20, 0x40). No es arbitrario: si se escribieran en otro
  orden, el receptor leería longitudes equivocadas.
- **`isEncrypted` (0x80) no añade un campo**: sustituye el contenido por bytes
  opacos, manteniendo el prefijo u16 de longitud.
- El tamaño mínimo es 13 bytes, que es lo que comprueba el decoder (`:188`).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .packet import ProtocolError, Reader

#: Tamaño mínimo aceptable por el decoder oficial (`:188`).
MIN_PAYLOAD_SIZE = 13


class UnsupportedPayloadField(ProtocolError):
    """El payload usa un campo cuyo layout todavía no se ha confirmado."""


class MessagePayload:
    """Payload de un mensaje (público, de canal o privado)."""

    __slots__ = (
        "timestamp",
        "message_id",
        "sender",
        "content",
        "encrypted_content",
        "is_relay",
        "is_private",
        "original_sender",
        "recipient_nickname",
        "sender_peer_id",
        "mentions",
        "channel",
    )

    def __init__(
        self,
        *,
        timestamp: int,
        message_id: str,
        sender: str,
        content: str = "",
        encrypted_content: bytes | None = None,
        is_relay: bool = False,
        is_private: bool = False,
        original_sender: str | None = None,
        recipient_nickname: str | None = None,
        sender_peer_id: str | None = None,
        mentions: list[str] | None = None,
        channel: str | None = None,
    ) -> None:
        if encrypted_content is not None and content:
            raise ValueError("no se pueden dar content y encrypted_content a la vez")
        self.timestamp = timestamp
        self.message_id = message_id
        self.sender = sender
        self.content = content
        self.encrypted_content = encrypted_content
        self.is_relay = is_relay
        self.is_private = is_private
        self.original_sender = original_sender
        self.recipient_nickname = recipient_nickname
        self.sender_peer_id = sender_peer_id
        self.mentions = list(mentions) if mentions else None
        self.channel = channel

    # -- flags --------------------------------------------------------------

    FLAGS = {
        "is_relay": 0x01,
        "is_private": 0x02,
        "original_sender": 0x04,
        "recipient_nickname": 0x08,
        "sender_peer_id": 0x10,
        "mentions": 0x20,
        "channel": 0x40,
        "encrypted": 0x80,
    }

    #: Flags que son banderas booleanas, no campos opcionales. La distinción
    #: importa: `False is not None` es `True` en Python, así que tratar
    #: `is_relay` como un campo opcional activaría el flag siempre.
    BOOL_FLAGS = frozenset({"is_relay", "is_private"})

    @property
    def is_encrypted(self) -> bool:
        return self.encrypted_content is not None

    def _flag(self, nombre: str) -> bool:
        if nombre == "encrypted":
            return self.is_encrypted
        if nombre in self.BOOL_FLAGS:
            return bool(getattr(self, nombre))
        return getattr(self, nombre) is not None

    @property
    def flags(self) -> int:
        flags = 0
        for nombre, bit in self.FLAGS.items():
            if self._flag(nombre):
                flags |= bit
        return flags

    # -- decodificación -----------------------------------------------------

    @classmethod
    def parse(cls, data: bytes) -> "MessagePayload":
        if len(data) < MIN_PAYLOAD_SIZE:
            raise ProtocolError(
                f"payload de mensaje demasiado corto: {len(data)} < {MIN_PAYLOAD_SIZE} B"
            )

        r = Reader(data)
        flags = r.u8("flags")
        timestamp = r.u64("timestamp")

        message_id = r.raw(r.u8("id_len"), "id").decode("utf-8")
        sender = r.raw(r.u8("sender_len"), "sender").decode("utf-8")

        length = r.u16("content_len")
        if flags & 0x80:
            content, encrypted = "", r.raw(length, "encrypted_content")
        else:
            content, encrypted = r.raw(length, "content").decode("utf-8"), None

        def opt_u8() -> str | None:
            return r.raw(r.u8("longitud opcional"), "campo opcional").decode("utf-8")

        original_sender = opt_u8() if flags & 0x04 else None
        recipient_nickname = opt_u8() if flags & 0x08 else None
        sender_peer_id = opt_u8() if flags & 0x10 else None

        mentions = None
        if flags & 0x20:
            count = r.u8("número de menciones")
            mentions = [r.raw(r.u8("longitud de mención"), "mención").decode("utf-8")
                        for _ in range(count)]

        channel = opt_u8() if flags & 0x40 else None

        if r.remaining:
            raise ProtocolError(
                f"quedan {r.remaining} bytes sin decodificar: el layout documentado "
                "está incompleto o las flags no coinciden con los campos"
            )

        return cls(
            timestamp=timestamp,
            message_id=message_id,
            sender=sender,
            content=content,
            encrypted_content=encrypted,
            is_relay=bool(flags & 0x01),
            is_private=bool(flags & 0x02),
            original_sender=original_sender,
            recipient_nickname=recipient_nickname,
            sender_peer_id=sender_peer_id,
            mentions=mentions,
            channel=channel,
        )

    # -- codificación -------------------------------------------------------

    def to_bytes(self) -> bytes:
        if len(self.message_id.encode("utf-8")) > 0xFF:
            raise ValueError("el id no puede pasar de 255 bytes")
        if len(self.sender.encode("utf-8")) > 0xFF:
            raise ValueError("el sender no puede pasar de 255 bytes")
        if self.mentions is not None and len(self.mentions) > 0xFF:
            raise ValueError("no se admiten más de 255 menciones")

        cuerpo = self.encrypted_content if self.is_encrypted else self.content.encode("utf-8")
        if len(cuerpo) > 0xFFFF:
            raise ValueError(f"el contenido no puede pasar de 65535 bytes: {len(cuerpo)}")

        partes = [
            struct.pack(">B", self.flags),
            struct.pack(">Q", self.timestamp),
            _u8_str(self.message_id),
            _u8_str(self.sender),
            struct.pack(">H", len(cuerpo)) + cuerpo,
        ]
        # Orden ascendente de flags, como en toBinaryPayload().
        for nombre in ("original_sender", "recipient_nickname", "sender_peer_id"):
            valor = getattr(self, nombre)
            if valor is not None:
                partes.append(_u8_str(valor))
        if self.mentions is not None:
            partes.append(struct.pack(">B", len(self.mentions)))
            for mencion in self.mentions:
                partes.append(_u8_str(mencion))
        if self.channel is not None:
            partes.append(_u8_str(self.channel))
        return b"".join(partes)

    # -- utilidades ---------------------------------------------------------

    def __repr__(self) -> str:
        extra = []
        if self.channel:
            extra.append(f"channel={self.channel!r}")
        if self.is_encrypted:
            extra.append("encrypted")
        return (
            f"MessagePayload(sender={self.sender!r}, content={self.content[:24]!r}"
            + (f", {', '.join(extra)}" if extra else "")
            + ")"
        )


def _u8_str(valor: str) -> bytes:
    raw = valor.encode("utf-8")
    if len(raw) > 0xFF:
        raise ValueError(f"el campo no puede pasar de 255 bytes: {len(raw)}")
    return bytes((len(raw),)) + raw


__all__ = ["MIN_PAYLOAD_SIZE", "MessagePayload", "UnsupportedPayloadField"]