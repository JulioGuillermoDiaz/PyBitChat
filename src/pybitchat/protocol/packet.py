"""Codificación binaria de la cabecera y el sobre de paquete BitChat.

Layout verificado empíricamente contra los volcados hex de paquetes reales de
iOS presentes en `reference/bitchat-tui/*.log`:

    offset  tamaño  campo
    ------  ------  ---------------------------------------------------
    0       1       version            = 0x01
    1       1       type               (MessageType)
    2       1       ttl
    3       8       timestamp          u64 big-endian, epoch Unix en ms
    11      1       flags              (PacketFlags)
    12      2       payload_len        u16 big-endian
    14      8       sender_id          si no hay padding previo
    22      8       recipient_id       sólo si HAS_RECIPIENT
    ..      N       payload            payload_len bytes
    ..      64      signature          sólo si HAS_SIGNATURE
    ..      M       padding            resto hasta el cubo de tamaño

Evidencia cruzada (paquete NoiseEncrypted de 512 B, `debug.log:37-42`):
los bytes 12-13 valen `0x01 0x14` = 276, que coincide exactamente con el
`Packet payload length: 276` registrado por el cliente Rust.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .types import (
    HEADER_SIZE,
    PEER_ID_SIZE,
    PADDING_BUCKETS,
    PROTOCOL_VERSION,
    SIGNATURE_SIZE,
    LegacyMessageType,
    MessageType,
    PacketFlags,
)


class ProtocolError(ValueError):
    """El byte stream no cumple el formato esperado."""


class Reader:
    """Lector secuencial big-endian sobre un buffer de bytes."""

    __slots__ = ("_buf", "_pos")

    def __init__(self, buf: bytes) -> None:
        self._buf = buf
        self._pos = 0

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._buf) - self._pos

    def _take(self, n: int, what: str) -> bytes:
        if n < 0:
            raise ProtocolError(f"longitud negativa para {what}: {n}")
        end = self._pos + n
        if end > len(self._buf):
            raise ProtocolError(
                f"truncado leyendo {what}: se piden {n} bytes en offset "
                f"{self._pos}, sólo quedan {self.remaining}"
            )
        chunk = self._buf[self._pos : end]
        self._pos = end
        return chunk

    def u8(self, what: str = "u8") -> int:
        return self._take(1, what)[0]

    def u16(self, what: str = "u16") -> int:
        return struct.unpack(">H", self._take(2, what))[0]

    def u32(self, what: str = "u32") -> int:
        return struct.unpack(">I", self._take(4, what))[0]

    def u64(self, what: str = "u64") -> int:
        return struct.unpack(">Q", self._take(8, what))[0]

    def raw(self, n: int, what: str = "raw") -> bytes:
        return self._take(n, what)

    def rest(self) -> bytes:
        chunk = self._buf[self._pos :]
        self._pos = len(self._buf)
        return chunk


def _u16_prefixed(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ProtocolError(
            f"campo con prefijo u16 supera el máximo: {len(value)} > 65535"
        )
    return struct.pack(">H", len(value)) + value


def _u8_prefixed(value: bytes) -> bytes:
    if len(value) > 0xFF:
        raise ProtocolError(
            f"campo con prefijo u8 supera el máximo: {len(value)} > 255"
        )
    return bytes((len(value),)) + value


@dataclass(frozen=True, slots=True)
class PacketHeader:
    """Cabecera de 14 bytes.

    El byte de tipo se guarda **crudo** (`raw_type`) porque BitChat tiene dos
    dialectos vivos y renumerados entre sí. Se exponen dos vistas:

    - `.type`        -> `MessageType` del dialecto actual, o `None`
    - `.legacy_type` -> `LegacyMessageType` del dialecto de `bitchat-tui`, o `None`

    Un valor crudo puede no existir en ninguno de los dos (tramas de versiones
    futuras), y eso no es un error de sintaxis: se conserva igual.
    """

    version: int
    raw_type: int
    ttl: int
    timestamp: int
    flags: PacketFlags
    payload_len: int

    @property
    def type(self) -> MessageType | None:
        """Tipo en el dialecto actual, o `None` si ese valor no existe allí."""
        return MessageType._value2member_map_.get(self.raw_type)

    @property
    def legacy_type(self) -> LegacyMessageType | None:
        """Tipo en el dialecto retirado, o `None` si no existe allí."""
        return LegacyMessageType._value2member_map_.get(self.raw_type)

    @property
    def type_name(self) -> str:
        """Nombre legible del tipo, con el dialecto indicado si hay ambigüedad."""
        actual, legacy = self.type, self.legacy_type
        if actual is not None and legacy is not None:
            return f"0x{self.raw_type:02x}({actual.name}/{legacy.name})"
        if actual is not None:
            return actual.name
        if legacy is not None:
            return legacy.name
        return f"0x{self.raw_type:02x}(desconocido)"

    @classmethod
    def parse(cls, r: Reader) -> "PacketHeader":
        version = r.u8("version")
        if version != PROTOCOL_VERSION:
            raise ProtocolError(f"versión de protocolo no soportada: {version:#04x}")
        raw_type = r.u8("type")
        ttl = r.u8("ttl")
        timestamp = r.u64("timestamp")
        flags = PacketFlags(r.u8("flags"))
        payload_len = r.u16("payload_len")
        return cls(version, raw_type, ttl, timestamp, flags, payload_len)

    def to_bytes(self) -> bytes:
        return b"".join(
            (
                struct.pack(">B", self.version),
                struct.pack(">B", self.raw_type),
                struct.pack(">B", self.ttl),
                struct.pack(">Q", self.timestamp),
                struct.pack(">B", int(self.flags)),
                struct.pack(">H", self.payload_len),
            )
        )


@dataclass(slots=True)
class Packet:
    """Sobre completo: cabecera + ids + payload + firma + relleno."""

    header: PacketHeader
    sender_id: bytes
    payload: bytes
    recipient_id: bytes | None = None
    signature: bytes | None = None
    padding: bytes = field(default=b"", repr=False)

    # -- construcción desde bytes -------------------------------------------

    @classmethod
    def from_bytes(cls, buf: bytes) -> "Packet":
        r = Reader(buf)
        header = PacketHeader.parse(r)
        assert r.pos == HEADER_SIZE, "cabecera mal dimensionada"

        sender_id = r.raw(PEER_ID_SIZE, "sender_id")

        recipient_id = None
        if header.flags & PacketFlags.HAS_RECIPIENT:
            recipient_id = r.raw(PEER_ID_SIZE, "recipient_id")

        payload = r.raw(header.payload_len, "payload")

        signature = None
        if header.flags & PacketFlags.HAS_SIGNATURE:
            signature = r.raw(SIGNATURE_SIZE, "signature")

        return cls(
            header=header,
            sender_id=sender_id,
            payload=payload,
            recipient_id=recipient_id,
            signature=signature,
            padding=r.rest(),
        )

    # -- serialización ------------------------------------------------------

    def to_bytes(self, *, include_padding: bool = True) -> bytes:
        flags = PacketFlags(0)
        if self.recipient_id is not None:
            flags |= PacketFlags.HAS_RECIPIENT
        if self.signature is not None:
            flags |= PacketFlags.HAS_SIGNATURE
        # Los flags de compresión no se propagan aquí: la compresión está
        # inactiva en la implementación de referencia (packet_creation.rs:125).

        parts = [
            struct.pack(">BBB", PROTOCOL_VERSION, self.header.raw_type, self.header.ttl),
            struct.pack(">Q", self.header.timestamp),
            struct.pack(">B", int(flags)),
            struct.pack(">H", len(self.payload)),
            self.sender_id,
        ]
        if self.recipient_id is not None:
            if len(self.recipient_id) != PEER_ID_SIZE:
                raise ProtocolError(
                    f"recipient_id debe tener {PEER_ID_SIZE} bytes, "
                    f"tiene {len(self.recipient_id)}"
                )
            parts.append(self.recipient_id)
        parts.append(self.payload)
        if self.signature is not None:
            if len(self.signature) != SIGNATURE_SIZE:
                raise ProtocolError(
                    f"la firma debe tener {SIGNATURE_SIZE} bytes, "
                    f"tiene {len(self.signature)}"
                )
            parts.append(self.signature)
        if include_padding:
            parts.append(self.padding)
        return b"".join(parts)

    # -- utilidades ---------------------------------------------------------

    @property
    def sender_id_hex(self) -> str:
        return self.sender_id.hex()

    @property
    def recipient_id_hex(self) -> str | None:
        return self.recipient_id.hex() if self.recipient_id is not None else None

    def __len__(self) -> int:
        return len(self.to_bytes())


def pkcs7_pad_to_bucket(data: bytes, buckets: tuple[int, ...] = PADDING_BUCKETS) -> bytes:
    """Rellena `data` al siguiente cubo de `buckets` con bytes PKCS#7.

    La app oficial rellena con bytes aleatorios y el último byte igual a la
    longitud del relleno (`packet_creation.rs:46-55`). La longitud del
    relleno debe caber en un byte, así que un payload que necesite más de
    255 bytes de relleno se emite sin rellenar.

    Nota: la implementación de referencia usa *bytes aleatorios* aquí pero
    *byte repetido* en `command_handling.rs:326`. Es una inconsistencia
    conocida del código original; aquí se usa la forma PKCS#7 estándar.
    """
    for bucket in buckets:
        if len(data) <= bucket:
            needed = bucket - len(data)
            if needed == 0:
                return data
            if needed > 255:
                # PKCS#7 no puede codificar un relleno de más de 255 bytes.
                return data
            return data + bytes([needed]) * needed
    # Por encima del cubo más grande no hay nada que hacer.
    return data