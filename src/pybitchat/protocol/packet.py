"""Codificación binaria de la cabecera y el sobre de paquete BitChat.

Layout verificado empíricamente contra los volcados hex de paquetes reales de
iOS presentes en `reference/bitchat-tui/*.log`, y contra `protocol/BinaryProtocol.kt`
de `permissionlesstech/bitchat-android`:

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

## Payload comprimido

Si `IS_COMPRESSED` (0x04) está activo, `payload_len` incluye el prefijo del
tamaño original y el payload va así:

    payload = original_size (u16 BE) ‖ datos DEFLATE crudo

Para v1 el tamaño original es **u16**. El u32 pertenece a v2
(`BinaryProtocol.kt:343` vs `:341`), que no se implementa aquí: ver la nota de
limitaciones más abajo.

## Limitación conocida: sólo v1

`BinaryProtocol.decode` acepta v1 y v2 (`BinaryProtocol.kt:409`), y define
`HEADER_SIZE_V2 = 16` con longitud u32 y ruta opcional. Este módulo **rechaza
v2**. Es aceptable porque la app emite siempre v1 —el valor por defecto de
`BitchatPacket.version` es `1u` (`:78`)—, así que un cliente v1 nunca verá un
v2 de un par Android. Habría que añadirlo sólo si apareciera un par que sí lo
emita.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field, replace

from . import compression
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


class UnsupportedVersionError(ProtocolError):
    """La versión de protocolo es válida pero todavía no está implementada."""


#: Versiones que el otro extremo acepta (`BinaryProtocol.kt:409`) pero que aquí
#: no se implementan. Sirve para dar un error útil en vez de "desconocida".
SUPPORTED_UPSTREAM_VERSIONS = frozenset({0x02})


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
            if version in SUPPORTED_UPSTREAM_VERSIONS:
                raise UnsupportedVersionError(
                    f"versión de protocolo v{version} reconocida pero no "
                    f"implementada: cabecera de 16 B, longitud u32 y ruta opcional"
                )
            raise ProtocolError(f"versión de protocolo desconocida: {version:#04x}")
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


@dataclass(frozen=True, slots=True)
class WirePayload:
    """Los bytes del payload **tal y como llegaron por el cable**.

    Existe por una razón que no es obvia y que no se puede ignorar. La salida
    de DEFLATE no es canónica: el `Deflater` de Java y el `zlib` de Python
    producen bytes distintos para la misma entrada. Como la verificación de firma
    re-codifica el paquete para reconstruir lo que se firmó, re-comprimir un
    payload ajeno cambiaría la preimagen y **haría que una firma válida dejara de
    validar**. De ahí la nota de `BinaryProtocol.kt:43-45`.

    Guardamos los bytes originales, sin el prefijo de tamaño, igual que hace
    `receivedCompressed` en `BinaryProtocol.kt:527-530`. Al re-codificar se
    reusan tal cual. Esto también evita que un relé que decrementa el TTL
    sustituya la codificación de quien lo originó (`BinaryProtocol.kt:46`).

    No es un `dataclass` con `eq` generado a propósito: comparar el *contenido*
    de dos bytearrays en un dataclass generado compara referencias, que es el
    fallo que el propio Android señala en `:51`.

    `payload` ata los bytes del cable al payload que producen: si alguien cambia
    el payload, `compressed` deja de ser válido y hay que comprimir de nuevo.
    """

    wire: bytes
    compressed: bool
    payload: bytes

    def matches(self, payload: bytes) -> bool:
        return self.compressed and self.payload == payload


@dataclass(slots=True)
class Packet:
    """Sobre completo: cabecera + ids + payload + firma + relleno."""

    header: PacketHeader
    sender_id: bytes
    payload: bytes
    recipient_id: bytes | None = None
    signature: bytes | None = None
    padding: bytes = field(default=b"", repr=False)
    #: Bytes originales del cable, si el payload vino comprimido. `None` si vino
    #: en claro o si lo generamos nosotros.
    wire_payload: WirePayload | None = field(default=None, repr=False)

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

        wire_payload = None
        if header.flags & PacketFlags.IS_COMPRESSED:
            # v1: el tamaño original ocupa 2 bytes dentro de payload_len.
            if header.payload_len < 2:
                raise ProtocolError(
                    f"payload comprimido demasiado corto: {header.payload_len} B "
                    "no alcanza ni para el tamaño original"
                )
            original_size = r.u16("original_size")
            comprimido = r.raw(header.payload_len - 2, "compressed_payload")
            try:
                payload = compression.decompress(comprimido, original_size)
            except compression.CompressionError as exc:
                raise ProtocolError(f"no se pudo descomprimir el payload: {exc}") from exc
            wire_payload = WirePayload(comprimido, True, payload)
        else:
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
            wire_payload=wire_payload,
        )

    # -- compresión ----------------------------------------------------------

    def with_compression(self) -> "Packet":
        """Devuelve una copia con el payload comprimido, si merece la pena.

        Android decide esto solo al codificar (`BinaryProtocol.kt:253`). Aquí es
        explícito, y el resultado es equivalente desde el punto de vista del
        receptor: éste infla lo que llegue. Lo que sí cambia es cuándo se
        decide, y hacerlo aquí permite que la firma se calcule sobre los bytes
        definitivos.

        Devuelve `self` sin cambios si la compresión no procede o no reduce.
        """
        if self.wire_payload is not None and self.wire_payload.matches(self.payload):
            return self
        comprimido = compression.compress(self.payload)
        if comprimido is None:
            return self
        return replace(
            self,
            wire_payload=WirePayload(comprimido, True, self.payload),
        )

    # -- serialización ------------------------------------------------------

    def _payload_wire(self) -> tuple[int, bytes]:
        """Flag de compresión y bytes a emitir, en orden de prioridad.

        Si el payload vino comprimido por alguien y sigue siendo el mismo, se
        reusan sus bytes. Re-comprimir aquí es justo el error que rompe las
        firmas ajenas.
        """
        if self.wire_payload is not None and self.wire_payload.matches(self.payload):
            cabecera = struct.pack(">H", len(self.payload))
            return int(PacketFlags.IS_COMPRESSED), cabecera + self.wire_payload.wire
        return 0, self.payload

    def to_bytes(self, *, include_padding: bool = True) -> bytes:
        flags = PacketFlags(0)
        if self.recipient_id is not None:
            flags |= PacketFlags.HAS_RECIPIENT
        if self.signature is not None:
            flags |= PacketFlags.HAS_SIGNATURE
        flag_compresion, cuerpo_payload = self._payload_wire()
        flags |= PacketFlags(flag_compresion)

        parts = [
            struct.pack(">BBB", PROTOCOL_VERSION, self.header.raw_type, self.header.ttl),
            struct.pack(">Q", self.header.timestamp),
            struct.pack(">B", int(flags)),
            struct.pack(">H", len(cuerpo_payload)),
            self.sender_id,
        ]
        if self.recipient_id is not None:
            if len(self.recipient_id) != PEER_ID_SIZE:
                raise ProtocolError(
                    f"recipient_id debe tener {PEER_ID_SIZE} bytes, "
                    f"tiene {len(self.recipient_id)}"
                )
            parts.append(self.recipient_id)
        parts.append(cuerpo_payload)
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