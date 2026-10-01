"""Payload de `VOICE_FRAME` (0x29): ráfaga de voz.

Layout de `features/voice/VoiceBurstPacket.kt`
(`permissionlesstech/bitchat-android`):

    offset  tamaño  campo
    ------  ------  -----------------------------------------------
    0       8       burst_id
    8       2       sequence            u16 big-endian
    10      1       flags               0x00 | 0x01 | 0x02 | 0x04

    y según flags, desde el offset 11:

    flags   contenido
    ------  ------------------------------------------------------------
    0x01    codec (u8)                        -- inicio de ráfaga
    0x02    total_data_packets (u16 BE)       -- fin de ráfaga
            duration_ms (u32 BE)
    0x04    (nada)                            -- cancelada
    0x00    [frame_len (u16 BE) ‖ frame] × N  -- datos

## Detalles que no son evidentes

- **`flags` se compara por igualdad exacta**, no por máscara: el decoder hace
  `when (flags) { FLAG_START -> … ; FLAG_END -> … ; FLAG_CANCELED -> … ; 0 -> … }`
  (`:105-122`). Un valor combinado como `0x03` no casa con ningún caso y se
  rechaza. Por eso aquí no se usan flags acumulables.
- **El códec sólo viaja en el mensaje de inicio.** Los paquetes de datos llevan
  `flags = 0` y no repiten el códec: se infiere del `Start` anterior.
- `MAX_FRAMES_PER_PACKET = 8` y `MAX_CONTENT_BYTES = 210` (`:74-75`). El
  segundo limita el contenido por paquete por debajo del MTU útil.
- Este tipo **no entra en la sincronización por gossip**: es efímero
  (`.never added to gossip sync`).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from .packet import ProtocolError, Reader

BURST_ID_SIZE = 8
HEADER_SIZE = BURST_ID_SIZE + 2 + 1

MAX_FRAMES_PER_PACKET = 8
MAX_CONTENT_BYTES = 210


class VoiceCodec(IntEnum):
    """Códec de audio del paquete. `AAC_LC_16K_MONO` es el único que define
    la app oficial (`VoiceBurstCodec.kt:8`)."""

    AAC_LC_16K_MONO = 0x01


class Kind(IntEnum):
    """Forma del paquete, según `flags`."""

    FRAMES = 0x00
    START = 0x01
    END = 0x02
    CANCELED = 0x04


@dataclass(slots=True)
class StartPayload:
    codec: VoiceCodec
    kind: Kind = Kind.START


@dataclass(slots=True)
class FramesPayload:
    frames: list[bytes]
    kind: Kind = Kind.FRAMES


@dataclass(slots=True)
class EndPayload:
    total_data_packets: int
    duration_ms: int
    kind: Kind = Kind.END


@dataclass(slots=True)
class CanceledPayload:
    kind: Kind = Kind.CANCELED


class VoiceFramePayload:
    """Ráfaga de voz: inicio, datos o fin."""

    __slots__ = ("burst_id", "sequence", "payload")

    def __init__(self, burst_id: bytes, sequence: int, payload) -> None:
        if len(burst_id) != BURST_ID_SIZE:
            raise ValueError(f"burst_id debe medir {BURST_ID_SIZE} bytes")
        if not 0 <= sequence <= 0xFFFF:
            raise ValueError(f"sequence fuera de rango: {sequence}")
        self.burst_id = burst_id
        self.sequence = sequence
        self.payload = payload

    @classmethod
    def parse(cls, data: bytes) -> "VoiceFramePayload":
        if len(data) < HEADER_SIZE:
            raise ProtocolError(
                f"trama de voz demasiado corta: {len(data)} < {HEADER_SIZE} B"
            )
        r = Reader(data)
        burst_id = r.raw(BURST_ID_SIZE, "burst_id")
        sequence = r.u16("sequence")
        flags = r.u8("flags")

        try:
            kind = Kind(flags)
        except ValueError as exc:
            raise ProtocolError(
                f"flags de voz no reconocidos: 0x{flags:02x}. La app oficial "
                "compara por igualdad exacta, así que los valores combinados fallan"
            ) from exc

        if kind is Kind.START:
            if r.remaining < 1:
                raise ProtocolError("falta el códec en el mensaje de inicio")
            raw = r.u8("codec")
            try:
                codec = VoiceCodec(raw)
            except ValueError as exc:
                raise ProtocolError(f"códec de voz desconocido: 0x{raw:02x}") from exc
            return cls(burst_id, sequence, StartPayload(codec))

        if kind is Kind.END:
            if r.remaining < 6:
                raise ProtocolError("el mensaje de fin necesita 6 bytes más")
            total = r.u16("total_data_packets")
            duration = r.u32("duration_ms")
            return cls(burst_id, sequence, EndPayload(total, duration))

        if kind is Kind.CANCELED:
            return cls(burst_id, sequence, CanceledPayload())

        # kind is Kind.FRAMES
        frames: list[bytes] = []
        while r.remaining:
            if len(frames) >= MAX_FRAMES_PER_PACKET:
                raise ProtocolError(
                    f"más de {MAX_FRAMES_PER_PACKET} tramas en un paquete"
                )
            if r.remaining < 2:
                raise ProtocolError("longitud de trama truncada")
            length = r.u16("longitud de trama")
            if length <= 0:
                raise ProtocolError("trama de longitud cero")
            frames.append(r.raw(length, "trama"))
        return cls(burst_id, sequence, FramesPayload(frames))

    def to_bytes(self) -> bytes:
        inicio = self.burst_id + struct.pack(">H", self.sequence)
        p = self.payload

        if isinstance(p, StartPayload):
            return inicio + struct.pack(">BB", Kind.START, p.codec)
        if isinstance(p, EndPayload):
            if p.duration_ms > 0xFFFFFFFF:
                raise ValueError(f"duración fuera de rango: {p.duration_ms}")
            return inicio + struct.pack(
                ">BHI", Kind.END, p.total_data_packets, p.duration_ms
            )
        if isinstance(p, CanceledPayload):
            return inicio + struct.pack(">B", Kind.CANCELED)
        if isinstance(p, FramesPayload):
            partes = [inicio + struct.pack(">B", Kind.FRAMES)]
            if len(p.frames) > MAX_FRAMES_PER_PACKET:
                raise ValueError(
                    f"máximo {MAX_FRAMES_PER_PACKET} tramas, van {len(p.frames)}"
                )
            for trama in p.frames:
                if not 0 < len(trama) <= 0xFFFF:
                    raise ValueError(f"trama de longitud inválida: {len(trama)}")
                partes.append(struct.pack(">H", len(trama)) + trama)
            return b"".join(partes)

        raise TypeError(f"tipo de payload de voz no soportado: {type(p).__name__}")


__all__ = [
    "BURST_ID_SIZE",
    "HEADER_SIZE",
    "MAX_CONTENT_BYTES",
    "MAX_FRAMES_PER_PACKET",
    "CanceledPayload",
    "EndPayload",
    "FramesPayload",
    "Kind",
    "StartPayload",
    "VoiceCodec",
    "VoiceFramePayload",
]