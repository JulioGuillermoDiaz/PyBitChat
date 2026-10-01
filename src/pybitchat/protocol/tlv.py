"""Payloads TLV del dialecto actual: `REQUEST_SYNC` y `FILE_TRANSFER`.

Ambos comparten el mismo encuadre TLV, con una excepción importante en
`FILE_TRANSFER`.

## TLV genérico (`REQUEST_SYNC`)

    [tipo u8][longitud u16 big-endian][valor]

Longitud de 2 bytes para todos los TLV (`RequestSyncPacket.kt:19-24`).

## `FILE_TRANSFER` y su excepción

    [tipo u8][longitud][valor]

Pero **la longitud es u16 big-endian salvo para `CONTENT` (0x04), que usa u32
big-endian**. Confirmado en las dos direcciones:

    encode  BitchatFilePacket.kt:86-88
        buf.put(TLVType.CONTENT.v.toByte())
        buf.putInt(content.size)        <- 4 bytes, no 2

    decode  BitchatFilePacket.kt:118-128
        if (t == TLVType.CONTENT) { ... off += 4 } else { ... off += 2 }

⚠️ El comentario de cabecera del fichero dice *"Length field for TLV is 2 bytes
for all TLVs"*, y es **falso**: está desactualizado respecto al código. Fiarse
del comentario rompe la interop en cuanto llega contenido.

## Compatibilidad hacia delante

El decoder oficial **salta los tags desconocidos en lugar de rechazarlos**
(`BitchatFilePacket.kt:130-141`), porque un par puede rellenar un paquete con
TLVs de longitud cero que no conocemos. Es el mismo motivo por el que el
contador de tags se reporta una vez al final: cualquier trabajo por TLV sería
escalable por el atacante.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .packet import ProtocolError, Reader

#: Longitud máxima de un valor TLV no-CONTENT.
MAX_TLV_VALUE = 0xFFFF


def _read_tlv_header(r: Reader, *, wide: bool) -> tuple[int, int]:
    """Lee tipo y longitud. `wide` usa u32 en lugar de u16."""
    tipo = r.u8("tipo TLV")
    longitud = r.u32("longitud TLV") if wide else r.u16("longitud TLV")
    if longitud < 0:
        raise ProtocolError(f"longitud TLV negativa: {longitud}")
    return tipo, longitud


def _tlv(tipo: int, valor: bytes, *, wide: bool = False) -> bytes:
    if wide:
        if len(valor) > 0xFFFFFFFF:
            raise ValueError("valor TLV demasiado largo")
        return struct.pack(">BI", tipo, len(valor)) + valor
    if len(valor) > MAX_TLV_VALUE:
        raise ValueError(f"valor TLV demasiado largo: {len(valor)} > {MAX_TLV_VALUE}")
    return struct.pack(">BH", tipo, len(valor)) + valor


# --------------------------------------------------------------------------
# REQUEST_SYNC (0x21)
# --------------------------------------------------------------------------


class SyncTlvType:
    P = 0x01  # parámetro Golomb-Rice, u8
    M = 0x02  # rango del hash (N * 2^P), u32 big-endian
    DATA = 0x03  # bitstream Golomb-Rice, opaco


@dataclass(slots=True)
class RequestSyncPayload:
    """Petición de sincronización por GCS (conjuntos ordenados comprimidos).

    No es un listado de mensajes: es un filtro probabilístico que permite
    sincronizar cachés de gossip sin enviar cada elemento.
    """

    p: int
    m: int
    data: bytes = b""

    #: Tamaño máximo aceptado del filtro, para no aceptar payloads gigantes.
    MAX_FILTER_BYTES = 0xFFFF

    @classmethod
    def parse(cls, data: bytes) -> "RequestSyncPayload":
        r = Reader(data)
        p = m = None
        bits = b""
        while r.remaining:
            tipo, longitud = _read_tlv_header(r, wide=False)
            valor = r.raw(longitud, f"valor TLV 0x{tipo:02x}")
            if tipo == SyncTlvType.P:
                if longitud != 1:
                    raise ProtocolError(f"P debe medir 1 byte, mide {longitud}")
                p = valor[0]
            elif tipo == SyncTlvType.M:
                if longitud != 4:
                    raise ProtocolError(f"M debe medir 4 bytes, mide {longitud}")
                (m,) = struct.unpack(">I", valor)
            elif tipo == SyncTlvType.DATA:
                bits = valor
            # Cualquier otro tag se ignora, igual que en la app oficial.
        if p is None or m is None:
            raise ProtocolError("faltan P o M en el payload de sincronización")
        return cls(p=p, m=m, data=bits)

    def to_bytes(self) -> bytes:
        if not 0 <= self.p <= 0xFF:
            raise ValueError(f"P fuera de rango: {self.p}")
        if not 0 <= self.m <= 0xFFFFFFFF:
            raise ValueError(f"M fuera de rango: {self.m}")
        if len(self.data) > self.MAX_FILTER_BYTES:
            raise ValueError(f"filtro demasiado grande: {len(self.data)} B")
        return b"".join(
            (
                _tlv(SyncTlvType.P, bytes((self.p,))),
                _tlv(SyncTlvType.M, struct.pack(">I", self.m)),
                _tlv(SyncTlvType.DATA, self.data),
            )
        )


# --------------------------------------------------------------------------
# FILE_TRANSFER (0x22)
# --------------------------------------------------------------------------


class FileTlvType:
    FILE_NAME = 0x01
    FILE_SIZE = 0x02
    MIME_TYPE = 0x03
    CONTENT = 0x04


#: El TLV de contenido usa longitud u32, el resto u16.
WIDE_LENGTH_TYPES = frozenset({FileTlvType.CONTENT})


@dataclass(slots=True)
class FileTransferPayload:
    """TLV de transferencia de fichero.

    El contenido puede llegar repartido en varios TLV `CONTENT`, porque cada uno
    está limitado a 65535 bytes por TLV aunque el payload completo pueda pasar
    de 64 KiB. Al decodificar se concatenan en orden.
    """

    filename: str | None = None
    file_size: int | None = None
    mime_type: str | None = None
    content: bytes = b""

    #: Tags desconocidos que se han saltado, para poder reportarlos.
    unknown_types: list[int] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> "FileTransferPayload":
        r = Reader(data)
        nombre = tamano = mime = None
        trozos: list[bytes] = []
        desconocidos: list[int] = []

        while r.remaining:
            # Una cabecera TLV necesita al menos tipo + 2 bytes de longitud.
            # Se rechaza una cabecera final truncada en vez de aceptarla en
            # silencio, que es lo que hace la app oficial.
            if r.remaining < 3:
                raise ProtocolError("cabecera TLV truncada al final del payload")

            # El tipo se lee antes que la longitud porque decide su anchura:
            # CONTENT es el único con longitud u32.
            tipo = r.u8("tipo TLV")
            if tipo in WIDE_LENGTH_TYPES:
                longitud = r.u32("longitud TLV u32")
            else:
                longitud = r.u16("longitud TLV u16")
            valor = r.raw(longitud, f"valor TLV 0x{tipo:02x}")

            if tipo == FileTlvType.FILE_NAME:
                nombre = valor.decode("utf-8")
            elif tipo == FileTlvType.FILE_SIZE:
                if longitud != 8:
                    raise ProtocolError(f"el tamaño debe medir 8 bytes, mide {longitud}")
                (tamano,) = struct.unpack(">Q", valor)
            elif tipo == FileTlvType.MIME_TYPE:
                mime = valor.decode("utf-8")
            elif tipo == FileTlvType.CONTENT:
                trozos.append(valor)
            else:
                # Se salta, no se rechaza: un par puede mandar TLVs que no
                # conocemos. Ver la nota de compatibilidad en el módulo.
                desconocidos.append(tipo)

        return cls(
            filename=nombre,
            file_size=tamano,
            mime_type=mime,
            content=b"".join(trozos),
            unknown_types=desconocidos,
        )

    def to_bytes(self) -> bytes:
        partes = []
        if self.filename is not None:
            partes.append(_tlv(FileTlvType.FILE_NAME, self.filename.encode("utf-8")))
        if self.file_size is not None:
            if not 0 <= self.file_size <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(f"tamaño fuera de rango: {self.file_size}")
            partes.append(_tlv(FileTlvType.FILE_SIZE, struct.pack(">Q", self.file_size)))
        if self.mime_type is not None:
            partes.append(_tlv(FileTlvType.MIME_TYPE, self.mime_type.encode("utf-8")))
        if self.content:
            partes.append(_tlv(FileTlvType.CONTENT, self.content, wide=True))
        return b"".join(partes)

__all__ = [
    "MAX_TLV_VALUE",
    "FileTlvType",
    "FileTransferPayload",
    "RequestSyncPayload",
    "SyncTlvType",
    "WIDE_LENGTH_TYPES",
]
