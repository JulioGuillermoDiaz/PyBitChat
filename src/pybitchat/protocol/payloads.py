"""Payloads de paquete BitChat.

Los layouts se han cerrado leyendo **las dos caras** del código de
`permissionlesstech/bitchat-android`: el `encode` y el `decode` de cada clase.
Un layout confirmado por una sola cara es una hipótesis, no un hecho.

## Dialecto actual (el que habla una app Android viva)

| MessageType         | Fichero Kotlin                  | Estado                    |
|---------------------|---------------------------------|---------------------------|
| ANNOUNCE 0x01       | —                               | ✅ Decodificado            |
| MESSAGE 0x02        | `model/BitchatMessage.kt`       | ✅ Decodificado (8 flags)  |
| NOISE_HANDSHAKE 0x10| `noise/NoiseSession.kt`         | 🟡 Los bytes son Noise     |
| NOISE_ENCRYPTED 0x11| `noise/NoiseSession.kt`         | ✅ Framing + descifrado    |
| FRAGMENT 0x20       | `model/FragmentPayload.kt`      | ✅ Decodificado            |
| REQUEST_SYNC 0x21   | `model/RequestSyncPacket.kt`    | ✅ Decodificado (GCS)      |
| FILE_TRANSFER 0x22  | `model/BitchatFilePacket.kt`    | ✅ Decodificado (TLV)      |
| VOICE_FRAME 0x29    | `features/voice/VoiceBurstPacket.kt` | ✅ Decodificado       |

## Dialecto retirado (sólo `bitchat-tui`, y su lógica es la que falló)

| LegacyMessageType         | Capturas | Estado                          |
|---------------------------|----------|---------------------------------|
| NOISE_HANDSHAKE_INIT 0x10 | 32 B     | 🟡 Longitud = clave efímera X25519 |
| NOISE_HANDSHAKE_RESP 0x11 | 64, 96 B | ❌ Sin decodificar — H2         |
| NOISE_IDENTITY_ANNOUNCE 0x13 | 160 B | ❌ **Tipo inexistente en el actual** — H3 |
| HANDSHAKE_REQUEST 0x25    | 50 B     | ❌ **Tipo inexistente en el actual** — H4 |
| PROTOCOL_ACK 0x22         | 58 B     | ❌ **Renumerado a FILE_TRANSFER** — H5 |

## Por qué hay dos dialects

Los dos se diferencian por **renumeración**, no por inclusión: `0x11` es
`NOISE_HANDSHAKE_RESP` en el viejo y `NOISE_ENCRYPTED` en el actual. Mezclarlos
no da error, da basura silenciosa. Por eso `decode_payload` exige `dialect` para
los valores ambiguos en vez de elegir por su cuenta.

Un payload cuyo layout no se conoce se conserva **opaco y byte-exacto** en lugar
de adivinar. Es deliberado: el cliente Rust `bitchat-tui` cometió exactamente ese
error y por eso falló en producción. Ver EVALUACION-MIGRACION.md §1.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from .message import MessagePayload, UnsupportedPayloadField
from .packet import ProtocolError, Reader
from .tlv import FileTransferPayload, RequestSyncPayload
from .types import (
    HEADER_SIZE,
    LEGACY_FRAGMENT_CHUNK_SIZE,
    MAX_FRAGMENT_SIZE,
    MAX_FRAGMENTS_PER_ID,
    NOISE_TRANSPORT_NONCE_PREFIX_LEN,
    PEER_ID_SIZE,
    LegacyMessageType,
    MessageType,
)
from .voice import VoiceFramePayload

# --------------------------------------------------------------------------
# ANNOUNCE (0x01) -- decodificado y validado
# --------------------------------------------------------------------------


@dataclass(slots=True)
class AnnouncePayload:
    """Anuncio de presencia.

    El payload es **sólo el nickname en UTF-8, sin prefijo de longitud**: la
    longitud la da `payload_len` de la cabecera. Confirmado con los vectores
    reales: payload de 9 B = `"anonymous"` y payload de 8 B = `"anon6328"`.

    No hay ningún otro campo, ni siquiera marca de tiempo.
    """

    nickname: str

    @classmethod
    def parse(cls, data: bytes) -> "AnnouncePayload":
        return cls(nickname=data.decode("utf-8"))

    def to_bytes(self) -> bytes:
        return self.nickname.encode("utf-8")


# --------------------------------------------------------------------------
# NOISE_ENCRYPTED (0x12) -- framing confirmado
# --------------------------------------------------------------------------


@dataclass(slots=True)
class NoiseCiphertext:
    """Mensaje de transporte Noise con el framing propietario de BitChat.

    Estructura:

        nonce_prefix (4 B, u32 little-endian) ‖ ciphertext

    ⚠️ El prefijo de nonce **no es Noise estándar**. Las librerías
    (`noisepramework`, `noiseprotocol`, `snow`) producirán bytes distintos y no
    podrán leer esto. Hay que usar la librería sólo para el handshake y aplicar
    esta capa encima. Ver EVALUACION-MIGRACION.md §5.1.

    Con los vectores reales el prefijo es siempre `00 00 00 00` porque todos
    los mensajes capturados usan nonce 0, el primero de la sesión.
    """

    nonce: int
    ciphertext: bytes

    @classmethod
    def parse(cls, data: bytes) -> "NoiseCiphertext":
        if len(data) < NOISE_TRANSPORT_NONCE_PREFIX_LEN:
            raise ProtocolError(
                f"payload de transporte Noise demasiado corto: {len(data)} B"
            )
        (nonce,) = struct.unpack(
            "<I", data[:NOISE_TRANSPORT_NONCE_PREFIX_LEN]
        )
        return cls(nonce=nonce, ciphertext=data[NOISE_TRANSPORT_NONCE_PREFIX_LEN:])

    def to_bytes(self) -> bytes:
        return struct.pack("<I", self.nonce) + self.ciphertext


# --------------------------------------------------------------------------
# FRAGMENT_START / CONTINUE / END (0x05-0x07) -- según spec
# --------------------------------------------------------------------------


class FragmentType(IntEnum):
    """Posición del fragmento dentro del mensaje original."""

    START = 0
    CONTINUE = 1
    END = 2


@dataclass(slots=True)
class FragmentPayload:
    """Fragmento de un paquete demasiado grande para un solo envío BLE.

    Estructura (de `reference/bitchat-tui/src/fragmentation.rs`):

        fragment_id (8 B) ‖ index u16 BE ‖ total u16 BE ‖ original_type u8 ‖ data

    ⚠️ La API pública de `fragmentation.rs` dice 500 B de fragmento, pero está
    muerta y es contradictoria: el código en producción (`main.rs:141-264`)
    trocea a **150 B**. Usar `FRAGMENT_CHUNK_SIZE`.

    ⚠️ Los fragmentos cortan el paquete **ya rellenado**, así que el header de
    14 B puede quedar partido entre dos fragmentos. El reensamblado debe
    concatenar bytes a secas, sin interpretar nada.
    """

    fragment_id: bytes
    index: int
    total: int
    original_type: MessageType
    data: bytes

    HEADER_SIZE = 8 + 2 + 2 + 1

    @classmethod
    def parse(cls, data: bytes) -> "FragmentPayload":
        if len(data) < cls.HEADER_SIZE:
            raise ProtocolError(f"fragmento truncado: {len(data)} B")
        r = Reader(data)
        fragment_id = r.raw(8, "fragment_id")
        index = r.u16("index")
        total = r.u16("total")
        raw_type = r.u8("original_type")
        try:
            original_type = MessageType(raw_type)
        except ValueError as exc:
            raise ProtocolError(f"tipo original desconocido: {raw_type:#04x}") from exc
        return cls(fragment_id, index, total, original_type, r.rest())

    def to_bytes(self) -> bytes:
        if len(self.fragment_id) != 8:
            raise ProtocolError("fragment_id debe tener 8 bytes")
        return b"".join(
            (
                self.fragment_id,
                struct.pack(">H", self.index),
                struct.pack(">H", self.total),
                struct.pack(">B", int(self.original_type)),
                self.data,
            )
        )

    @property
    def is_first(self) -> bool:
        return self.index == 0

    @property
    def is_last(self) -> bool:
        return self.index == self.total - 1


#: Margen que la app reserva para el relleno (`FragmentManager.kt:104`).
#:
#: `MessagePadding.optimalBlockSize` mete el paquete en el siguiente cubo, y
#: este margen absorbe lo que el cálculo no puede saber de antemano.
PADDING_RESERVE = 16

#: Bloque de transporte al que se ajusta cada fragmento
#: (`AppConstants.Fragmentation.FRAGMENT_SIZE_THRESHOLD`).
TRANSPORT_BLOCK = 512


def max_fragment_data_size(*, has_recipient: bool = False, hops: int = 0) -> int:
    """Bytes de datos del paquete original que caben en un fragmento.

    Reproduce el cálculo de `FragmentManager.createFragments` (`:106-108`):

        overhead = cabecera + sender + [recipient] + [ruta]
                  + cabecera_de_fragmento + margen_de_relleno
        datos = min(512 - overhead, MAX_FRAGMENT_SIZE)

    El margen de relleno no es opcional: `MessagePadding.optimalBlockSize`
    mete el paquete en el siguiente cubo, y sin reservarlo el fragmento se pasa
    de largo y salta al cubo de 1024.

    ## Por qué no basta con `MAX_FRAGMENT_SIZE`

    Sin destinatario ni ruta, el total del fragmento queda en
    `14 + 8 + 469 = 491` y sobra margen de sobra. El problema aparece con la
    **ruta**: cada salto añade `1 + 8 × saltos` bytes al sobre, y
    `MAX_FRAGMENT_SIZE` es una constante fija que no los contempla. Con seis
    saltos el fragmento mide 548 B y el relleno lo empuja a 1024, con lo que
    cada fragmento pasa a costar el doble de lo previsto. Reduciendo los datos
    en función de la ruta, como hace la app, el bloque se respeta siempre.

    ⚠️ La app usa 13 para el tamaño de cabecera y el real es 14
    (`FragmentManager.kt:98` contra `BinaryProtocol.kt:208`). Aquí se usa 14:
    un byte de más de margen sólo hace el fragmento ligeramente más
    conservador, y equivocarse al revés sí desbordaría el bloque.
    """
    overhead = (
        HEADER_SIZE
        + PEER_ID_SIZE
        + (PEER_ID_SIZE if has_recipient else 0)
        + (1 + hops * PEER_ID_SIZE if hops else 0)
        + FragmentPayload.HEADER_SIZE
        + PADDING_RESERVE
    )
    datos = min(TRANSPORT_BLOCK - overhead, MAX_FRAGMENT_SIZE)
    if datos <= 0:
        raise ValueError(
            f"la ruta deja sin sitio para datos: el sobre se come "
            f"{overhead} B de un bloque de {TRANSPORT_BLOCK} B"
        )
    return datos


def max_fragment_payload_size(*, has_recipient: bool = False, hops: int = 0) -> int:
    """Tamaño total del payload de fragmento, cabecera de fragmento incluida.

    Es `max_fragment_data_size` más `FragmentPayload.HEADER_SIZE`, acotado por
    `MAX_FRAGMENT_SIZE`.
    """
    return min(
        max_fragment_data_size(has_recipient=has_recipient, hops=hops)
        + FragmentPayload.HEADER_SIZE,
        MAX_FRAGMENT_SIZE,
    )


def split_into_fragments(
    padded_packet: bytes,
    mtype: int,
    fragment_id: bytes | None = None,
    *,
    chunk_size: int | None = None,
    has_recipient: bool = False,
    hops: int = 0,
) -> list[bytes]:
    """Trocea un paquete ya rellenado en payloads de fragmento.

    `padded_packet` debe incluir el relleno: los fragmentos cortan el paquete
    final tal cual va a ir, y el receptor lo reensambla y descifra después.

    `chunk_size` es el tamaño **total** de cada payload de fragmento, cabecera
    incluida. Si se omite se calcula con `max_fragment_payload_size()`, que
    descuenta el sobre real del bloque de 512.

    **Pasa `has_recipient=True` y `hops=N` para mensajes privados y enrutados.**
    Sin eso se usaría el sobre de un fragmento sin destino ni ruta, que es
    menor que el real, y con rutas largas el fragmento se saldría del bloque.

    `bitchat-tui` usaba 150 B porque venía ajustado al MTU de iOS (185); ese
    valor es un tercer dialecto y no debe usarse salvo como reserva
    conservadora cuando el MTU real sea desconocido.

    ⚠️ No producir más de `MAX_FRAGMENTS_PER_ID` (256) fragmentos por conjunto:
    el receptor los rechaza y el mensaje queda inentregable.
    """
    if chunk_size is None:
        chunk_size = max_fragment_payload_size(
            has_recipient=has_recipient, hops=hops
        )

    if chunk_size <= FragmentPayload.HEADER_SIZE:
        raise ValueError(
            f"chunk_size debe superar la cabecera de fragmento "
            f"({FragmentPayload.HEADER_SIZE} B)"
        )
    if chunk_size > MAX_FRAGMENT_SIZE:
        raise ValueError(
            f"chunk_size {chunk_size} excede MAX_FRAGMENT_SIZE ({MAX_FRAGMENT_SIZE}); "
            "el receptor no aceptaría un fragmento mayor"
        )
    if fragment_id is None:
        import os

        fragment_id = os.urandom(8)
    if len(fragment_id) != 8:
        raise ValueError("fragment_id debe tener 8 bytes")

    per_chunk = chunk_size - FragmentPayload.HEADER_SIZE
    chunks = [padded_packet[i : i + per_chunk] for i in range(0, len(padded_packet), per_chunk)]
    total = len(chunks)
    if total > MAX_FRAGMENTS_PER_ID:
        raise ValueError(
            f"el mensaje necesita {total} fragmentos, el máximo del receptor es "
            f"{MAX_FRAGMENTS_PER_ID}: sería inentregable"
        )
    return [
        FragmentPayload(fragment_id, i, total, mtype, chunk).to_bytes()
        for i, chunk in enumerate(chunks)
    ]


# --------------------------------------------------------------------------
# Payloads aún sin decodificar
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OpaquePayload:
    """Payload que se conserva crudo porque su layout todavía no se conoce.

    No se intenta interpretar. Se mantienen los bytes intactos para poder
    reemitirlos y para analizarlos cuando se consiga una captura nueva.
    """

    msg_type: int
    raw: bytes

    #: Identificador corto del caso abierto asociado, para rastrearlo.
    open_question: str | None = None


#: Dialecto de un paquete.
CURRENT = "current"
LEGACY = "legacy"

#: Qué casos abiertos cubre cada tipo opaco, por dialecto.
#:
#: La clave es `(dialecto, valor_crudo)` y no sólo el valor crudo porque los dos
#: dialectos se diferencian por **renumeración**: `PROTOCOL_ACK` (legacy) y
#: `FILE_TRANSFER` (actual) son ambos `0x22`, pero el primero sigue sin
#: decodificar y el segundo está resuelto. Con una clave de un solo int, una
#: entrada pisaría a la otra y se perdería una de las dos respuestas.
OPEN_QUESTIONS: dict[tuple[str, int], str] = {
    (LEGACY, int(LegacyMessageType.NOISE_HANDSHAKE_INIT)): "H2",
    (LEGACY, int(LegacyMessageType.NOISE_HANDSHAKE_RESP)): "H2",
    (LEGACY, int(LegacyMessageType.NOISE_IDENTITY_ANNOUNCE)): "H3",
    (LEGACY, int(LegacyMessageType.HANDSHAKE_REQUEST)): "H4",
    (LEGACY, int(LegacyMessageType.PROTOCOL_ACK)): "H5",
    (CURRENT, int(MessageType.NOISE_HANDSHAKE)): "H2",
}

#: Casos cerrados leyendo el código de la app Android, con su referencia.
#:
#: | Caso | Tipo                 | Fuente                               |
#: |------|----------------------|--------------------------------------|
#: | H6   | `REQUEST_SYNC` 0x21  | `model/RequestSyncPacket.kt`         |
#: | H7   | `FILE_TRANSFER` 0x22 | `model/BitchatFilePacket.kt`         |
#: | H8   | `VOICE_FRAME` 0x29   | `features/voice/VoiceBurstPacket.kt` |
#:
#: H3, H4 y H5 **no** se cierran: sus tipos no existen en el dialecto actual
#: (`0x13` y `0x25` no aparecen en `MessageType`, y `0x22` es `FILE_TRANSFER`,
#: no `PROTOCOL_ACK`). Son artefactos del dialecto retirado y decodificarlos no
#: aporta nada para interoperar con una app actual.
RESOLVED_QUESTIONS: dict[tuple[str, int], str] = {
    (CURRENT, int(MessageType.REQUEST_SYNC)): "H6",
    (CURRENT, int(MessageType.FILE_TRANSFER)): "H7",
    (CURRENT, int(MessageType.VOICE_FRAME)): "H8",
}


def open_question_for(raw_type: int, dialect: str | None) -> str | None:
    """Caso abierto que corresponde a un tipo en un dialecto dado.

    Sin dialecto se busca en los dos: sólo se llama en tipos que no son
    ambiguos, así que hay como mucho un candidato.
    """
    raw = int(raw_type)
    if dialect is not None:
        return OPEN_QUESTIONS.get((dialect, raw))
    for d in (CURRENT, LEGACY):
        if (d, raw) in OPEN_QUESTIONS:
            return OPEN_QUESTIONS[(d, raw)]
    return None


# --------------------------------------------------------------------------
# Despacho
# --------------------------------------------------------------------------

#: Decoders del dialecto **actual**, indexados por valor crudo.
_DECODERS_CURRENT: dict[int, type] = {
    int(MessageType.ANNOUNCE): AnnouncePayload,
    int(MessageType.MESSAGE): MessagePayload,
    int(MessageType.NOISE_ENCRYPTED): NoiseCiphertext,
    int(MessageType.FRAGMENT): FragmentPayload,
    int(MessageType.REQUEST_SYNC): RequestSyncPayload,
    int(MessageType.FILE_TRANSFER): FileTransferPayload,
    int(MessageType.VOICE_FRAME): VoiceFramePayload,
}

#: Decoders del dialecto **retirado**, indexados por valor crudo.
_DECODERS_LEGACY: dict[int, type] = {
    int(LegacyMessageType.ANNOUNCE): AnnouncePayload,
    int(LegacyMessageType.MESSAGE): MessagePayload,
    int(LegacyMessageType.NOISE_ENCRYPTED): NoiseCiphertext,
    int(LegacyMessageType.FRAGMENT_START): FragmentPayload,
    int(LegacyMessageType.FRAGMENT_CONTINUE): FragmentPayload,
    int(LegacyMessageType.FRAGMENT_END): FragmentPayload,
}


def _ambiguous_values() -> frozenset[int]:
    """Valores cuyo **significado** depende del dialecto.

    No importa que uno de los dos tenga decoder: lo que cuenta es que el mismo
    número de tipo designe paquetes con layouts distintos. Casos:

    | Valor | legacy                  | actual                |
    |-------|-------------------------|-----------------------|
    | 0x02  | `KEY_EXCHANGE`          | `MESSAGE`             |
    | 0x11  | `NOISE_HANDSHAKE_RESP`  | `NOISE_ENCRYPTED`     |
    | 0x20  | `VERSION_HELLO`         | `FRAGMENT`            |
    | 0x22  | `PROTOCOL_ACK`          | `FILE_TRANSFER`       |

    Para estos valores, decodificar sin saber el dialecto produce un resultado
    plausible y **silenciosamente incorrecto**, así que se rechaza.
    """
    comunes = set(MessageType._value2member_map_) & set(LegacyMessageType._value2member_map_)
    return frozenset(
        v
        for v in comunes
        if MessageType._value2member_map_[v].name != LegacyMessageType._value2member_map_[v].name
    )


AMBIGUOUS_VALUES = _ambiguous_values()

#: Valores con decoder confirmado, en cualquiera de los dos dialectos.
DECODED_TYPES = frozenset(_DECODERS_CURRENT) | frozenset(_DECODERS_LEGACY)

#: Valores que se conservan opacos, indexados por dialecto.
#:
#: Hace falta la vista por dialecto porque `0x22` está opaco en legacy
#: (`PROTOCOL_ACK`) y decodificado en current (`FILE_TRANSFER`).
OPAQUE_BY_DIALECT: dict[str, frozenset[int]] = {
    d: frozenset(raw for dia, raw in OPEN_QUESTIONS if dia == d)
    for d in (CURRENT, LEGACY)
}

#: Valores opacos en **algún** dialecto. Para una comprobación de cobertura.
OPAQUE_TYPES = frozenset().union(*OPAQUE_BY_DIALECT.values())


def decode_payload(raw_type: int, data: bytes, dialect: str | None = None):
    """Decodifica el payload de un paquete.

    Parámetros
    ----------
    raw_type:
        Valor crudo del byte de tipo.
    dialect:
        `CURRENT`, `LEGACY`, o `None` si no se sabe.

    El dialecto es obligatorio en la práctica porque hay valores que existen en
    ambos dialectos con layouts distintos. Si `dialect` es `None` y el valor es
    ambiguo, se devuelve un `OpaquePayload` marcado como tal en vez de adivinar.

    Si un decoder confirmado falla, la excepción se propaga: eso indica un bug
    real en nuestro codec o un payload corrupto, y no debe esconderse detrás de
    un fallback opaco.
    """
    raw = int(raw_type)

    actual = _DECODERS_CURRENT.get(raw)
    legacy = _DECODERS_LEGACY.get(raw)

    if dialect == CURRENT:
        decoder = actual
    elif dialect == LEGACY:
        decoder = legacy
    elif dialect is not None:
        raise ValueError(f"dialecto desconocido: {dialect!r}")
    elif raw in AMBIGUOUS_VALUES:
        nombre_actual = MessageType._value2member_map_[raw].name
        nombre_legacy = LegacyMessageType._value2member_map_[raw].name
        return OpaquePayload(
            raw,
            data,
            f"ambiguo: actual={nombre_actual} legacy={nombre_legacy}; "
            "pasa dialect= para decodificar",
        )
    else:
        # No ambiguo: sólo pertenece a un dialecto, o significa lo mismo en
        # ambos. Es seguro usar el decoder disponible.
        decoder = actual or legacy

    if decoder is None:
        return OpaquePayload(raw, data, open_question_for(raw, dialect))

    try:
        return decoder.parse(data)
    except UnsupportedPayloadField as exc:
        # Layout conocido en su base, pero con campos opcionales sin
        # confirmar. Se conserva opaco en vez de perder información.
        return OpaquePayload(raw, data, f"flags-no-confirmados: {exc}")


__all__ = [
    "AMBIGUOUS_VALUES",
    "AnnouncePayload",
    "CURRENT",
    "DECODED_TYPES",
    "FragmentPayload",
    "FragmentType",
    "LEGACY",
    "NoiseCiphertext",
    "OPEN_QUESTIONS",
    "OPAQUE_BY_DIALECT",
    "OPAQUE_TYPES",
    "OpaquePayload",
    "PADDING_RESERVE",
    "RESOLVED_QUESTIONS",
    "TRANSPORT_BLOCK",
    "decode_payload",
    "max_fragment_data_size",
    "max_fragment_payload_size",
    "open_question_for",
    "split_into_fragments",
]