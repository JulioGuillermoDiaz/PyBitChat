"""Constantes del protocolo BitChat.

Todas las constantes proceden de `reference/bitchat-tui/src/data_structures.rs`
y han sido verificadas contra los volcados hex de paquetes reales de iOS
extraídos de los ficheros `.log` commiteados en ese repositorio.

Referencia:
  - data_structures.rs:111-142  -> MessageType
  - data_structures.rs:62-69    -> flags de payload de mensaje
  - data_structures.rs:56-60    -> flags de paquete
"""

from __future__ import annotations

from enum import IntEnum, IntFlag

# --------------------------------------------------------------------------
# Cabecera de paquete
# --------------------------------------------------------------------------

#: Versión de protocolo observada en todos los vectores.
PROTOCOL_VERSION = 0x01

#: Longitud de la cabecera v1. Confirmado por el código de Android
#: (`BinaryProtocol.kt:208`, `HEADER_SIZE_V1 = 14`) y verificado empíricamente
#: contra 21 paquetes reales. ⚠️ El README de `bitchat-android` y el código Rust
#: dicen "13 bytes": ambos están equivocados.
HEADER_SIZE = 14

#: La v2 usa longitud de payload de 4 bytes, luego 16 de cabecera, y añade
#: el flag `HAS_ROUTE` para la ruta explícita de origen.
HEADER_SIZE_V2 = 16

#: Longitud del identificador de remitente/destinatario en bytes.
PEER_ID_SIZE = 8

#: Tamaño de una firma Ed25519.
SIGNATURE_SIZE = 64


class PacketFlags(IntFlag):
    """Flags de la cabecera del paquete.

    `BinaryProtocol.kt:214-217` define los cuatro. El flag `HAS_ROUTE` (0x08)
    **no existe** en `bitchat-tui`, que es una de las diferencias que delatan
    que el Rust implementa un dialecto retirado.
    """

    HAS_RECIPIENT = 0x01
    HAS_SIGNATURE = 0x02
    IS_COMPRESSED = 0x04
    HAS_ROUTE = 0x08


# --------------------------------------------------------------------------
# Tipos de mensaje
# --------------------------------------------------------------------------


class MessageType(IntEnum):
    """Diálecto **actual** de BitChat, tal y como lo define la app Android.

    Fuente: `permissionlesstech/bitchat-android`,
    `app/src/main/java/com/bitchat/android/protocol/BinaryProtocol.kt`.

    Este es el enum que hay que usar para hablar con apps actuales.

    ⚠️ **No confundir con `LegacyMessageType`.** Los dos dialectos comparten
    algunos valores numéricos con **significados distintos**, así que un
    cliente que mezcle ambos intercambia mensajes con tipos equivocados de
    forma silenciosa. Ver la nota de dialecto al final del módulo.
    """

    ANNOUNCE = 0x01
    #: Todos los mensajes de usuario, privados y de difusión.
    MESSAGE = 0x02
    LEAVE = 0x03
    #: Mensaje del handshake Noise. Uno solo para las tres fases del handshake.
    NOISE_HANDSHAKE = 0x10
    #: Mensaje de transporte Noise cifrado.
    NOISE_ENCRYPTED = 0x11
    #: Fragmentación. Uno solo; no hay variantes start/continue/end.
    FRAGMENT = 0x20
    #: Petición de sincronización basada en GCS.
    REQUEST_SYNC = 0x21
    #: Transferencia de ficheros.
    FILE_TRANSFER = 0x22
    #: Trama de voz efímera; nunca entra en la sincronización por gossip.
    VOICE_FRAME = 0x29


class LegacyMessageType(IntEnum):
    """Diálecto de `bitchat-tui`, retirado. **Sólo para interpretar vectores.**

    Fuente: `reference/bitchat-tui/src/data_structures.rs:111-142`.

    Existe únicamente porque los vectores de `debug.log` fueron capturados
    contra un par que hablaba este dialecto (agosto de 2025). No debe usarse
    para construir ni para emitir tráfico: hacerlo produce paquetes que las
    apps actuales no interpretan.

    Diferencias con `MessageType`, donde los valores se solapan pero el
    significado cambia:

    | Valor | Legacy (`bitchat-tui`) | Actual (Android) |
    |-------|------------------------|------------------|
    | 0x02  | `KeyExchange`          | `MESSAGE`        |
    | 0x04  | `Message`              | *no definido*    |
    | 0x10  | `NoiseHandshakeInit`   | `NOISE_HANDSHAKE`|
    | 0x11  | `NoiseHandshakeResp`   | `NOISE_ENCRYPTED`|
    | 0x12  | `NoiseEncrypted`       | *no definido*    |
    | 0x20  | `ProtocolAck`          | `FRAGMENT`       |
    | 0x05  | `FragmentStart`        | *no definido*    |
    | 0x06  | `FragmentContinue`     | *no definido*    |
    | 0x07  | `FragmentEnd`          | *no definido*    |
    """

    ANNOUNCE = 0x01
    KEY_EXCHANGE = 0x02
    LEAVE = 0x03
    MESSAGE = 0x04
    FRAGMENT_START = 0x05
    FRAGMENT_CONTINUE = 0x06
    FRAGMENT_END = 0x07
    CHANNEL_ANNOUNCE = 0x08
    CHANNEL_RETENTION = 0x09
    DELIVERY_ACK = 0x0A
    DELIVERY_STATUS_REQUEST = 0x0B
    READ_RECEIPT = 0x0C

    NOISE_HANDSHAKE_INIT = 0x10
    NOISE_HANDSHAKE_RESP = 0x11
    NOISE_ENCRYPTED = 0x12
    NOISE_IDENTITY_ANNOUNCE = 0x13

    VERSION_HELLO = 0x20
    VERSION_ACK = 0x21

    PROTOCOL_ACK = 0x22
    PROTOCOL_NACK = 0x23
    SYSTEM_VALIDATION = 0x24
    HANDSHAKE_REQUEST = 0x25


class MessageFlags(IntFlag):
    """Flags del payload de mensaje (`data_structures.rs:62-69`).

    Estos flags gobiernan qué campos opcionales están presentes. El orden
    de lectura de los campos depende de ellos, no de su posición fija.

    `HAS_SENDER_PEER_ID` (0x10) se ha verificado empíricamente: en el
    vector del mensaje "hi" el byte de flags es 0x10 y la longitud del
    payload (76) sólo cuadra si el peer_id está presente.
    """

    IS_RELAY = 0x01
    IS_PRIVATE = 0x02
    HAS_ORIGINAL_SENDER = 0x04
    HAS_RECIPIENT_NICKNAME = 0x08
    HAS_SENDER_PEER_ID = 0x10
    HAS_MENTIONS = 0x20
    HAS_CHANNEL = 0x40
    IS_ENCRYPTED = 0x80


# --------------------------------------------------------------------------
# GATT (Bluetooth Low Energy)
# --------------------------------------------------------------------------

#: Servicio BLE principal (mainnet). Fuente: BLEService.swift de
#: permissionlesstech/bitchat, y `data_structures.rs:48`.
BITCHAT_SERVICE_UUID = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"

#: Servicio BLE de testnet (sufijo 'A' en lugar de 'C').
BITCHAT_SERVICE_UUID_TESTNET = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5A"

#: Característica única para todo el tráfico.
#: `data_structures.rs:50`.
BITCHAT_CHARACTERISTIC_UUID = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"


# --------------------------------------------------------------------------
# Relleno
# --------------------------------------------------------------------------

#: Cubos de relleno. `MessagePadding.kt:12` (`blockSizes`).
PADDING_BUCKETS = (256, 512, 1024, 2048)

#: `MessagePadding.optimalBlockSize` descuenta ~16 B de sobrecoste de cifrado
#: antes de elegir cubo.
PADDING_ENCRYPTION_OVERHEAD = 16

#: `MessagePadding.pad` no rellena si el relleno no cabe en un byte.
MAX_PADDING_LENGTH = 255


def should_pad_for_ble(msg_type: int) -> bool:
    """Política de relleno BLE, según `BLEPacketPaddingPolicy.kt`.

    Traduce literalmente:

        MessageType.NOISE_ENCRYPTED, NOISE_HANDSHAKE -> true
        else -> false

    Y es lo que la app pasa a `toBinaryData(padding = ...)` en
    `BluetoothPacketBroadcaster.kt:215, 237, 350`.

    ## Aviso: contradicción sin resolver con el tráfico real

    El 2026-10-02 se capturaron paquetes de la app Android que **sí** vienen
    rellenados, y no son tramas Noise:

    | Paquete | Tipo        | Contenido | Relleno | Byte         |
    |---------|-------------|-----------|---------|--------------|
    | 1       | ANNOUNCE    | 166 B     | 90 B    | `0x5a` = 90  |
    | 2       | MESSAGE     | 96 B      | 160 B   | `0xa0` = 160 |

    El relleno es PKCS#7 exacto: la longitud del relleno **es** el valor del
    byte, y el total cae en el siguiente cubo. No es basura ni resto de buffer.

    Pero por esas rutas, para un ANNOUNCE la política da `false` y no debería
    haber relleno. Hay tres salidas posibles y **ninguna comprobada**:

    1. Esos paquetes salieron por una ruta distinta de las tres del broadcaster.
    2. `toBinaryData` rellena igual, o hay otro relleno aguas arriba.
    3. La política no es lo que dice su nombre y hay que releerla.

    **No se cambia el comportamiento con una observación que no se explica.**
    La función sigue reflejando el código, que es lo verificable, y el conflicto
    queda escrito aquí. Cuando se sepa de dónde salieron esos paquetes se
    corrige, con la explicación al lado.

    Lo que sí está confirmado contra tráfico real es el relleno *cuando lo hay*:
    `pkcs7_pad_to_bucket` produce byte a byte los mismos 0x5a y 0xa0.

    Nota: `bitchat-tui` rellenaba **todo** a cubos (`packet_creation.rs`) y sus
    vectores de 2025 muestran un announce de 256 B con 39 reales.
    """
    try:
        mt = MessageType(msg_type)
    except ValueError:
        return False
    return mt in (MessageType.NOISE_ENCRYPTED, MessageType.NOISE_HANDSHAKE)
# --------------------------------------------------------------------------
# Fragmentación
# --------------------------------------------------------------------------

#: Valores del dialecto actual, de `AppConstants.Fragmentation`.
#: `bitchat-tui` usa 150 B (ajustado a iOS, MTU 185) y umbral 500: es un
#: tercer valor, distinto del actual y del de Android.
FRAGMENT_SIZE_THRESHOLD = 512
MAX_FRAGMENT_SIZE = 469

#: El receptor **rechaza** conjuntos con más fragmentos que este (`AppConstants.
#: Fragmentation.MAX_FRAGMENTS_PER_ID`; lo advierte el propio comentario de
#: `FragmentingPacketSender.kt`). Enviar más es directamente inentregable.
MAX_FRAGMENTS_PER_ID = 256

#: 1 MiB por conjunto de fragmentos.
MAX_FRAGMENT_TOTAL_BYTES = 1_048_576

#: Conjuntos de fragmentos simultáneos.
MAX_ACTIVE_FRAGMENT_SETS = 64

#: `FragmentingPacketSender(interFragmentDelayMs = 20L)`.
FRAGMENT_DELAY_MS = 20

#: Tamaño de MTU máximo en Android 14+: el stack pide 517 al primer cliente
#: GATT. En Linux con BlueZ `bleak` devuelve 23 salvo `_acquire_mtu()`.
BLE_MTU_ANDROID_14 = 517
BLE_MTU_BLUEZ_DEFAULT = 23

#: Tamaño del chunk heredado de `bitchat-tui`. **No usar** salvo como valor
#: conservador de reserva cuando el MTU real sea desconocido.
LEGACY_FRAGMENT_CHUNK_SIZE = 150


# --------------------------------------------------------------------------
# Noise
# --------------------------------------------------------------------------

#: Perfil Noise de BitChat. El handshake es Noise XX estándar; el transporte
#: usa un framing propio (ver `payloads.NoiseCiphertext`).
NOISE_PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"

#: Longitud del prefijo de nonce que BitChat antepone al ciphertext de
#: transporte. NO es Noise estándar: ver EVALUACION-MIGRACION.md §5.1.
#: Confirmado en `NoiseSession.kt:39` (`NONCE_SIZE_BYTES = 4`).
NOISE_TRANSPORT_NONCE_PREFIX_LEN = 4

# --------------------------------------------------------------------------
# Transporte Noise: anti-replay
# --------------------------------------------------------------------------
# Valores de `NoiseSession.kt` en `permissionlesstech/bitchat-android`:
#   :40  REPLAY_WINDOW_SIZE  = 1024
#   :41  REPLAY_WINDOW_BYTES = REPLAY_WINDOW_SIZE / 8 = 128

#: Ventana deslizante de anti-replay, en nonces.
NOISE_REPLAY_WINDOW = 1024

#: Bitset de nonces ya vistos: un bit por nonce de la ventana.
NOISE_REPLAY_WINDOW_BYTES = NOISE_REPLAY_WINDOW // 8

#: Umbral a partir del cual conviene renegociar la sesión
#: (`AppConstants.Noise.HIGH_NONCE_WARNING_THRESHOLD`).
NOISE_HIGH_NONCE_WARNING = 1_000_000_000

# --------------------------------------------------------------------------
# Vectores canónicos Noise-C
# --------------------------------------------------------------------------
#
# Publicados por `permissionlesstech/bitchat-android` en
# `app/src/test/kotlin/com/bitchat/android/noise/NoiseExternalVectorTest.kt`.
# Son los vectores oficiales de Cacophony/Noise-C para este perfil, y son la
# única forma de validar el handshake sin hardware.

#: `(payload_claro, ciphertext_esperado)` de cada mensaje.
NOISE_C_VECTORS: dict[str, tuple[str, str]] = {
    "msg1": (
        "4c756477696720766f6e204d69736573",
        "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"
        "4c756477696720766f6e204d69736573",
    ),
    "msg2": (
        "4d757272617920526f746862617264",
        "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"
        "81cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b9"
        "bd5269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f"
        "8814c7194e83f23dbd8d162c9326ad",
    ),
    "msg3": (
        "462e20412e20486179656b",
        "c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a8"
        "0ae475b9df0f169ae80a89be0865b57f58c9fea0d4ec82a286427402f113e4b6"
        "ae769a1d95941d49b25030",
    ),
    "transport_a": (
        "4361726c204d656e676572",
        "96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df",
    ),
    "transport_b": (
        "4a65616e2d426170746973746520536179",
        "3e40f15f6f3a46ae446b253bf8b1d9ffb6ed9b174d272328ff91a7e2e5c79c07f5",
    ),
    "transport_c": (
        "457567656e2042f6686d20766f6e2042617765726b",
        "eb3f3515110702e047a6c9da4478b6ead94873c11c0f2d710ddb3f09fce024b3"
        "a58502ae3f",
    ),
}

#: Claves y prologue fijos, para que el handshake sea determinista.
NOISE_C_PROLOGUE = "4a6f686e2047616c74"  # "John Galt"
NOISE_C_INITIATOR_STATIC = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"
NOISE_C_RESPONDER_STATIC = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"
NOISE_C_INITIATOR_EPHEMERAL = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
NOISE_C_RESPONDER_EPHEMERAL = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"


# --------------------------------------------------------------------------
# Nota de dialecto
# --------------------------------------------------------------------------
#
# Hay al menos tres dialectos de BitChat en juego:
#
#   1. `bitchat-tui` (Rust, agosto 2025)  -> `LegacyMessageType`
#   2. Los vectores de `debug.log`       -> `LegacyMessageType`
#   3. La app Android actual             -> `MessageType`
#
# 1 y 2 coinciden entre sí. El 3 **renumera** varios tipos, y donde el valor
# numérico se solapa el significado cambia (0x02, 0x11, 0x20).
#
# Consecuencia práctica: los vectores sirven para validar la **estructura** del
# paquete (cabecera de 14 B, flags dirigidos, formato de payload), pero **no**
# la numeración de tipos ni la política de relleno. Un test que dé por bueno
# un `MESSAGE` en 0x04 contra una app actual está probando lo equivocado.
