"""Handshake Noise XX: construcción y empaquetado de los mensajes.

Este módulo es **sólo empaque**. La criptografía ya está hecha y verificada con
39 vectores de Cacophony en `noise/session.py`; aquí se connects la sesión al
formato de paquete de BitChat.

## Lo que hace la app, leído de su código

`NoiseSession.kt:275-305` — `startHandshake()`:

    val messageBuffer = ByteArray(XX_MESSAGE_1_SIZE)
    val messageLength = handshakeStateLocal.writeMessage(messageBuffer, 0, null, 0, 0)
    ...
    val firstMessage = messageBuffer.copyOf(messageLength)
    if (firstMessage.size != XX_MESSAGE_1_SIZE) { ... }

Tres cosas que hay que respetar:

1. **`msg1` son 32 bytes.** Es `-- e, es` de Noise XX, sin carga: los
   parámetros `null, 0, 0` son el payload vacío.
2. **`signature = null`.** La app **no** firma el handshake, y el
   `BinaryProtocol.encode` sólo añade los 64 B si `signature != null`.
3. **El payload va sin comprimir**, pero `encode` lo comprime *si conviene*
   (`CompressionUtil.shouldCompress`). Un `msg1` de 32 B no se comprime.

`MessageHandler.kt:366-397` — `handleNoiseHandshake()`:

    val recipientID = packet.recipientID?.toHexString()
    if (recipientID != myPeerID) {
        return
    }
    val response = delegate?.processNoiseHandshakeMessage(packet.payload, peerID)
    if (response != null) {
        val responsePacket = BitchatPacket(
            version = 1u,
            type = MessageType.NOISE_HANDSHAKE.value,
            senderID = hexStringToByteArray(myPeerID),
            recipientID = hexStringToByteArray(peerID),
            ...
            signature = null,
            ttl = AppConstants.MESSAGE_TTL_HOPS
        )

De aquí sale lo más importante de este módulo, y **no es evidente**:

> **El handshake debe ir dirigido.** `recipientID` tiene que ser el `peer_id`
> de la app, o la línea 375-377 lo descarta **en silencio**. No hay error, no
> hay log: simplemente `return`.

Un `NOISE_HANDSHAKE` sin `recipient_id` no es un handshake mal formado, es un
paquete que la app ignora. Por eso `construir_msg1` exige el destinatario y no
lo hace opcional.

La respuesta vuelve con el **mismo tipo** (`NOISE_HANDSHAKE`), no con un tipo
de respuesta: "Single handshake type (0x10) with response determined by payload
analysis".

## Quién inicia

`NoiseSessionManager.kt:116` — `initiateHandshake()`, y el comentario de la
línea 113:

    // SIMPLIFIED: Initiate handshake - no tie breaker, just start

No hay desempate por comparación de `peer_id`: quien decide puede empezar
cuando quiera. Eso elimina el problema de "los dos empezamos a la vez", que
en Noise XX se resuelve con `e, es` ↔ `e, ee, se`.

## Relleno

`BinaryProtocol.kt:227` — `fun encode(packet: BitchatPacket, padding: Boolean = true)`.

El relleno es **opcional y por defecto activado**, y `BLEPacketPaddingPolicy`
sólo lo marca para las tramas Noise (`NOISE_HANDSHAKE` y `NOISE_ENCRYPTED`), que
es justo este caso. Ver `should_pad_for_ble()` para el conflicto conocido entre
esa política y el tráfico capturado.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..noise.session import PROTOCOL_NAME, HandshakeSession, NoiseError
from ..protocol.identity import Identity
from ..protocol.packet import Packet, PacketHeader, pkcs7_pad_to_bucket
from ..protocol.types import MessageType, PacketFlags, should_pad_for_ble

#: Tamaño de `msg1` en Noise XX: `-- e, es`, dos clave públicas de 32 B.
#: `NoiseSession.kt:293` reserva `XX_MESSAGE_1_SIZE` y avisa si no cuadra.
MSG1_SIZE = 32

#: TTL que usa la app para el handshake (`MessageHandler.kt:393`).
#: `MESSAGE_TTL_HOPS`, el mismo que en iOS.
TTL_HANDSHAKE = 6


def construir_msg1(
    identidad: Identity,
    *,
    remote_static_public: bytes | None = None,
    protocol_name: bytes = PROTOCOL_NAME,
) -> tuple[bytes, HandshakeSession]:
    """Construye `msg1` de Noise XX. Devuelve `(mensaje, sesión)`.

    `msg1` son 32 bytes y **no** lleva carga: es `-- e, es`.

    ## El destinatario no es opcional

    `remote_static_public` es el `peer_id` de la app... **no**: es su **clave
    Noise pública**, los 32 bytes del TLV `0x02` de su announce.

    En Noise XX el iniciador **no** necesita la clave estática del receptor para
    el primer mensaje: `msg1` sólo lleva la efímera y la estática propias. El
    parámetro se acepta para dejar la firma de la sesión completa y para el
    caso de reenviar, pero **msg1 sale igual sin él**.

    Aun así, `msg2` sí va dirigido: `recipient_id` es lo que hace que la app
    acepte el paquete (`MessageHandler.kt:375`). Eso lo pone `empaquetar`, no
    esta función.

    Se acepta porque mantiene el estado de la sesión completo desde el primer
    momento y permite verificar `remote_static_public` en cuanto se recibe
    `msg2`.
    """
    sesion = HandshakeSession(
        initiator=True,
        protocol_name=protocol_name,
        static_private=identidad.noise_private,
        remote_static_public=remote_static_public,
    )
    mensaje = sesion.write_handshake(b"")
    if len(mensaje) != MSG1_SIZE:
        raise NoiseError(
            f"msg1 debería medir {MSG1_SIZE} B y mide {len(mensaje)}. "
            f"El perfil {protocol_name!r} no encaja con XX."
        )
    return mensaje, sesion


def empaquetar(
    mensaje: bytes,
    identidad: Identity,
    destinatario_peer_id: bytes,
    *,
    ttl: int = TTL_HANDSHAKE,
    timestamp: int | None = None,
    con_releno: bool | None = None,
) -> bytes:
    """Envuelve un mensaje de handshake en un paquete `NOISE_HANDSHAKE` v1.

    ## `destinatario_peer_id` es obligatorio a propósito

    Sin `recipient_id` la app **descarta el paquete en silencio**
    (`MessageHandler.kt:375-377`): no hay error ni log, sólo un `return`. Un
    handshake sin destinatario no se puede detectar como fallo; parece que la
    app nunca contesta. Por eso aquí no es opcional aunque el `Packet` lo
    permita.

    `firmado = False`: la app manda `signature = null` en el handshake
    (`MessageHandler.kt:392`), así que no lleva los 64 B.

    `con_releno` por defecto **sí**, porque `BinaryProtocol.encode` tiene
    `padding: Boolean = true` y `NOISE_HANDSHAKE` es una trama Noise, que es
    justo donde `BLEPacketPaddingPolicy` marca el relleno.
    """
    if len(mensaje) == 0:
        raise ValueError("el mensaje de handshake está vacío")

    if con_releno is None:
        con_releno = should_pad_for_ble(int(MessageType.NOISE_HANDSHAKE))

    cabecera = PacketHeader(
        version=1,
        raw_type=int(MessageType.NOISE_HANDSHAKE),
        ttl=ttl,
        timestamp=timestamp if timestamp is not None else int(time.time() * 1000),
        flags=PacketFlags(0),
        payload_len=len(mensaje),
    )
    paquete = Packet(
        header=cabecera,
        sender_id=identidad.peer_id,
        payload=mensaje,
        recipient_id=destinatario_peer_id,
    )
    crudo = paquete.to_bytes(include_padding=False)
    return pkcs7_pad_to_bucket(crudo) if con_releno else crudo


def iniciar_handshake(
    identidad: Identity,
    *,
    peer_id_remoto: bytes,
    noise_public_remoto: bytes | None = None,
    ttl: int = TTL_HANDSHAKE,
) -> tuple[bytes, HandshakeSession]:
    """Atajo: construye `msg1` y lo empaqueta en un solo paso.

    `peer_id_remoto` es el `peer_id` de 8 B de la app —el mismo que aparece en
    el `sender_id` de sus paquetes— y es lo que va en `recipient_id`.

    `noise_public_remoto` son los 32 B del TLV `0x02` de su announce. No hace
    falta para `msg1`, pero pasarlo deja la sesión completa desde el principio.
    """
    mensaje, sesion = construir_msg1(
        identidad, remote_static_public=noise_public_remoto
    )
    paquete = empaquetar(
        mensaje, identidad, peer_id_remoto, ttl=ttl
    )
    return paquete, sesion


__all__ = [
    "MSG1_SIZE",
    "TTL_HANDSHAKE",
    "construir_msg1",
    "empaquetar",
    "iniciar_handshake",
]