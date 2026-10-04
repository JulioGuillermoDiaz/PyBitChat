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
from ..protocol.identity import Identity, peer_id_from_noise_key
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


def completar_handshake(
    sesion: HandshakeSession,
    identidad: Identity,
    msg2: bytes,
    peer_id_remoto: bytes,
    *,
    ttl: int = TTL_HANDSHAKE,
    verificar_peer_id: bool = True,
) -> tuple[bytes, HandshakeSession]:
    """Procesa `msg2` y produce `msg3`. Es el último mensaje de XX.

    XX son tres: `-> e`, `<- e, ee, s`, `-> se`. Mandamos el primero, la app
    contesta con el segundo, y éste cierra.

    ## Tras `msg2` la sesión **no** está completa, y es lo normal

    Medido: `message_patterns` del initiator va 3 → 2 → 1. Queda `-> se`, que es
    este `msg3`. `complete` sólo pasa a `True` después de escribirlo.

    ## `msg2` son 96 B

    Verificado contra la app real el 2026-10-04: su respuesta al `msg1` mide
    96 B, y `HandshakeSession` como *responder* produce también 96 B. Mismo
    tamaño = misma configuración Noise: perfil, tag y orden de tokens.

    El desglose no está verificado token a token, así que **no** se afirma aquí:
    96 = 32 + 48 + 16 encaja con `e` + `ee` + parte de `s`, pero también con
    otras reparticiones. Lo que se sabe es que el tamaño coincide, y por eso la
   ライブラリ y la app hablan el mismo idioma.

    ## El `peer_id` se verifica contra la clave

    `msg2` incluye la clave estática de la app, que ya sustrae y comprueba. Es
    la **única** comprobación criptográfica de la identidad que tenemos: si
    `sha256(clave)[:8]` no da el `peer_id` que esperábamos, el mensaje no es de
    quien creemos y no hay que seguir.

    Por eso `verificar_peer_id` es `True` por defecto. Desactivarlo es para
    pruebas, no para producción: sin esta comprobación, cualquier peer podría
    hacer pasar su clave por otra.
    """
    sesion.read_handshake(msg2, payload_size=0)

    # NO se exige `sesion.complete` aquí. XX tiene **tres** mensajes, y
    # `message_patterns` del initiator va 3 → 2 → 1: queda `-> se`, que es este
    # `msg3`. Exigir `complete` sería pedir que un patrón de tres cerrara en
    # dos. `complete` sólo pasa a `True` tras escribir el msg3.
    if verificar_peer_id:
        remote = sesion.remote_static_public
        if remote is None:
            raise NoiseError(
                "msg2 no trajo clave estática remota: no se puede verificar "
                "quién es el otro lado"
            )
        calculado = peer_id_from_noise_key(remote)
        if calculado != peer_id_remoto:
            raise NoiseError(
                f"la clave estática del msg2 da peer_id {calculado.hex()} y "
                f"esperábamos {peer_id_remoto.hex()}. El mensaje no es de "
                f"ese par: no se responde."
            )

    msg3 = sesion.write_handshake(b"")
    paquete = empaquetar(msg3, identidad, peer_id_remoto, ttl=ttl)
    return paquete, sesion


__all__ = [
    "MSG1_SIZE",
    "TTL_HANDSHAKE",
    "completar_handshake",
    "construir_msg1",
    "empaquetar",
    "iniciar_handshake",
]