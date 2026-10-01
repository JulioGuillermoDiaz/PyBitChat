"""Implementación del protocolo binario de BitChat.

El objetivo de este paquete es ser la única fuente de verdad del formato de
bytes, verificada contra los paquetes reales de la app oficial. Nada aquí
debe copiarse de `reference/bitchat-tui`, cuya implementación tiene bugs
documentados en EVALUACION-MIGRACION.md.
"""

from .message import MessagePayload, UnsupportedPayloadField
from .packet import (
    HEADER_SIZE,
    Packet,
    PacketHeader,
    ProtocolError,
    Reader,
    pkcs7_pad_to_bucket,
)
from .payloads import (
    AnnouncePayload,
    FragmentPayload,
    NoiseCiphertext,
    OpaquePayload,
    decode_payload,
    split_into_fragments,
)
from .types import (
    BITCHAT_CHARACTERISTIC_UUID,
    BITCHAT_SERVICE_UUID,
    BITCHAT_SERVICE_UUID_TESTNET,
    BLE_MTU_ANDROID_14,
    BLE_MTU_BLUEZ_DEFAULT,
    FRAGMENT_DELAY_MS,
    FRAGMENT_SIZE_THRESHOLD,
    HEADER_SIZE_V2,
    LEGACY_FRAGMENT_CHUNK_SIZE,
    MAX_FRAGMENT_SIZE,
    MAX_FRAGMENTS_PER_ID,
    NOISE_C_VECTORS,
    NOISE_PROTOCOL_NAME,
    NOISE_TRANSPORT_NONCE_PREFIX_LEN,
    PADDING_BUCKETS,
    PEER_ID_SIZE,
    PROTOCOL_VERSION,
    SIGNATURE_SIZE,
    LegacyMessageType,
    MessageFlags,
    MessageType,
    PacketFlags,
    should_pad_for_ble,
)

__all__ = [
    "AnnouncePayload",
    "BITCHAT_CHARACTERISTIC_UUID",
    "BITCHAT_SERVICE_UUID",
    "BITCHAT_SERVICE_UUID_TESTNET",
    "BLE_MTU_ANDROID_14",
    "BLE_MTU_BLUEZ_DEFAULT",
    "FRAGMENT_DELAY_MS",
    "FRAGMENT_SIZE_THRESHOLD",
    "FragmentPayload",
    "HEADER_SIZE",
    "HEADER_SIZE_V2",
    "LEGACY_FRAGMENT_CHUNK_SIZE",
    "MAX_FRAGMENT_SIZE",
    "MAX_FRAGMENTS_PER_ID",
    "MessageFlags",
    "MessagePayload",
    "MessageType",
    "LegacyMessageType",
    "NOISE_C_VECTORS",
    "NOISE_PROTOCOL_NAME",
    "NOISE_TRANSPORT_NONCE_PREFIX_LEN",
    "NoiseCiphertext",
    "OpaquePayload",
    "PADDING_BUCKETS",
    "PEER_ID_SIZE",
    "PROTOCOL_VERSION",
    "Packet",
    "PacketFlags",
    "PacketHeader",
    "ProtocolError",
    "Reader",
    "SIGNATURE_SIZE",
    "UnsupportedPayloadField",
    "decode_payload",
    "pkcs7_pad_to_bucket",
    "should_pad_for_ble",
    "split_into_fragments",
]