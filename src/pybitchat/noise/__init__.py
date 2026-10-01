"""Capa de Noise de BitChat: handshake estándar + framing propietario.

Dos piezas con responsabilidades distintas, y separarlas es la clave para
entender el código:

- `session.py`  handshake Noise XX/IK/NK. **Estándar.** Motor: `noiseprotocol`,
  porque BitChat usa la revisión 32/33 de la spec y una implementación propia
  basada en la 34 no reproduce sus vectores.
- `framing.py`  transporte. **Propietario de BitChat:** antepone un prefijo de
  nonce de 4 bytes que ninguna implementación estándar espera.
"""

from .framing import (
    MAX_NONCE,
    NONCE_PREFIX_LEN,
    REPLAY_WINDOW,
    REPLAY_WINDOW_BYTES,
    NoiseTransportCipher,
    decode_transport,
    encode_transport,
)
from .primitives import (
    chacha_decrypt,
    chacha_encrypt,
    chacha_nonce,
    generate_x25519_private,
    hash,
    hkdf,
    hmac_hash,
    x25519,
    x25519_public_from_private,
)
from .session import (
    PROTOCOL_NAME,
    SUPPORTED_PROFILES,
    HandshakeSession,
    NoiseError,
    generate_static_private,
)
from .state_errors import CipherStateError, HandshakeError, ReplayError

__all__ = [
    "CipherStateError",
    "HandshakeError",
    "HandshakeSession",
    "MAX_NONCE",
    "NONCE_PREFIX_LEN",
    "NoiseError",
    "NoiseTransportCipher",
    "PROTOCOL_NAME",
    "SUPPORTED_PROFILES",
    "chacha_decrypt",
    "chacha_encrypt",
    "chacha_nonce",
    "decode_transport",
    "encode_transport",
    "generate_static_private",
    "generate_x25519_private",
    "hash",
    "hkdf",
    "hmac_hash",
    "x25519",
    "x25519_public_from_private",
]

