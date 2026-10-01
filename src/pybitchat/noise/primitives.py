"""Primitivas criptográficas del perfil Noise de BitChat.

Perfil `Noise_XX_25519_ChaChaPoly_SHA256`: DH = X25519, AEAD =
ChaCha20-Poly1305, hash = SHA-256.

⚠️ **El motor del handshake NO es este módulo.** Está en `session.py`, sobre
`noiseprotocol`, porque BitChat usa la revisión 32/33 de Noise y una
implementación propia basada en la 34 no reproduce sus vectores.

Lo que sí vive aquí es lo que la librería no cubre: el HKDF de Noise (para
poder derivar claves de epoch y verificar vectores) y las primitivas AEAD que
usa el framing propietario de `framing.py`.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

#: Longitud de clave y hash del perfil.
DH_LEN = 32
HASH_LEN = 32
TAG_LEN = 16

#: Longitud del nonce AEAD de ChaCha20-Poly1305.
NONCE_LEN = 12

#: Longitud del nombre del perfil, y por tanto de `ck` tras
#: `InitializeSymmetric` (no se hashea porque es <= HASHLEN).
PROTOCOL_NAME_LEN = 32


def hash(data: bytes) -> bytes:
    """SHA-256."""
    return hashlib.sha256(data).digest()


def hmac_hash(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256, como lo usa Noise."""
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf(chaining_key: bytes, input_key_material: bytes, num_outputs: int) -> list[bytes]:
    """HKDF **de Noise**, no el de RFC 5869 (§4.3).

        temp_key = HMAC-HASH(chaining_key, input_key_material)
        output1  = HMAC-HASH(temp_key, 0x01)
        output2  = HMAC-HASH(temp_key, output1 || 0x02)
        output3  = HMAC-HASH(temp_key, output2 || 0x03)

    El HKDF estándar empieza con un `extract` con salt. Mezclarlos produce
    claves distintas e incompatibles.
    """
    if not 1 <= num_outputs <= 3:
        raise ValueError(f"num_outputs debe estar entre 1 y 3, es {num_outputs}")
    temp_key = hmac_hash(chaining_key, input_key_material)
    outputs = [hmac_hash(temp_key, b"\x01")]
    for i in range(2, num_outputs + 1):
        outputs.append(hmac_hash(temp_key, outputs[-1] + bytes((i,))))
    return outputs


# --------------------------------------------------------------------------
# X25519
# --------------------------------------------------------------------------


def generate_x25519_private() -> bytes:
    """Clave privada X25519 aleatoria de 32 bytes."""
    return X25519PrivateKey.generate().private_bytes_raw()


def x25519_public_from_private(private: bytes) -> bytes:
    _check_len("clave privada X25519", private, DH_LEN)
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def x25519(private: bytes, public: bytes) -> bytes:
    """DH X25519."""
    _check_len("clave privada X25519", private, DH_LEN)
    _check_len("clave pública X25519", public, DH_LEN)
    return X25519PrivateKey.from_private_bytes(private).exchange(
        X25519PublicKey.from_public_bytes(public)
    )


# --------------------------------------------------------------------------
# ChaCha20-Poly1305
# --------------------------------------------------------------------------


def chacha_nonce(n: int) -> bytes:
    """Nonce de 12 bytes: 4 a cero + contador u64 little-endian (§12.2)."""
    if not 0 <= n < 2**64:
        raise ValueError(f"el nonce debe caber en 64 bits, es {n}")
    return b"\x00" * 4 + n.to_bytes(8, "little")


def chacha_encrypt(key: bytes, nonce: int, plaintext: bytes, ad: bytes) -> bytes:
    _check_len("clave ChaCha", key, 32)
    return ChaCha20Poly1305(key).encrypt(chacha_nonce(nonce), plaintext, ad or None)


def chacha_decrypt(key: bytes, nonce: int, ciphertext: bytes, ad: bytes) -> bytes:
    _check_len("clave ChaCha", key, 32)
    try:
        return ChaCha20Poly1305(key).decrypt(chacha_nonce(nonce), ciphertext, ad or None)
    except InvalidTag as exc:
        raise ValueError("tag AEAD inválido") from exc


def _check_len(what: str, value: bytes, expected: int) -> None:
    if len(value) != expected:
        raise ValueError(f"{what} debe tener {expected} bytes, tiene {len(value)}")


__all__ = [
    "DH_LEN",
    "HASH_LEN",
    "NONCE_LEN",
    "PROTOCOL_NAME_LEN",
    "TAG_LEN",
    "chacha_decrypt",
    "chacha_encrypt",
    "chacha_nonce",
    "generate_x25519_private",
    "hash",
    "hkdf",
    "hmac_hash",
    "x25519",
    "x25519_public_from_private",
]