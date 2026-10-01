"""Framing de transporte de BitChat: la única desviación propietaria.

El handshake es Noise estándar (ver `session.py`). Lo que **no** es estándar es
lo que BitChat hace con los mensajes ya cifrados:

    ┌──────────────┬───────────────────────────────┐
    │ nonce  4 B   │  ciphertext ChaCha20-Poly1305 │
    │ **big-endian**│ (+ tag de 16 B)               │
    └──────────────┴───────────────────────────────┘

⚠️ **Las dos endiannesses del sistema son opuestas**, y es la trampa principal
de esta capa:

| Dónde | Endianness | Fuente |
|---|---|---|
| Prefijo de 4 B en el cable | **BIG-endian** | `NoiseSession.kt:133-143`, `nonceToBytes` |
| Nonce AEAD de 12 B | **little-endian** | `ChaChaCore.java:144-150`, `initIV` |

El prefijo es big-endian porque `nonceToBytes` rellena del índice 3 al 0 con el
byte menos significativo primero, lo que deja el MSB en el índice 0. El nonce
AEAD es little-endian porque `initIV` pone `iv` en las palabras 14 y 15 del
estado ChaCha, que se serializan en little-endian, dando 4 bytes a cero
seguidos de 8 bytes de `n` en little-endian.

## La clave de transporte se usa tal cual

`ChaChaPolyCipherState.setNonce(long nonce)` es literalmente `n = nonce`
(`ChaChaPolyCipherState.java:287-288`). **No deriva una clave de epoch**, al
contrario que el `SetNonce` de la spec de Noise (§5.1), que haría
`k = HMAC(k, n)`.

Comprobado contra los vectores Noise-C: con la clave de split directa el
ciphertext de transporte coincide byte a byte; con la derivación de epoch no
coincide en absoluto.

⚠️ Consecuencia de seguridad: al no rekeyar, **la misma clave sirve para todos
los nonces de la sesión**. Por eso la ventana anti-replay no es opcional: es
la única defensa frente a que alguien capture una trama y la reenvíe, porque el
AEAD no detecta repeticiones.
"""

from __future__ import annotations

from .primitives import chacha_decrypt, chacha_encrypt
from .state_errors import CipherStateError, ReplayError

#: Longitud del prefijo de nonce (`NoiseSession.kt:39`).
NONCE_PREFIX_LEN = 4

#: Ventana deslizante de anti-replay (`NoiseSession.kt:40-41`).
REPLAY_WINDOW = 1024
REPLAY_WINDOW_BYTES = REPLAY_WINDOW // 8

#: Límite de rekey de Noise. El prefijo de 4 B impone el mismo tope.
MAX_NONCE = 2**32


def encode_transport(nonce: int, ciphertext: bytes) -> bytes:
    """Antepone el prefijo de nonce de 4 bytes **big-endian**.

    ⚠️ Little y big endian coinciden hasta el nonce 255. A partir del **256**
    divergen, así que un error aquí no se manifiesta hasta el mensaje 256 de
    la sesión y mata el cifrado en ambos sentidos.
    """
    if not 0 <= nonce < MAX_NONCE:
        raise ValueError(f"nonce fuera de rango: {nonce}")
    return nonce.to_bytes(NONCE_PREFIX_LEN, "big") + ciphertext


def decode_transport(data: bytes) -> tuple[int, bytes]:
    """Separa el prefijo de nonce **big-endian** del ciphertext."""
    if len(data) < NONCE_PREFIX_LEN:
        raise ValueError(f"trama demasiado corta: {len(data)} B")
    return int.from_bytes(data[:NONCE_PREFIX_LEN], "big"), data[NONCE_PREFIX_LEN:]


class NoiseTransportCipher:
    """Canal de transporte de BitChat.

    La clave se usa **tal cual**, sin derivación de epoch, y el nonce de la
    trama manda sobre cualquier contador interno: es lo que permite al receptor
    descifrar mensajes que llegan reordenados por el relay.
    """

    __slots__ = ("_send_key", "_send_nonce", "_recv_key", "_highest", "_seen")

    def __init__(self, send_key: bytes, recv_key: bytes) -> None:
        if not send_key or not recv_key:
            raise CipherStateError("el canal de transporte necesita clave")
        self._send_key = send_key
        self._send_nonce = 0
        self._recv_key = recv_key
        #: Mayor nonce recibido, y bitset de los vistos por debajo de él.
        self._highest = -1
        self._seen = bytearray(REPLAY_WINDOW_BYTES)

    @classmethod
    def from_states(cls, send_state, recv_state) -> "NoiseTransportCipher":
        """Construye desde los `CipherState` que devuelve el handshake."""
        return cls(send_state.k, recv_state.k)

    @property
    def send_nonce(self) -> int:
        return self._send_nonce

    @property
    def highest_received_nonce(self) -> int:
        return self._highest

    def encrypt(self, plaintext: bytes, *, associated_data: bytes = b"") -> bytes:
        """Cifra y devuelve la trama completa con prefijo de nonce."""
        nonce = self._send_nonce
        if nonce >= MAX_NONCE:
            raise CipherStateError("nonce agotado: hay que renegociar la sesión")
        ciphertext = chacha_encrypt(self._send_key, nonce, plaintext, associated_data)
        self._send_nonce += 1
        return encode_transport(nonce, ciphertext)

    def decrypt(self, frame: bytes, *, associated_data: bytes = b"") -> bytes:
        """Verifica el nonce, comprueba el anti-replay y descifra.

        El chequeo de reenvío va **antes** del descifrado: si el nonce ya se
        vio, la trama se rechaza sin gastar CPU en un descifrado que además le
        confirmaría al atacante que la clave es la correcta.
        """
        nonce, ciphertext = decode_transport(frame)
        if nonce >= MAX_NONCE:
            raise CipherStateError(f"nonce fuera de rango: {nonce}")
        if self._is_seen(nonce):
            raise ReplayError(f"nonce {nonce} ya procesado: posible reenvío")

        plaintext = chacha_decrypt(self._recv_key, nonce, ciphertext, associated_data)
        self._mark_seen(nonce)
        return plaintext

    def _is_seen(self, nonce: int) -> bool:
        """¿Se ha procesado ya este nonce?

        Tres casos, en el orden de `NoiseSession.isValidNonce` (`:49-62`):
        más antiguo que la ventana (rechazo), más nuevo (se acepta), y dentro de
        la ventana (se mira el bit).
        """
        if nonce > self._highest:
            return False
        offset = self._highest - nonce
        if offset >= REPLAY_WINDOW:
            return True  # demasiado antiguo: fuera de la ventana
        index, bit = divmod(offset, 8)
        return bool(self._seen[index] & (1 << bit))

    def _mark_seen(self, nonce: int) -> None:
        """Registra el nonce y desplaza la ventana si es más nuevo."""
        if nonce <= self._highest:
            offset = self._highest - nonce
            index, bit = divmod(offset, 8)
            self._seen[index] |= 1 << bit
            return

        shift = nonce - self._highest
        if shift >= REPLAY_WINDOW:
            self._seen = bytearray(REPLAY_WINDOW_BYTES)
        else:
            byte_shift, bit_shift = divmod(shift, 8)
            nuevo = bytearray(REPLAY_WINDOW_BYTES)
            if byte_shift:
                largo = REPLAY_WINDOW_BYTES - byte_shift
                nuevo[:largo] = self._seen[byte_shift:]
            if bit_shift:
                for i in range(REPLAY_WINDOW_BYTES - 1, 0, -1):
                    nuevo[i] = (
                        (nuevo[i] << bit_shift) | (nuevo[i - 1] >> (8 - bit_shift))
                    ) & 0xFF
                nuevo[0] = (nuevo[0] << bit_shift) & 0xFF
            self._seen = nuevo

        self._highest = nonce
        self._seen[0] |= 1  # el nonce más alto ocupa el bit 0


__all__ = [
    "MAX_NONCE",
    "NONCE_PREFIX_LEN",
    "REPLAY_WINDOW",
    "REPLAY_WINDOW_BYTES",
    "NoiseTransportCipher",
    "decode_transport",
    "encode_transport",
]