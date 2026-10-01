"""Handshake Noise de BitChat, sobre `noiseprotocol`.

⚠️ **Por qué `noiseprotocol` y no una implementación propia.**

La especificación de Noise cambió `MixKey` entre revisiones, y las apps de
BitChat usan la **rev. 32/33**, no la 34:

    rev. 32/33 (noiseprotocol, y lo que hace BitChat):
        ck, temp = HKDF(ck, ikm, 2)
        InitializeKey(temp)          # la clave es la salida 2
        # sin MixHash(temp)

    rev. 34 (spec actual, snow):
        ck, temp_h = HKDF(ck, ikm, 2)
        InitializeKey(ck)             # la clave es la salida 1
        MixHash(temp_h)

Ambas son Noise "válido" pero producen claves distintas. Se comprobó: una
implementación propia basada en la rev. 34 no difiere **ni un byte** del
mensaje 2 del vector oficial, porque el error sólo aparece en el primer dato
criptográfico real.

`noiseprotocol` reproduce los vectores de `NoiseExternalVectorTest.kt` de
`permissionlesstech/bitchat-android` byte a byte, así que es el motor.

⚠️ El payload de los mensajes de handshake de BitChat es **siempre vacío**; la
carga útil viaja en el mensaje de transporte cifrado. Los vectores de Noise-C
sí llevan payload, y por eso el API expone el parámetro.

Lo propio de BitChat (prefijo de 4 bytes en el nonce de transporte) **no** está
aquí: vive en `framing.py`.
"""

from __future__ import annotations

from noise.backends.default.backend import DefaultNoiseBackend
from noise.backends.default.keypairs import KeyPair25519
from noise.exceptions import (
    NoiseHandshakeError,
    NoiseInvalidMessage,
    NoiseMaxNonceError,
    NoiseProtocolNameError,
)
from noise.noise_protocol import NoiseProtocol

from .framing import NoiseTransportCipher
from .primitives import DH_LEN, generate_x25519_private

#: Perfil de BitChat. 32 bytes exactos, así que `InitializeSymmetric` no lo
#: hashea: lo usa tal cual como `ck` inicial.
PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"

#: Perfiles declarados por el cliente oficial (`NoiseProtocol.swift`).
SUPPORTED_PROFILES = (
    b"Noise_XX_25519_ChaChaPoly_SHA256",
    b"Noise_IK_25519_ChaChaPoly_SHA256",
    b"Noise_NK_25519_ChaChaPoly_SHA256",
)

_ERRORES = (NoiseHandshakeError, NoiseInvalidMessage, NoiseMaxNonceError)


class HandshakeSession:
    """Una sesión de handshake Noise en curso."""

    def __init__(
        self,
        *,
        initiator: bool,
        protocol_name: bytes = PROTOCOL_NAME,
        prologue: bytes = b"",
        static_private: bytes | None = None,
        ephemeral_private: bytes | None = None,
        remote_static_public: bytes | None = None,
    ) -> None:
        if protocol_name not in SUPPORTED_PROFILES:
            raise NoiseError(f"perfil no soportado: {protocol_name!r}")

        self.protocol_name = protocol_name
        self.initiator = initiator
        self._complete = False
        #: Par `(c1, c2)` que devuelve la librería en el último mensaje. Hay que
        #: capturarlo ahí: después `handshake_done()` borra `symmetric_state`,
        #: `hash_fn` y compañía del `NoiseProtocol`, y volver a pedir el split
        #: revienta con AttributeError.
        self._split_result: tuple | None = None

        keypairs = {
            "s": KeyPair25519.from_private_bytes(
                static_private or generate_x25519_private()
            )
        }
        if ephemeral_private is not None:
            keypairs["e"] = KeyPair25519.from_private_bytes(ephemeral_private)
        if remote_static_public is not None:
            keypairs["rs"] = KeyPair25519.from_public_bytes(remote_static_public)

        # Hay que pasar por `initialise_handshake_state()` y no llamar a
        # `HandshakeState.initialize()` a mano: aquél además deja el estado
        # simétrico y el resto de campos en el `NoiseProtocol`, que `split()` y
        # `handshake_done()` consultan y borran después.
        self._proto = NoiseProtocol(protocol_name, DefaultNoiseBackend())
        self._proto.initiator = initiator
        self._proto.prologue = prologue
        self._proto.keypairs = keypairs
        self._proto.initialise_handshake_state()
        self._state = self._proto.handshake_state

    # -- properties ---------------------------------------------------------

    @property
    def complete(self) -> bool:
        """¿Se han consumido todos los mensajes del patrón?"""
        return self._complete or not self._state.message_patterns

    @property
    def handshake_hash(self) -> bytes:
        """Huella del handshake. Ambos lados deben obtener la misma.

        ⚠️ Al terminar, `noiseprotocol` **borra** `symmetric_state` del
        `NoiseProtocol` y guarda el valor final en `handshake_hash`. Por eso hay
        que leer de uno u otro según la fase.
        """
        estado = getattr(self._state, "symmetric_state", None)
        if estado is not None and hasattr(estado, "get_handshake_hash"):
            return estado.get_handshake_hash()
        final = getattr(self._proto, "handshake_hash", None)
        if isinstance(final, bytes):
            return final
        raise NoiseError("el handshake hash no está disponible en esta fase")

    @property
    def static_public(self) -> bytes:
        """Clave pública estática local, que es la identidad ante los demás."""
        return self._state.s.public_bytes

    @property
    def remote_static_public(self) -> bytes | None:
        """Clave pública estática del otro, si ya se ha recibido."""
        rs = getattr(self._state, "rs", None)
        return getattr(rs, "public_bytes", None)

    # -- mensajes -----------------------------------------------------------

    def write_handshake(self, payload: bytes = b"") -> bytes:
        """Produce el siguiente mensaje de handshake."""
        if self.complete:
            raise NoiseError("el handshake ya se completó")
        buffer = bytearray()
        try:
            resultado = self._state.write_message(payload, buffer)
        except _ERRORES as exc:
            raise NoiseError(f"handshake rechazado: {exc}") from exc
        except Exception as exc:
            raise NoiseError(f"fallo al escribir el mensaje de handshake: {exc}") from exc
        self._nota(resultado)
        return bytes(buffer)

    def read_handshake(self, message: bytes, payload_size: int = 0) -> bytes:
        """Consume el siguiente mensaje de handshake.

        `payload_size` es el número de bytes de carga útil esperados. En el
        tráfico real de BitChat es **0**.
        """
        if self.complete:
            raise NoiseError("el handshake ya se completó")
        # `read_message` **añade** el texto plano al buffer, igual que
        # `write_message` concatena el mensaje. Si se reserva con ceros, la
        # carga útil acaba después de ellos y se devuelve basura.
        buffer = bytearray()
        try:
            resultado = self._state.read_message(message, buffer)
        except _ERRORES as exc:
            raise NoiseError(f"handshake rechazado: {exc}") from exc
        except Exception as exc:
            raise NoiseError(f"fallo al leer el mensaje de handshake: {exc}") from exc
        self._nota(resultado)
        leido = bytes(buffer)
        if payload_size and len(leido) != payload_size:
            raise NoiseError(
                f"el mensaje lleva {len(leido)} B de carga útil, "
                f"se esperaban {payload_size}"
            )
        return leido

    def _nota(self, resultado) -> None:
        """Registra si este mensaje ha cerrado el handshake."""
        if not self._state.message_patterns:
            self._complete = True
        if resultado is not None:
            self._split_result = resultado

    # -- transporte ---------------------------------------------------------

    def split(self) -> NoiseTransportCipher:
        """Termina el handshake y devuelve el canal de transporte.

        `send` y `recv` ya vienen ordenados por el rol de la sesión.
        """
        if not self.complete:
            raise NoiseError("no se puede cerrar el transporte con el handshake a medias")
        if self._split_result is None:
            raise NoiseError("las claves de transporte no están disponibles")
        c1, c2 = self._split_result
        send, recv = (c1, c2) if self.initiator else (c2, c1)
        return NoiseTransportCipher.from_states(send, recv)


def generate_static_private() -> bytes:
    """Clave estática nueva, para producción."""
    return generate_x25519_private()


class NoiseError(Exception):
    """Fallo del handshake, envuelto para no filtrar la librería de abajo."""


__all__ = [
    "DH_LEN",
    "HandshakeSession",
    "PROTOCOL_NAME",
    "SUPPORTED_PROFILES",
    "NoiseError",
    "generate_static_private",
]