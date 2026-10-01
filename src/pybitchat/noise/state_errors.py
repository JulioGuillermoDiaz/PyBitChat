"""Errores propios de la capa de Noise de BitChat.

Se separan de los de `noiseprotocol` para que el resto del programa no dependa
de la librería concreta: si mañana se cambia el motor del handshake, los
`except` de aquí siguen significando lo mismo.
"""

from __future__ import annotations


class NoiseError(Exception):
    """Error genérico de la capa de Noise."""


class CipherStateError(NoiseError):
    """El estado de cifrado no puede seguir: sin clave, o nonce agotado."""


class ReplayError(CipherStateError):
    """El nonce ya se había procesado: la trama es un reenvío.

    Existe porque el AEAD **no** detecta reenvíos: la clave se deriva del
    nonce de forma determinista, así que una trama capturada repetida se
    descifraría sin error. Hace falta estado explícito, que es lo que hace la
    app oficial con su ventana de 1024 nonces.
    """


class HandshakeError(NoiseError):
    """El handshake se ha rechazado o se ha usado fuera de orden."""


__all__ = ["CipherStateError", "HandshakeError", "NoiseError", "ReplayError"]
