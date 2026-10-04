"""Identidad del par: anuncio TLV, claves estáticas y firma.

Fuente: `model/IdentityAnnouncement.kt`, `model/PeerCapabilities.kt` y
`model/UnknownAnnouncementTLV.kt` de `permissionlesstech/bitchat-android`.

## Por qué existe

El `ANNOUNCE` **no** es sólo un nickname. En el dialecto actual es un TLV con la
identidad criptográfica completa:

    [tipo u8][longitud u8][valor]      <- ¡longitud de UN byte, no u16!

| TLV | Contenido | Obligatorio |
|-----|-----------|-------------|
| `0x01` | nickname, UTF-8 | sí |
| `0x02` | clave pública Noise (X25519 estática) | sí |
| `0x03` | clave pública de firma (Ed25519) | sí |
| `0x05` | capacidades, bitfield **little-endian** | no |
| `0x04` | TLV de gossip | no |
| resto | se conservan y se reenvían | — |

⚠️ **La longitud del TLV es de un byte.** Es un TLV distinto del de
`BitchatFilePacket`, que usa u16 salvo para `CONTENT`. Confundir los dos rompe
el handshake entero.

## Verificado contra tráfico real

El primer ANNOUNCE capturado de la app Android, byte a byte:

    01 0a  61 6e 65 77 65 6c 6c 73 37 34            nickname "anewells74"
    02 20  97 35 85 b6 50 28 36 ff 57 67 93 ...     Noise X25519 (32 B)
    03 20  7a da 9d ab 1b ec 9e b2 74 cf ...         Ed25519 (32 B)

    2+10 + 2+32 + 2+32 = 80 bytes = payload_len 0x0050

Sin las dos claves públicas la app **no tiene con qué cifrar nada** y no nos
trata como par. Ése es el motivo de que un announce de sólo-nickname no
provoque handshake.

## Detalles del decode que conviene conocer

- El bucle de la app es `while offset + 2 <= size` (`:97`). **Un byte suelto al
  final se ignora en silencio**, porque la condición falla antes de leer. Se
  replica por fidelidad al otro extremo; aquí no se distingue de un TLV vacío.
- Si la longitud declarada se sale del buffer, se rechaza el **anuncio entero**,
  no sólo ese TLV (`:108`).
- Nickname, clave Noise y clave de firma son **las tres obligatorias** (`:137`).
  Si falta una, `decode` devuelve `None`.
- Los TLV desconocidos se **conservan**, no se descartan (`:128-132`), para que
  un decodificar/re-codificar no borre extensiones de clientes más nuevos.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from ..noise.primitives import DH_LEN, generate_x25519_private, x25519_public_from_private
from .packet import Packet, PacketHeader, ProtocolError
from .types import PEER_ID_SIZE, PacketFlags

#: Longitud de cada clave. Ambas son de 32 bytes.
KEY_LEN = 32
SIGNATURE_LEN = 64


class TlvType:
    """Tags del TLV de anuncio (`IdentityAnnouncement.kt:22-26`)."""

    NICKNAME = 0x01
    NOISE_PUBLIC_KEY = 0x02
    SIGNING_PUBLIC_KEY = 0x03
    GOSSIP = 0x04
    CAPABILITIES = 0x05


# --------------------------------------------------------------------------
# Capacidades
# --------------------------------------------------------------------------


class Capability:
    """Bits de funcionalidad del TLV `0x05` (`PeerCapabilities.kt`).

    Empaquetado **little-endian**, con al menos un byte aunque valga cero. Al
    decodificar se leen sólo los 64 bits bajos y se ignoran los bytes de más:
    es la misma tolerancia hacia delante que usa iOS.
    """

    PREKEYS = 1 << 0
    WIFI_BULK = 1 << 1
    GATEWAY = 1 << 2
    GROUPS = 1 << 3
    BOARD = 1 << 4
    VOUCH = 1 << 5
    MESH_DIAGNOSTICS = 1 << 6
    BRIDGE = 1 << 7
    PRIVATE_MEDIA = 1 << 8
    PRIVATE_MEDIA_RECEIPTS = 1 << 9
    #: Reservado por iOS: se decodifica pero no se anuncia ni se usa.
    NON_DESTRUCTIVE_NOISE_REPLACEMENT = 1 << 10

    #: Lo que implementa este cliente (`LOCAL_SUPPORTED` en la app = PRIVATE_MEDIA).
    LOCAL_SUPPORTED = PRIVATE_MEDIA


def encode_capabilities(valor: int) -> bytes:
    """Bitfield little-endian, con un byte mínimo aunque valga cero.

    Traduce el `do { … } while` de `PeerCapabilities.encoded()`: siempre al
    menos un byte, para que un TLV de longitud 0 no se confunda con ausencia.
    """
    if valor < 0:
        raise ValueError(f"capacidades negativas: {valor}")
    salida = bytearray()
    restante = valor
    while True:
        salida.append(restante & 0xFF)
        restante >>= 8
        if restante == 0:
            break
    return bytes(salida)


def decode_capabilities(data: bytes) -> int:
    """Lee los 64 bits bajos en little-endian e ignora el resto."""
    valor = 0
    for i, byte in enumerate(data[:8]):
        valor |= byte << (8 * i)
    return valor


# --------------------------------------------------------------------------
# El anuncio
# --------------------------------------------------------------------------


@dataclass(slots=True)
class UnknownTlv:
    """Un TLV que este cliente no entiende, conservado literal."""

    type: int
    value: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.type <= 0xFF:
            raise ValueError(f"el tipo de TLV debe caber en un byte: {self.type}")

    def to_bytes(self) -> bytes:
        return bytes((self.type, len(self.value))) + self.value


@dataclass(slots=True)
class IdentityAnnouncement:
    """Identidad de un par: nickname y sus dos claves públicas.

    Equivale a `IdentityAnnouncement` de la app. Las tres primeras son
    obligatorias; sin ellas el receptor no puede sostener un handshake.
    """

    nickname: str
    noise_public_key: bytes
    signing_public_key: bytes
    capabilities: int | None = None
    unknown_tlvs: list[UnknownTlv] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.nickname:
            raise ValueError("el nickname no puede estar vacío")

    # -- codificación -------------------------------------------------------

    @staticmethod
    def _tlv(tipo: int, valor: bytes) -> bytes:
        if len(valor) > 0xFF:
            raise ValueError(
                f"el TLV {tipo:#04x} mide {len(valor)} B y el longitud es de un "
                "solo byte"
            )
        return bytes((tipo, len(valor))) + valor

    def to_bytes(self) -> bytes:
        """Serializa el TLV, en el orden que espera la app.

        El orden importa: nickname, Noise, firma, capacidades y luego los TLV
        desconocidos al final, que es como los emite `encode()`.
        """
        partes = [
            self._tlv(TlvType.NICKNAME, self.nickname.encode("utf-8")),
            self._tlv(TlvType.NOISE_PUBLIC_KEY, self.noise_public_key),
            self._tlv(TlvType.SIGNING_PUBLIC_KEY, self.signing_public_key),
        ]
        if self.capabilities is not None:
            partes.append(
                self._tlv(TlvType.CAPABILITIES, encode_capabilities(self.capabilities))
            )
        for tlv in self.unknown_tlvs:
            partes.append(tlv.to_bytes())
        return b"".join(partes)

    @classmethod
    def parse(cls, data: bytes) -> "IdentityAnnouncement":
        """Decodifica el TLV. Lanza `ProtocolError` si falta algo obligatorio.

        Las reglas son las de `IdentityAnnouncement.decode`, incluidas dos
        decisiones que parecen improcedentes pero hay que replicar:
        un byte suelto final se ignora, y una longitud que se sale del buffer
        invalida el anuncio entero.
        """
        offset = 0
        nickname = noise_key = signing_key = None
        capabilities = None
        desconocidos: list[UnknownTlv] = []

        while offset + 2 <= len(data):
            tipo = data[offset]
            longitud = data[offset + 1]
            offset += 2
            if offset + longitud > len(data):
                raise ProtocolError(
                    f"TLV {tipo:#04x} declara {longitud} B y sólo quedan "
                    f"{len(data) - offset}"
                )
            valor = data[offset : offset + longitud]
            offset += longitud

            if tipo == TlvType.NICKNAME:
                nickname = valor.decode("utf-8")
            elif tipo == TlvType.NOISE_PUBLIC_KEY:
                noise_key = valor
            elif tipo == TlvType.SIGNING_PUBLIC_KEY:
                signing_key = valor
            elif tipo == TlvType.CAPABILITIES:
                capabilities = decode_capabilities(valor)
            else:
                # Se conserva, no se tira: reenviar un anuncio no debe borrar
                # las extensiones de un cliente más nuevo.
                desconocidos.append(UnknownTlv(tipo, valor))

        faltan = [
            nombre
            for nombre, valor in (
                ("nickname", nickname),
                ("noise_public_key", noise_key),
                ("signing_public_key", signing_key),
            )
            if valor is None
        ]
        if faltan:
            raise ProtocolError(
                "anuncio incompleto, faltan: " + ", ".join(faltan)
            )
        if not nickname:
            raise ProtocolError("el nickname del anuncio está vacío")

        return cls(nickname, noise_key, signing_key, capabilities, desconocidos)


# --------------------------------------------------------------------------
# Identidad propia
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Identity:
    """Par de claves de este cliente.

    Dos claves con propósitos distintos, igual que en la app:

    - **X25519** para Noise. Es la clave estática `s` del handshake XX. No
      firma nada.
    - **Ed25519** para firmar paquetes. Noise no firma: autentica con el
      intercambio de claves y el HMAC del transcript.

    Confundirlas daría un announce que la app acepta pero con el que no puede
    establecer sesión.
    """

    nickname: str
    #: Clave privada Noise en bruto, 32 bytes.
    noise_private: bytes
    #: Clave privada Ed25519 en bruto, 32 bytes (el formato "seed").
    signing_private: bytes
    capabilities: int = Capability.LOCAL_SUPPORTED

    @classmethod
    def generate(
        cls,
        nickname: str,
        *,
        capabilities: int = Capability.LOCAL_SUPPORTED,
        noise_private: bytes | None = None,
        signing_private: bytes | None = None,
    ) -> "Identity":
        """Crea una identidad. Sin argumentos, claves nuevas.

        Acepta claves concretas para poder restaurar una identidad guardada, que
        es lo que hace la app al reiniciar: la identidad debe sobrevivir al
        proceso o los paresyte_old no pueden volver a encontrarnos.
        """
        if len(nickname.encode("utf-8")) > 0xFF:
            raise ValueError("el nickname no puede pasar de 255 bytes")
        return cls(
            nickname=nickname,
            noise_private=noise_private or generate_x25519_private(),
            signing_private=signing_private or _generate_ed25519_seed(),
            capabilities=capabilities,
        )

    # -- claves públicas -----------------------------------------------------

    @property
    def noise_public(self) -> bytes:
        return x25519_public_from_private(self.noise_private)

    @property
    def signing_public(self) -> bytes:
        return _ed25519_key(self.signing_private).public_key().public_bytes_raw()

    @property
    def peer_id(self) -> bytes:
        """Identificador de 8 bytes que va en la cabecera de cada paquete.

        Derivado de la clave Noise, no elegido. Ver `peer_id_from_noise_key`.
        """
        return peer_id_from_noise_key(self.noise_public)

    @property
    def peer_id_hex(self) -> str:
        return self.peer_id.hex()

    def announcement(self) -> IdentityAnnouncement:
        """El `ANNOUNCE` que emitimos: identidad completa, no sólo nickname."""
        return IdentityAnnouncement(
            nickname=self.nickname,
            noise_public_key=self.noise_public,
            signing_public_key=self.signing_public,
            capabilities=self.capabilities,
        )

    def announce_packet(self, *, ttl: int = 3, timestamp: int | None = None) -> bytes:
        """El paquete `ANNOUNCE` completo, listo para escribir en GATT.

        El `sender_id` sale de la clave, así que el paquete es coherente consigo
        mismo: quien lo reciba puede comprobar que el identificador corresponde a
        la clave que announcea.
        """
        carga = self.announcement().to_bytes()
        import time

        cabecera = PacketHeader(
            version=1,
            raw_type=0x01,  # MessageType.ANNOUNCE
            ttl=ttl,
            timestamp=int(time.time() * 1000) if timestamp is None else timestamp,
            flags=PacketFlags(0),
            payload_len=len(carga),
        )
        return Packet(
            header=cabecera, sender_id=self.peer_id, payload=carga
        ).to_bytes()

    # -- firma --------------------------------------------------------------

    def sign(self, datos: bytes) -> bytes:
        """Firma con Ed25519. Devuelve 64 bytes."""
        return _ed25519_key(self.signing_private).sign(datos)

    def verify(self, datos: bytes, firma: bytes) -> bool:
        """Comprueba una firma con nuestra clave pública.

        Devuelve `False` en vez de lanzar: una firma inválida es tráfico de red
        corrupto o hostil, no un error de programación. Quien llama decide.
        """
        if len(firma) != SIGNATURE_LEN:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(self.signing_public).verify(firma, datos)
        except Exception:
            return False
        return True

    # -- persistencia -------------------------------------------------------

    def exportar(self) -> dict:
        """Serializa para guardarla. Las claves privadas en claro.

        El punto honesto: **esto no cifra nada**. Cifrar la identidad es lo
        siguiente que hay que hacer; guardarla en claro en disco es aceptable
        sólo como andamiaje, no como diseño final. Un atacante con el fichero
        puede impersonar a este par.
        """
        return {
            "nickname": self.nickname,
            "noise_private": self.noise_private.hex(),
            "signing_private": self.signing_private.hex(),
            "capabilities": self.capabilities,
        }

    @classmethod
    def importar(cls, datos: dict) -> "Identity":
        return cls(
            nickname=datos["nickname"],
            noise_private=bytes.fromhex(datos["noise_private"]),
            signing_private=bytes.fromhex(datos["signing_private"]),
            capabilities=int(datos.get("capabilities", Capability.LOCAL_SUPPORTED)),
        )

    # -- en disco ------------------------------------------------------------

    #: Dónde se guarda por defecto. Fuera del repo: es material secreto y no
    #: debe acabar en un commit por accidente.
    RUTA_POR_DEFECTO = Path.home() / ".local" / "share" / "pybitchat" / "identity.json"

    def guardar(self, ruta: "Path | None" = None) -> Path:
        destino = Path(ruta) if ruta else self.RUTA_POR_DEFECTO
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(
            json.dumps(self.exportar(), indent=2) + "\n", encoding="utf-8"
        )
        try:
            destino.chmod(0o600)
        except OSError:
            pass  # en Windows el modo POSIX no aplica
        return destino

    @classmethod
    def cargar_o_crear(
        cls,
        nickname: str,
        *,
        ruta: "Path | None" = None,
        capabilities: int = Capability.LOCAL_SUPPORTED,
    ) -> "Identity":
        """Recupera la identidad guardada, o crea una si no hay.

        Que la identidad **persista** no es opcional: el `peer_id` se deriva de la
        clave, así que una identidad nueva en cada arranque es un par distinto
        cada vez. Los demás nunca volverían a encontrarnos y las sesiones Noise
        previas quedarían huérfanas.

        ## `nickname` no cambia nada si el fichero existe

        Si `ruta` ya existe, se importa y el `nickname` de `identidad` es el que
        tenga dentro. El parmetro se acepta para el caso de que no exista todavía
        y no avisa de que se ha ignorado.

        Para una identidad **de verdad** nueva hay que pasar otro `ruta`. Es lo
        que hay que hacer para probar si la app rehusa un `peer_id` que ya
        conoce: ver `smoke_ble.py` y `ESTADO.md` §3.2ter.
        """
        destino = Path(ruta) if ruta else cls.RUTA_POR_DEFECTO
        if destino.exists():
            try:
                return cls.importar(json.loads(destino.read_text(encoding="utf-8")))
            except (ValueError, KeyError, json.JSONDecodeError):
                # Un fichero corrupto no puede impedir arrancar: se genera una
                # identidad nueva y se avisa con la excepción, no se traga.
                pass
        nueva = cls.generate(nickname, capabilities=capabilities)
        nueva.guardar(destino)
        return nueva


# --------------------------------------------------------------------------
# Identificador de par
# --------------------------------------------------------------------------

#: Longitud del identificador de par.
PEER_ID_LEN = PEER_ID_SIZE


def peer_id_from_noise_key(noise_public_key: bytes) -> bytes:
    """El `sender_id` de 8 bytes se **deriva** de la clave Noise.

    Son los 8 primeros bytes de `SHA-256(clave_pública_X25519)`. Verificado
    contra tráfico real de la app Android el 2026-10-02:

        clave Noise  973585b6502836ff5767934bdb4c62458c48b87e94c02d470797e93d21052f6b
        SHA-256(...)  34e01ccea10a8c6d...          <-- primeros 8
        sender_id     34e01ccea10a8c6d            <-- el que iba en el paquete

    ## Por qué importa

    El identificador **no se elige**: sale de la clave. Eso significa que un par
    puede comprobar que el `sender_id` de un announce corresponde a la clave
    Noise que dice anunciar, y es lo que impide suplantar a otro.

    También explica por qué un announce con un `sender_id` inventado no sirve de
    nada: no está atado a ninguna clave, y no hay forma de responderle.

    `SecureIdentityStateManager` calcula también huellas SHA-256 de la clave
    pública, lo que es coherente con esta derivación. No se localizó la línea
    exacta que la produce; la confirmación es empírica.
    """
    if len(noise_public_key) != KEY_LEN:
        raise ValueError(
            f"la clave Noise debe medir {KEY_LEN} B, tiene {len(noise_public_key)}"
        )
    return hashlib.sha256(noise_public_key).digest()[:PEER_ID_LEN]


# --------------------------------------------------------------------------
# Claves Ed25519
# --------------------------------------------------------------------------


def _ed25519_key(semilla: bytes) -> Ed25519PrivateKey:
    if len(semilla) != KEY_LEN:
        raise ValueError(f"la semilla Ed25519 debe medir {KEY_LEN} B")
    return Ed25519PrivateKey.from_private_bytes(semilla)


def _generate_ed25519_seed() -> bytes:
    """Semilla Ed25519 de 32 bytes.

    El formato "seed" de Ed25519 es lo que permite guardar la clave como bytes
    crudos y reutilizarla; es lo que espera el resto del código.
    """
    clave = Ed25519PrivateKey.generate()
    return clave.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


__all__ = [
    "DH_LEN",
    "KEY_LEN",
    "PEER_ID_LEN",
    "SIGNATURE_LEN",
    "Capability",
    "Identity",
    "IdentityAnnouncement",
    "TlvType",
    "UnknownTlv",
    "decode_capabilities",
    "encode_capabilities",
    "peer_id_from_noise_key",
]