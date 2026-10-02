"""Abstracción de transporte BLE.

El motivo de que exista: **toda la lógica de malla debe poder probarse sin
Bluetooth**. El transporte es la única pieza que necesita hardware; el resto
—codificación, fragmentación, reensamblado, Noise, reenvío— es lógica pura y
tiene que poder recibir y entregar bytes sin que haya un adaptador detrás.

## Qué garantiza un transporte

- Los paquetes son **byte-exactos**: lo que entrega `on_receive` es exactamente
  lo que otro cliente escribió. No se reinterpreta ni se normaliza aquí. Si un
  paquete llega corrupto o truncado, la capa de arriba tiene que poder
  rechazarlo; si el transporte lo arregla, esa capacidad se pierde.
- El reenvío **no** comprime ni recodifica. Si el paquete venía comprimido se
  reenvían sus bytes originales (ver `WirePayload` en `protocol/packet.py`),
  porque la salida de DEFLATE no es canónica y re-comprimir rompería las firmas
  ajenas.
- `send` no bloquea. Un enlace lento no debe parar el bucle de malla.

## Por qué `bleak` no aparece aquí

`bleak` es asíncrono y habla BlueZ en Linux o WinRT en Windows. Para que la
lógica de malla no dependa de eso, `Transport` es una clase abstracta sencilla
con callbacks, y la implementación real irá en `ble/bleak_transport.py` en la
Fase 2b, cuando haya un adaptador.

No es una abstracción gratuita: obliga a que el camino real del enlace pase por
una indirección. A cambio, se pueden provocar a voluntad todas las rutas de
error —reensamblado a medias, timeout, descarte por metadatos inconsistentes—
que en hardware real son imposibles de provocar cuando interesa.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass

PEER_ID_SIZE = 8


class TransportError(RuntimeError):
    """El transporte no pudo enviar o recibir."""


@dataclass(frozen=True, slots=True)
class Peer:
    """Un par visible en el enlace."""

    peer_id: bytes
    rssi: int | None = None
    connected: bool = False

    def __post_init__(self) -> None:
        if len(self.peer_id) != PEER_ID_SIZE:
            raise ValueError(
                f"peer_id debe medir {PEER_ID_SIZE} bytes, tiene {len(self.peer_id)}"
            )

    @property
    def peer_id_hex(self) -> str:
        return self.peer_id.hex()


class Transport(ABC):
    """Enlace bidireccional con otros pares."""

    @abstractmethod
    async def start(self, on_receive: Callable[[bytes, bytes], None]) -> None:
        """Arranca el enlace.

        `on_receive(peer_id, data)` se invoca **una vez por paquete recibido**,
        con los bytes tal cual. Si el enlace entrega algo corrupto, la capa de
        arriba tiene que poder rechazarlo.
        """

    @abstractmethod
    async def stop(self) -> None:
        """Para el enlace. Debe poder llamarse sin `start` previo."""

    @abstractmethod
    async def send(self, peer_id: bytes, data: bytes) -> None:
        """Envía `data` a `peer_id` sin bloquear.

        Levanta `TransportError` si no se pudo entregar, pero un fallo con un par
        **no** debe detener el envío a los demás: son vecinos independientes.
        """

    @abstractmethod
    def peers(self) -> Iterable[Peer]:
        """Pares conocidos ahora mismo."""


class MockTransport(Transport):
    """Transporte en memoria, sin Bluetooth.

    Modela lo que importa de un enlace real y omite lo que no:

    - entrega los bytes **sin alterarlos**, como haría el enlace;
    - puede simular pérdida, para probar reensamblados a medias;
    - registra todo lo enviado, para poder afirmar sobre lo que salió;
    - opcionalmente devuelve en bucle lo que se envía, para probar la malla
      contra uno mismo.

    No simula advertisings, conexiones GATT ni temporizadores de peer. Eso
    pertenece al transporte real y probarlo aquí sólo daría falsa confianza: el
    punto de este doble es verificar la lógica de malla, no que BLE funcione.
    """

    def __init__(self, *, loopback: bool = False) -> None:
        self._loopback = loopback
        #: Pares a los que llega todo lo enviado.
        self._fiables: set[bytes] = set()
        #: Descarta uno de cada N envíos a pares no fiables.
        self._drop_every: int | None = None
        self._envios: dict[bytes, list[bytes]] = {}
        self._peers: dict[bytes, Peer] = {}
        self._on_receive: Callable[[bytes, bytes], None] | None = None
        self._arranca = False
        self._contador = 0

    # -- configuración para tests -------------------------------------------

    def add_peer(self, peer_id: bytes, *, rssi: int | None = None,
                 fiable: bool = False) -> Peer:
        """Registra un par. `fiable=True` recibe todo lo que se le envíe."""
        pid = bytes(peer_id)
        self._peers[pid] = Peer(pid, rssi, connected=True)
        if fiable:
            self._fiables.add(pid)
        return self._peers[pid]

    def drop_every(self, n: int | None) -> None:
        """Pierde uno de cada n envíos a pares no fiables.

        Con `n=2` se pierde la mitad. Sirve para comprobar que un conjunto de
        fragmentos se purga al vencer el timeout en vez de acumularse para
        siempre.
        """
        self._drop_every = n

    # -- Transport -----------------------------------------------------------

    async def start(self, on_receive: Callable[[bytes, bytes], None]) -> None:
        self._on_receive = on_receive
        self._arranca = True

    async def stop(self) -> None:
        self._arranca = False
        self._on_receive = None

    async def send(self, peer_id: bytes, data: bytes) -> None:
        pid = bytes(peer_id)
        if len(pid) != PEER_ID_SIZE:
            raise TransportError(
                f"peer_id debe medir {PEER_ID_SIZE} bytes, tiene {len(pid)}"
            )
        if not self._arranca:
            raise TransportError("el transporte no está arrancado")

        self._envios.setdefault(pid, []).append(data)

        if not self._loopback:
            return
        if pid not in self._fiables:
            self._contador += 1
            if self._drop_every and self._contador % self._drop_every == 0:
                return
        self.entregar(pid, data)

    def peers(self) -> Iterable[Peer]:
        return list(self._peers.values())

    # -- simulación de entrada ----------------------------------------------

    def entregar(self, peer_id: bytes, data: bytes) -> None:
        """Simula que un par nos manda `data`.

        Es la vía normal para alimentar un paquete entrante en los tests, sin pasar por
        `send`: así se prueba el camino de recepción, que es el interesante.
        """
        if self._on_receive is None:
            raise TransportError("el transporte no está arrancado")
        self._on_receive(bytes(peer_id), data)

    # -- inspección ----------------------------------------------------------

    def enviado_a(self, peer_id: bytes) -> list[bytes]:
        """Todo lo que se envió a ese par, en orden."""
        return list(self._envios.get(bytes(peer_id), []))


__all__ = [
    "PEER_ID_SIZE",
    "MockTransport",
    "Peer",
    "Transport",
    "TransportError",
]