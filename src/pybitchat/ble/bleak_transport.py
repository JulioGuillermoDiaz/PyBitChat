"""Transporte BLE real sobre `bleak`. Fase 2b.

Implementa `mesh.transport.Transport` contra el Adaptador Bluetooth. Es la
única pieza del proyecto que necesita hardware.

⚠️ **API de bleak fijada a la 3.x.** La 1.x y la 2.x tienen otra API y no son
compatibles con este fichero:

| | bleak 1.x | bleak 3.x |
|---|---|---|
| RSSI del anuncio | `BLEDevice.rssi` | `AdvertisementData.rssi` |
| `discover(return_adv=True)` | `list[tuple]` | `dict[str, tuple]` |
| `client.services` | `await` | propiedad, iterable, **sin `len()`** |
| MTU | `client._acquire_mtu()` | `client._backend._acquire_mtu()`, luego `mtu_size` |

Por eso `bleak>=3.0` va fijado en `requirements.txt`: sin eso, una instalación
distinta produce fallos en tiempo de ejecución y no de importación, que es peor.

## Lo que se verificó contra hardware real

Medido en un Lenovo V15 con Realtek `0bda:4853` y bleak 3.0.2, contra la app
Android:

| | |
|---|---|
| Descubrimiento | la app anuncia `F47B5E2D-…` en el advertising |
| Servicio | `F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C` |
| Characteristic | `A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D` |
| Propiedades | `read, write, write-without-response, notify` |
| MTU negociado | **517** |
| Emparejamiento | **no necesario** |

### Por qué 517 no es arbitrario

`AppConstants.Fragmentation.FRAGMENT_SIZE_THRESHOLD` es **512**, el bloque de
relleno. La cabecera ATT se come 3 bytes: `512 + 3 = 515`. Los 517 dan margen y
Android los eligió para que **un paquete relleno quepa entero sin fragmentar**.

El valor por defecto de BlueZ es **23**, que fragmentaría casi todo. Por eso
`_acquire_mtu()` no es opcional: sin él, el 23 se usa en silencio y los envíos
grandes fallan.

### Las direcciones rotan

Android usa direcciones privadas resolubles para el advertising, y **rota**. En
tres escaneos consecutivos se observaron tres MAC distintas para el mismo
teléfono.

Por eso aquí **no se cachean direcciones**. Cada intento de conexión resuelve el
par por UUID de servicio. Un cliente que guarde la MAC se rompe solo cada cuarto
de hora, y parece un bug en vez de un error de diseño.

## El identificador de par no es la MAC

`Transport.send(peer_id, …)` usa la identidad **de BitChat** (8 bytes dentro
del paquete), no la dirección BLE. El advertising **no** la incluye: sólo lleva
el UUID del servicio.

Consecuencia: no se puede enviar a un par antes de conocer su identidad de
BitChat. Ésta se establece al **recibir** su primer paquete, que es donde va el
`sender_id`. `bind_peer()` permite fijarla antes, si se conoce por otra vía (QR,
huella o un announce overheard).

Esto no es una limitación del transporte: es cómo funciona el protocolo.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Iterable

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic

from ..mesh.transport import PEER_ID_SIZE, Peer, Transport, TransportError
from .gatt import CHARACTERISTIC_UUID, SERVICE_UUID, es_nuestro_servicio

log = logging.getLogger(__name__)

#: MTU mínimo para que un paquete relleno quepa sin trocear:
#: 512 del bloque de relleno + 3 de cabecera ATT, con margen.
MTU_MINIMO = 515


class BleakTransport(Transport):
    """Transporte BLE sobre bleak.

    No comprime ni reinterpreta nada: los bytes entran y salen tal cual. Si el
    otro extremo nos manda un paquete corrupto, el error tiene que llegar a la
    capa de arriba para que pueda descartarlo; arreglarlo aquí perdería esa
    capacidad.
    """

    def __init__(
        self,
        *,
        scan_timeout: float = 15.0,
        connect_timeout: float = 25.0,
        intervalo_barrido: float = 2.0,
    ) -> None:
        self._scan_timeout = scan_timeout
        self._connect_timeout = connect_timeout
        self._intervalo_barrido = intervalo_barrido

        self._on_receive = None
        self._clients: dict[str, BleakClient] = {}
        #: MAC -> identidad de BitChat, establecida al recibir su primer paquete.
        self._mac_a_peer: dict[str, bytes] = {}
        #: Identidad de BitChat -> MAC.
        self._peer_a_mac: dict[bytes, str] = {}
        self._vistos: dict[str, float] = {}
        self._bucle: asyncio.Task | None = None
        self._parado = asyncio.Event()
        self._arrancado = False

    # -- Transport -----------------------------------------------------------

    async def start(self, on_receive) -> None:
        if self._arrancado:
            raise TransportError("el transporte ya está arrancado")
        self._on_receive = on_receive
        self._parado.clear()
        self._arrancado = True
        self._bucle = asyncio.create_task(self._descubrir())

    async def stop(self) -> None:
        self._arrancado = False
        self._parado.set()
        if self._bucle is not None:
            self._bucle.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._bucle
            self._bucle = None
        for mac in list(self._clients):
            await self._desconectar(mac)
        self._on_receive = None

    async def send(self, peer_id: bytes, data: bytes) -> None:
        pid = bytes(peer_id)
        if len(pid) != PEER_ID_SIZE:
            raise TransportError(
                f"peer_id debe medir {PEER_ID_SIZE} bytes, tiene {len(pid)}"
            )
        mac = self._peer_a_mac.get(pid)
        if mac is None or mac not in self._clients:
            raise TransportError(
                f"no hay enlace con {pid.hex()}: su identidad de BitChat se "
                "establece al recibir su primer paquete, o con bind_peer()"
            )
        cliente = self._clients[mac]
        if not cliente.is_connected:
            raise TransportError(f"el enlace con {mac} no está conectado")

        car = cliente.services.get_characteristic(CHARACTERISTIC_UUID)
        if car is None:
            raise TransportError(f"{mac} no expone el characteristic de BitChat")

        limite = car.max_write_without_response_size
        if len(data) > limite:
            # **No** se trocea aquí a propósito. Un troceo a nivel GATT
            # produciría trozos que el otro extremo interpretaría como paquetes
            # de BitChat enteros, que es peor que no enviar nada. Con MTU 517 no
            # debería ocurrir; si ocurre, el problema es el MTU.
            raise TransportError(
                f"el paquete de {len(data)} B excede el máximo escribible "
                f"({limite} B). El MTU no se ha negociado bien; comprobar "
                "_acquire_mtu()"
            )
        await cliente.write_gatt_char(car, data, response=False)

    def peers(self) -> Iterable[Peer]:
        for mac, cliente in self._clients.items():
            if cliente.is_connected:
                yield Peer(
                    self._mac_a_peer.get(mac, b"\x00" * PEER_ID_SIZE),
                    connected=True,
                )

    # -- asociación ----------------------------------------------------------

    def bind_peer(self, mac: str, peer_id: bytes) -> None:
        """Asocia una dirección BLE con una identidad de BitChat.

        Necesario para poder **enviar** antes de haber recibido nada del par, que
        es el caso de los mensajes dirigidos a un par que aún no nos ha
        contestado.
        """
        pid = bytes(peer_id)
        if len(pid) != PEER_ID_SIZE:
            raise TransportError(f"peer_id debe medir {PEER_ID_SIZE} bytes")
        clave = mac.upper()
        self._mac_a_peer[clave] = pid
        self._peer_a_mac[pid] = clave

    # -- descubrimiento y conexión -------------------------------------------

    async def _descubrir(self) -> None:
        """Busca pares y mantiene los enlaces, sin cachear direcciones."""
        while not self._parado.is_set():
            try:
                await self._barrido()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("fallo el barrido de descubrimiento")
            if not self._parado.is_set():
                await asyncio.sleep(self._intervalo_barrido)

    async def _barrido(self) -> None:
        encontrados = await BleakScanner.discover(
            timeout=self._scan_timeout, return_adv=True
        )
        for mac, (dev, adv) in encontrados.items():
            clave = mac.upper()
            if clave in self._clients:
                continue
            # Resolver por UUID, no confiar en que la MAC siga siendo válida:
            # rota. Cada descubrimiento es una resolución de nuevo.
            if not self._anunciado(clave, adv) and self._known_peer(clave) is None:
                continue
            self._vistos[clave] = asyncio.get_event_loop().time()
            await self._conectar(dev, clave)
            return  # una conexión por barrido: conectar es lento

    @staticmethod
    def _anunciado(mac: str, adv) -> bool:
        """¿Anuncia este par el servicio de BitChat?

        Delega en `es_nuestro_servicio`, que compara UUID y no texto. Comparar
        contra `SERVICE_UUID.hex` **nunca coincide**: `.hex` va sin guiones y el
        anuncio los lleva.
        """
        return any(es_nuestro_servicio(u) for u in (adv.service_uuids or []))

    def _known_peer(self, mac: str) -> bytes | None:
        return self._mac_a_peer.get(mac)

    async def _conectar(self, dev, mac: str) -> None:
        cliente = BleakClient(dev, timeout=self._connect_timeout)
        try:
            await cliente.connect()
        except Exception as exc:
            with contextlib.suppress(Exception):
                await cliente.disconnect()
            log.debug("no se pudo conectar con %s: %s", mac, exc)
            return

        # El MTU **no** se negocia solo. Sin esto BlueZ se queda en 23 y todo
        # lo que pase de 20 B falla al escribir.
        try:
            await cliente._backend._acquire_mtu()
        except Exception as exc:
            log.warning("no se pudo negociar el MTU con %s: %s", mac, exc)
        mtu = cliente.mtu_size
        if mtu < MTU_MINIMO:
            log.warning(
                "MTU %d con %s, por debajo de %d. Los envíos grandes fallarán; "
                "conviene revisar la negociación del MTU",
                mtu, mac, MTU_MINIMO,
            )

        async def al_recibir(car: BleakGATTCharacteristic, datos: bytearray) -> None:
            self._al_recibir(mac, bytes(datos))

        try:
            await cliente.start_notify(CHARACTERISTIC_UUID, al_recibir)
        except Exception as exc:
            log.warning("no se pudieron activar notificaciones en %s: %s", mac, exc)
            with contextlib.suppress(Exception):
                await cliente.disconnect()
            return

        self._clients[mac] = cliente
        log.info("enlace con %s abierto, MTU %d", mac, mtu)

    async def _desconectar(self, mac: str) -> None:
        cliente = self._clients.pop(mac, None)
        if cliente is not None:
            with contextlib.suppress(Exception):
                await cliente.disconnect()
        # La identidad puede no quedar: al rotar la dirección,_MAC es distinta.
        # Por eso no se borra _mac_a_peer al desconectar.
        self._vistos.pop(mac, None)

    # -- recepción -----------------------------------------------------------

    def _al_recibir(self, mac: str, datos: bytes) -> None:
        """Un paquete ha llegado. Se entrega **byte a byte**."""
        self._vistos[mac] = asyncio.get_event_loop().time()
        if self._on_receive is not None:
            self._on_receive(self._mac_a_peer.get(mac, b"\x00" * PEER_ID_SIZE), datos)


__all__ = ["MTU_MINIMO", "BleakTransport"]