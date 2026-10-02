"""Anuncio BLE como peripheral, hablando D-Bus directamente con BlueZ.

## Por qué no `bleak`

`bleak` 3.0.2 **no puede ser peripheral en Linux**. Su único soporte de servidor
GATT/peripheral es `backends/corebluetooth/PeripheralDelegate.py`, que es macOS.
En BlueZ sólo hay `advertisement_monitor`, que sirve para **escanear**, no para
anunciar.

Así que este módulo habla con `org.bluez.LEAdvertisingManager1` por D-Bus, con
`dbus-fast` (que ya viene como dependencia de bleak).

## Qué anuncia exactamente la app

De `BluetoothGattServerManager.startAdvertising` (`:389-407`):

**Paquete de advertising**
- `ServiceUUIDs`: `F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C`
- sin potencia de transmisión, sin nombre de dispositivo

**Scan response**
- `ServiceData[F47B5E2D-…]`: los **8 primeros bytes del peerID**

Y el motivo está escrito en el propio código:

> *Add stable identity (first 8 bytes of peerID) to Scan Response. This allows
> scanners to deduplicate devices even if MAC address rotates*

## La consecuencia importante

La app **no identifica a los peers por la MAC**, sino por el `peer_id` del scan
response. Y las MAC rotan, como vimos en seis direcciones distintas.

Por eso no nos encontraba: no estábamos anunciando, así que nunca aparecíamos
con nuestro `peer_id`. Conectar a ella no basta: hay que existir en el anuncio.

## Limitación conocida: el scan response es experimental

En BlueZ, lo que va al scan response son las propiedades `ScanResponse*`, marcadas
como experimentales y no presentes en todas las versiones. Este módulo:

1. Intenta mandarlo al scan response, que es lo faithful.
2. Si BlueZ lo rechaza, cae a ponerlo en el paquete de advertising, que no es
   idéntico pero sí es funcional.

Se registra qué camino se usó, porque la diferencia importa al depurar.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from typing import Any

from .gatt import SERVICE_UUID

log = logging.getLogger(__name__)

#: Interfaz del gestor de anuncios de BlueZ.
IFACE_MANAGER = "org.bluez.LEAdvertisingManager1"
#: Interfaz que debe implementar el objeto de anuncio que registramos.
IFACE_ADVERTISEMENT = "org.bluez.LEAdvertisement1"

#: Nombre de bus D-Bus que tomamos. Lleva **puntos**, como todo nombre de bus.
NOMBRE_SERVICIO = "org.bluez.pybitchat"

#: Ruta del objeto donde se publica la interfaz `LEAdvertisement1`.
#:
#: ⚠️ Lleva **barras**, no puntos. Cada elemento de una ruta de objeto D-Bus
#: tiene que cumplir `[A-Za-z0-9_]`, así que un punto dentro de un elemento es
#: inválido y BlueZ lo rechaza con `InvalidObjectPathError`. Confundir el nombre
#: de bus con la ruta de objeto es el error más obvio de este fichero, y sólo
#: aparece al ejecutar.
RUTA_SERVICIO = "/org/bluez/pybitchat"

#: Ruta del anuncio. Debe empezar por la del servicio, porque es donde se
#: publica el objeto que BlueZ va a llamar para liberarlo.
RUTA_ANUNCIO = f"{RUTA_SERVICIO}/advertisement"


def _adaptador() -> str:
    """Nombre del adaptador, del entorno.

    `BLUEZ_ADAPTER` permite fijarlo sin dependencias; si no, se toma el primero
    que BlueZ reporte.
    """
    return os.environ.get("BLUEZ_ADAPTER", "hci0")


def opciones_anuncio(
    peer_id: bytes,
    *,
    servicio=SERVICE_UUID,
    scan_response: bool = True,
) -> dict[str, Any]:
    """Construye el diccionario de opciones de `RegisterAdvertisement`.

    `peer_id` son los 8 bytes del identificador. No el nombre, no la MAC.
    """
    if len(peer_id) != 8:
        raise ValueError(f"el peer_id debe medir 8 bytes, tiene {len(peer_id)}")

    base: dict[str, Any] = {
        "Type": "peripheral",
        "ServiceUUIDs": [str(servicio)],
        # Se declara `ServiceData` en vez de `ScanResponseServiceData` según
        # `scan_response`, porque BlueZ los trata en campos distintos.
        ("ScanResponseServiceData" if scan_response else "ServiceData"): {
            str(servicio): bytes(peer_id)
        },
    }
    if scan_response:
        # Duplicar el UUID en el scan response ayuda a algunos escáneres, que
        # leen el UUID sólo de ahí.
        base["ScanResponseServiceUUIDs"] = [str(servicio)]
    return base


class Advertiser:
    """Anuncia el servicio de BitChat con nuestro `peer_id`.

    Uso:

        adv = Advertiser(b"\\x01" * 8)
        await adv.start()
        ...
        await adv.stop()
    """

    def __init__(self, peer_id: bytes, *, adaptador: str | None = None) -> None:
        self.peer_id = bytes(peer_id)
        if len(self.peer_id) != 8:
            raise ValueError("el peer_id debe medir 8 bytes")
        self._adaptador = adaptador or _adaptador()
        self._bus = None
        self._proxy = None
        self._ruta: str | None = None
        #: Último error, para poder informar sin que haya que ir al log.
        self.ultimo_error: str | None = None
        #: `True` si el peer_id fue al scan response, `False` si cayó al
        #: paquete de advertising.
        self.en_scan_response = False

    # -- ciclo de vida -------------------------------------------------------

    async def start(self) -> bool:
        """Registra el anuncio. Devuelve `False` si no se pudo.

        No lanza: no se puede anunciar es un estado degradado pero sobrevivible (la
        app simply won't find us), and the caller decides what to do.
        """
        from dbus_fast import BusType
        from dbus_fast.aio import MessageBus

        try:
            self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            introspect = await self._bus.introspect("org.bluez", "/")
            obj = self._bus.get_proxy_object("org.bluez", "/", introspect)
            raiz = obj.get_interface("org.freedesktop.DBus.ObjectManager")

            # Buscar el adaptador pedido entre los que BlueZ expone.
            # `GetManagedObjects` devuelve un **dict** ruta -> interfaces, así
            # que hay que iterar `.items()`: recorrerlo a pelo daría las claves y
            # `for ruta, interfaces` fallaría al desempaquetar cada string.
            hci = None
            nombres: list[str] = []
            for ruta, interfaces in (await raiz.call_get_managed_objects()).items():
                if IFACE_MANAGER not in interfaces:
                    continue
                nombre = os.path.basename(ruta.rstrip("/"))
                nombres.append(nombre)
                if nombre == self._adaptador:
                    hci = ruta
            nombre_adaptadores = nombres
            if hci is None:
                log.error("no se encuentra el adaptador %s", self._adaptador)
                self.ultimo_error = (
                    f"el adaptador {self._adaptador!r} no expone "
                    f"{IFACE_MANAGER}. Adaptadores que BlueZ sí expone: "
                    f"{sorted(nombre_adaptadores)}"
                )
                return False

            self._ruta = RUTA_ANUNCIO
            await self._exportar_anuncio()
            self._proxy = obj.get_interface(IFACE_MANAGER, hci)

            if await self._registrar(con_scan_response=True):
                self.en_scan_response = True
            elif await self._registrar(con_scan_response=False):
                self.en_scan_response = False
            else:
                log.error("BlueZ rechazó el anuncio en las dos formas")
                await self.stop()
                return False

            log.info(
                "anunciando peer_id=%s (%s)",
                self.peer_id.hex(),
                "scan response" if self.en_scan_response else "advertising",
            )
            return True
        except Exception as exc:
            log.exception("fallo al anunciar")
            self.ultimo_error = f"{type(exc).__name__}: {exc}"
            await self.stop()
            return False

    async def _registrar(self, *, con_scan_response: bool) -> bool:
        opciones = opciones_anuncio(
            self.peer_id, scan_response=con_scan_response
        )
        try:
            await self._proxy.call_register_advertisement(self._ruta, opciones)
            return True
        except Exception as exc:
            log.info(
                "registro con scan_response=%s rechazado: %s",
                con_scan_response, exc,
            )
            return False

    async def _exportar_anuncio(self) -> None:
        """Publica el objeto que BlueZ llamará para liberar el anuncio.

        BlueZ no anuncia nada hasta que este objeto existe. Sin él,
        `RegisterAdvertisement` falla.

        ## La firma del método

        `dbus_fast.service.method` **no puede deducirla** de un método sin
        argumentos y sin valor de retorno: falla con

            TypeError: Argument 'signature' has incorrect type
            (expected str, got NoneType)

        La convención de dbus-fast (igual que dbus-next) es que **la firma
        D-Bus va en la anotación de retorno**, y que un método que no devuelve
        nada se declara con la cadena vacía. De ahí el `-> ""`, que no es
        decorativo: sin él el decorador aborta.
        """
        from dbus_fast.service import ServiceInterface, method

        class _Anuncio(ServiceInterface):
            def __init__(self) -> None:
                super().__init__(IFACE_ADVERTISEMENT)

            @method()
            async def Release(self) -> "":  # noqa: N802, E704 - firma D-Bus vacía
                log.info("BlueZ liberó el anuncio")

        self._bus.export(RUTA_SERVICIO, _Anuncio())

    async def stop(self) -> None:
        """Da de baja el anuncio. No lanza si nunca se arrancó."""
        if self._proxy is not None and self._ruta is not None:
            with contextlib.suppress(Exception):
                await self._proxy.call_unregister_advertisement(self._ruta)
        if self._bus is not None:
            with contextlib.suppress(Exception):
                self._bus.unexport(RUTA_SERVICIO, None)
            with contextlib.suppress(Exception):
                self._bus.disconnect()
        self._proxy = None
        self._bus = None

    async def __aenter__(self) -> "Advertiser":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()


__all__ = [
    "IFACE_ADVERTISEMENT",
    "IFACE_MANAGER",
    "NOMBRE_SERVICIO",
    "RUTA_ANUNCIO",
    "RUTA_SERVICIO",
    "Advertiser",
    "opciones_anuncio",
]