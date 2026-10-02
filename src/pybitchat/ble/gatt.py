"""Identidad GATT de BitChat: UUIDs y constantes de conexión.

Fuente: `util/AppConstants.kt`, sección `Mesh` y `Mesh.Gatt`
(`permissionlesstech/bitchat-android`), más `mesh/BluetoothGattServerManager.kt`.

## Cómo funciona el enlace

BitChat usa **GATT y advertising a la vez**, y son papeles distintos:

- **Advertising** (`BluetoothGattServerManager.startAdvertising`) hace el
  dispositivo *descubrible*. Es lo que permite que el otro te encuentre.
- **GATT** mueve los datos. Quien tiene elcharacteristic acepta escrituras del
  otro lado; no es un flujo maestro-esclavo, ambos son servidor y cliente.

Por eso hacen falta los dos. Implementar sólo GATT te deja invisible, y sólo
advertising no transporta nada.

## Los UUID son fijos, no derivados

No se generan al azar ni se negocian: son constantes en el código. Es lo que
hace que dos implementaciones distintas se entiendan sin handshake de servicio.
Si se generaran dinámicamente, ningún cliente ajeno encontraría el servicio.

El `DESCRIPTOR_UUID` sí es el CCCD estándar de Bluetooth
(`00002902-0000-1000-8000-00805f9b34fb`), que es lo que habilita las
notificaciones. Es el único que no es propio de BitChat.

## Validación cruzada

Los mismos valores aparecen en dos sitios independientes:

- `BLEService.swift` de `permissionlesstech/bitchat` y `data_structures.rs:48`
  del cliente Rust.
- `util/AppConstants.kt`, sección `Mesh.Gatt`, en la app Android.

Que coincidan no es casualidad: son el mismo protocolo visto desde dos
implementaciones. La prueba está en `tests/test_transport.py`
(`TestGatt.test_cuidos_coinciden_con_protocol`), que compara ambas fuentes
para que no se separen sin que nadie se entere.

Este módulo **no redefine** los UUID: los toma de `protocol/types.py`, que ya
era la fuente de verdad del formato de bytes. Aquí sólo se convierten a
`uuid.UUID`, se añade el CCCD y seocumentedn las constantes de conexión.
"""

from __future__ import annotations

import uuid as _uuid

from ..protocol.types import (
    BITCHAT_CHARACTERISTIC_UUID,
    BITCHAT_SERVICE_UUID,
    BITCHAT_SERVICE_UUID_TESTNET,
)
from ..protocol.types import PEER_ID_SIZE as _PEER_ID_SIZE

#: Servicio GATT que expone BitChat (`AppConstants.Mesh.Gatt.SERVICE_UUID`).
SERVICE_UUID = _uuid.UUID(BITCHAT_SERVICE_UUID)

#: Servicio de testnet: mismo UUID con el último byte en 'A' en vez de 'C'.
SERVICE_UUID_TESTNET = _uuid.UUID(BITCHAT_SERVICE_UUID_TESTNET)

#: Characteristic por el que viajan los paquetes
#: (`AppConstants.Mesh.Gatt.CHARACTERISTIC_UUID`).
CHARACTERISTIC_UUID = _uuid.UUID(BITCHAT_CHARACTERISTIC_UUID)

#: CCCD estándar de Bluetooth, para habilitar notificaciones. No es de BitChat.
DESCRIPTOR_UUID = _uuid.UUID("00002902-0000-1000-8000-00805f9b34fb")


def es_nuestro_servicio(valor: object) -> bool:
    """¿Este UUID del anuncio es el de BitChat?

    Compara **como UUID**, no como texto. Es la diferencia entre funcionar y no
    funcionar: `uuid.UUID.hex` devuelve 32 caracteres sin guiones y `str(uuid)`
    devuelve 36 con guiones, así que comparar cualquiera de los dos contra el
    otro falla siempre.

    No es un detalle teórico: con la comparación por texto, el descubrimiento se
    quedaba mudo y parecía que el teléfono había desaparecido. Comparar
    `UUID(...)` normaliza ambos formatos y hace la pregunta correcta.

    `valor` llega de bleak como `str`, `UUID` o, en alguna versión, como bytes
    little-endian; por eso el `try` y no una aserción.
    """
    try:
        return _uuid.UUID(str(valor)) == SERVICE_UUID
    except (ValueError, AttributeError, TypeError):
        return False

#: Tamaño del campo de identidad de peer, en bytes. Reexportado de `types.py`
#: para que quien use sólo el paquete `ble` no tenga que importar el protocolo.
PEER_ID_SIZE = _PEER_ID_SIZE

# --------------------------------------------------------------------------
# Ciclo de vida de pares (`AppConstants.Mesh`)
# --------------------------------------------------------------------------

#: Un par sin tráfico durante esto se considera perdido (`STALE_PEER_TIMEOUT_MS`).
STALE_PEER_TIMEOUT_MS = 180_000

#: Cada cuánto se depuran los pares muertos (`PEER_CLEANUP_INTERVAL_MS`).
PEER_CLEANUP_INTERVAL_MS = 60_000

#: Margen antes de tirar la conexión de un par que ya no está
#: (`PEER_DISCONNECT_GRACE_MS`).
PEER_DISCONNECT_GRACE_MS = 10_000

#: Espera entre reintentos de conexión (`CONNECTION_RETRY_DELAY_MS`).
CONNECTION_RETRY_DELAY_MS = 5_000

#: Intentos de conexión antes de rendirse (`MAX_CONNECTION_ATTEMPTS`).
MAX_CONNECTION_ATTEMPTS = 3


__all__ = [
    "CHARACTERISTIC_UUID",
    "CONNECTION_RETRY_DELAY_MS",
    "DESCRIPTOR_UUID",
    "MAX_CONNECTION_ATTEMPTS",
    "PEER_ID_SIZE",
    "PEER_CLEANUP_INTERVAL_MS",
    "PEER_DISCONNECT_GRACE_MS",
    "SERVICE_UUID",
    "SERVICE_UUID_TESTNET",
    "STALE_PEER_TIMEOUT_MS",
    "es_nuestro_servicio",
]