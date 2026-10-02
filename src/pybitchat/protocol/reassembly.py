"""Reensamblado de fragmentos en el lado receptor.

Fuente: `mesh/FragmentManager.kt` y `model/FragmentPayload.kt` de
`permissionlesstech/bitchat-android`.

El emisor trocea un paquete **ya rellenado** para que quepa en un bloque de
transporte. El receptor hace lo inverso: acumula fragmentos por `fragment_id` y
los concatena cuando están todos.

## Por qué el orden de concatenación es fijo

Los fragmentos se reassemblan **siempre en orden de índice** (`FragmentManager.kt:264`,
bucle `for i in 0 until expectedTotal`). No se usan ni el orden de llegada ni el
de emisión. Esto importa porque el primer fragmento puede perderse o llegar
descolocado, y aun así el resultado debe ser idéntico al original.

## Consistencia del conjunto

Cada conjunto recuerda su `(originalType, total)` la primera vez que llega un
fragmento. Si otro fragmento del mismo `fragment_id` **no coincide**, se rechaza
y además **se borra el conjunto entero** (`FragmentManager.kt:198-203`). No es
excesivo: si dos emisores distintos comparten `fragment_id` pero con totales o
tipos distintos, cualquier reensamblado sería inventado.

## Límites

De `util/AppConstants.kt`, sección `Fragmentation`:

| Constante | Valor | Qué protege |
|-----------|-------|-------------|
| `MAX_FRAGMENTS_PER_ID` | 256 | Nº de fragmentos por conjunto |
| `MAX_FRAGMENT_TOTAL_BYTES` | 1 MiB | Bytes por conjunto |
| `MAX_ACTIVE_FRAGMENT_SETS` | 64 | Conjuntos simultáneos |
| `MAX_GLOBAL_FRAGMENT_TOTAL_BYTES` | 4 MiB | Memoria total en búfer |
| `FRAGMENT_TIMEOUT_MS` | 30 s | Expiración de un conjunto |

Los cuatro primeros son de **memoria**, y se comprueban *antes* de asignar. Un
par podría fragmentar un payload enorme y, sin tope por conjunto, agotar la
memoria del proceso.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from enum import Enum

from .packet import ProtocolError, Reader
from .types import PEER_ID_SIZE

#: Tamaño de la cabecera de `FragmentPayload`: id(8) + index(2) + total(2) + tipo(1)
FRAGMENT_HEADER_SIZE = 8 + 2 + 2 + 1

MAX_FRAGMENTS_PER_ID = 256
MAX_FRAGMENT_TOTAL_BYTES = 1_048_576
MAX_ACTIVE_FRAGMENT_SETS = 64
MAX_GLOBAL_FRAGMENT_TOTAL_BYTES = 4 * 1_048_576
FRAGMENT_TIMEOUT_S = 30.0


class RejectReason(Enum):
    """Por qué se rechazó un fragmento.

    Existe para que los tests puedan afirmar **por qué** algo se descartó, y no
    sólo que se descartó. Un rechazo silencioso es indistinguible de un bug.
    """

    PAYLOAD_TOO_SHORT = "payload demasiado corto para ser un fragmento"
    INVALID = "payload de fragmento inválido"
    TOO_MANY_FRAGMENTS = "total supera MAX_FRAGMENTS_PER_ID"
    INCONSISTENT_METADATA = "el conjunto ya tiene otro total u original_type"
    TOO_MANY_SETS = "ya hay MAX_ACTIVE_FRAGMENT_SETS conjuntos en curso"
    SET_TOO_LARGE = "el conjunto supera MAX_FRAGMENT_TOTAL_BYTES"
    GLOBAL_LIMIT = "supera MAX_GLOBAL_FRAGMENT_TOTAL_BYTES"
    EXPIRED = "el conjunto venció por timeout"


@dataclass(slots=True)
class Rejection:
    fragment_id: bytes
    reason: RejectReason
    #: Texto original del error, para diagnóstico.
    detalle: str | None = None

    def __str__(self) -> str:
        base = f"{self.reason.value} (id={self.fragment_id.hex()})"
        return f"{base}: {self.detalle}" if self.detalle else base


@dataclass(slots=True)
class Fragment:
    """Un fragmento individual, ya validado."""

    fragment_id: bytes
    index: int
    total: int
    original_type: int
    data: bytes

    HEADER_SIZE = FRAGMENT_HEADER_SIZE

    @classmethod
    def parse(cls, data: bytes) -> "Fragment":
        """Decodifica y valida un payload de fragmento.

        Las mismas cinco comprobaciones que `FragmentPayload.isValid`
        (`FragmentPayload.kt:123-129`): id de 8 bytes, índice no negativo, total
        positivo, **índice menor que el total** y datos no vacíos.

        El índice es `u16`, así que `index >= 0` es estructural, pero se
        comprueba igual para no depender de ese detalle.
        """
        if len(data) < FRAGMENT_HEADER_SIZE:
            raise ProtocolError(
                f"fragmento truncado: {len(data)} B < {FRAGMENT_HEADER_SIZE} B"
            )
        r = Reader(data)
        fragment_id = r.raw(8, "fragment_id")
        index = r.u16("index")
        total = r.u16("total")
        original_type = r.u8("original_type")
        cuerpo = r.rest()

        if len(fragment_id) != 8:
            raise ProtocolError("fragment_id debe medir 8 bytes")
        if index >= total:
            raise ProtocolError(f"índice {index} fuera de rango: total es {total}")
        if not cuerpo:
            raise ProtocolError("fragmento sin datos")
        return cls(fragment_id, index, total, original_type, cuerpo)

    def to_bytes(self) -> bytes:
        return b"".join(
            (
                self.fragment_id,
                struct.pack(">H", self.index),
                struct.pack(">H", self.total),
                bytes((self.original_type,)),
                self.data,
            )
        )

    @property
    def is_first(self) -> bool:
        return self.index == 0

    @property
    def is_last(self) -> bool:
        return self.index == self.total - 1


@dataclass(slots=True)
class _Set:
    """Estado de un conjunto en curso."""

    original_type: int
    total: int
    #: Índice -> datos. El diccionario indexa por posición, que es lo que hace
    #: seguro el reensamblado en orden.
    partes: dict[int, bytes] = field(default_factory=dict)
    #: Suma de `len(datos)`. Se lleva aparte para no recalcular.
    bytes: int = 0
    #: Instante de creación, para el timeout.
    creado: float = 0.0


class FragmentReassembler:
    """Acumula fragmentos y devuelve el paquete original cuando están todos.

    El reloj es inyectable (`reloj`) para que los tests puedan simular el
    timeout de 30 s sin dormir.

    Uso:

        >>> r = FragmentReassembler()
        >>> r.add(datos_fragmento)          # -> None hasta que esté completo
        >>> limpio = r.add(datos_ultimo)    # -> bytes del paquete reensamblado
    """

    def __init__(self, reloj=time.monotonic) -> None:
        self._reloj = reloj
        self._sets: dict[bytes, _Set] = {}
        self._global_bytes = 0

    # -- introspection -------------------------------------------------------

    @property
    def conjuntos_activos(self) -> int:
        return len(self._sets)

    @property
    def bytes_en_bufer(self) -> int:
        return self._global_bytes

    def forget(self, fragment_id: bytes) -> None:
        """Olvida un conjunto. Lo llama el reensamblado al completarlo."""
        s = self._sets.pop(fragment_id, None)
        if s is not None:
            self._global_bytes -= s.bytes

    # -- caducidad -----------------------------------------------------------

    def purgar(self) -> list[Rejection]:
        """Descarta los conjuntos que han superado el timeout.

        Devuelve lo descartado para poder registrarlo. Un par que manda un
        fragmento y desaparece ocuparía memoria hasta el siguiente `purgar`.
        """
        ahora = self._reloj()
        caducados = [
            fid for fid, s in self._sets.items()
            if ahora - s.creado > FRAGMENT_TIMEOUT_S
        ]
        resultado = []
        for fid in caducados:
            resultado.append(Rejection(fid, RejectReason.EXPIRED))
            self.forget(fid)
        return resultado

    # -- llegada de un fragmento ---------------------------------------------

    def add(self, data: bytes) -> bytes | Rejection | None:
        """Procesa un payload de fragmento.

        Tres resultados posibles, y se distinguen a propósito:

        - `bytes`  -> el conjunto se completó; el valor es el paquete reensamblado.
        - `Rejection` -> el fragmento se descartó, con el motivo.
        - `None`   -> el fragmento se aceptó y el conjunto sigue incompleto.

        Que "incompleto" sea `None` y no un error es deliberado: recibir la mitad
        de un mensaje es el caso normal, no una incidencia. Lo que no se permite
        es un descarte sin motivo registrado.
        """
        try:
            frag = Fragment.parse(data)
        except ProtocolError as exc:
            # `add` devuelve `Rejection` en vez de propagar: un fragmento mal
            # formado es tráfico de red, no un fallo de programación. El detalle
            # del `ProtocolError` se conserva en el motivo para diagnóstico.
            motivo = (
                RejectReason.PAYLOAD_TOO_SHORT
                if len(data) < FRAGMENT_HEADER_SIZE
                else RejectReason.INVALID
            )
            return Rejection(data[:8].ljust(8, b"\x00"), motivo, detalle=str(exc))

        return self._add_fragment(frag)

    def _add_fragment(self, frag: Fragment) -> bytes | Rejection | None:
        fid = frag.fragment_id

        if frag.total > MAX_FRAGMENTS_PER_ID:
            return Rejection(fid, RejectReason.TOO_MANY_FRAGMENTS)

        existente = self._sets.get(fid)

        if existente is not None:
            # Un mismo fragment_id con otro total u otro tipo significa que
            # hay dos emisores distintos. Lo que se reensamblara sería
            # inventado, así que se descarta el conjunto completo.
            if existente.total != frag.total or existente.original_type != frag.original_type:
                self.forget(fid)
                return Rejection(fid, RejectReason.INCONSISTENT_METADATA)
        else:
            if len(self._sets) >= MAX_ACTIVE_FRAGMENT_SETS:
                return Rejection(fid, RejectReason.TOO_MANY_SETS)
            existente = _Set(
                original_type=frag.original_type,
                total=frag.total,
                creado=self._reloj(),
            )
            self._sets[fid] = existente

        # Tamaño acumulado: un reenvío del mismo índice sustituye, no suma.
        anterior = len(existente.partes.get(frag.index, b""))
        nuevo = existente.bytes - anterior + len(frag.data)
        if nuevo > MAX_FRAGMENT_TOTAL_BYTES:
            self.forget(fid)
            return Rejection(fid, RejectReason.SET_TOO_LARGE)

        delta = len(frag.data) - anterior
        if self._global_bytes + delta > MAX_GLOBAL_FRAGMENT_TOTAL_BYTES:
            return Rejection(fid, RejectReason.GLOBAL_LIMIT)

        existente.partes[frag.index] = frag.data
        existente.bytes = nuevo
        self._global_bytes += delta

        if len(existente.partes) != existente.total:
            # Aún no está completo. No es un error.
            return None

        # Reensamblado en orden de índice, nunca en orden de llegada.
        ensamblado = b"".join(existente.partes[i] for i in range(existente.total))
        self.forget(fid)
        return ensamblado


__all__ = [
    "FRAGMENT_HEADER_SIZE",
    "FRAGMENT_TIMEOUT_S",
    "MAX_ACTIVE_FRAGMENT_SETS",
    "MAX_FRAGMENTS_PER_ID",
    "MAX_FRAGMENT_TOTAL_BYTES",
    "MAX_GLOBAL_FRAGMENT_TOTAL_BYTES",
    "Fragment",
    "FragmentReassembler",
    "PEER_ID_SIZE",
    "Rejection",
    "RejectReason",
]