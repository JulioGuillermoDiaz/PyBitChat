"""Prueba de humo del enlace BLE contra la app Android.

Conecta con el teléfono, envía un `ANNOUNCE` y registra todo lo que llegue por
notificaciones. Sirve para responder a una pregunta concreta:

    ¿basta con ser central, o hace falta que también anunciemos y sirvamos GATT?

Si la app contesta a nuestro ANNOUNCE sobre la conexión GATT existente, el lado
central basta. Si no contesta, hace falta la mitad peripheral completa (anuncio
propio + servidor GATT), que bleak soporta de forma limitada en BlueZ.

Uso:
    .venv/bin/python tools/smoke_ble.py                 # 20 s de escucha
    .venv/bin/python tools/smoke_ble.py --nickname yo   # nombre propio
    .venv/bin/python tools/smoke_ble.py --segundos 60

Requiere el móvil **desbloqueado con BitChat en primer plano**: Android deja de
anunciar cuando la app pasa a segundo plano.

⚠️ Envía un announce con un `sender_id` fijo y claramente identificable. Si la
malla tiene otros peers, verán un par nuevo. Es inocuo, pero no es invisible.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from pybitchat.ble.gatt import (  # noqa: E402
    CHARACTERISTIC_UUID,
    SERVICE_UUID,
)
from pybitchat.protocol.packet import Packet, PacketHeader  # noqa: E402
from pybitchat.protocol.payloads import decode_payload, CURRENT  # noqa: E402
from pybitchat.protocol.types import MessageType, PacketFlags  # noqa: E402

#: `bleak` se importa **dentro** de las funciones, no aquí. Así `construir_announce`
#: y `hexdump` se pueden probar sin el adaptador ni la dependencia, y la lógica de
#: paquetes queda cubierta en cualquier máquina.

#: Identificador de par con el que sale esta herramienta. Deliberadamente
#: reconocible para poder distinguir sus paquetes de los de otros peers.
SENDER_ID = bytes.fromhex("5049424348415401")  # "PIBCHAT" + 0x01


def hexdump(datos: bytes, sangria: str = "    ") -> str:
    """Volcado hexadecimal legible, en líneas de 16 bytes."""
    if not datos:
        return sangria + "(vacío)"
    lineas = []
    for i in range(0, len(datos), 16):
        trozo = datos[i : i + 16]
        hexa = " ".join(f"{b:02x}" for b in trozo)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in trozo)
        lineas.append(f"{sangria}{i:04x}  {hexa:<47}  {ascii_}")
    return "\n".join(lineas)


def construir_announce(nickname: str, ttl: int = 3) -> bytes:
    """Monta un paquete ANNOUNCE con nuestro códec.

    El payload es **sólo** el nickname en UTF-8, sin prefijo de longitud
    (`AnnouncePayload`, validado contra los vectores reales).

    No se rellena: `should_pad_for_ble` dice que sólo van rellenadas las tramas
    Noise.
    """
    carga = nickname.encode("utf-8")
    cabecera = PacketHeader(
        version=1,
        raw_type=int(MessageType.ANNOUNCE),
        ttl=ttl,
        timestamp=int(time.time() * 1000),
        flags=PacketFlags(0),
        payload_len=len(carga),
    )
    return Packet(header=cabecera, sender_id=SENDER_ID, payload=carga).to_bytes()


async def resolver_telefono(timeout: float):
    """Busca el teléfono por UUID de servicio, sin cachear direcciones."""
    from bleak import BleakScanner

    print(f"buscando el teléfono (announce {SENDER_ID.hex()})…")
    encontrados = await BleakScanner.discover(timeout=timeout, return_adv=True)
    for mac, (dev, adv) in encontrados.items():
        if SERVICE_UUID.hex.upper() in {
            str(u).upper() for u in (adv.service_uuids or [])
        }:
            print(f"  encontrado: {mac}  rssi={adv.rssi}")
            return mac, dev, adv
    return None


async def principal(args: argparse.Namespace) -> int:
    from bleak import BleakClient

    hallado = await resolver_telefono(args.scan)
    if hallado is None:
        print("\nNO aparece el teléfono.")
        print("¿Está desbloqueado con BitChat en primer plano?")
        print("Android deja de anunciar cuando la app pasa a segundo plano.")
        return 1
    mac, dev, _ = hallado

    recibidos: list[bytes] = []

    async def al_recibir(car, datos: bytearray) -> None:
        datos = bytes(datos)
        recibidos.append(datos)
        print(f"\n--- paquete recibido: {len(datos)} B "
              f"(nº {len(recibidos)}) ---")
        print(hexdump(datos[:96]))
        try:
            p = Packet.from_bytes(datos)
            print(f"    tipo={p.header.type_name}  ttl={p.header.ttl}  "
                  f"sender={p.sender_id.hex()}  payload={len(p.payload)} B")
            carga = decode_payload(p.header.raw_type, p.payload, CURRENT)
            print(f"    carga={type(carga).__name__}: {carga!r}")
        except Exception as exc:
            print(f"    no se pudo decodificar: {type(exc).__name__}: {exc}")

    async with BleakClient(dev, timeout=args.timeout) as cliente:
        try:
            await cliente._backend._acquire_mtu()
        except Exception as exc:
            print(f"  _acquire_mtu falló: {exc}")
        print(f"  conectado. MTU = {cliente.mtu_size}")

        await cliente.start_notify(CHARACTERISTIC_UUID, al_recibir)
        print("  notificaciones activadas")

        car = cliente.services.get_characteristic(CHARACTERISTIC_UUID)
        if car is None:
            print("  el teléfono no expone el characteristic de BitChat")
            return 1

        paquete = construir_announce(args.nickname)
        print(f"\nenviando ANNOUNCE: {len(paquete)} B")
        print(hexdump(paquete))
        limite = car.max_write_without_response_size
        if len(paquete) > limite:
            print(f"\nERROR: excede el máximo escribible ({limite} B). "
                  f"MTU no negociado bien.")
            return 1
        await cliente.write_gatt_char(car, paquete, response=False)
        print("  enviado")

        print(f"\nescuchando {args.segundos} s…")
        await asyncio.sleep(args.segundos)

    print(f"\n{'=' * 60}")
    print(f"total de paquetes recibidos: {len(recibidos)}")
    if not recibidos:
        print("\nSilencio. Dos posibilidades, y hay que distinguirlas:")
        print("  1. La app no responde porque no nos ha descubierto: haría")
        print("     falta anunciar como peripheral y servir GATT.")
        print("  2. La app no responde aunque nos haya descubierto: el modelo")
        print("     de BitChat es otro del que suponemos.")
        print("\nPara distinguirlas: si el móvil muestra el peer en su lista de")
        print("pares, nos descubrió y es el caso 2. Si no aparece, es el caso 1.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--nickname", default="pybitchat-probe",
                   help="nickname del announce (por defecto: pybitchat-probe)")
    p.add_argument("--segundos", type=float, default=20.0,
                   help="segundos de escucha (por defecto: 20)")
    p.add_argument("--scan", type=float, default=15.0,
                   help="segundos de escaneo (por defecto: 15)")
    p.add_argument("--timeout", type=float, default=25.0,
                   help="segundos de conexión (por defecto: 25)")
    args = p.parse_args()
    return asyncio.run(principal(args))


if __name__ == "__main__":
    raise SystemExit(main())