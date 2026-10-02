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
    es_nuestro_servicio,
)
from pybitchat.protocol.identity import Identity  # noqa: E402
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

    Deprecation en favor de `Identity.announce_packet()`: este construía un
    announce de **sólo nickname**, que es el formato del dialecto retirado. La app
    actual necesita la identidad completa, así que esta función queda sólo como
    referencia de lo que **no** hay que hacer.

    Para el announce correcto usa `Identity`, que deriva además el `sender_id`
    de la clave Noise.
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


def contar_uuids(anuncios: dict) -> int:
    """Suma los UUID de servicio de todos los dispositivos vistos.

    Vive fuera de `resolver_telefono` para poder probarse sin `bleak` ni
    adaptador. Existe además por una razón práctica: si el recuento sale a
    cero, el problema no es el teléfono sino que el adaptador no está
    escaneando, y eso cambia por completo la diagnóstico.
    """
    return sum(len(adv.service_uuids or ()) for _dev, adv in anuncios.values())


async def resolver_telefono(timeout: float):
    """Busca el teléfono por UUID de servicio, sin cachear direcciones."""
    from bleak import BleakScanner

    print("buscando el teléfono…")
    encontrados = await BleakScanner.discover(timeout=timeout, return_adv=True)
    print(f"  {len(encontrados)} dispositivos, {contar_uuids(encontrados)} UUID de servicio")
    for mac, (dev, adv) in encontrados.items():
        if any(es_nuestro_servicio(u) for u in (adv.service_uuids or [])):
            print(f"  encontrado: {mac}  rssi={adv.rssi}")
            return mac, dev, adv
    if not encontrados:
        print("  el adaptador no vio NADA: no es el teléfono")
    else:
        print("  hay dispositivos pero ninguno anuncia BitChat")
    return None


async def principal(args: argparse.Namespace) -> int:
    from bleak import BleakClient

    # La identidad se carga de disco o se crea una vez. Que persista importa:
    # el peer_id se deriva de la clave Noise, así que regenerarla en cada
    # arranque haría que fuéramos un par distinto cada vez y nadie nos
    # volvería a encontrar.
    identidad = Identity.cargar_o_crear(args.nickname, ruta=args.identity)
    print(f"identidad: nickname={identidad.nickname!r}  "
          f"peer_id={identidad.peer_id_hex}")
    print(f"  (guardada en {identidad.guardar(args.identity)})")

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
        # Volcado **completo**. Antes se truncaba a 96 B, que es justo lo que
        # dejó incompleta la clave de firma del announce en la primera captura.
        print(hexdump(datos))
        try:
            p = Packet.from_bytes(datos)
            print(f"    tipo={p.header.type_name}  ttl={p.header.ttl}  "
                  f"sender={p.sender_id.hex()}  payload={len(p.payload)} B")
            carga = decode_payload(p.header.raw_type, p.payload, CURRENT)
            print(f"    carga={type(carga).__name__}: {carga!r}")
        except Exception as exc:
            print(f"    no se pudo decodificar: {type(exc).__name__}: {exc}")

    print(f"  conectando a {mac} (timeout {args.timeout}s)…")
    try:
        async with BleakClient(dev, timeout=args.timeout) as cliente:
            return await _sesion(cliente, args, identidad, recibidos, al_recibir)
    except TimeoutError:
        print("\nTIMEOUT al conectar.")
        print("El escaneo funciona, así que el radio ve al teléfono; lo que falla")
        print("es el establecimiento del enlace. Causas habituales:")
        print("  - Quedó una conexión GATT colgada de una ejecución anterior.")
        print("    Se limpia con:  bluetoothctl devices Connected")
        print("                    bluetoothctl remove <MAC>")
        print("  - Android ya está conectado a otro cliente de este adaptador.")
        print("  - Reintentar: a veces basta con volver a lanzarlo.")
        raise SystemExit(2)


async def _sesion(cliente, args, identidad, recibidos, al_recibir) -> int:
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

    paquete = args.paquete or identidad.announce_packet(ttl=3)
    print(f"\nenviando ANNOUNCE de {args.nickname!r}")
    print(f"  peer_id = {identidad.peer_id_hex}  (sha256 de la clave Noise, [:8])")
    print(f"  clave Noise = {identidad.noise_public.hex()}")
    print(f"  tamaño = {len(paquete)} B")
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

    return _informe(recibidos)


def _informe(recibidos: list[bytes]) -> int:
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
    p.add_argument("--identity", type=Path, default=None,
                   help="fichero de identidad (por defecto: "
                        "~/.local/share/pybitchat/identity.json)")
    p.add_argument("--paquete", type=Path, default=None,
                   help="usar este fichero en vez de construir el announce; "
                        "permite reenviar bytes capturados tal cual")
    p.add_argument("--segundos", type=float, default=20.0,
                   help="segundos de escucha (por defecto: 20)")
    p.add_argument("--scan", type=float, default=15.0,
                   help="segundos de escaneo (por defecto: 15)")
    p.add_argument("--timeout", type=float, default=25.0,
                   help="segundos de conexión (por defecto: 25)")
    args = p.parse_args()
    if args.paquete:
        args.paquete = args.paquete.read_bytes()
    return asyncio.run(principal(args))


if __name__ == "__main__":
    raise SystemExit(main())
