"""Prueba de anuncio BLE: ¿nos encuentra la app?

Anuncia el servicio de BitChat con nuestro `peer_id` en el scan response y
comprueba, **escaneando con el propio script**, si la app aparece en el anuncio.

Por qué el `peer_id` y no la MAC: la app identifica a los peers por los 8
primeros bytes del peerID que van en el scan response, porque las MAC rotan. Sin
ese dato no hay forma de que nos asocie a nada.

Uso:
    .venv/bin/python tools/probe_advertise.py
    .venv/bin/python tools/probe_advertise.py --segundos 30

Requiere el móvil **desbloqueado con BitChat en primer plano**: Android deja de
anunciar cuando la app pasa a segundo plano.

Distingue los fallos: BlueZ puede rechazar el anuncio entero, y eso es distinto
de que se anuncie y no nos vean.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from pybitchat.ble.advertiser import Advertiser  # noqa: E402
from pybitchat.ble.gatt import es_nuestro_servicio  # noqa: E402
from pybitchat.protocol.identity import Identity  # noqa: E402


async def principal(args: argparse.Namespace) -> int:
    identidad = Identity.cargar_o_crear(args.nickname)
    print(f"identidad: peer_id={identidad.peer_id_hex}  "
          f"nickname={identidad.nickname!r}")

    print("\n--- registro del anuncio ---")
    anuncio = Advertiser(identidad.peer_id)
    ok = await anuncio.start()
    if not ok:
        print(f"\nNO se pudo anunciar: {anuncio.ultimo_error}")
        print("\nCausas habituales:")
        print("  - BlueZ sin permiso de advertising. Se comprueba con:")
        print("      bluetoothctl list")
        print("    y debe poner 'Supported' incluyendo 'peripheral'.")
        print("  - El adaptador no soporta advertising.")
        print("  - Ya hay demasiados anunciantes activos.")
        await anuncio.stop()
        return 1

    donde = "scan response" if anuncio.en_scan_response else "paquete de advertising"
    print(f"anunciando. peer_id en: {donde}")
    print("  (si BlueZ no soporta ScanResponse, cae al paquete de advertising;")
    print("   funciona pero no es idéntico a lo que hace la app)")

    print(f"\n--- esperando {args.segundos} s a que aparezca un par announcing ---")
    await asyncio.sleep(args.segundos)
    await anuncio.stop()
    print("anuncio retirado.")

    print("\n--- ahora escaneamos a ver qué hay por ahi ---")
    from bleak import BleakScanner

    encontrados = await BleakScanner.discover(timeout=12.0, return_adv=True)
    print(f"{len(encontrados)} dispositivos\n")
    for mac, (dev, adv) in encontrados.items():
        es_bitchat = any(es_nuestro_servicio(u) for u in (adv.service_uuids or []))
        if es_bitchat or dev.name:
            print(f"{mac}  {dev.name!r}  rssi={adv.rssi}")
            if es_bitchat:
                print(f"    svc={adv.service_uuids}")
                print(f"    service_data={adv.service_data}")
                print("    ^ ese service_data deberia ser el peer_id de 8 bytes")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--nickname", default="pybitchat-probe")
    p.add_argument("--segundos", type=float, default=25.0)
    args = p.parse_args()
    asyncio.run(principal(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())