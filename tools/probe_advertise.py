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


def _bonito(mapa) -> str:
    """Convierte las claves de los dict de bleak a texto legible.

    bleak puede devolver las claves como `str`, `UUID` o bytes little-endian
    según la plataforma. Si no se normalizan, el error al comparar sale como
    "not in" y no dice qué se estaba comparando.
    """
    partes = []
    for clave, valor in mapa.items():
        partes.append(f"{clave}: {valor.hex() if hasattr(valor, 'hex') else valor}")
    return "{" + ", ".join(partes) + "}"


def resumen(anuncios) -> tuple[list[str], int]:
    """Informe de un escaneo. `anuncios` son datos ya planos.

    Cada elemento es `(mac, nombre, uuids, service_data, rssi)`. Se construye
    así, y no con los objetos de bleak, para que la función sea comprobable
    sin adaptador: los tests le pasan diccionarios y no necesitan hardware.

    Devuelve `(lineas, cuantos_bitchat)`.
    """
    lineas: list[str] = []
    cuantos = 0
    for mac, nombre, uuids, service_data, rssi in anuncios:
        uuids = list(uuids or [])
        es_bitchat = any(es_nuestro_servicio(u) for u in uuids)
        cuantos += 1 if es_bitchat else 0
        marca = "BITCHAT" if es_bitchat else "      "
        lineas.append(
            f"[{marca}] {mac}  {nombre or '(sin nombre)'}  rssi={rssi}"
        )
        if uuids:
            lineas.append(f"           svc={uuids}")
            for u in uuids:
                if not es_nuestro_servicio(u):
                    lineas.append(f"           ^ UUID desconocido: {u}")
        else:
            lineas.append("           sin UUID de servicio")
        if service_data:
            lineas.append(f"           service_data={_bonito(service_data)}")
            for uuid, dato in service_data.items():
                if es_nuestro_servicio(uuid):
                    etiqueta = "  <- peer_id" if len(dato) == 8 else "  <- ?"
                    lineas.append(f"             {dato.hex()}{etiqueta}")
    return lineas, cuantos


async def principal(args: argparse.Namespace) -> int:
    identidad = Identity.cargar_o_crear(args.nickname)
    print(f"identidad: peer_id={identidad.peer_id_hex}  "
          f"nickname={identidad.nickname!r}")

    print("\n--- registro del anuncio ---")
    anuncio = Advertiser(identidad.peer_id)
    ok = await anuncio.start()
    if not ok:
        print(f"\nNO se pudo anunciar: {anuncio.ultimo_error}")
        # Se imprime lo que se mandó. BlueZ rechaza por el *contenido* del
        # anuncio, y sin verlo no hay forma de saber qué campo no acepta.
        print("\nOpciones enviadas (con su firma D-Bus):")
        from pybitchat.ble.advertiser import opciones_anuncio

        for scan in (True, False):
            print(f"\n  intento con scan_response={scan}:")
            for clave, valor in opciones_anuncio(
                identidad.peer_id, scan_response=scan
            ).items():
                print(f"    {clave:32} Variant({valor.signature!r}, {valor.value!r})")

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

    # Se informa de **todo**, no sólo de lo que tiene nombre o UUID conocido. El
    # filtro de antes (`es_bitchat or dev.name`) ocultaba cinco de los siete
    # dispositivos, y el teléfono puede ser uno de los que no tienen nombre: un
    # móvil Android no siempre anuncia su nombre local, así que buscar por
    # `dev.name` descarta justo al peer que nos interesa.
    #
    # Un anuncio sin UUID conocido **también** es información: significa que la
    # app no está anunciando, y la causa es el móvil, no nuestro código.
    datos = [
        (
            mac,
            dev.name,
            list(adv.service_uuids or []),
            dict(adv.service_data or {}),
            adv.rssi,
        )
        for mac, (dev, adv) in sorted(encontrados.items())
    ]
    lineas, cuantos = resumen(datos)
    for linea in lineas:
        print(linea)

    print()
    if cuantos:
        print(f"hay {cuantos} dispositivos anunciando BitChat")
    else:
        print("NINGUN dispositivo anuncia BitChat")
        print("  Si el móvil está desbloqueado y con la app en primer plano,")
        print("  y no aparece, el problema no es este script.")
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