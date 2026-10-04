"""Analiza el `msg2` del handshake capturado, sin Bluetooth ni hardware.

Existe por una razón concreta: el 2026-10-04 la app respondió a nuestro `msg1`
con un `NOISE_HANDSHAKE` de 96 B, se lee **sin error de descifrado**, pero
`remote_static_public` queda `None`. Con nuestro propio intercambio, la misma
librería sí lo pone. Mismo tamaño, distinto resultado, y no sabemos por qué.

No se puede resolver desde la máquina donde se escribe el código: allí no está
`noiseprotocol`, que sólo se instala en el host Linux. Esta herramienta vive en
el host y contesta la pregunta con datos.

## Qué mira, y por qué cada cosa

    1. Los paquetes del fichero, walked por su propia longitud declarada.
       No se asume 256 B: si el último va relleno a otro tamaño, asumir da
       basura y el error no señala el origen.

    2. El `msg2` desglosado en tokens de XX, con los tamaños queNoise produce
       para cada uno. `E` son 32; los cifrados son 48 (32 + tag de 16). La suma
       tiene que dar 96. Si no da, el patrón no es el que creemos.

    3. Si `read_handshake` deja la clave estática remota o no.

    4. El resultado **con la identidad real**, no con una clave inventada. Un
       descifrado puede "funcionar" con cualquier clave local y aun así no
       decir nada sobre el remoto.

Uso:
    ./.venv/bin/python tools/probe_msg2.py
    ./.venv/bin/python tools/probe_msg2.py capturas/recibido.bin
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
if str(RAIZ / "src") not in sys.path:
    sys.path.insert(0, str(RAIZ / "src"))

from pybitchat.noise.session import HandshakeSession  # noqa: E402
from pybitchat.protocol.identity import Identity, peer_id_from_noise_key  # noqa: E402
from pybitchat.protocol.packet import Packet, ProtocolError  # noqa: E402
from pybitchat.protocol.types import MessageType  # noqa: E402

#: Tipo del handshake en el dialecto actual.
TIPO_HANDSHAKE = int(MessageType.NOISE_HANDSHAKE)

#: Tamaños de los tokens de XX. `E` va en claro (32 B); lo cifrado lleva un
#: tag Poly1305 de 16 B, así que 32 + 16 = 48.
LEN_E = 32
LEN_CIFRADO = 48


def _error(msg: str) -> None:
    print(f"  ERROR: {msg}")


def leer_paquetes(datos: bytes) -> list[Packet]:
    """Parte el fichero en paquetes, usando la longitud que declara cada uno.

    No se asume un tamaño fijo. Un paquete relleno a 256 B tiene 256 bytes en
    el cable pero su longitud real es menor, y recorrer a saltos de 256
   Syncronía  el siguiente paquete por el sitio equivocado.
    """
    paquetes: list[Packet] = []
    offset = 0
    while offset < len(datos):
        resto = datos[offset:]
        try:
            p = Packet.from_bytes(resto)
        except (ProtocolError, IndexError, ValueError) as exc:
            _error(
                f"no se pudo leer un paquete en el offset {offset}: "
                f"{type(exc).__name__}: {exc}"
            )
            print(f"  (se han leído {len(paquetes)} paquete(s) antes del fallo)")
            break
        paquetes.append(p)
        # Se avanza por el tamaño **declarado**, no por el del fichero.
        largo = len(p.to_bytes(include_padding=False))
        if largo <= 0:
            _error(f"paquete de tamaño 0 en el offset {offset}; parando")
            break
        offset += largo
    return paquetes


def desglosar(msg2: bytes) -> list[str]:
    """Parte `msg2` según los tokens de XX. Devuelve líneas legibles.

    El desglose por tokens ** presupone que el patrón es XX canónico. Con un
    `msg2` que no lo es, las líneas son aritmética sobre una suposición y no
    dicen nada del formato real.

    Por eso, cuando los tamaños no cuadran, el informe lo dice y **no** presenta
    el reparto como si fuera el bueno. Un informe que muestra
    "S -> 16 B" sin avisar de que el patrón no es XX lleva a debuggear un token
    que no existe.
    """
    lineas = []
    restante = len(msg2)
    # msg2 de XX = `E, EE, S, ES`
    for nombre, largo in (
        ("E", LEN_E),
        ("EE", LEN_CIFRADO),
        ("S", LEN_CIFRADO),
        ("ES", LEN_CIFRADO),
    ):
        if restante <= 0:
            break
        tomado = min(largo, restante)
        if tomado == largo:
            lineas.append(f"  {nombre:3} -> {tomado:3d} B (quedan {restante - tomado})")
        else:
            # No queda sitio para el token entero. Se dice explícitamente en
            # vez de escribir un tamaño que no es real.
            lineas.append(
                f"  {nombre:3} -> {tomado:3d} B de {largo} (NO CABE; "
                f"quedan {restante})"
            )
        restante -= largo

    esperado = LEN_E + 3 * LEN_CIFRADO
    cuadra = len(msg2) == esperado
    lineas.append("")
    lineas.append(f"  msg2 mide {len(msg2)} B")
    lineas.append(f"  XX canónico E,EE,S,ES mide {esperado} B")
    lineas.append(f"  -> {'coincide' if cuadra else 'NO coincide'}")
    if not cuadra:
        lineas.append("")
        lineas.append("  ⚠ El reparto de arriba es aritmética sobre XX canónico,")
        lineas.append("    y este msg2 NO es XX canónico por tamaño. El")
        lineas.append("    desglose por tokens **no describe el formato real**.")
        lineas.append("")
        diferencia = len(msg2) - esperado
        lineas.append(f"    diferencia: {diferencia:+d} B")
        if diferencia < 0:
            faltan = -diferencia
            lineas.append(
                f"    faltan {faltan} B. Candidatos, sin decidir cuál:"
            )
            lineas.append(
                f"     - un token cifrado sin tag: 16 B menos por token "
                f"({faltan // 16} token/s)"
            )
            lineas.append(
                f"     - un token en claro en vez de cifrado: 16 B menos "
                f"por token ({faltan // 16} token/s)"
            )
            if faltan % 32 != 0:
                lineas.append(
                    f"     - {faltan} no es múltiplo de 16 ni de 32: "
                    f"queda algo más sin explicar"
                )
    return lineas


def probar_read(msg2: bytes, identidad: Identity) -> None:
    """Intenta leer el `msg2` con la identidad real y dice qué queda puesto."""
    print("\n--- read_handshake con la identidad real ---")
    try:
        import noiseprotocol  # noqa: F401
    except ImportError:
        # Se dice aquí, y no antes, para que el desglose de arriba ya haya salido.
        print("  omitido: `noiseprotocol` no está instalado, así que no se")
        print("  puede descifrar. Los pasos anteriores no lo necesitan.")
        return

    sesion = HandshakeSession(
        initiator=True, static_private=identidad.noise_private
    )
    try:
        carga = sesion.read_handshake(msg2, payload_size=0)
        print(f"  leído sin error. carga útil: {len(carga)} B")
    except Exception as exc:
        print(f"  ERROR al leer: {type(exc).__name__}: {exc}")
        print("  Si falla aquí, el problema es el descifrado, no la identidad.")
        return

    remoto = sesion.remote_static_public
    print(f"  remote_static_public: "
          f"{remoto.hex() if remoto else 'None'}")
    if remoto:
        pid = peer_id_from_noise_key(remoto)
        print(f"  peer_id derivado:     {pid.hex()}")
        print(f"  nuestro peer_id:     {identidad.peer_id_hex}")
        print(f"  -> son el mismo peer: {pid == identidad.peer_id}")
    else:
        print()
        print("  La clave estática remota NO quedó puesta. Eso es lo que")
        print("  hay que explicar: el descifrado funcionó, pero el token")
        print("  que la lleva no se aplicó, o se aplicó en otro sitio.")
        print("  Candidatos a revisar:")
        print("   - la versión de noiseprotocol (0.3.1) y cómo expone `rs`")
        print("   - si `rs` sólo se rellena al hacer split()")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "fichero",
        nargs="?",
        type=Path,
        default=RAIZ / "capturas" / "recibido.bin",
        help="captura de paquetes (por defecto capturas/recibido.bin)",
    )
    args = p.parse_args()

    if not args.fichero.exists():
        print(f"no existe {args.fichero}")
        print("Se genera con:  ./.venv/bin/python tools/smoke_ble.py --handshake \\")
        print("                    --peer-id <hex> --noise-public <hex>")
        return 1

    datos = args.fichero.read_bytes()
    print(f"fichero: {args.fichero}  ({len(datos)} B)")

    # `noiseprotocol` sólo hace falta para **descifrar**, no para leer los
    # paquetes ni desglosar el `msg2`. Comprobarlo al principio y salir con
    # código 1 tiraba por el suelo un informe que se puede hacer sin ella: la
    # primera versión hacía exactamente eso, y contestaba "NO INSTALADO" sin
    # dar el desglose, que es justo el dato que se pedía.
    #
    # Se comprueba más abajo, donde se usa, para que la falta se note en su
    # sitio y no impida el resto.
    hay_noise = True
    try:
        import noiseprotocol
        print(f"noiseprotocol: {getattr(noiseprotocol, '__version__', '?')}")
    except ImportError:
        hay_noise = False
        print("noiseprotocol: NO INSTALADO")
        print("  Se puede leer y desglosar el msg2 igualmente; sólo falta")
        print("  el paso de descifrarlo. Se instala con:")
        print("    ./.venv/bin/pip install -r requirements.txt")

    identidad = Identity.cargar_o_crear("pybitchat-probe")
    print(f"identidad:  peer_id={identidad.peer_id_hex}")

    paquetes = leer_paquetes(datos)
    print(f"\npaquetes leídos: {len(paquetes)}")
    tipos: dict[int, int] = {}
    for p_ in paquetes:
        tipos[p_.header.raw_type] = tipos.get(p_.header.raw_type, 0) + 1
    print("por tipo:")
    for t, n in sorted(tipos.items()):
        nombre = MessageType(t).name if t in MessageType._value2member_map_ else "?"
        print(f"  0x{t:02x} {nombre:22} x{n}")

    hands = [p_ for p_ in paquetes if p_.header.raw_type == TIPO_HANDSHAKE]
    if not hands:
        print(f"\nNo hay ningún NOISE_HANDSHAKE (0x{TIPO_HANDSHAKE:02x}) en la")
        print("captura. No se puede analizar el msg2.")
        print("El fichero es de una ejecución sin handshake.")
        return 1

    print(f"\nNOISE_HANDSHAKE encontrados: {len(hands)}")
    msg2 = hands[0].payload
    print(f"  payload del primero: {len(msg2)} B")

    print("\n--- desglose según los tokens de XX ---")
    for linea in desglosar(msg2):
        print(linea)

    probar_read(msg2, identidad)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())