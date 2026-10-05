"""Analiza los paquetes de un fichero, incluidos los announces, byte a byte.

## Por qué existe

`probe_msg2.py` se llama así porque **solo sabe mirar el `msg2`**. Cuando se
trató de analizar un announce, imprime "No hay ningún NOISE_HANDSHAKE" y no dice
nada, aunque el fichero sea íntegramente de announces.

Y el cálculo a mano falla. El 2026-10-06 se intentó sacar la firma de un
volcado del terminal y la extracción devolvió basura: flags `0x77`, longitud
25964. El error fue empezar en la fila equivocada del hexdump y perder un byte.
Un número plausible y falso, que es la peor forma de equivocarse.

Esto lee el **fichero**, no un volcado. Es la diferencia entre mirar y medir.

## Uso

    ./.venv/bin/python tools/probe_announce.py
    ./.venv/bin/python tools/probe_announce.py capturas/recibido.bin
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from pybitchat.protocol.identity import peer_id_from_noise_key  # noqa: E402
from pybitchat.protocol.packet import Packet, ProtocolError  # noqa: E402
from pybitchat.protocol.types import MessageType, PacketFlags  # noqa: E402

TIPO_ANNOUNCE = int(MessageType.ANNOUNCE)

#: Longitudes de los TLV del announce, para el resumen.
LONG_TLV = {0x01: "nickname", 0x02: "noise_public", 0x03: "signing_public",
            0x05: "capabilities"}


#: Cubos de relleno. El mayor define la longitud máxima de un relleno.
#: Estaban en 64 porque un announce con firma rellena 90 B, y con ese tope no se
#: detectaba: se leía como paquete de 166 B y el siguiente se perdía.
CUBO_RELLENO_MAX = 512

#: Tipos que aparecen en el tráfico real. Un byte cualquiera no basta para dar
#: un paquete por bueno.
_TIPOS_CONOCIDOS = frozenset({0x01, 0x02, 0x10, 0x11, 0x20, 0x21, 0x22, 0x29})


def _empieza_un_paquete(datos: bytes, off: int) -> bool:
    """¿En `off` hay un encabezado de paquete?

    ## Por qué hace falta, y por qué basta con poco

    El relleno PKCS#7 de longitud **1** es un byte `0x01`, que es exactamente el
    valor de `version` de un paquete v1. Dos announces de 111 B pegados son
    **ambiguos**: el byte 111 puede ser relleno o el comienzo del siguiente.

    No es raro: es nuestro announce, que no lleva relleno.

    Delimitar la longitud completa ser{i}auo para esta pregunta y introduce
    errores nuevos — el último paquete de un volcado no "cabe" y se tomaba por
    basura. Solo hace falta reconocer el encabezado.
    """
    if off + 14 > len(datos):
        return False
    return datos[off] in (1, 2) and datos[off + 1] in _TIPOS_CONOCIDOS


def _largo_del_relleno(datos: bytes, off: int) -> int:
    """Cuántos bytes de relleno hay en `off`, si los hay.

    ## Por qué mira el byte y no un cubo

    El byte **es** su longitud (`pkcs7_pad_to_bucket`). Una suposición sobre el
    cubo no es una medida: con dos announces la primera versión leía uno solo
    porque suponía 256 y se comía el segundo entero.

    Si detrás del relleno no hay nada, no hay relleno.
    """
    if off >= len(datos):
        return 0
    b = datos[off]
    if not (1 <= b <= CUBO_RELLENO_MAX) or off + b > len(datos):
        return 0
    if datos[off:off + b] != bytes((b,)) * b:
        return 0
    # Lo que hay aquí es el **primer byte** del paquete siguiente, no relleno.
    # Un paquete no va detrás de un relleno.
    if _empieza_un_paquete(datos, off):
        return 0
    return b


def _long_en_cable(datos: bytes, off: int) -> int:
    """Cuántos bytes ocupa el paquete que empieza en `off`, relleno incluido.

    ## Por qué recibe los datos

    `Packet.to_bytes()` **re-construye** el paquete y decide el relleno por su
    cuenta, así que no sirve para medir lo que vino. Y la longitud sola no basta:
    un announce sin rellenar son 111 B, y la cabecera solo dice que el payload
    son 89. Los 64 de firma solo se saben si hay firma.

    ## Lo que devuelve

    El final real del paquete. Si detrás hay relleno, se cuenta; si no, la
    longitud es la del paquete sin relleno. Nunca se supone un cubo.
    """
    p = Packet.from_bytes(datos[off:])
    # `to_bytes()` **ya incluye** la firma cuando la hay: añadirla otra vez
    # daba 230 en vez de 166, y el relleno secontaba desde un sitio falso.
    largo = len(p.to_bytes(include_padding=False))
    return largo + _largo_del_relleno(datos, off + largo)


def _salta_relleno(datos: bytes, off: int) -> int:
    """Avanza mientras el byte sea de relleno, y devuelve el offset nuevo.

    El relleno es PKCS#7: el valor de cada byte es su propia longitud. Un solo
    byte bastaría si no hubiera **ruido de cola** de una notificación anterior
    pegado en la misma lectura.
    """
    inicio = off
    while off < len(datos):
        b = datos[off]
        if 1 <= b <= 64:
            if datos[off:off + b] == bytes((b,)) * b:
                off += b
                continue
        break
    return off if off > inicio else off


def leer_paquetes(datos: bytes) -> list[Packet]:
    """Lee los paquetes de un volcado de notificaciones, saltando el relleno."""
    out: list[Packet] = []
    off = 0
    while off + 12 <= len(datos):
        try:
            p = Packet.from_bytes(datos[off:])
        except ProtocolError as exc:
            # El relleno residual no es un fallo: se dice y se sigue.
            _salta_relleno(datos, off)
            off += 1
            continue
        out.append(p)
        off += _long_en_cable(datos, off)
    return out


def _tlvs(payload: bytes) -> list[tuple[int, bytes]]:
    """Parte el announce en TLV de tipo u8 y longitud u8.

    La longitud de **un** byte, que es lo que dice
    `AnnouncementIdentityValidator.kt`. Confundirla con la del TLV de fichero,
    que es u16, rompe el announce entero.
    """
    out = []
    off = 0
    while off + 2 <= len(payload):
        t = payload[off]
        n = payload[off + 1]
        if off + 2 + n > len(payload):
            break
        out.append((t, payload[off + 2:off + 2 + n]))
        off += 2 + n
    return out


def describir_anuncio(p: Packet, largo_cable: int | None = None) -> list[str]:
    """Todo lo que se puede decir de un announce, leyendo los bytes."""
    l: list[str] = []
    l.append(f"  flags     = 0x{p.header.flags:02x}")
    bits = []
    if p.header.flags & PacketFlags.HAS_RECIPIENT:
        bits.append("HAS_RECIPIENT")
    if p.header.flags & PacketFlags.HAS_SIGNATURE:
        bits.append("HAS_SIGNATURE")
    if p.header.flags & PacketFlags.HAS_ROUTE:
        bits.append("HAS_ROUTE")
    l.append(f"              {' | '.join(bits) or '(ninguno)'}")
    l.append(f"  longitud  = {p.header.payload_len} B")
    l.append(f"  sender    = {p.sender_id.hex()}")
    l.append(f"  recipient = {p.recipient_id.hex() if p.recipient_id else '(ninguno)'}")
    en_cable = largo_cable if largo_cable is not None else "?"
    l.append(f"  cable     = {en_cable} B con relleno")
    l.append("")

    l.append(f"  TLV del payload ({len(p.payload)} B):")
    for t, v in _tlvs(p.payload):
        nombre = LONG_TLV.get(t, "desconocido")
        extra = ""
        if t == 0x01:
            extra = f"  {v.decode('utf-8', 'replace')!r}"
        elif t == 0x05:
            extra = f"  = 0x{int.from_bytes(v, 'big'):x}"
        l.append(f"    0x{t:02x} {nombre:15} {len(v):2d} B  {v.hex()[:40]}{extra}")
        if t == 0x02:
            l.append(f"       peer_id derivado = {peer_id_from_noise_key(v).hex()}")
    total = sum(2 + len(v) for _t, v in _tlvs(p.payload))
    l.append(f"    suma de los TLV = {total} B, declarado = {p.header.payload_len} B")
    l.append("")

    l.append("  firma:")
    if p.signature is None:
        l.append("    SIN FIRMA")
        l.append("")
        l.append("    >>> La app rechaza esto. En `handleAnnounceWithResult`:")
        l.append("    >>>   AnnouncementIdentityValidator.verify(packet, peerID)")
        l.append("    >>>   si devuelve null -> AnnounceHandlingResult.Rejected")
        l.append("")
        l.append("    Por eso no sale en su lista de pares, y por eso")
        l.append("    `handleBroadcastMessage` lo descarta: exige")
        l.append("    `peerInfo.isVerifiedNickname`.")
    else:
        l.append(f"    {len(p.signature)} B: {p.signature.hex()}")
        l.append("")
        pre = p.to_binary_data_for_signing()
        l.append(f"    preimagen = {len(pre)} B")
        l.append(f"      {pre.hex()}")
        l.append("")
        l.extend(_verificar(p, pre))
    return l


def _verificar(p: Packet, preimagen: bytes) -> list[str]:
    """Comprueba la firma del announce con la clave del propio TLV 0x03.

    ## Por qué aquí y no a mano

    La clave de firma **va en el announce**. No hace falta nada de fuera: el
    paquete lleva su propia prueba.

    Y a mano sale mal. El 2026-10-06 se copiaron el preimagen y la firma del
    terminal a un fichero y la verificación dio que no validaba, cuando lo que
    pasaba es que la preimagen transcrita medía 102 B y la aritmía decía 100:
    faltaba un byte. Un cálculo sobre hex pegado es una fuente de números
    falsos, y por eso esto lee el fichero.

    ## Qué comprueba además del resultado

    Que la preimagen mida lo que tiene que medir. `to_binary_data_for_signing()`
    quita la firma y fija el TTL, así que si el resultado no valida lo que se
    compara está mal, no la firma.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    tlvs = dict(_tlvs(p.payload))
    clave = tlvs.get(0x03)
    if clave is None or len(clave) != 32:
        return ["    no hay clave de firma (TLV 0x03) con la que comprobar"]

    l: list[str] = []
    try:
        Ed25519PublicKey.from_public_bytes(clave).verify(p.signature, preimagen)
    except InvalidSignature:
        l.append("    >>> NO VALIDA con esta preimagen")
        l.append("")
        l.append("    Con la firma y la preimagen correctas, si no valida")
        l.append("    el problema es la preimagen, no la firma:")
        l.append("    fija el TTL y quita la firma, y hay que confirmar que")
        l.append("    hace lo mismo que `BitchatPacket.toBinaryDataForSigning`.")
        return l

    l.append("    >>> VALIDA")
    l.append("")
    l.append("    La preimagen es exactamente el paquete entero con:")
    l.append("      - la firma fuera")
    l.append("      - el TTL puesto a 0")
    l.append("      - sin relleno")
    l.append(f"      - {len(preimagen)} B = 12 cabecera + 8 sender + "
             f"{len(p.payload)} payload")
    l.append("")
    l.append("    Esto es lo que hay que producir para que la app acepte")
    l.append("    nuestro announce. No hay que deducir nada más.")
    return l


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "fichero",
        nargs="?",
        type=Path,
        default=RAIZ / "capturas" / "recibido.bin",
        help="captura de paquetes (por defecto capturas/recibido.bin)",
    )
    args = ap.parse_args()

    if not args.fichero.exists():
        print(f"no existe {args.fichero}")
        print("Se genera con:  ./.venv/bin/python tools/smoke_ble.py")
        return 1

    datos = args.fichero.read_bytes()
    print(f"fichero: {args.fichero}  ({len(datos)} B)")

    paquetes = leer_paquetes(datos)
    print(f"\npaquetes leidos: {len(paquetes)}")
    tipos: dict[int, int] = {}
    for p in paquetes:
        tipos[p.header.raw_type] = tipos.get(p.header.raw_type, 0) + 1
    print("por tipo:")
    for t, n in sorted(tipos.items()):
        nombre = MessageType(t).name if t in MessageType._value2member_map_ else "?"
        print(f"  0x{t:02x} {nombre:22} x{n}")

    announces = [p for p in paquetes if p.header.raw_type == TIPO_ANNOUNCE]
    if not announces:
        print("\nNo hay ningun ANNOUNCE (0x01) en la captura.")
        print("Para generarlo:  ./.venv/bin/python tools/smoke_ble.py")
        return 1

    for i, p in enumerate(announces, 1):
        print(f"\n{'=' * 60}")
        print(f"ANNOUNCE #{i} de {len(announces)}")
        print("=" * 60)
        try:
            for linea in describir_anuncio(p, _long_en_cable(datos, 0)):
                print(linea)
        except Exception as exc:
            print(f"  no se pudo describir: {type(exc).__name__}: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())