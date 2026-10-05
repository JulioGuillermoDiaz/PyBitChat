#!/usr/bin/env python3
"""Lee el `logcat` de Android mientras corre `smoke_ble`, y dice qué pasa dentro.

## Por qué esto, y no mirar la app

El único dato que nos faltaba para el `0x11` era saber **qué hace la app por
dentro** al recibir nuestro `msg3`. Desde fuera hay tres escenarios y no se
distinguen:

- la sesión se establece y el `0x11` no sale por otro motivo,
- la app lo intenta y no puede,
- la app nunca menciona el handshake.

Los tres se ven idénticos en la traza BLE: tras el `msg3` no llega nada, y el
propio script dice que en Noise XX el tercer mensaje no tiene respuesta.

En el código de la app, en cambio, cada uno **deja una línea de log distinta**:

```kotlin
// NoiseSessionManager
Log.i(TAG, "Noise handshake completed with $peerID")
Log.e(TAG, "Handshake failed with $peerID: ${e.message}")
Log.d(TAG, "Expiring stale handshake with $peerID")

// BluetoothMeshService
Log.i(TAG, "Noise handshake completed with $peerID")

// EncryptionService
Log.d(TAG, "\u2705 Noise session established with $peerID, fingerprint: ...")
```

Y hay una cuarta línea que es la más útil de todas, y que solo aparece si algo
más upstream tiró el paquete:

```kotlin
// BluetoothGattServerManager
Log.d(TAG, "Server: Dropping packet from stale connection ${device.address}")
// PacketProcessor
Log.w(TAG, "Received packet with no peer ID, skipping")
```

## Qué hay que tener

- `adb` en el `PATH`: `sudo apt install android-tools-adb`
- el móvil por **USB**, con depuración activada, **y** conectado por BLE al host.
  No se estorban: el USB lleva los logs y la radio hace el BLE.

## Por qué se filtra por texto y no por etiqueta

Las etiquetas (`NoiseSessionManager`, `SecurityManager`, …) están aquí porque
las leí del código, y eso puede quedarse corto: la app las renombra, cambia el
código de un log o añade otro. Un filtro por etiqueta que se queda corto
produce una ausencia, y **una ausencia es indistinguible de un evento que no
ocurrió**.

Así que se filtra por frases del mensaje, que son mucho más estables, y se
conservan también los `WARN` y `ERROR` de cualquier etiqueta. Ante la duda,
sobra.

## Lo que hace

1. `adb logcat -c` para no arrastrar ruido de antes.
2. Lanza `logcat` en modo `time`, filtrando.
3. Corre `smoke_ble` con los argumentos que se le pasen.
4. Un par de segundos de margen por si el `0x11` llega tarde.
5. Guarda **todo** en `capturas/logcat.txt` y resume por pantalla.

Nada de esto se puede probar desde la VM Windows: aquí no hay `adb` ni BLE. Lo
que sí está probado son el filtro y el veredicto, que son funciones puras sobre
texto de log (`tests/test_probe_logcat.py`).
"""

import argparse
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent

#: `(frase, etiqueta, explicacion)`. La frase se busca en el mensaje del log;
#: el orden importa, porque hay solapamientos: "Noise handshake completed" está
#: dentro de la línea de `EncryptionService` que dice "session established", y
#: la de `SecurityManager` es la única que lleva "completed" con mayúscula.
SIGNALES: tuple[tuple[str, str, str], ...] = (
    (
        "Noise handshake completed with",
        "COMPLETADO",
        "la app cerro el handshake: la sesion esta establecida en su lado",
    ),
    (
        "Handshake failed with",
        "FALLIDO",
        "lo intento y no pudo; el motivo va detras de los dos puntos",
    ),
    (
        "Expiring stale handshake",
        "EXPIRADO",
        "le paso el tiempo: HANDSHAKE_TIMEOUT_MS es 10 s",
    ),
    (
        "Expiring stale responder candidate",
        "EXPIRADO-CANDIDATO",
        "el candidato a responder se fue antes de recibir nuestro msg3",
    ),
    (
        "Authenticated Noise key derives to",
        "IDENTIDAD-DISTINTA",
        "la clave que autentico el handshake no deriva al peer_id que reclama",
    ),
    (
        "Rejecting malformed, unbound, or invalidly signed ANNOUNCE",
        "ANNOUNCE-RECHAZADO",
        "el announce no paso AnnouncementIdentityValidator",
    ),
    (
        "Rejecting ANNOUNCE",
        "ANNOUNCE-RECHAZADO-2",
        "el announce no paso una de las comprobaciones de clave persistida",
    ),
    (
        "Dropping public message from unverified peer",
        "NO-VERIFICADO",
        "nos tiene, pero no verificados: isVerifiedNickname en false",
    ),
    (
        "Dropping packet from stale connection",
        "CONEXION-VIEJA",
        "el servidor GATT no encontro linkID: el paquete no llego a la capa Noise",
    ),
    (
        "Received packet with no peer ID",
        "SIN-PEER-ID",
        "el transporte no resolvio el peerID y el paquete se tira aqui",
    ),
    (
        "Failed to parse packet from",
        "NO-PARSEABLE",
        "el paquete llego pero no se pudo decodificar",
    ),
    (
        "Ignoring ANNOUNCE from stale BLE link",
        "LINK-VIEJO",
        "el announce paso, pero el link ya no es el que se uso al conectar",
    ),
    (
        "Noise session established with",
        "SESION-ESTABLECIDA",
        "EncryptionService confirma sesion: es la vista final del mismo hecho",
    ),
)

#: Palabras sueltas que tambien se conservan. Son las que aparecen en los
#: mensajes de excepcion de Noise, cuyo texto no es fijo.
SUELTAS = (
    "handshake",
    "Handshake",
    "HANDSHAKE",
    "Noise",
    "session",
    "Session",
    "expired",
    "Expired",
)

#: `I/NoiseSessionManager( 1234): el mensaje`. Se separa para buscar en el
#: mensaje y no en la etiqueta.
_LINEA_LOG = re.compile(
    r"^(?P<fecha>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<nivel>[VDIWEF])/(?P<etiqueta>[^(:]*)\(\s*\d+\):\s?(?P<mensaje>.*)$"
)


def _clasificar(linea: str) -> tuple[str | None, str | None, str | None]:
    """`(etiqueta, explicacion, motivo)` de una línea de log, o vacíos.

    Se busca en el **mensaje**, nunca en la etiqueta, por lo que se explica en
    el docstring del módulo. El motivo es lo que va detrás de `:` cuando la
    línea dice "failed with ...: <motivo>", que es justo el dato que buscas.
    """
    m = _LINEA_LOG.match(linea.rstrip())
    texto = m.group("mensaje") if m else linea
    nivel = m.group("nivel") if m else None

    for frase, etiqueta, explicacion in SIGNALES:
        if frase in texto:
            motivo = None
            if ":" in texto:
                # "Handshake failed with 34e0...: Invalid state"
                posible = texto.split(":", 1)[1].strip()
                if posible:
                    motivo = posible
            return etiqueta, explicacion, motivo

    # Respaldo: WARN y ERROR de cualquier etiqueta, y palabras sueltas. Antes
    # que perder una linea, sobra.
    if nivel in ("W", "E") or any(s in texto for s in SUELTAS):
        return "OTRA", "no clasificada; se conserva por si el veredicto falla", None
    return None, None, None


def _veredicto(clasificadas: list[tuple[str, str, str | None]]) -> list[str]:
    """Qué significa lo clasificado, en tres ramas.

    Las tres son exhaustivas y son justo las hipótesis de `ESTADO.md` §5. La
    que más vale es la tercera: si la app no menciona el handshake en ningún
    momento, el problema **no** es su procesamiento, y eso descarta de un plumazo
    todo lo que se podría sospechar del `msg3`.
    """
    etiquetas = [c[0] for c in clasificadas]
    hubo_o_no = set(etiquetas)

    completados = hubo_o_no & {"COMPLETADO", "SESION-ESTABLECIDA"}
    intentados = hubo_o_no & {
        "FALLIDO", "EXPIRADO", "EXPIRADO-CANDIDATO", "IDENTIDAD-DISTINTA",
    }
    perdidos = hubo_o_no & {
        "CONEXION-VIEJA", "SIN-PEER-ID", "NO-PARSEABLE", "LINK-VIEJO",
    }
    announces = hubo_o_no & {
        "ANNOUNCE-RECHAZADO", "ANNOUNCE-RECHAZADO-2", "NO-VERIFICADO",
    }

    l: list[str] = []

    if completados:
        l.append("VEREDICTO: la app COMPLETO el handshake.")
        l.append("")
        l.append("  La sesion Noise esta establecida en su lado. Eso deja fuera")
        l.append("  el msg3, el nonce, el orden de los mensajes y la derivacion de")
        l.append("  la clave. El problema es otro: o el 0x11 no se emite, o no va")
        l.append("  dirigido a nosotros.")
        l.append("")
        l.append("  Siguiente sitio a mirar: `AuthenticatedPeerStateCoordinator")
        l.append("  .ensureSession`, que es quien llama a `sendState`. Ojo: solo")
        l.append("  se llama si `establishedNow` fue true, asi que si esta linea")
        l.append("  sale y aun no hay 0x11, el fallo esta entre ambas.")
        return l

    if intentados:
        l.append("VEREDICTO: la app lo INTENTO y NO PUDO.")
        l.append("")
        l.append("  Entraste en la capa Noise y ahi fallo. El motivo esta en las")
        l.append("  lineas de arriba, y es el dato que buscabamos.")
        l.append("")
        for etiqueta, explicacion, motivo in clasificadas:
            if etiqueta in {"FALLIDO", "EXPIRADO", "EXPIRADO-CANDIDATO",
                            "IDENTIDAD-DISTINTA"}:
                l.append(f"  {etiqueta}: {explicacion}")
                if motivo:
                    l.append(f"    motivo: {motivo}")
        return l

    if perdidos:
        l.append("VEREDICTO: el paquete NO LLEGO a la capa Noise.")
        l.append("")
        l.append("  Aqui la app nunca habla del handshake, y eso ya es un dato:")
        l.append("  el problema no es el msg3 ni el Noise, es que el paquete se")
        l.append("  perdio antes.")
        for etiqueta, explicacion, motivo in clasificadas:
            if etiqueta in {"CONEXION-VIEJA", "SIN-PEER-ID", "NO-PARSEABLE",
                            "LINK-VIEJO"}:
                l.append(f"  {etiqueta}: {explicacion}")
                if motivo:
                    l.append(f"    detalle: {motivo}")
        return l

    if announces:
        l.append("VEREDICTO: el announce no pasa.")
        l.append("")
        l.append("  Antes de Noise. La sesion no se puede establecer sin que nos")
        l.append("  tenga como par verificado, asi que esto va primero.")
        for etiqueta, explicacion, _ in clasificadas:
            if etiqueta in {"ANNOUNCE-RECHAZADO", "ANNOUNCE-RECHAZADO-2",
                            "NO-VERIFICADO"}:
                l.append(f"  {etiqueta}: {explicacion}")
        return l

    if not clasificadas:
        l.append("VEREDICTO: ni una linea util.")
        l.append("")
        l.append("  O no se capturo nada, o el filtro se quedo corto. Lo segundo")
        l.append("  es mas probable de lo que parece: los nombres de etiqueta se")
        l.append("  leen del codigo de la app, no de su log real.")
        l.append("")
        l.append("  Para comprobarlo sin cambiar nada:")
        l.append("    adb logcat -d -v time > /tmp/logcat-crudo.txt")
        l.append("  y ahi buscar 'Noise', 'handshake', 'Expiring' a mano. Es un")
        l.append("  fichero de texto y se lee con grep.")
        return l

    l.append("VEREDICTO: hay lineas, pero ninguna de las que buscabamos.")
    l.append("")
    l.append("  Todas las señales caidas estan en el fichero, para leerlas.")
    etiquetas_vistas = sorted({c[0] for c in clasificadas})
    l.append(f"  Vistas: {', '.join(etiquetas_vistas)}")
    return l


def _adb(args: list[str]) -> list[str]:
    return ["adb", *args]


def _hay_adb() -> bool:
    from shutil import which

    return which("adb") is not None


def _dispositivos() -> list[str]:
    """Salida de `adb devices`, con el `*` de "autorizado" ya comprobado."""
    salida = subprocess.run(
        _adb(["devices"]), capture_output=True, text=True, timeout=30
    ).stdout
    lineas = []
    for linea in salida.splitlines()[1:]:
        if "\tdevice" in linea:
            lineas.append(linea.split("\t")[0])
    return lineas


def _leer(stream, destino: list[str], encontrados: list[tuple[str, str, str | None]],
          cambiar: threading.Event) -> None:
    """Acumula lineas de `logcat` y guarda solo las que interesan."""
    for cruda in stream:
        if cambiar.is_set():
            break
        linea = cruda.rstrip("\n")
        if not linea.strip():
            continue
        destino.append(linea)
        etiqueta, explicacion, motivo = _clasificar(linea)
        if etiqueta is not None:
            encontrados.append((etiqueta, explicacion, motivo))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--segundos-gracia", type=float, default=3.0,
                    help="segundos de escucha extra tras acabar smoke_ble "
                         "(por defecto 3; el 0x11 puede tardar)")
    ap.add_argument("--guardar", type=Path,
                    default=RAIZ / "capturas" / "logcat.txt",
                    help="fichero donde se guarda todo el log (por defecto "
                         "capturas/logcat.txt)")
    ap.add_argument("--sin-smoke", action="store_true",
                    help="solo escucha, sin lanzar smoke_ble. Para lo que ya "
                         "este corriendo en otra terminal")
    ap.add_argument("smoke", nargs=argparse.REMAINDER,
                    help="argumentos para smoke_ble.py, tras --")
    args = ap.parse_args()

    smoke = [s for s in args.smoke if s != "--"]

    if not _hay_adb():
        print("No hay `adb` en el PATH.")
        print("  sudo apt install android-tools-adb")
        print("y el movil por USB con la depuracion activada.")
        return 1

    dispositivos = _dispositivos()
    if not dispositivos:
        print("`adb devices` no ve ningun movil autorizado.")
        print()
        print("  - este el cable puesto?")
        print("  - la depuracion USB esta activada en el movil?")
        print("  - aparece el dialogo de autorizacion y lo aceptaste?")
        print()
        print("  Ojo: el movil tambien tiene que estar conectado por BLE, que")
        print("  es lo distinto. El USB es solo para leer el log.")
        return 1
    print(f"movil por adb: {dispositivos[0]}")

    todas: list[str] = []
    encontradas: list[tuple[str, str, str | None]] = []
    cambiar = threading.Event()

    subprocess.run(_adb(["logcat", "-c"]), capture_output=True, timeout=30)
    print("logcat limpio")

    # El `logcat` arranca antes que `smoke_ble`: si no, se pierden las lineas
    # del principio, que son justo las del announce.
    lector = subprocess.Popen(
        _adb(["logcat", "-v", "time"]),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        bufsize=1,
    )
    hilo = threading.Thread(
        target=_leer, args=(lector.stdout, todas, encontradas, cambiar),
        daemon=True,
    )
    hilo.start()
    print("logcat escuchando")

    salida = 0
    if smoke and not args.sin_smoke:
        print(f"\ncorriendo smoke_ble {' '.join(smoke)}\n")
        proceso = subprocess.run(
            [sys.executable, str(RAIZ / "tools" / "smoke_ble.py"), *smoke]
        )
        salida = proceso.returncode
        print(f"\nsmoke_ble salio con {salida}")
    else:
        print(f"\nesuchando {args.segundos_gracia} s (sin smoke)")

    time.sleep(args.segundos_gracia)
    cambiar.set()
    lector.terminate()
    try:
        lector.wait(timeout=5)
    except subprocess.TimeoutExpired:
        lector.kill()
    hilo.join(timeout=5)

    destino = args.guardar
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text("\n".join(todas) + "\n", encoding="utf-8")

    print("=" * 60)
    print(f"lineas de log: {len(todas)}")
    print(f"relevantes:    {len(encontradas)}")
    print(f"guardadas en:  {destino}")
    print()

    if not encontradas:
        print("Ninguna linea clasificada.")
        print()
        print("Eso NO significa que la app no hablara. Puede que:")
        print("  - el movil no estuviera en primer plano con BitChat abierto")
        print("  - el filtro se quedara corto (los nombres salen del codigo)")
        print()
        print(f"Todo el log esta en {destino}. Es texto: se lee con grep.")
        return 1

    vistas: dict[str, list[str]] = {}
    for etiqueta, explicacion, motivo in encontradas:
        vistas.setdefault(etiqueta, [])
        texto = f"{etiqueta}: {explicacion}"
        if motivo:
            texto += f"\n    motivo: {motivo}"
        if texto not in vistas[etiqueta]:
            vistas[etiqueta].append(texto)

    for etiqueta, lineas in vistas.items():
        print(f"  {etiqueta}  x{len(lineas)}")
        for linea in lineas[:4]:
            print(f"    {linea}")
        if len(lineas) > 4:
            print(f"    ... y {len(lineas) - 4} mas")
    print()

    for linea in _veredicto(encontradas):
        print(linea)

    return salida


if __name__ == "__main__":
    raise SystemExit(main())