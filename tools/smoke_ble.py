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
from pybitchat.protocol.packet import (  # noqa: E402
    MESSAGE_TTL_HOPS,
    Packet,
    PacketHeader,
)
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


def construir_announce(nickname: str, ttl: int = MESSAGE_TTL_HOPS) -> bytes:
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


#: RSSI que bleak pone cuando BlueZ **no** mide ninguno. Mínimo de un entero
#: con signo de 8 bits, y el valor "sin dato" del protocolo.
RSSI_SIN_DATO = -127

#: MTU por defecto de BlueZ. Es el valor que se queda si `_acquire_mtu()` falla,
#: y en ese caso un paquete de 256 B no cabe. Ver la nota de `_sesion`.
MTU_POR_DEFECTO = 23


def contar_uuids(anuncios: dict) -> int:
    """Suma los UUID de servicio de todos los dispositivos vistos.

    Vive fuera de `resolver_telefono` para poder probarse sin `bleak` ni
    adaptador. Existe además por una razón práctica: si el recuento sale a
    cero, el problema no es el teléfono sino que el adaptador no está
    escaneando, y eso cambia por completo la diagnóstico.
    """
    return sum(len(adv.service_uuids or ()) for _dev, adv in anuncios.values())


def es_rssi_real(rssi) -> bool:
    """¿Este RSSI es una medida, o el valor por defecto de bleak?

    `scanner.py:209` del backend BlueZ de bleak hace

        rssi=props.get("RSSI", -127)

    así que **`-127` significa "BlueZ no dio RSSI"**, no "señal mínima". Es el
    mínimo representable de un entero con signo de 8 bits, el valor que el
    protocolo usa para "sin dato".

    Importa porque un `-127` no dice nada de la distancia: no es un candidato
    débil, es un candidato **no medido**. Elegirlo y luego fallar al conectar
    hace pensar que el enlace se rompió, cuando lo que quizá pasó es que se
    eligió un dispositivo que nunca se oyó de verdad.
    """
    return rssi is not None and rssi > RSSI_SIN_DATO


async def resolver_telefono(timeout: float):
    """Busca el teléfono por UUID de servicio, sin cachear direcciones."""
    from bleak import BleakScanner

    print("buscando el teléfono…")
    encontrados = await BleakScanner.discover(timeout=timeout, return_adv=True)
    print(f"  {len(encontrados)} dispositivos, "
          f"{contar_uuids(encontrados)} UUID de servicio")

    candidatos = [
        (mac, dev, adv)
        for mac, (dev, adv) in encontrados.items()
        if any(es_nuestro_servicio(u) for u in (adv.service_uuids or []))
    ]

    if not candidatos:
        if not encontrados:
            print("  el adaptador no vio NADA: no es el teléfono")
        else:
            print("  hay dispositivos pero ninguno anuncia BitChat")
            # Esta es la causa más frecuente y **no** se deduce de los datos.
            # Antes de culpar al código o al adaptador, hay que descartar el
            # estado de la app: tras un rato sin actividad deja de anunciarse
            # hasta que se cierre y se vuelva a abrir.
            print()
            print("  Antes que nada, comprueba esto en el móvil:")
            print("    - BitChat en primer plano y el móvil desbloqueado")
            print("    - **Tras 15 min sin actividad hay que cerrar BitChat")
            print("      y volver a abrirlo**, o no anunciará")
            print()
            print("  Es la causa más frecuente y no se deduce del escaneo:")
            print("  una app que no anuncia es indistinguible de una app")
            print("  que se ha quedado dormida.")
        return None

    # Todos los que dicen anunciar BitChat, no sólo el primero. Con varios
    # candidatos, cuál elegir deja de ser obvio, y quedarse con el primero en
    # orden de aparición es arbitrario: el orden de un dict de bleak no
    # significa nada.
    print(f"  {len(candidatos)} candidato(s) con el UUID de BitChat:")
    for mac, _dev, adv in candidatos:
        marca = "" if es_rssi_real(adv.rssi) else "   <- RSSI no medido"
        print(f"    {mac}  rssi={adv.rssi}{marca}")

    medidos = [c for c in candidatos if es_rssi_real(c[2].rssi)]
    if medidos:
        mac, dev, adv = max(medidos, key=lambda c: c[2].rssi)
        print(f"  elegido: {mac}  rssi={adv.rssi} (el más fuerte de los medidos)")
        return mac, dev, adv

    # Ninguno tiene medida. Se usa el primero, pero avisando: si la conexión
    # falla, el culpable más probable es que se eligió a ciegas.
    mac, dev, adv = candidatos[0]
    print(f"  AVISO: ninguno tiene RSSI medido. Se usa {mac} a ciegas.")
    print("  Si falla la conexión, el problema puede ser que no se oyó de")
    print("  verdad: sube --scan y comprueba si la app anuncia en primer plano.")
    return mac, dev, adv


async def principal(args: argparse.Namespace) -> int:
    from bleak import BleakClient

    # La identidad se carga de disco o se crea una vez. Que persista importa:
    # el peer_id se deriva de la clave Noise, así que regenerarla en cada
    # arranque haría que fuéramos un par distinto cada vez y nadie nos
    # volvería a encontrar.
    identidad = Identity.cargar_o_crear(args.nickname, ruta=args.identity)
    # `--nickname` **no** crea una identidad nueva: si el fichero existe, gana.
    # Es la trampa de por qu{e} se repiten las mismas claves sin querer, y
    # `--nickname` parece lo contrario porque el flag se llama as{i}.
    if identidad.nickname != args.nickname:
        ruta = args.identity or Identity.RUTA_POR_DEFECTO
        print(f"AVISO: --nickname {args.nickname!r} ignorado. El fichero "
              f"{ruta}")
        print(f"  tiene el nickname {identidad.nickname!r} y `cargar_o_crear` "
              f"gana.")
        print(f"  Para una identidad de verdad nueva: --identity <otro fichero>")
    print(f"identidad: nickname={identidad.nickname!r}  "
          f"peer_id={identidad.peer_id_hex}")
    print(f"  (guardada en {identidad.guardar(args.identity)})")

    hallado = await resolver_telefono(args.scan)
    if hallado is None:
        print("\nNO aparece el teléfono.")
        print("¿Está desbloqueado con BitChat en primer plano?")
        print("Android deja de anunciar cuando la app pasa a segundo plano.")
        return 1
    mac, dev, adv = hallado

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
            return await _sesion(cliente, args, identidad, recibidos, al_recibir, mac)
    except TimeoutError:
        print("\nTIMEOUT al conectar.")
        print()
        # Se distingue lo que está **verificado** de lo que se supone. Antes
        # la lista de causas iba detrás de "el radio ve al teléfono", que es
        # una afirmación que no siempre es cierta: se puede ver el anuncio y
        # que la MAC no corresponda a un dispositivo que acepte conexiones.
        if not es_rssi_real(adv.rssi):
            print("  Lo que sabemos:")
            print(f"    - el anuncio con el UUID de BitChat es visible "
                  f"(rssi={adv.rssi})")
            print("    - ese RSSI es el valor por defecto de bleak, NO una medida")
            print("      (scanner.py:209 usa props.get('RSSI', -127))")
            print()
            print("  Hipótesis, por orden de probabilidad:")
            print("    - La dirección del anuncio no es la del dispositivo que")
            print("      acepta conexiones. Android rotó la MAC al apagar y")
            print("      encender el BT. Se comprueba con:  bluetoothctl info <MAC>")
            print("    - La app anuncia pero no acepta conexiones entrantes hasta")
            print("      que el móvil esté desbloqueado.")
        else:
            print("  Lo que sabemos:")
            print(f"    - anuncio con RSSI medido ({adv.rssi} dBm), señal real")
            print()
            print("  Causas habituales:")
            print("    - Conexión GATT colgada de una ejecución anterior:")
            print("        bluetoothctl devices Connected")
            print("        bluetoothctl remove <MAC>")
            print("    - Android ya conectado a otro cliente de este adaptador.")
            print("    - Reintentar: el primer intento es el que negocia.")
        raise SystemExit(2)


def _preparar(args, identidad, mac):
    """Decide qué paquete enviar e imprime de dónde sale.

    Tres modos, y el handshake necesita el `peer_id` del móvil, que es **otro**
    distinto del de la MAC por la que nos conectamos: las MAC rotan, el
    `peer_id` no.
    """
    from pybitchat.noise.handshake import iniciar_handshake

    sesion = None

    if args.paquete:
        paquete = args.paquete
        print(f"\nreenviando bytes de {args.paquete} sin interpretarlos")
    elif args.handshake:
        # El `peer_id` de la app viene del announce, no de la MAC. Si el
        # usuario lo pasa, se usa; si no, se deriva y se avisa.
        peer_id = args.peer_id or identidad.peer_id
        if args.peer_id is None:
            print(
                f"\nAVISO: sin --peer-id se usa el nuestro ({peer_id.hex()}).\n"
                "  Si el móvil no lo tiene, descartará el paquete en silencio\n"
                "  (MessageHandler.kt:375). Pásalo con --peer-id."
            )
        # La sesión **se devuelve** aunque ya no se use para responder. Devolverla
        # evita que un día alguien añada un segundo camino y reintroduzca el
        # `None` que antes provocaba un error sin origen.
        paquete, sesion = iniciar_handshake(
            identidad,
            peer_id_remoto=peer_id,
            noise_public_remoto=args.noise_public,
            ttl=args.ttl_handshake,
        )
        print(f"\nenviando NOISE_HANDSHAKE (msg1, {args.ttl_handshake} saltos)")
        print(f"  nuestro peer_id  = {identidad.peer_id_hex}")
        print(f"  destinatario     = {peer_id.hex()}")
        if args.noise_public:
            print(f"  Noise remota     = {args.noise_public.hex()}")
    else:
        firmar = getattr(args, "firmar", False)
        paquete = identidad.announce_packet(ttl=MESSAGE_TTL_HOPS, firmar=firmar)
        if firmar:
            print(f"\nenviando ANNOUNCE de {args.nickname!r} **FIRMADO**")
            print("  Sin firma la app lo descarta: `AnnouncementIdentityValidator")
            print("  .verify` devuelve null y no nos registra como par. Ver")
            print("  `MessageHandler.handleAnnounceWithResult`.")
        else:
            print(f"\nenviando ANNOUNCE de {args.nickname!r} sin firma")
            print("  (con --firmar lo acepta la app; ver ESTADO.md)")

    print(f"  peer_id = {identidad.peer_id_hex}  (sha256 de la clave Noise, [:8])")
    print(f"  clave Noise = {identidad.noise_public.hex()}")
    print(f"  tamaño = {len(paquete)} B")
    print(hexdump(paquete))
    return paquete, sesion


def _leer_msg2(msg2: bytes, sesion, args) -> None:
    """Lee el `msg2` con la sesión viva y dice qué sale.

    ## Por qué aquí y no en `probe_msg2.py`

    Descifrar el `msg2` exige la clave efímera **privada** del `msg1` que la app
    recibió. Esa solo existe en el proceso que lo mandó. Un script posterior
    sobre la captura no la tiene, por mucho que `noiseprotocol` esté
    instalada.

    `probe_msg2.py` lo intentó y por eso imprimía `leído sin error, carga
    útil: 64 B`: había leído el `msg2` sin escribir el `msg1`, el motor se
    comía el token `E` y los 64 B de cola quedaban sin descifrar. Al no haber
    clave, un Poly1305 que nunca se comprueba no puede fallar.

    ## Los tres desenlaces, y todos se distinguen

    | Carga útil | Qué ha pasado |
    |---|---|
    | 0 B | el motor consumió `[e, ee, s, es]`. Es el caso bueno |
    | 64 B | consumió solo `[e]`: el `msg1` no llegó a escribirse |
    | error al leer | el Poly1305 no validó: el `ck` no es el nuestro |

    | Resultado | Consecuencia |
    |---|---|
    | 0 B y la clave es la de `--noise-public` | el `msg3` con criterio |
    | 0 B y la clave es otra | el tag valida pero no es su identidad |
    | error | el `ck` derivado de nuestro `msg1` no es el suyo |
    """
    from pybitchat.protocol.identity import peer_id_from_noise_key

    print()
    print("  --- leyendo el msg2 con la sesión viva ---")
    if sesion is None:
        print("    no hay sesión: el handshake se mandó sin ella.")
        return {"estado": "sin-sesion", "msg3": None}
    try:
        carga = sesion.read_handshake(msg2, payload_size=0)
    except Exception as exc:
        print(f"    ERROR al leer: {type(exc).__name__}: {exc}")
        print("    El Poly1305 no validó. O el `ck` derivado de nuestro `msg1`")
        print("    no es el que la app usó, o el `msg2` no es XX con ChaChaPoly.")
        return {"estado": "error", "msg3": None}

    if carga:
        print(f"    carga útil: {len(carga)} B")
        print()
        print("    Debería ser **0 B**. Si no lo es, el motor no consumió el")
        print("    patron de `msg2` y lo de la cola va sin descifrar: no ha")
        print("    podido fallar porque no se ha intentado.")
        if len(carga) == len(msg2) - 32:
            print()
            print("    64 = 96 - 32: solo se ha comido el token `E`. Pasa cuando")
            print("    el `msg1` no se escribió, y el `msg1` sí se escribió.")
            print("    Es un bug de quien llama, no del protocolo.")
        return {"estado": "payload", "msg3": None}

    remoto = sesion.remote_static_public
    print("    leído. carga útil: 0 B  <- lo esperado")
    print(f"    remote_static_public: {remoto.hex() if remoto else None}")
    if not remoto:
        print()
        print("    El tag validó pero la clave estática no quedó puesta. Con el")
        print("    token `S` presente no debería pasar.")
        return {"estado": "sin-estatica", "msg3": None}

    esperado = args.noise_public
    print()
    if esperado is None:
        print("    Pasa --noise-public para compararla con la de la app.")
        return {"estado": "sin-comparar", "msg3": None}
    igual = remoto == esperado
    print(f"    TLV 0x02 del announce  {esperado.hex()}")
    print(f"    clave del msg2         {remoto.hex()}")
    print(f"    -> {'IGUAL' if igual else 'DISTINTA'}")
    if not igual:
        print()
        print("    El tag validó y la clave no es la suya. Habría que mirar si")
        print("    el `msg2` trae otro token, o si la app usa una clave estática")
        print("    distinta para el handshake que para el announce.")
        return {"estado": "distinta", "msg3": None}

    pid = peer_id_from_noise_key(remoto)
    print(f"    peer_id derivado:      {pid.hex()}")
    if args.peer_id is not None:
        print(f"    peer_id de la app:      {args.peer_id.hex()}")
        print(f"    -> {'IGUAL' if pid == args.peer_id else 'DISTINTO'}")
    print()
    print("    La cadena de derivación coincide con la de la app.")
    return {"estado": "igual", "estatica": remoto, "peer_id": pid, "msg3": None}


def construir_msg3(sesion, resultado, args) -> bytes | None:
    """Construye el `msg3` si toca, o devuelve `None` y explica por qué no.

    ## Las dos condiciones, y las dos hacen falta

    1. **`--msg3`** está puesto. Sin el flag nada cambia en las ejecuciones que
       se usan para otra cosa.
    2. **La lectura dio `IGUAL`.** Es la que dice que el `ck` de la sesión es el
       de la app. Si el Poly1305 no validó, enviar un `msg3` sería ruido con
       la forma correcta.

    El segundo caso es el que de verdad protege. Un `msg3` con bytes plausibles y
    una derivación equivocada es peor que no enviar nada: en el protocolo, desde
    fuera, un mensaje mal derivado y uno ausente pueden ser la misma cosa, y no
    tenemos forma de distinguirlos sin adivinar.

    ## Lo que produce

    `write_handshake(b"")` sobre la sesión viva: 64 B, `s` cifrada + `se` + el tag
    de la carga vacía. Sale de `noiseprotocol`, no de código nuestro, y con el
    estado verificado es el que la app espera.
    """
    from pybitchat.noise.handshake import MSG3_SIZE

    if not getattr(args, "msg3", False):
        print("  `msg3` no construido: falta --msg3.")
        return None
    if resultado.get("estado") != "igual":
        print(f"  `msg3` NO enviado: la lectura dio "
              f"{resultado.get('estado')!r}, no 'igual'.")
        print("  Con una derivación que no cuadra, enviarlo sería ruido con la")
        print("  forma correcta. Es el caso que este flag protege.")
        return None
    if sesion is None:
        print("  `msg3` NO enviado: no hay sesión viva.")
        return None

    try:
        mensaje = sesion.write_handshake(b"")
    except Exception as exc:
        print(f"  `msg3` NO se pudo construir: {type(exc).__name__}: {exc}")
        return None

    if len(mensaje) != MSG3_SIZE:
        # No se envía un tamaño que no es el del protocolo, ni a modo de prueba.
        print(f"  `msg3` NO enviado: mide {len(mensaje)} B y el perfil da "
              f"{MSG3_SIZE}.")
        return None

    print(f"  `msg3` construido: {len(mensaje)} B  (s cifrada + se + tag)")
    try:
        cifrador = sesion.split()
    except Exception as exc:
        print(f"  split() falló: {type(exc).__name__}: {exc}")
        return mensaje
    print(f"  split() correcto: la sesión está establecida. Canal de "
          f"transporte disponible.")
    print(f"  {cifrador!r}")
    return mensaje


async def _enviar_msg3(cliente, car, args, identidad, sesion, resultado) -> bool:
    """Construye y envía el `msg3`. Devuelve si se ha enviado algo."""
    from pybitchat.noise.handshake import empaquetar

    print("\n  --- el msg3 ---")
    mensaje = construir_msg3(sesion, resultado, args)
    if mensaje is None:
        return False

    if args.peer_id is None:
        print("  NO enviado: sin --peer-id la app lo descarta en silencio")
        print("  (`MessageHandler.kt:375-377`).")
        return False

    paquete = empaquetar(mensaje, identidad, args.peer_id, ttl=args.ttl_handshake)
    limite = car.max_write_without_response_size
    if len(paquete) > limite:
        print(f"  NO enviado: {len(paquete)} B excede el máximo escribible "
              f"({limite} B).")
        return False

    print(f"  empaquetado: {len(paquete)} B, tipo 0x10, dirigido a "
          f"{args.peer_id.hex()}")
    await cliente.write_gatt_char(car, paquete, response=False)
    print("  ENVIADO")
    return True


async def _escuchar_handshake(
    cliente, car, args, identidad, recibidos, sesion=None
) -> int:
    """Escucha la respuesta de la app a nuestro `msg1`.

    ## No responde. Es deliberado.

    Antes esta función escribía el `msg3` con `completar_handshake()`, que
    además verificaba el `peer_id`. Se retiró esa función el 2026-10-04: la
    verificación **no se sostenía**, porque el `msg2` real de la app no deja
    ninguna clave estática de la que derivar el `peer_id`.

    Escribir un `msg3` sin saber el formato del `msg2` sería adivinar en la
    única parte del protocolo donde adivinar es criptográficamente grave. Aquí
    sólo se registra lo que llega.

    Lo que sí está verificado:

    | Lo que llega | Significa |
    |---|---|
    | `NOISE_HANDSHAKE` de 96 B | la app procesó nuestro `msg1` |
    | `NOISE_ENCRYPTED` (`0x11`) | la sesión está cifrada |

    ## Lo que sí hace además: leerlo

    `probe_msg2.py` **no** puede descifrar el `msg2`: le falta la clave efímera
    privada del `msg1`, que solo existía en el proceso que lo mandó. Aquí está
    la sesión viva, así que este es el sitio donde se lee. Ver `_leer_msg2`.
    """
    print(f"\nescuchando la respuesta hasta {args.segundos} s…")
    await asyncio.sleep(args.segundos)

    vistos = 0
    resultado = None
    enviados_msg3 = False
    for datos in list(recibidos):
        paquete = _primero_inesperado(datos)
        if paquete is None:
            continue
        vistos += 1
        if paquete.header.raw_type == 0x10 and resultado is None:
            print(f"\n  respuesta de la app: NOISE_HANDSHAKE de "
                  f"{len(paquete.payload)} B")
            print(f"    payload = {paquete.payload.hex()}")
            resultado = _leer_msg2(paquete.payload, sesion, args)
            if await _enviar_msg3(
                cliente, car, args, identidad, sesion, resultado
            ):
                enviados_msg3 = True
    if enviados_msg3:
        print(f"\nescuchando {args.segundos} s más, por si la app contesta...")
        antes = len(recibidos)
        await asyncio.sleep(args.segundos)
        nuevos = 0
        for datos in list(recibidos)[antes:]:
            paquete = _primero_inesperado(datos)
            if paquete is None:
                continue
            nuevos += 1
            nombre = (
                MessageType(paquete.header.raw_type).name
                if paquete.header.raw_type in MessageType._value2member_map_
                else "?"
            )
            print(f"  {nombre} (0x{paquete.header.raw_type:02x}) de "
                  f"{len(paquete.payload)} B")
        if nuevos == 0:
            print("  nada nuevo. El `msg3` se ha enviado y no hay respuesta:")
            print("  eso NO significa que esté mal. El handshake establishment")
            print("  no tiene respuesta propia en Noise; lo que llega después son")
            print("  mensajes ya cifrados con la clave de transporte.")

    if vistos == 0:
        print("\n  no llegó nada. Causas, en orden:")
        print("   - Sin --peer-id el paquete se descartó en silencio.")
        print("   - La app no nos ha descubierto todavía.")
        print("   - El móvil lleva >15 min sin actividad y no anuncia.")

    destino = args.guardar
    _guardar(recibidos, destino)
    print(f"  {len(recibidos)} paquete(s) guardados en {destino} "
          f"({destino.stat().st_size} B)")

    return _informe(recibidos)


def _primero_inesperado(datos):
    """Primer paquete legible de un `bytearray` recibido, o `None`.

    Se usa `Packet.from_bytes` en lugar de asumir el formato: así un paquete
    malformado da `None` y no rompe la sesión.
    """
    from pybitchat.protocol.packet import Packet, ProtocolError

    try:
        return Packet.from_bytes(bytes(datos))
    except (ProtocolError, IndexError, ValueError):
        return None


def _sin_characteristic(cliente) -> int:
    """El telófano anunció BitChat pero no sirvió el characteristic. Ver §3.

    ## Por qué esto necesita su propio camino

    El anuncio y el GATT son cosas distintas. Que el `UUID` de servicio aparezca
    en el scanning **no** garantiza que el servidor GATT exponga el
    characteristic en esa conexión: la app puede estar en un estado en el que
    publica el anuncio y todavía no levanta el servicio, o la MAC rotada
    apuntó a un estado anterior.

    Y sin characteristic no hay nada que hacer: no hay por dónde escribir ni por
    dónde escuchar. Sale con código 1 y un motivo, no con un traceback.

    ## Lo que se mira antes de culpar al código

    | Síntoma | Causa probable |
    |---|---|
| 1 solo candidato, y menos `UUID` que de costumbre | el móvil announce |
    | MTU 23 | `_acquire_mtu` falló; BlueZ se queda en su valor por defecto |
| varios candidatos, MTU 517, y sin characteristic | el GATT de la app |

    Los tres son del entorno. Este caso se registró como **"el teléfono no
    sirvió el characteristic"**, que es lo que se sabe, y no como un fallo
    nuestro.
    """
    print("\n  el teléfono anuncia BitChat pero no sirvió el characteristic.")
    print(f"    characteristic buscado: {CHARACTERISTIC_UUID}")
    # `client.services` es un `BleakGATTServiceCollection`, que **no** tiene
    # `__len__`: se recorre con `iter()`. Pasó el 2026-10-05 y el `len()` lanzó
    # `TypeError` con un cliente real, mientras el test pasaba con un doble que
    # sí lo tenía. Un doble que no copia la API real valida el error.
    servicios = getattr(cliente, "services", None)
    if servicios is not None:
        try:
            lista = list(servicios)
            print(f"    servicios descubiertos: {len(lista)}")
            for s in lista:
                print(f"      {s.uuid}  ({s.description})")
                for c in getattr(s, "characteristics", ()):
                    print(f"        - {c.uuid}  ({c.description})")
        except Exception as exc:
            print(f"    (no se pudieron listar: {type(exc).__name__}: {exc})")
    print()
    print("  El anuncio y el GATT son cosas distintas: que el UUID aparezca en")
    print("  el escaneo no garantiza que el servicio se sirva en esta conexión.")
    print()
    print("  Antes de culpar al código, comprueba:")
    print("   - si salían varios candidatos y la MTU es 517. Con un solo")
    print("     candidato, o con MTU 23, el problema es el móvil")
    print("   - si el móvil lleva más de 15 min sin actividad: ciérralo y")
    print("     vuelve a abrir BitChat")
    print("   - si BitChat está en primer plano y el teléfono desbloqueado")
    return 1


async def _sesion(cliente, args, identidad, recibidos, al_recibir, mac) -> int:
    try:
        await cliente._backend._acquire_mtu()
    except Exception as exc:
        print(f"  _acquire_mtu falló: {exc}")
    print(f"  conectado. MTU = {cliente.mtu_size}")

    # MTU 23 es el valor por defecto de BlueZ, no el negociado. Se avisa porque
    # un paquete de 256 B no cabe, y el envio grande falla **en silencio**: no
    # hay excepción, simplemente no llega. Es el mismo modo de fallo que el
    # characteristic ausente — el código no puede distinguirlo — y por eso
    # se dice aquí en vez de dejar que lo descubra el `max_write_without_response_size`
    # mucho después y con menos contexto.
    if cliente.mtu_size <= MTU_POR_DEFECTO:
        print(f"  AVISO: MTU = {cliente.mtu_size}, que es el valor por defecto de "
              f"BlueZ.")
        print("    La negociación no se completó, y un paquete de 256 B no cabe.")
        print("    Un envío que no cabe **no da error**: no llega y no se sabe")
        print("    por qué. Suele venir con el characteristic ausente, así que")
        print("    las dos cosas suelen ser el mismo síntoma de un lado.")

    # El characteristic se resuelve **antes** de activar las notificaciones, y
    # no después. `start_notify` lo busca por dentro y lanza
    # `BleakCharacteristicNotFoundError` si no lo encuentra, así que un `if
    # car is None` colocado después es código muerto: nunca se alcanza.
    #
    # Pasó el 2026-10-05 con un traceback en vez de un diagnóstico, porque el
    # teléfono se anunció pero no sirvió el characteristic en esa conexión.
    car = cliente.services.get_characteristic(CHARACTERISTIC_UUID)
    if car is None:
        return _sin_characteristic(cliente)

    try:
        await cliente.start_notify(car, al_recibir)
    except Exception as exc:
        print(f"  no se pudieron activar las notificaciones: "
              f"{type(exc).__name__}: {exc}")
        return 1
    print("  notificaciones activadas")

    paquete, sesion = _preparar(args, identidad, mac)

    limite = car.max_write_without_response_size
    if len(paquete) > limite:
        print(f"\nERROR: excede el máximo escribible ({limite} B). "
              f"MTU no negociado bien.")
        return 1
    await cliente.write_gatt_char(car, paquete, response=False)
    print("  enviado")

    if args.handshake:
        return await _escuchar_handshake(
            cliente, car, args, identidad, recibidos, sesion
        )
    await asyncio.sleep(args.segundos)

    # Se guarda lo recibido **siempre**, aunque el script termine bien. Los
    # bytes son la evidencia: el próximo paso es arreglar el decodificador del
    # ANNOUNCE, y para eso hace falta el paquete real, no una transcripción en
    # el terminal que hay que volver a capturar desde el host Linux.
    destino = args.guardar
    _guardar(recibidos, destino)
    print(f"  {len(recibidos)} paquete(s) guardados en {destino} "
          f"({destino.stat().st_size} B)")

    return _informe(recibidos)


def _guardar(recibidos: list[bytes], destino: Path) -> int:
    """Concatena los paquetes recibidos en `destino`. Devuelve el nº escrito.

    Se guarda también cuando la lista está vacía, y crea el directorio si hace
    falta. Sin datos, su ausencia significaría "no se guardó" y no "no llegó
    nada": son preguntas distintas, y no se pueden distinguir si el fichero
    sólo aparece cuando hay algo que escribir.
    """
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_bytes(b"".join(recibidos))
    return len(recibidos)


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
        print("\nAntes de ninguna de las dos: si el móvil lleva más de 15 min")
        print("sin actividad, la app deja de anunciarse hasta que se cierre y")
        print("se vuelva a abrir. Es la causa más frecuente.")
    return 0


def _hex(valor: str, n_bytes: int) -> bytes:
    """Convierte hex en `bytes`, o explica qué está mal.

    Sin esto, un `~` de más al pegar da:

        invalid <lambda> value: '9735...6b~'

    que no dice ni cuántos bytes se esperaban ni dónde está el problema. Y el
    fallo real es casi siempre de copiar y pegar, así que el mensaje tiene que
    ayudar a corregirlo.

    `n_bytes` es obligatorio: el número de bytes esperado es lo que hace falta
    para decir "te faltan 4", que es el error que se repite.
    """
    limpio = valor.strip()
    if limpio.lower().startswith("0x"):
        limpio = limpio[2:]
    # `bytes.fromhex` acepta espacios en medio (y los ignora). Eso hace que un
    # pegado con separadores de bloque pase **en silencio** y el fallo aparezca
    # mucho más tarde, al descifrar. Se rechazan a propósito: quien pega una
    # clave la quiere exacta.
    if any(c.isspace() for c in limpio):
        blanco = "".join(sorted({c for c in limpio if c.isspace()}))
        raise argparse.ArgumentTypeError(
            f"el hexadecimal no lleva espacios dentro, y hay {blanco!r}. "
            f"Se esperaba {n_bytes} bytes = {n_bytes * 2} dígitos hex seguidos."
        )
    try:
        datos = bytes.fromhex(limpio)
    except ValueError:
        malos = [c for c in limpio if c not in "0123456789abcdefABCDEF"]
        detalle = (
            f"caracteres no válidos: {''.join(sorted(set(malos)))!r}"
            if malos
            else "longitud impar o formato incorrecto"
        )
        raise argparse.ArgumentTypeError(
            f"no es hexadecimal ({detalle}). Se esperaba {n_bytes} bytes = "
            f"{n_bytes * 2} dígitos hex, sin espacios ni prefijos raros."
        ) from None
    if len(datos) != n_bytes:
        raise argparse.ArgumentTypeError(
            f"se esperaban {n_bytes} bytes ({n_bytes * 2} hex) y llegaron "
            f"{len(datos)} ({len(datos) * 2} hex)."
        )
    return datos


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
    p.add_argument("--guardar", type=Path,
                   default=RAIZ / "capturas" / "recibido.bin",
                   help="fichero donde se guardan los paquetes recibidos")
    p.add_argument("--firmar", action="store_true",
                   help="firma el announce con Ed25519. **Sin esto la app lo "
                        "descarta**: sin firma no nos registra como par verificado")
    p.add_argument("--msg3", action="store_true",
                   help="envía el `msg3` (64 B) si la lectura del `msg2` dio "
                        "IGUAL. Implica --handshake")
    p.add_argument("--handshake", action="store_true",
                   help="enviar NOISE_HANDSHAKE (msg1) en vez de ANNOUNCE")
    p.add_argument("--peer-id", type=lambda s: _hex(s, 8), default=None,
                   help="peer_id de 8 bytes de la app, en hex. Va en "
                        "recipient_id; sin él la app descarta el paquete")
    p.add_argument("--noise-public", type=lambda s: _hex(s, 32),
                   default=None,
                   help="clave Noise pública de 32 bytes de la app, en hex "
                        "(TLV 0x02 de su announce)")
    p.add_argument("--ttl-handshake", type=int, default=6,
                   help="saltos del handshake (por defecto 6, como la app)")
    args = p.parse_args()
    # `--msg3` sin `--handshake` no tendr{i}a ninguna sesi{o}n que completar:
    # el `msg3` es la respuesta a un `msg2`, y el `msg2` solo se pide al mandar
    # el `msg1`. Se activa el handshake en vez de fallar con un error seco, porque
    # el usuario ya ha pedido lo que quiere.
    if args.msg3:
        args.handshake = True
    # En hexadecimal, para los informes y para comparar con el `peer_id` derivado.
    args.peer_id_hex = args.peer_id.hex() if args.peer_id else None
    if args.paquete:
        args.paquete = args.paquete.read_bytes()
    return asyncio.run(principal(args))


if __name__ == "__main__":
    raise SystemExit(main())
