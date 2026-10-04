# Estado del proyecto — punto de reanudación

**Fecha de corte:** 2026-10-03
**Objetivo:** cliente BitChat en Python para **Android + Linux** (iOS fuera de
alcance). Es una **reimplementación**, no un port de `bitchat-tui`.

**En una línea:** el enlace BLE funciona en las dos direcciones contra la app
Android real, y la identidad se intercambia y se decodifica. **Falta el
handshake Noise**, que es lo único que queda para cerrar el enlace.

> ⚠️ **Antes de nada:** no se porta `bitchat-tui`. Habla un dialecto retirado, así
> que portarlo daría un cliente incapaz de hablar con ninguna app actual. Ver
> `EVALUACION-MIGRACION.md` §1 y §11.

---

## 1. Donde estamos: **el enlace funciona y la identidad se intercambia**

Se ha verificado con **trafico real de la app Android**, no con captura del Rust
ni con lectura del codigo.

| | Estado |
|---|---|
| Codec de payloads, v1 y v2 | ✅ |
| Noise XX handshake (Cacophony/Noise-C) | ✅ 39 vectores |
| Conformidad con los tests de la app | ✅ 48 casos portados |
| **Descubrimiento del telefono** | ✅ **visto en 9 direcciones distintas** |
| **Conexion GATT sin emparejar** | ✅ |
| **MTU 517** | ✅ coincide con Android 14+ |
| **Anuncio como peripheral** | ✅ **funciona** - BlueZ lo acepta, `ce990ff` |
| **Envio de identidad valida** | ✅ **la app responde con la suya** |
| **Decodificacion del announce** | ✅ TLV de identidad, `63154e3` |
| `peer_id` derivado de la clave | ✅ confirmado contra trafico real |
| Relleno PKCS#7 a 256 B | ✅ confirmado en 4 capturas |
| **Handshake Noise con la app real** | ❌ **falta - es lo unico que queda** |

### El hito del 2026-10-03

Primera sesion en que **la app responde a nuestro announce con el suyo**, y en
que lo leemos bien. El intercambio de identidad es completo:

```
enviando ANNOUNCE de 'pybitchat-probe'   111 B   -> enviado
--- paquete recibido: 256 B (nº 1) ---  ANNOUNCE      payload 80, firma 64
--- paquete recibido: 256 B (nº 2) ---  ANNOUNCE      payload 80, firma 64
--- paquete recibido: 256 B (nº 3) ---  REQUEST_SYNC  carga OK
total de paquetes recibidos: 3
```

Decodificado con los bytes reales:

```
nickname       = 'anewells74'
noise_public   = 973585b6502836ff5767934bdb4c62458c48b87e94c02d470797e93d21052f6b
signing_public = 7ada9dab1bec9eb274cfaa0e3489b259d3219f069fe84cb694aa7c5871a61a88
peer_id derivado = 34e01ccea10a8c6d  == sender_id del paquete
```

Lo del `peer_id` es la prueba buena: sale de `sha256(clave Noise)[:8]` y
coincide con el `sender_id` **sin que nadie lo haya puesto ahi**. Si el TLV
estuviera mal leido, no saldria.

Los paquetes se guardan en `capturas/recibido.bin`, asi que el trabajo de
decodificar se hace sobre los bytes y no sobre el terminal.

### Lo que se midio contra el telefono

- Servicio `F47B5E2D-...` y characteristic `A1B2C3D4-...`, sin emparejar.
- **MTU 517** tras `_acquire_mtu()`. El valor por defecto de BlueZ es **23**, y
  sin pedirlo el envio grande falla en silencio.
- **Las MAC rotan**: nueve direcciones distintas en nueve escaneos. Es una
  direccion privada resoluble de Android. Por eso `bleak_transport` resuelve
  por UUID en cada conexion y no cachea nada.
- El movil anuncia BitChat con **2-3 MACs a la vez**, todas con el UUID de
  servicio. Se elige la de mayor RSSI **medido**; `-127` es el valor por defecto
  de bleak cuando BlueZ no mide (`scanner.py:209`), no una senal mala.

## 2. Los cuatro hallazgos que cambiaron el diseño

### 2.1 `ANNOUNCE` **no** es sólo un nickname

Es un TLV con la identidad criptográfica entera
(`model/IdentityAnnouncement.kt`):

```
[tipo u8][longitud u8][valor]      <- ¡longitud de UN byte!

0x01 NICKNAME           obligatorio
0x02 NOISE_PUBLIC_KEY   obligatorio, X25519 estática
0x03 SIGNING_PUBLIC_KEY obligatorio, Ed25519
0x05 CAPABILITIES       opcional, bitfield little-endian
```

⚠️ La longitud es de **un byte**, a diferencia del TLV de `BitchatFilePacket`
que usa u16. Confundir los dos rompe el handshake entero.

`AnnouncePayload` (sólo nickname) es el formato del **dialecto retirado**.

### 2.2 El `peer_id` **se deriva**, no se elige

Son los 8 primeros bytes de `SHA-256(clave pública X25519)`. Verificado:

```
clave Noise  973585b6502836ff…   (real, del móvil)
sender_id    34e01ccea10a8c6d     = sha256(...)[:8]  ✓
```

Un par puede comprobar que el `sender_id` corresponde a la clave que dice
anunciar. Ése es el mecanismo anti-suplantación, y explica por qué un
`sender_id` inventado no sirve de nada.

### 2.3 La app **identifica por `peer_id`, no por MAC**

De `BluetoothGattServerManager.kt:389-407`:

- **Paquete de advertising**: sólo `ServiceUUIDs`, sin tx-power ni nombre.
- **Scan response**: `ServiceData[UUID]` = los 8 primeros bytes del peerID.

> *Add stable identity to Scan Response. This allows scanners to deduplicate
> devices even if MAC address rotates*

**Consecuencia:** conectar a la app no basta. Hay que **existir en el anuncio**,
porque si no nunca aparecemos con nuestro `peer_id`.

### 2.4 La salida de DEFLATE **no es canónica**

Java y Python producen bytes distintos para la misma entrada. Como la
verificación de firma re-codifica el paquete, re-comprimir un payload ajeno
**haría que una firma válida dejara de validar**. Implementado como
`WirePayload`, igual que Android.

---

## 3. Los tres problemas abiertos

### 3.1 El `msg2` de 96 B no encaja con el patron que dice el codigo

**Es el problema abierto que queda. Sustituye al "no llega el handshake".**

### Lo que funciona

El 2026-10-04 la app **respondio** a nuestro `msg1`:

    recipient = 4baf99fa0b9298ba   <- nuestro peer_id
    payload   = 96 B, tipo 0x10

Eso prueba que procesa nuestro `msg1` y contesta a quien se lo envia. Todo el
`noise/handshake.py` que hace falta para el `msg1` **esta verificado**: la
app lo acepta.

### Lo que no encaja

Tres fuentes discrepan y no se sabe cual manda:

| Fuente | Dice que `msg2` mide |
|---|---|
| `Pattern.java:157` + `HandshakeState` | **128 B** (`E` 32 + `EE` 48 + `S` 48 + `ES` 0) |
| comentario `NoiseSession.kt:32` | **96 B** (`(32 + 48) + 16 (MAC)`) |
| **bytes reales** | **96 B** |

`ES` es un `mixDH` y ocupa **0 B**, no 48. Y el comentario de la app,
`(32 + 48) + 16`, no corresponde a ningún patrón de `Pattern.java`. Los bytes
reales (96) coinciden con el comentario, pero el código que dice "96" no produce
96 B. Uno de los dos miente y no está claro cuál.

### Lo que si se sabe, y es poco

- El `msg2` **se lee sin error de descifrado**: la etiqueta Poly1305 valida.
- Aun asi, `read_handshake` **no deja ninguna clave estatica remota**, asi que
  no hay de que derivar un `peer_id`.
- La app manda un **announce completo despues** de cada handshake. Las claves
  parece que viajan ahi, no en el handshake. **No esta confirmado.**

### Por que se retiro `completar_handshake`

Escribia el `msg3` y verificaba `sha256(clave del msg2)[:8] == peer_id`. Como
no hay clave, la verificacion no verificaba, y su `verificar_peer_id=False`
debia ser justo el caso real. Es peor que no tenerla: da seguridad falsa.
`tests/test_noise_handshake.py::TestRetiradaDeCompletarHandshake` impide que
vuelva.

Escribir un `msg3` sin saber el formato del `msg2` es adivinar en la unica parte
del protocolo donde adivinar es criptograficamente grave.

### El announce NO va antes del handshake (revertido)

Se probó y **empeoró** las cosas. La comparación de las dos ejecuciones:

| | Enviado | `msg2` |
|---|---|---|
| 04-oct | handshake **solo** | ✅ 96 B |
| 05-oct | announce **+** handshake | ❌ ninguno |

La hipótesis era que sin presentación previa la app no tiene un par al que
dirigir el handshake —el móvil no mostraba ninguno—. **No se comprobó que el
handshake ya funcionara sin announce**, y funcionaba, con dos sesiones de
evidencia. El dato que lo refutaba estaba en este mismo documento desde el
03-oct.

Revertido en `2f300bb` (vuelto atrás en el commit siguiente).

Lo que **no** se revierte, porque sigue siendo cierto y no depende del orden:
un announce **no** lleva `recipient_id` —eso es lo que lo hace broadcast— y el
handshake **sí** lo lleva, que es lo que hace que la app lo acepte
(`MessageHandler.kt:375`).

### Como investigarlo

```bash
./.venv/bin/python tools/probe_msg2.py
```

Da el desglose aunque falte `noiseprotocol`. Con ella instalada, ademas prueba
`read_handshake` con la identidad real y dice si la clave aparece.

### El error de razonamiento de este tramo

Tres cifras seguidas para `msg2`: **176**, luego **96**, y el correcto **128**.
Las tres equivocadas:

| Cifra | Por que fallo |
|---|---|
| 176 | contou `ES` como si ocupara 48 B |
| 96 | **cuadra por suma, no por protocolo** |
| 128 | no se calculo hasta el final |

El del medio es el grave: encontrar una descomposicion que encaja con los bytes
reales y llamarla hallazgo. Es el mismo error que en el relleno PKCS#7 - un
dato inventado que hace cuadrar una conclusion - repetido dos dias despues.

**Una suma que cuadra no es un hallazgo.** Hay que mirar el codigo que produce
los bytes, y comprobar que el comentario que lo explica sea del mismo commit.

### 3.2 Relleno: es PKCS#7, confirmado - tras fallar dos veces

Las capturas, con la **firma** de 64 B dentro del contenido:

| Paquete | Real | Relleno | Byte |
|---|---|---|---|
| ANNOUNCE (02-oct) | 166 B | 90 B | `0x5a` = 90 |
| filler (02-oct) | 96 B | 160 B | `0xa0` = 160 |
| ANNOUNCE (03-oct) | 166 B | 90 B | `0x5a` = 90 |
| ANNOUNCE (03-oct, 2o) | 166 B | 90 B | `0x5a` = 90 |

La longitud del relleno **es** el valor del byte, en las cuatro. `166 = 14 + 8 +
80 + 64` y `256 - 166 = 90 = 0x5a`.

**Este dato se afirmo bien, se nego mal, y se volvio a afirmar bien.** Se
consigna por que, porque el error dice mas que el resultado:

1. La primera vez cuadraba **por casualidad**: el caso del test estaba escrito
   `14 + 8 + 80 + 64`, con los 64 de la firma **supuestos**.
2. Al medir con bytes reales se concluyo que no era PKCS#7, porque se conto
   desde los 102 B sin la firma: `256 - 102 = 154`, contra un byte de 90. El
   fallo fue **no mirar `packet.py`**, que ya define `SIGNATURE_SIZE = 64` y lee
   la firma justo tras el payload. Ese fichero estaba a un `grep` de distancia.

`pkcs7_pad_to_bucket` **si** reproduce el relleno real de la app.

### 3.2bis Los 64 bytes: son la firma, pero no valida

```
102 B tal cual        -> truncado leyendo signature: 64 B en offset 102
102 + 64              -> OK, payload 80, firma si (64 B)
```

La posicion y el tamano son correctos. Lo que **no** se ha resuelto:

- **No valida** como firma Ed25519 con la clave `0x03` del propio announce,
  sobre seis mensajes candidatos (payload TLV, cabecera+sender+payload,
  sender+payload, TLV sin la clave de firma, solo el nickname, TLV completo).
- **Cambia en cada announce**: con el payload byte a byte identico, las tres
  firmas difieren en 64 de 64 bytes. Una firma determinista daria lo mismo, asi
  que o cubre algo que cambia (el timestamp de la cabecera) o no es una firma.
- El byte de `flags` del announce real es `0x00`: la app **no** activa
  `HAS_SIGNATURE` pero manda los 64 bytes. Con `flags=0` el parser no los
  consume, y por eso hubo que concatenarlos a mano.

En cambio el **relleno si es identico** en las tres capturas (90 bytes de
`0x5a`), que es justo lo que hace PKCS#7. Lo que no se entiende es la firma.

### 3.2ter `REQUEST_SYNC`: `m` cambio de 256 a 384

Dato del 03-oct, sin explicar:

| | payload | `p` | `m` | `data` |
|---|---|---|---|---|
| primera sesion | 16 B | 7 | **256** | 1 B |
| segunda sesion | 18 B | 7 | **384** | 3 B |

`p` se mantiene; `m` sube de 256 a 384 y `data` de 1 a 3 bytes (los +2 del
payload). 384 = 256 x 3/2, y no es multiplo de 256, asi que no parece un tamano
de paquete sino un **limite de bytes a pedir**. No se ha comprobado que lo fija:
puede depender de la MTU negociada o de lo que la app tiene que mandar.

### 3.3 Un `MESSAGE` con 72 bytes de `0xff` sin explicar

`payload_len = 2` pero el contenido son 96 B. Los 72 sobrantes son `0xff`, que
es el identificador de emisor general de BitChat repetido.

Además nuestro `MESSAGE` rechaza el payload de 4 bytes (`"exit"`) porque
`MIN_PAYLOAD_SIZE = 13`. **No está claro si la app se sale de spec o si nuestro
mínimo es demasiado estricto.**

---

## 4. Cómo arrancar

### En el host Linux (donde está el Bluetooth)

```bash
cd ~/PyBitChat && git pull
./.venv/bin/python tools/run_tests.py ; echo "exit=$?"
```

**Mira el `exit=`, no el texto.** Ver §6, punto 11.

> **Sólo en el host Linux salen los 462 tests sin `skipped=`.** El 2026-10-04
> fue la primera vez: en la VM de Windows faltan `bleak` y `dbus_fast`, así que
> 10 tests se saltan y **no comprueban nada**. Contarlos como verdes era el
> error, y por eso el runner ahora imprime **qué** se salta y por qué.
>
> Un `skipped=10` en la VM no es un problema. Un test roto esperándose en el
> host, sí. Ejecutar la suite completa **allí** antes de dar por buena una
> jornada.

Si falta el venv:
```bash
sudo apt install -y python3.14-venv build-essential python3-dev
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

### Probar el enlace

```bash
./.venv/bin/python tools/smoke_ble.py        # conectar y enviar announce
./.venv/bin/python tools/probe_advertise.py  # anunciar y comprobar
```

Móvil **desbloqueado con BitChat en primer plano**: Android deja de anunciar
cuando la app pasa a segundo plano.

> **Tras 15 min sin actividad, hay que cerrar BitChat y volver a abrirlo.**
>
> Anotado por el usuario el 2026-10-03. Es el dato que más tiempo costó hoy.
> Sin esto se diagnostica como si fuera un fallo del anuncio o del escaneo.
>
> **Lo que se veía:** la app sencillamente **no aparecía** en el escaneo.
> `smoke_ble.py` informaba `hay dispositivos pero ninguno anuncia BitChat`, y
> los 11 dispositivos que sí aparecían eran otros. El recuento de UUIDs de
> servicio caía de 29 a 9, que es la pista: se había perdido una entrada.
>
> **El error de razonamiento que induce:** "la app no anuncia" se lee como un
> hecho sobre el estado del móvil, cuando en realidad es un estado *por
> preparar*. Nada en el código lo distingue de "el móvil está apagado".
>
> **Antes de sacar conclusiones del escaneo, comprobar esto primero.** Es más
> barato que cualquier análisis del announcement, y no se deduce de los datos.

| Fichero | Qué prueba |
|---|---|
| `tools/smoke_ble.py` | Conecta, envía announce, registra lo que llega |
| `tools/probe_advertise.py` | Anuncia y escanea, para ver si nos encuentra |
| `tools/extract_vectors.py` | Regenera `tests/fixtures/vectors.json` |

Opciones útiles de `smoke_ble.py`:

| Opción | Por qué |
|---|---|
| `--scan 30` | el escaneo corto es la causa más fácil de un falso negativo |
| `--guardar RUTA` | dónde escribir los paquetes; por defecto `capturas/recibido.bin` |
| `--identity RUTA` | usar otra identidad, para no tocar la guardada |
| `--paquete RUTA` | reenviar bytes capturados tal cual, sin reconstruir |

### Reparto de tests

| Fichero | Tests | Cubre |
|---|---|---|
| `test_transport.py` | 78 | Compresión, reensamblado, GATT, transporte |
| `test_identity.py` | 64 | TLV de identidad, `peer_id`, firma, relleno |
| `test_current_payloads.py` | 52 | `ANNOUNCE` TLV, `MESSAGE`, fichero, voz |
| `test_conformance.py` | 48 | Conformidad con los tests de la app |
| `test_noise_vectors.py` | 39 | Handshake XX, framing, anti-replay |
| `test_smoke_ble.py` | 28 | Announce, hexdump, elección de peer, RSSI |
| `test_advertiser.py` | 27 | Anuncio: `Variant`, firmas, rutas D-Bus |
| `test_payloads.py` | 25 | Fragmentación, opacidad |
| `test_probe_advertise.py` | 22 | Informe de escaneo, tiempos, limitaciones |
| `test_dialect.py` | 21 | Constantes Android con `file:line` |
| `test_dispatch.py` | 19 | Despacho por dialecto y ambigüedad |
| `test_golden_packets.py` | 19 | Los 21 paquetes reales, byte a byte |
| `test_run_tests.py` | 8 | El runner: informe de saltados, código de salida |
| `test_bleak_transport.py` | 12 | Transporte real; 6 se saltan sin `bleak` |
| **Total** | **462** | 0 saltados en Linux; 10 saltados en Windows |

### Ficheros del proyecto

- `src/pybitchat/protocol/` — `types.py` (enums, constantes, política de
  relleno), `packet.py` (cabecera v1/v2, compresión, `WirePayload`, firma),
  `identity.py` (identidad, TLV, `peer_id`, firma Ed25519), `payloads.py`
  (despacho por dialecto), `compression.py`, `reassembly.py`, `message.py`,
  `tlv.py`, `voice.py`
- `src/pybitchat/noise/` — `session.py`, `framing.py`, `primitives.py`
- `src/pybitchat/ble/` — `gatt.py` (UUIDs), `bleak_transport.py`,
  `advertiser.py`
- `src/pybitchat/mesh/transport.py` — `Transport` abstracto y `MockTransport`
- `EVALUACION-MIGRACION.md` — informe, 939 líneas, 14 secciones
- `capturas/recibido.bin` — paquetes reales del móvil (**no** versionado)

---

## 5. Por donde seguir

### Primero: el handshake Noise (0x10)

**Es lo unico que queda para cerrar el enlace.** El decodificador del announce
ya esta arreglado (`63154e3`), asi que la pregunta de si hace falta el servidor
GATT esta contestada por el §1: la app nos descubrio, conecto y respondio a
nuestro announce sobre la conexion que **nosotros** abrimos. El lado central
basta.

Y ahora hay algo que antes no habia: **la clave Noise de la app es publica y la
tenemos**, esta en el TLV `0x02` de su announce:

```
973585b6502836ff5767934bdb4c62458c48b87e94c02d470797e93d21052f6b
```

Lo que ya esta hecho y verificado:

- La parte criptografica: Noise XX con `noiseprotocol`, 39 vectores de Cacophony
  verificados.
- La preimagen de firma: `to_binary_data_for_signing()` en `packet.py`.
- La identidad y el `peer_id` derivado, con el announce real de 80 B.

Lo que falta: **el transporte que mueva `msg1`** y lo envíe como
`NOISE_HANDSHAKE`. Ningun `0x10` ha llegado de la app, asi que hay dos
posibilidades que no se pueden distinguir sin probar: que nosotros no lo
mandemos, o que la app no lo mande porque no nos ha emparejado todavia.

**Detalle que ya se sabe:** el TTL se fija a 0 al firmar, porque baja en cada
salto y si entrara en la preimagen cualquier paquete reenviado una sola vez
llegaria con firma invalida.

**Orden de trabajo, con tests antes que hardware** (§6, punto 12):

1. Escribir `msg1` de Noise XX con la clave de la identidad propia.
2. Test con vector conocido: comprobar byte a byte contra Cacophony.
3. Enviarlo como `NOISE_HANDSHAKE` en un `smoke_ble` y ver si la app contesta
   con `NOISE_ENCRYPTED`.

### Despues: los problemas abiertos

1. **Los 64 bytes que `packet.py` llama firma** (§3.2bis). Es lo mas util: se
   sabe donde esta y cuanto mide, pero no valida como Ed25519, cambia en cada
   announce con el payload identico, y la app no activa `HAS_SIGNATURE`.
2. **Los 72 bytes de `0xff`** (§3.3). Candidatos: `Special recipient IDs` en
   `BinaryProtocol.kt:32`, o relleno deliberado.
3. **El `MESSAGE` de 4 bytes** que rechazamos. ¿Se sale la app de spec o nuestro
   `MIN_PAYLOAD_SIZE = 13` es demasiado estricto?
4. **`REQUEST_SYNC` con `m = 384`** (§3.2ter). No se sabe que lo fija.

### El servidor GATT: **no** es lo siguiente

Se dejaria como paso siguiente porque es lo que falta por la lista de
piezas, pero **hace falta para el primer hito ya se ha comprobado que no**: la
app nos escribio por la conexion que nosotros abrimos.

Si algun dia hace falta (por ejemplo, si la app deixa de poder escribirnos), no
hay atajo: bleak 3.0.2 no puede ser peripheral en Linux, asi que habria que
implementarlo a mano con `org.bluez.GattManager1`, `GattService1` y
`GattCharacteristic1`, igual que el anuncio. Tests de formato primero: rutas de
objeto, firmas D-Bus, nombres de interfaz.

---

## 6. Decisiones que **no** conviene re-litigar

1. **No portar `bitchat-tui`.** Habla un dialecto retirado.
2. **Motor de handshake = `noiseprotocol`**, no hecho a mano. BitChat usa Noise
   **rev 32/33** (`MixKey` sin `MixHash(temp)`), no rev 34.
3. **Dos enums, no uno.** Los dialectos se diferencian por **renumeración**:
   `0x11` es `NOISE_HANDSHAKE_RESP` en el viejo y `NOISE_ENCRYPTED` en el
   actual. Mezclarlos no da error, da basura silenciosa. `decode_payload` exige
   `dialect=` para los 6 valores ambiguos.
4. **Un payload desconocido se conserva opaco y byte-exacto.** Nunca se adivina.
   Es el error exacto que tumbó al cliente Rust.
5. **El registro de huecos se indexa por `(dialecto, valor)`.** `PROTOCOL_ACK`
   (legacy) y `FILE_TRANSFER` (actual) son ambos `0x22`.
6. **El prefijo de transporte es big-endian; el nonce del AEAD,
   little-endian.** Son opuestos.
7. **El prologue de producción va vacío** (`NoiseSession.kt:244` no llama a
   `setPrologue`). Ojo: `HandshakeState.java:512-516` siempre hace `mixHash`
   aunque sea vacío — es un no-op que **cambia `h`**, así que no se puede
   "optimizar".
8. **La cabecera es de 14 bytes** en v1 y **16** en v2. El README de Android
   dice 13 porque copió la constante equivocada de `FragmentManager.kt:98`
   (`headerSize = 13`), que es un off-by-one propagado.
9. **DEFLATE crudo** (`wbits=-15`). Con el valor por defecto de `zlib` se
   meterían 2 bytes de cabecera que el receptor no puede descomprimir.
10. **Nunca re-comprimir un payload ajeno.** Ver §2.4.
11. **`-match` en PowerShell NO distingue mayúsculas.** Se Creía tener "286
    tests en verde" con cuatro testsyendo rojos, porque `$txt -match '^OK$'` casaba
    con las líneas en minúscula `... ok` que imprime cada test que pasa. Por
    eso existe `tools/run_tests.py`, que **usa el código de salida del proceso**.
    Ver §5 para el comando.
12. **Los fallos que sólo aparecen en hardware son por suposición, no por
    lógica.** En el módulo de anuncio hubo tres: dict recorrido como lista de
    pares, nombre de bus usado como ruta de objeto, y firma de método deducida
    de una anotación que no la lleva. **La API hay que leerla antes de
    escribirla**, como se hizo con el Kotlin de la app, donde no ha habido ni un
    fallo de ese tipo en 450 tests.
13. **Medir antes de concluir, y mirar el código antes de concluir otra vez.**
    El relleno se afirmó bien, se negó mal y se volvió a afirmar bien en la misma
    jornada (§3.2). Los dos errores fueron aritmética: contar desde los 102 B
    sin la firma de 64, y **no mirar `packet.py`**, que ya tenía
    `SIGNATURE_SIZE = 64` y leía la firma en el offset correcto. Ese fichero
    estaba a un `grep` de distancia.
14. **Un test que afirma lo que no se sabe es peor que no tener test.**
    `test_el_byte_de_relleno_es_la_longitud_del_relleno` protegía el error: si
    alguien "arreglaba" el código para que cuadrase un PKCS#7 falso, el test
    pasaba. Los tests se revisan cuando cambia el understanding, no sólo cuando
    cambia el código.
15. **Guardar los bytes reales en cuanto llegan.** `smoke_ble.py` ahora escribe
    `capturas/recibido.bin` siempre, incluso vacío. Recapturar desde el host
    Linux cuesta un viaje; trabajar sobre los ficheros, no.
16. **Los datos del entorno van en el mensaje de error.** El `UnicodeDecodeError`
    en la posición 14 del announce no apuntaba a un problema de codificación:
    la posición 14 era exactamente donde empezaba la clave binaria. Los bytes
    dicen cuál es el fallo.
17. **Un test saltado no es un test verde.** `test_bleak_transport.py` tiene su
    clase entera bajo `@skipUnless(TIENE_BLEAK)`, y `bleak` no está en la VM de
    Windows: **6 tests no se ejecutaban nunca aquí** y se contaban como
    buenos. Cuando por fin corrieron en el host, uno falló a la primera. El
    runner ahora enumera **qué** se salta y por qué, y `skipped=0` en el host
    es la señal de que todo está comprobado de verdad.
18. **La suite completa se ejecuta donde están las dependencias.** La VM sirve
    para escribir; el host, para verificar. Un fallo de API puede llevar días
    escondido tras un `skipUnless` sin que nadie lo note.

---

## 7. Notas de estilo

- La documentación es en español y explica **por qué**, no sólo qué.
- Cuando un layout está confirmado por una sola cara del código se dice
  explícitamente que es una hipótesis.
- Cada constante de Android lleva `file:line` de procedencia.
- Los tests llevan nombre descriptivo en español y, cuando cubren un caso
  raro, el motivo por el que ese caso importa.
- Un descarte o un rechazo **lleva el motivo registrado**, no falla en silencio.