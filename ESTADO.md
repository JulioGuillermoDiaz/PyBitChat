# Estado del proyecto — punto de reanudación

**Fecha de corte:** 2026-10-05
**Objetivo:** cliente BitChat en Python para **Android + Linux** (iOS fuera de
alcance). Es una **reimplementación**, no un port de `bitchat-tui`.

**En una línea:** el enlace BLE funciona en las dos direcciones, la identidad se
intercambia y se decodifica, y **el handshake Noise XX completo se ha cerrado**
contra la app Android real.

> ⚠️ **Antes de nada:** no se porta `bitchat-tui`. Habla un dialecto retirado, así
> que portarlo daría un cliente incapaz de hablar con ninguna app actual. Ver
> `EVALUACION-MIGRACION.md` §1 y §11.

---

## 1. Dónde estamos

Todo verificado con **tráfico real de la app Android**, no con capturas del Rust ni
con lectura del código.

| | Estado |
|---|---|
| Codec de payloads, v1 y v2 | ✅ |
| Noise XX (Cacophony/Noise-C) | ✅ 39 vectores |
| Conformidad con los tests de la app | ✅ 48 casos portados |
| **Descubrimiento del teléfono** | ✅ **9 direcciones distintas** |
| **Conexión GATT sin emparejar** | ✅ |
| **MTU 517** | ✅ coincide con Android 14+ |
| **Anuncio como peripheral** | ✅ BlueZ lo acepta, `ce990ff` |
| **Envío de identidad válida** | ✅ **la app responde con la suya** |
| **Decodificación del announce** | ✅ TLV de identidad, `63154e3` |
| `peer_id` derivado de la clave | ✅ contra tráfico real |
| Relleno PKCS#7 a 256 B | ✅ en 4 capturas |
| Firma Ed25519 de la app | ✅ preimagen deducida, valida |
| **`msg1` Noise XX aceptado por la app** | ✅ **32 B, 6 de 9 sesiones** |
| **`msg2` descifrado y verificado** | ✅ **Poly1305 válido, `s` = la del announce** |
| **`msg3` construido y enviado** | ✅ **64 B, `split()` correcto**, 2 veces |
| `NOISE_ENCRYPTED` (`0x11`) | ❌ nunca enviado ni recibido |
| Servidor GATT (la app conecta a nosotros) | ❌ no implementado |

### El hito del 2026-10-05

El **handshake XX completo**, con los tres mensajes y los tamaños correctos:

    msg1  32 B  enviado. La app lo acepta y contesta
    msg2  96 B  recibido. Poly1305 válido, `s` descifrada, coincide con el announce
    msg3  64 B  construido y enviado. split() correcto: sesión establecida

La prueba que lo sostiene es una sola línea del terminal:

    remote_static_public: 973585b6...0eb1cf     <- descifrado del msg2
    TLV 0x02 del announce  973585b6...0eb1cf     <- el que la app anunció
    -> IGUAL
    peer_id derivado:      34e01ccea10a8c6d     <- el que esperábamos
    peer_id de la app:      34e01ccea10a8c6d
    -> IGUAL

Si el `ck` derivado de nuestro `msg1` no fuera el de la app, el Poly1305 no habría
validado. Y la clave descifrada deriva al `peer_id` de la app sin que nadie lo haya
puesto ahí.

### Lo que eso **no** demuestra

Que **nuestro** `split()` haya funcionado. Eso solo lo dice de nuestro lado: si
nuestro `ck` estuviera mal, `split()` funcionaría igual y las claves de
transporte serían distintas de las de la app.

Desde fuera, un handshake establecido a un lado y no al otro **no se distinguen**:
en Noise XX el tercer mensaje no tiene respuesta. Por eso no llegó ningún
`NOISE_ENCRYPTED`: la app seguía mandando `ANNOUNCE` y `REQUEST_SYNC` en claro,
que es lo normal cuando no tiene nada cifrado que decir. **Su silencio no es un
fallo, y no es prueba de nada.**

La prueba de que los dos lados están establecidos es **enviar un `0x11` propio
y ver si la app lo descifra**. Ver §5.

### El intercambio de identidad, desde el 2026-10-03

```
enviando ANNOUNCE de 'pybitchat-probe'   111 B   -> enviado
--- paquete recibido: 256 B (nº 1) ---  ANNOUNCE      payload 80, firma 64
--- paquete recibido: 256 B (nº 2) ---  ANNOUNCE      payload 80, firma 64
--- paquete recibido: 256 B (nº 3) ---  REQUEST_SYNC  carga OK
```

```
nickname          = 'anewells74'
noise_public      = 973585b6502836ff…
signing_public    = 7ada9dab1bec9eb2…
peer_id derivado  = 34e01ccea10a8c6d  == sender_id del paquete
```

Lo del `peer_id` es la prueba buena: sale de `sha256(clave Noise)[:8]` y coincide
con el `sender_id` **sin que nadie lo haya puesto ahí**.

### Lo que se midió contra el teléfono

- Servicio `F47B5E2D-…` y characteristic `A1B2C3D4-…`, sin emparejar.
- **MTU 517** tras `_acquire_mtu()`. El valor por defecto de BlueZ es **23**, y
  sin pedirlo el envío grande falla en silencio.
- **Las MAC rotan**: nueve direcciones distintas en nueve escaneos. Es una
  dirección privada resoluble de Android. Por eso `bleak_transport` resuelve por
  UUID en cada conexión y no cachea nada.
- El móvil anuncia BitChat con **2-3 MACs a la vez**, todas con el UUID de
  servicio. Se elige la de mayor RSSI **medido**; `-127` es el valor por defecto de
  bleak cuando BlueZ no mide (`scanner.py:209`), no una señal mala.
- **La respuesta al handshake es intermitente con la identidad guardada**: 3 de 5
  sesiones. Con identidad **nueva**, 3 de 3 a la primera. Lo más probable es que la
  app conserve una sesión para ese `peer_id` en un estado del que no sale;
  **no verificado**, y el mejor patrón que hay. Ver §3.1.

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

## 3. Problemas

Ocho problemas. **Cinco resueltos**, y el `0x11` es el trabajo que toca.

### 3.1 ~~El handshake se ignoraba~~ → qué la identidad persistida

**Síntoma:** el `msg2` llegaba unas veces y otras no, sin patrón en el orden de
los paquetes ni en el announce previo.

**Hipótesis, no verificada:** `Identity.cargar_o_crear` recupera el fichero si
existe, y el `peer_id` se deriva de la clave. Con la identidad guardada, para la app
siempre es el mismo par. Si guarda una `NoiseSession` para ese `peer_id` y queda en
un estado del que no sale, el handshake se ignoraría.

**El recuento que la apoya:**

| Identidad | Sesiones | `msg2` |
|---|---|---|
| guardada, `4baf99fa0b9298ba` | 5 | **3 sí, 2 no** |
| nueva cada vez | 3 | **3 sí, 0 no** |

Tres de tres a la primera con identidad nueva; dos de cinco con la guardada. Es el
mejor patrón que hay, y **no es una prueba**: `n=3` contra `n=5`, y no se ha
controlado nada más. Lo que sí hace es justificar la regla de abajo.

**Cómo se cierra:** más ejecuciones alternando identidad. Si con la guardada
vuelve a fallar y con la nueva vuelve a funcionar a la primera, es que la app
guarda estado del `peer_id` y la hipótesis es correcta.

**Operativamente:** para una ejecución de prueba, **identidad nueva**:

    ./.venv/bin/python tools/smoke_ble.py --msg3 \
        --identity /tmp/nueva.json \
        --peer-id 34e01ccea10a8c6d \
        --noise-public 973585b6…0eb1cf

Ojo: **`--nickname` no crea identidad nueva.** El fichero gana y el flag se ignora
en silencio, que es justo lo que invita a creer lo contrario. Para eso está
`--identity`.

### 3.2 ~~Los tres tamaños del handshake~~ → 32 / 96 / 64, derivados y medidos

**Estaba cerrado y nadie lo había derivado.** Se dieron tres cifras seguidas
para el `msg2` — 176, 96 y 128 — y **las tres estaban mal**. La cuenta:

    E(32) + EE(0) + S(32+16) + ES(0) + tag(16) = 96

`EE`, `ES` y `SE` son `mixDH`: derivan clave y **no emiten bytes**. Contarlos como 48
da 176, 144 o 128 según qué tokens se olviden, y ninguna es 96.

El tag sale porque `ChaChaPolyCipherState.getMACLength()` es `haskey ? 16 : 0`:
en `msg1` todavía no hay clave y no se emite; en `msg2` ya la hay, porque el primer
`mixKey` ocurre en `EE`.

**Además de deducido, medido:** un XX completo con los dos roles de nuestro
`HandshakeSession` da 32 / 96 / 64 exactos, con las mismas huellas de handshake.
`tests/test_tamanos_handshake.py` monta el handshake entero.

Los tres tamaños son derivación del código de la app **y** medición con
nuestro motor. Las dos cosas hacen falta: una suma correcta sobre bytes ajenos no
prueba que el cifrado sea el nuestro.

### 3.3 ~~El `msg2` no se podía leer~~ → solo en el proceso que lo mandó

`probe_msg2.py` contestaba siempre que no:

    leído sin error. carga útil: 64 B
    remote_static_public: None

Las dos líneas eran síntomas del mismo error: **nunca se escribió el `msg1`**.

`noiseprotocol` no lleva un contador de mensajes: lleva una lista de patrones, uno
por mensaje, y cada `read_message` hace `pop(0)` del primero
(`noise/state.py:362`). `PatternXX.tokens` es:

    [[e], [e, ee, s, es], [s, se]]

El `msg1` se lleva el primero. Sin `msg1` escrito, el `pop(0)` se come `[e]`, procesa
**un** token, y los 64 B de cola quedan de carga útil. Sin `mix_key` no hay clave,
así que ese tramo ni se intenta descifrar: sale tal cual. De ahí el "leído sin
error": **no lee nada, y por eso no puede fallar.**

**Y ni siquiera escribiendo un `msg1` nuevo serviría.** Descifrar el `msg2` real
exige la clave efímera **privada** del `msg1` que la app recibió de verdad, y esa
solo existía en el proceso que lo mandó. La captura no la tiene.

Por eso la lectura vive en `smoke_ble.py` (`_leer_msg2`), no en un script sobre el
fichero. Los cuatro desenlaces se distinguen por la salida:

| Salida | Qué ha pasado |
|---|---|
| `carga útil: 0 B` + `IGUAL` | la derivación coincide con la de la app |
| `carga útil: 0 B` + `DISTINTA` | el tag validó pero no es su identidad |
| `carga útil: 64 B` | el motor solo consumió `[e]`: bug de quien llama |
| `ERROR al leer` | el Poly1305 no validó: el `ck` no es el nuestro |

### 3.4 ~~El announce antes del handshake~~ → no, y tampoco al revés

Se probó y se deshizo. Mandar el announce antes **empeoró** las cosas:

| | Enviado | `msg2` |
|---|---|---|
| 04-oct | handshake **solo** | ✅ 96 B, dos veces |
| 05-oct, 1ª | announce **+** handshake | ❌ |
| 05-oct, 2ª | announce **+** handshake | ✅ 96 B |

La primera vez que falló, la conclusión "el announce empeora las cosas" era una
muestra de **una**. A la segunda volvió a llegar el `msg2` con el announce puesto.

Lo que **sí** es cierto, y se conserva: un announce **no** lleva `recipient_id` —
eso es lo que lo hace broadcast — y el handshake **sí** lo lleva, y por eso la app
lo acepta (`MessageHandler.kt:375-377`).

### 3.5 ~~El relleno~~ → PKCS#7, confirmado tras fallar dos veces

Tras dos intentos fallidos, confirmado en cuatro capturas reales. Los bytes de
relleno se ven en todos los paquetes de 256 B: `c2`, `5a`, `42`, `98`, `95`, `94` —
todos el byte de longitud repetido.

**Lo que costó encontrar:** que `should_pad_for_ble()` dice una cosa y el tráfico
capturado otra. Se dejó como está y se documentó la contradicción: seguir el
código es lo verificable, la captura es una muestra.

### 3.6 ~~La firma~~ → Ed25519, preimagen deducida

`BinaryProtocol.kt:116-131`. La preimagen es el paquete entero con **TTL=0,
flags=0x00, sin firma, y relleno PKCS#7 a 256 B**. El TTL se fija a 0 porque baja en
cada salto, y si entrara en la preimagen cualquier paquete reenviado una sola vez
dejaría de validar.

Los 64 B que parecía sobrantes en un announce son la firma, no relleno. La app firma
sus announces (`flags=0x02`); nuestros handshakes van sin firma porque así lo hace
ella (`MessageHandler.kt:392`).

### 3.7 ~~El `MESSAGE` de 72 B de `0xff`~~ → sin explicar, y no bloquea nada

Queda abierto y **no importa**. Es un `MESSAGE` de la app cuyo payload son 72 bytes
de `0xff`. No bloquea nada: el enlace funciona sin descifrarlo.

### 3.8 `REQUEST_SYNC`: `m` es un múltiplo de 128, pero **no crece**

**Corregido el 2026-10-05.** Se escribió que `m` "subía con cada intento", y la
sesión siguiente lo refutó: **`m` bajó de 896 a 256**.

| fecha | payload | `p` | `m` | `data` | ¿`msg2`? |
|---|---|---|---|---|---|
| 03-oct mañana | 16 B | 7 | 256 | 1 B | no |
| 03-oct mañana | 16 B | 7 | 256 | 3 B | no |
| 03-oct tarde | 18 B | 7 | 384 | 3 B | no |
| 04-oct s1 | 17 B | 7 | 256 | 3 B | **sí** |
| 04-oct s2 | 16 B | 7 | 256 | 3 B | **sí** |
| 05-oct 1ª | 18 B | 7 | 512 | 4 B | no |
| 05-oct 2ª | 18 B | 7 | 512 | 4 B | **sí** |
| 05-oct 3ª | 21 B | 7 | 768 | 8 B | no |
| 05-oct 4ª | 21 B | 7 | 768 | 8 B | **sí** |
| 05-oct 5ª | 22 B | 7 | **896** | 8 B | **sí** |
| 05-oct 6ª | **16 B** | 7 | **256** | **2 B** | **sí** |

Lo que sí se sostiene:

- `p` = 7 en las once, sin moverse.
- **Todos los `m` son múltiplos de 128**: 2x, 3x, 4x, 6x, 7x. Once puntos, y con
  384 y 896 ya no hay forma de que sea casualidad. Es un número de **bytes**,
  no de paquetes — por eso no es múltiplo de 256.
- **`m` no es monotónico**: subió hasta 896 y volvió a 256. Y `data` bajó de
  8 a 2 B. Así que **no** es un contador acumulado. Lo que lo fija sigue sin
  mirar, y no se sabe qué reinicia.

El formato sí está claro: TLV con tipo de 1 B y longitud de 2 B en big-endian.
`p` es el TLV `0x01`, `m` el `0x02`, y `data` el `0x03`. Comprobado con el payload
de la 6ª sesión, `01 0001 07 020004 00000100 030002 7a1c`: `p`=7, `m`=256, y
`data` de 2 B.

Lo que produce `m` y `data` está sin mirar, y es lo primero que habría que buscar
en `MessageHandler.kt` antes de culpar al BLE.

---

### 3.9 El characteristic no aparece, y el MTU se queda en 23

**Abierto el 2026-10-05. Del entorno, no del código.** Dos sesiones seguidas, con
el móvil reiniciado y en primer plano:

| | Antes (4 sesiones, todas bien) | Ahora (2 sesiones) |
|---|---|---|
| candidatos con el UUID de BitChat | 2-3 | **1** |
| MTU | **517** | **23** |
| characteristic servido | sí | **no** |
| `_acquire_mtu` | bien | `coroutine raised StopIteration` |
| handshake | msg2 + msg3 | ni llega a enviarse |

**El aviso de MTU y el characteristic ausente son casi siempre la misma cosa.** Un
envío que no cabe **no da error**: no llega y no se sabe por qué. Por eso el
script avisa de los dos por separado.

Lo que **no** se sabe: por qué la app anuncia pero no sirve GATT, y por qué la
negociación de MTU falla. Con un solo candidato y MTU 23 la hipótesis más
barata es que el móvil está en un estado en el que publica el anuncio y no levanta
el GATT. Reiniciar BitChat **no** lo ha arreglado; lo siguiente a probar es apagar
y encender el Bluetooth, o el airplane mode.

### 3.10 Un doble de test que valida el error

`BleakGATTServiceCollection` **no tiene `__len__`**, y `_sin_characteristic` hacía
`len(cliente.services)`. Con un cliente real lanzaba `TypeError`. El test pasaba,
porque el doble **sí** tenía `__len__`: estaba modelado sobre lo que yo creía
que era la API, no sobre lo que es.

Un doble que se aparta de la API real valida el error en lugar de detectarlo. El
doble ahora **no** lleva `__len__` a propósito, y hay un test que comprueba que
sigue sin tenerlo, para que nadie lo añada por comodidad.

Las tres llamadas del código van con `list()` y recorren `characteristics`, que es
donde se busca el UUID.

---

## 4. Cómo arrancar

### En el host Linux (donde está el Bluetooth)

```bash
cd ~/PyBitChat && git pull
./.venv/bin/python tools/run_tests.py ; echo "exit=$?"
```

**Mira el `exit=`, no el texto.** Ver §6, punto 11.

> **Sólo en el host Linux salen los 616 tests sin `skipped=`.** En la VM de
> Windows faltan `bleak` y `dbus_fast`, así que **14 tests se saltan y no
> comprueban nada**. Contarlos como verdes era un error real, y por eso el
> runner ahora imprime **qué** se salta y por qué.
>
> Un `skipped=14` en la VM no es un problema. Un test roto esperándose en el
> host, sí. Ejecutar la suite completa **allí** antes de dar por buena una
> jornada.
>
> El motor de Noise (`noise.noise_protocol`) **sí** importa en la VM, así que
> los tests de handshake se ejecutan en los dos sitios. La distribución en PyPI
> se llama `noiseprotocol`; el módulo, `noise`. Ver §6, punto 21.

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
| `--handshake` | mandar el `msg1` en vez de un announce |
| `--msg3` | mandar el `msg3` **solo si** la lectura del `msg2` dio `IGUAL` |
| `--peer-id HEX` | `recipient_id`. Sin el, la app lo descarta |
| `--noise-public HEX` | clave Noise de la app, para comparar |
| `--identity RUTA` | identidad nueva. Prueba la intermitencia |
| `--scan 30` | el escaneo corto causa fáciles falsos negativos |
| `--segundos N` | cuanto esperar. 20 s, y 20 más tras el `msg3` |
| `--guardar RUTA` | dónde escribir. Por defecto `capturas/recibido.bin` |
| `--paquete RUTA` | reenviar bytes capturados tal cual |

Y dos avisos que el script emite solo:

- si `--nickname` se ha ignorado por existir el fichero de identidad
- si `peek` no encuentra el characteristic de BitChat

### Reparto de tests

**616 tests.** En el host Linux salen los 616 sin `skipped=`; en la VM de Windows se
saltan 14, que son los que necesitan `bleak`, `dbus_fast` o el motor de Noise.

| Fichero | Tests | Cubre |
|---|---|---|
| `test_transport.py` | 78 | Compresión, reensamblado, GATT, transporte |
| `test_identity.py` | 64 | TLV de identidad, `peer_id`, firma, relleno |
| `test_current_payloads.py` | 52 | `ANNOUNCE` TLV, `MESSAGE`, fichero, voz |
| `test_conformance.py` | 48 | Conformidad con los tests de la app |
| `test_noise_handshake.py` | 44 | `msg1`, empaquetado, destino obligatorio |
| `test_probe_msg2.py` | 42 | Desglose, salto de relleno, estado del motor |
| `test_noise_vectors.py` | 39 | Handshake XX, framing, anti-replay |
| `test_smoke_ble.py` | 28 | Announce, hexdump, elección de peer, RSSI |
| `test_advertiser.py` | 27 | Anuncio: `Variant`, firmas, rutas D-Bus |
| `test_payloads.py` | 25 | Fragmentación, opacidad |
| `test_probe_advertise.py` | 22 | Informe de escaneo, tiempos, limitaciones |
| `test_tamanos_handshake.py` | 21 | 32/96/64, deducidos **y** medidos |
| `test_dialect.py` | 21 | Constantes Android con `file:line` |
| `test_msg3.py` | 20 | Las dos guardas del `msg3`, sin BLE |
| `test_golden_packets.py` | 19 | Los paquetes reales, byte a byte |
| `test_dispatch.py` | 19 | Despacho por dialecto y ambigùedad |
| `test_leer_msg2.py` | 18 | Los cuatro desenlaces de `_leer_msg2` |
| `test_bleak_transport.py` | 12 | Transporte real; se salta sin `bleak` |
| `test_msg2_en_proceso.py` | 9 | La firma del error de `pop(0)` |
| `test_run_tests.py` | 8 | El runner: informe de saltados, código de salida |
| **Total** | **616** | 14 saltados en Windows, 0 en Linux |

### Ficheros del proyecto

**`src/pybitchat/protocol/`** — el formato de paquete

| Módulo | Qué hace |
|---|---|
| `types.py` | enums, constantes Android con `file:line`, política de relleno |
| `packet.py` | cabecera v1/v2, compresión, `WirePayload`, firma, relleno |
| `identity.py` | identidad persistente, TLV de identidad, `peer_id`, firma |
| `payloads.py` | despacho por dialecto; opaco lo que no se conoce |
| `tlv.py` | TLV genérico, longitud de 1 B |
| `compression.py` | DEFLATE crudo, `wbits=-15` |
| `reassembly.py`, `payloads` | fragmentación y reensamblado |
| `message.py`, `voice.py` | `MESSAGE` y tramas de voz |

**`src/pybitchat/noise/`** — el handshake

| Módulo | Qué hace |
|---|---|
| `session.py` | `HandshakeSession` sobre `noiseprotocol`; 39 vectores |
| `handshake.py` | `msg1`, tamaños derivados, empaquetado del `NOISE_HANDSHAKE` |
| `framing.py` | transporte: nonce de 4 B big-endian + ChaChaPoly, anti-replay |
| `primitives.py` | X25519, ChaChaPoly, HKDF |
| `state_errors.py` | errores propios, para no filtrar la librería de abajo |

**`src/pybitchat/ble/`** — el enlace

| Módulo | Qué hace |
|---|---|
| `gatt.py` | UUIDs del servicio y del characteristic |
| `bleak_transport.py` | conexión, MTU, escritura |
| `advertiser.py` | anuncio como peripheral sobre `LEAdvertisingManager1` |

**`tools/`**

| Guion | Para qué |
|---|---|
| `run_tests.py` | la suite entera, por **código de salida**, e informa de saltados |
| `smoke_ble.py` | conecta, manda `msg1`, lee el `msg2`, envía el `msg3` |
| `probe_advertise.py` | anuncia y escanea, para ver si nos encuentran |
| `probe_msg2.py` | desglose de los 96 B del `msg2` desde un fichero |
| `extract_vectors.py` | regenera `tests/fixtures/vectors.json` |

**Otros**: `src/pybitchat/mesh/transport.py` (interfaz y `MockTransport`),
`EVALUACION-MIGRACION.md` (informe de 14 secciones), `capturas/recibido.bin`
(paquetes reales del móvil, **no** versionado).

---

## 5. Por dónde seguir

### Lo siguiente: `NOISE_ENCRYPTED` (`0x11`)

**Es el paso que falta para poder hablar con la app a través de ella.** El
handshake está cerrado de nuestro lado; lo que no está probado es que el de la app
lo esté también.

La prueba es una sola: **mandar un `0x11` y ver si la app lo descifra.** Si lo
descifra, los dos lados estaban establecidos y las claves coinciden.

El soporte ya existe:

- `NoiseTransportCipher.encrypt()` antepone el nonce de 4 B en **big-endian**, que
  es lo que espera `NoiseSession.kt:133-143`. El nonce AEAD de 12 B va en
  little-endian (`ChaChaCore.java:144-150`). Ver `noise/framing.py`, que lo
  documenta con `file:line`.
- Habría que elegir el payload: el mismo `IdentityAnnouncement` en claro dentro
  del `0x11`, o uno nuevo de presentación. **Es una decisión, no un detalle.**

Lo que **no** se haría sin decidir: mandar mensajes de verdad, ficheros o voz.
Todo eso va dentro del `0x11`, así que el formato del payload se decide una vez y
se reutiliza.

### Lo que quedó abierto, en orden de irrelevancia

1. **La intermitencia del `msg2`** (§3.1). Alternar identidades en ejecuciones
   seguidas. Barato, y si es la identidad persistida, afecta a cualquier
   automatización posterior.
2. **El servidor GATT.** No implementado. La app nos descubre, conecta y responde
   sobre la conexión que **nosotros** abrimos, así que el lado central basta para
   este alcance. Si algún día hace falta para que la app nos encuentre sin que
   nosotros iniciemos, ahí sí.
3. **Qué produce `m` y `data` en `REQUEST_SYNC`** (§3.8). No bloquea nada.
4. **El `MESSAGE` de 72 B de `0xff`** (§3.7). No bloquea nada.
5. **`REQUEST_SYNC` sin entender.** La app lo manda pidiendo cosas; no sabemos qué
   quiere ni si hay que contestar. Al día de la sesión completa puede empezar a
   importar.

### Lo que **no** se debe rehacer

- El `msg1` de 32 B. Correcto, y verificado por el Poly1305 del `msg2`.
- El `msg2` de 96 B. Correcto, y verificado descifrándolo.
- El `msg3` de 64 B. Correcto, y `split()` funciona.
- `should_pad_for_ble()`. Se dejó como está a pesar de la contradicción con el
  tráfico capturado: seguir el código es lo verificable. Ver §3.5.

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

19. **Una cuenta que cuadra no es un hallazgo.** Se dio `msg2` = 176, luego 96,
    luego 128, y **las tres estaban mal**: `EE`, `ES` y `SE` son `mixDH` y no
    emiten bytes. El 96 era el correcto desde el principio y nadie lo derivo
    del codigo que lo produce. **Derivar el tamano del codigo**, no de la
    captura ni de un comentario, que tambien miente.
    `tests/test_tamanos_handshake.py` existe para que las tres cuentas
    erroneas no puedan volver a aparecer.

20. **Un nombre de distribución no es un nombre de módulo.** La
    distribución en PyPI es `noiseprotocol`; el módulo que instala es `noise`, y
    lo que se importa es `noise.noise_protocol`. Preguntar por
    `find_spec("noiseprotocol")` devuelve `None` **siempre**, con la
    distribución instalada. Costó una ida y vuelta al host, y `pip` decía
    "already satisfied" mientras el script decía que no estaba: los dos
    tenían razón.
21. **Un informe que no puede fallar no es un informe.** Decir "leído sin error"
    cuando lo que pasó fue que **no se intentó descifrar** es peor que
    callarse: un Poly1305 que nunca se comprueba no puede fallar, y eso se lee
    como una prueba. Cuando una comprobación se hace con la sesión en mal
    estado, el fallo tiene que ser **visible en la salida**, no en una ausencia
    de error.
22. **Antes de descartar algo por "no se puede", comprobar si es verdad.** La
    afirmación "el `msg2` no entrega clave estática" se escribió sin el motor
    instalado, así que `read_message` **nunca se ejecutó**. Era una afirmación
    sobre algo no medido, y mantuvo el problema "abierto" días. Lo que sí era
    verdad: `read_handshake` necesita el `msg1` de la misma sesión, y eso solo
    ocurre en el proceso que lo mandó.
23. **Un flag que no hace lo que su nombre indica es una trampa.** `--nickname`
    no crea una identidad nueva: si el fichero existe, gana y el flag se ignora
    **en silencio**. Un flag cuyo nombre sugiere un cambio y no lo hace es peor
    que no tenerlo. Ahora avisa.
24. **La respuesta no esperada no es un fallo.** No llegó ningún
    `NOISE_ENCRYPTED` tras el handshake, y la explicación fácil —"algo
    falló" — era falsa: en Noise XX el tercer mensaje no tiene respuesta, y la
    app solo manda cifrado cuando tiene algo cifrado que decir. **Anotarlo como
    problema sería inventarse un problema.**
25. **Derivar y medir son cosas distintas.** La cuenta 32/96/64 sale del
    código de la app; medirla con nuestro motor demuestra que el **nuestro**
    coincide con el suyo. Lo primero no basta: una suma correcta sobre bytes
    ajenos no prueba que el cifrado sea el nuestro. `TestTamanosMedidos` monta
    el handshake entero por eso.

## 7. Notas de estilo

- La documentación es en español y explica **por qué**, no sólo qué.
- Cuando un layout está confirmado por una sola cara del código se dice
  explícitamente que es una hipótesis.
- Cada constante de Android lleva `file:line` de procedencia.
- Los tests llevan nombre descriptivo en español y, cuando cubren un caso
  raro, el motivo por el que ese caso importa.
- Un descarte o un rechazo **lleva el motivo registrado**, no falla en silencio.
- Una afirmación sobre algo **no medido** se marca como tal, o no se escribe. Ese
  es el origen de la lección 22.
- Nada de cálculos sobre bytes transcritos a mano desde el terminal. Si hay que
  mirar bytes, se leen del fichero. Una transcripción con un solo carácter mal da
  un número plausible y falso.
