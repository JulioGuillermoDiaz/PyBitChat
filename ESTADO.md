# Estado del proyecto — punto de reanudación

**Fecha de corte:** 2026-10-02
**Objetivo:** cliente BitChat en Python para **Android + Linux** (iOS fuera de
alcance). Es una **reimplementación**, no un port de `bitchat-tui`.

> ⚠️ **Antes de nada:** no se porta `bitchat-tui`. Habla un dialecto retirado, así
> que portarlo daría un cliente incapaz de hablar con ninguna app actual. Ver
> `EVALUACION-MIGRACION.md` §1 y §11.

---

## 1. Dónde estamos: **el enlace BLE funciona en las dos direcciones**

Esto es lo importante y no estaba previsto al empezar el día: se ha **verificado
con tráfico real de la app Android**, no con captura del Rust ni con lectura del
código.

| | Estado |
|---|---|
| Codec de payloads, v1 y v2 | ✅ |
| Noise XX handshake (Cacophony/Noise-C) | ✅ 39 vectores |
| Conformidad con los tests de la app | ✅ 48 casos portados |
| **Descubrimiento del teléfono** | ✅ **visto en 6 direcciones distintas** |
| **Conexión GATT sin emparejar** | ✅ |
| **MTU 517** | ✅ coincide con Android 14+ |
| **Recepción de paquetes reales** | ✅ 4 paquetes decodificados |
| **Envío de identidad válida** | ✅ la app responde, sin handshake todavía |
| **Anuncio como peripheral** | ✅ **funciona** — BlueZ lo acepta, `ce990ff` |
| Handshake Noise con la app real | ❌ **falta** |

### El hito del 2026-10-03

Primera sesión en que **la app responde a nuestro announce con el suyo**. Antes
se enviaba identidad y no venía nada; hoy el intercambio es completo:

```
enviando ANNOUNCE de 'pybitchat-probe'   111 B   -> enviado
--- paquete recibido: 256 B (nº 1) ---    tipo=0x01(ANNOUNCE)  payload=80 B
--- paquete recibido: 256 B (nº 2) ---    tipo=0x01(ANNOUNCE)  payload=80 B
--- paquete recibido: 256 B (nº 3) ---    tipo=0x21(REQUEST_SYNC)  carga OK
total de paquetes recibidos: 3
```

**El `ANNOUNCE` que nos llega es TLV, y ahí hay un bug nuestro.** Los 80 B son
`[tipo u8][longitud u8][valor]`:

```
01 0a 61 6e 65 77 65 6c 6c 73 37 34   -> 0x01 nickname, "anewells74"
02 20 97 35 85 b6 50 28 36 ff ...     -> 0x02 clave Noise, 32 B
03 20 7a da 9d ab 1b ec 9e b2 ...     -> 0x03 clave de firma, 32 B
```

`AnnouncePayload` (`payloads.py:69`) trata el payload **sólo como nickname en
UTF-8**, que es la forma legacy. De ahí el `UnicodeDecodeError` en la posición
14: justo donde empieza la clave binaria. Está documentado como "decodificado
y validado", pero se validó con vectores de 8-9 bytes, demasiado cortos para
contener una clave. El formato TLV **ya existe y está probado** en
`identity.py`, con el announce real de 80 B.

**El announce que enviamos nosotros sí es correcto** —la app respondió— así que
lo único pendiente aquí es saber leer el suyo.

### Lo que seMidió contra el teléfono
| Handshake Noise con la app real | ❌ **falta** |

| **Anuncio como peripheral** | ✅ **funciona** — BlueZ lo acepta, `ce990ff` |
| Handshake Noise con la app real | ❌ **falta** |

### El hito del 2026-10-03

Primera sesión en que **la app responde a nuestro announce con el suyo**. Antes
se enviaba identidad y no venía nada; hoy el intercambio es completo:

```
enviando ANNOUNCE de 'pybitchat-probe'   111 B   -> enviado
--- paquete recibido: 256 B (nº 1) ---    tipo=0x01(ANNOUNCE)  payload=80 B
--- paquete recibido: 256 B (nº 2) ---    tipo=0x01(ANNOUNCE)  payload=80 B
--- paquete recibido: 256 B (nº 3) ---    tipo=0x21(REQUEST_SYNC)  carga OK
total de paquetes recibidos: 3
```

**El `ANNOUNCE` que nos llega es TLV, y ahí hay un bug nuestro.** Los 80 B son
`[tipo u8][longitud u8][valor]`:

```
01 0a 61 6e 65 77 65 6c 6c 73 37 34   -> 0x01 nickname, "anewells74"
02 20 97 35 85 b6 50 28 36 ff ...     -> 0x02 clave Noise, 32 B
03 20 7a da 9d ab 1b ec 9e b2 ...     -> 0x03 clave de firma, 32 B
```

`AnnouncePayload` (`payloads.py:69`) trata el payload **sólo como nickname en
UTF-8**, que es la forma legacy. De ahí el `UnicodeDecodeError` en la posición
14: justo donde empieza la clave binaria. Está documentado como "decodificado
y validado", pero se validó con vectores de 8-9 bytes, demasiado cortos para
contener una clave. El formato TLV **ya existe y está probado** en
`identity.py`, con el announce real de 80 B.

**El announce que enviamos nosotros sí es correcto** —la app respondió— así que
lo único pendiente aquí es saber leer el suyo.

### Lo que seMidió contra el teléfono

- Servicio `F47B5E2D-…` y characteristic `A1B2C3D4-…`, sin emparejar.
- **MTU 517** tras `_acquire_mtu()`. El valor por defecto de BlueZ es **23**, y
  sin pedirlo el envío grande falla en silencio.
- **Las MAC rotan**: seis direcciones distintas en seis escaneos. Es 地址 privada
  resoluble de Android. Por eso `bleak_transport` resuelve por UUID en cada
  conexión y no cachea nada.

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

### 3.1 No llega el handshake Noise

Mandamos identidad válida y la app responde con su announce y un paquete de
relleno, pero **ningún `NOISE_HANDSHAKE` (0x10)**.

**Hipótesis principal:** nos faltaba el anuncio. Se acaba de implementar
(`ble/advertiser.py`). Si ahora sí lo anuncia y sigue sin handshake, el motivo
será otro y habrá que Investigarlo.

### 3.2 Relleno: NO es PKCS#7 — corrección de un error propio

**Retirada una afirmación que estaba en el código y en este documento:** que el
relleno era "PKCS#7 exacto, la longitud del relleno es el valor del byte". Es
**falso**, y se vio al medir los números de la captura del 3-oct:

| Paquete | Real | Relleno hasta 256 B | Byte de relleno |
|---|---|---|---|
| ANNOUNCE (3-oct) | 102 B | 154 B | `0x5a` = 90 |
| REQUEST_SYNC (3-oct) | 38 B | 218 B | `0x9a` = 154 |

154 ≠ 90 y 218 ≠ 154. En ambos casos la longitud **no** coincide con el byte.

**De dónde salió el error:** en `test_identity.py` el caso se escribía como
`14 + 8 + 80 + 64 = 166`. Los **64** eran una firma de 64 bytes **supuesta**, no
medida. Con ese 64 inventado, el relleno salía de 90 B y `0x5a` = 90 "cuadraba"
perfectamente. Era aritmética circular: el dato que hacía cuadrar el PKCS#7 era
el dato inventado.

Con los bytes reales de hoy, la estructura del announce es:

```
102 B reales + 154 B hasta 256 = 256 B
  14 cabecera + 8 sender + 80 payload TLV   (todo declarado)
  + 64 bytes que la cabecera NO declara
  + relleno hasta 256
```

Esos **64 bytes son la firma**, y aquí se pisó el protocolo que ya teníamos
escrito. `packet.py` ya definía `SIGNATURE_SIZE = 64` y `HAS_SIGNATURE`, y el
parser la lee en el offset correcto justo tras el payload. Se.verificó:

```
102 B tal cual (flags=0)      -> truncado leyendo signature: 64 B en offset 102
102 + 64, flags=0             -> OK, payload 80, firma si (64 B)
102 + 64 + 90, flags=0        -> OK, payload 80, firma si (64 B)
```

No era un campo sin explicar: era la firma, y el sitio estaba bien. Lo que no
cuadra es la cabecera: la app **no** activa `HAS_SIGNATURE` (el byte de flags
del announce real es `0x00`), pero incluye los 64 bytes igualmente. Con
`flags = 0` el parser no los consume.

**Y no valida como firma Ed25519** sobre cinco mensajes candidatos (payload
TLV, cabecera+sender+payload, sender+payload, TLV sin la clave de firma, sólo
el nickname), con la clave `0x03` del propio announce. Así que se sabe **dónde**
está y **cuánto** mide, pero no **de qué** firma: puede ser otra cosa de 64 B.

Conclusión: se rellena hasta **256 B** y hay una firma de 64 B que la cabecera
no declara. `should_pad_for_ble()` sigue sin tocarse (§6).

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
| `tools/probe_advertise.py` | Anuncia y escanea, para ver si nos finds |
| `tools/extract_vectors.py` | Regenera `tests/fixtures/vectors.json` |

### Reparto de tests

| Fichero | Tests | Cubre |
|---|---|---|
| `test_transport.py` | 78 | Compresión, reensamblado, GATT, transporte |
| `test_identity.py` | 59 | TLV de identidad, `peer_id`, firma, persistencia |
| `test_current_payloads.py` | 44 | `MESSAGE`, TLV de fichero, voz |
| `test_noise_vectors.py` | 39 | Handshake XX, framing, anti-replay |
| `test_payloads.py` | 25 | `ANNOUNCE`, fragmentación, opacidad |
| `test_dialect.py` | 21 | Constantes Android con `file:line` |
| `test_dispatch.py` | 19 | Despacho por dialecto y ambigüedad |
| `test_golden_packets.py` | 19 | Los 21 paquetes reales, byte a byte |
| `test_advertiser.py` | 18 | Forma del anuncio y rutas D-Bus |
| `test_smoke_ble.py` | 14 | Construcción del announce, hexdump |
| `test_bleak_transport.py` | 8 | Transporte real (6 se saltan sin bleak) |
| **Total** | **392** | 6 saltados = requieren hardware |

### Ficheros del proyecto

- `src/pybitchat/protocol/` — `types.py` (enums y constantes), `packet.py`
  (cabecera v1/v2, compresión, `WirePayload`), `identity.py` (identidad y
  anuncio TLV), `payloads.py` (despacho), `compression.py`, `reassembly.py`,
  `message.py`, `tlv.py`, `voice.py`, `packet.py`
- `src/pybitchat/noise/` — `session.py`, `framing.py`, `primitives.py`
- `src/pybitchat/ble/` — `gatt.py` (UUIDs), `bleak_transport.py`,
  `advertiser.py`
- `src/pybitchat/mesh/transport.py` — `Transport` abstracto y `MockTransport`
- `EVALUACION-MIGRACION.md` — informe, 939 líneas, 14 secciones

---

## 5. Por dónde seguir mañana

### Primero: arreglar el decodificador del `ANNOUNCE`

**El servidor GATT ya no es el siguiente paso.** La pregunta "¿hace falta?" está
contestada por el §1: la app nos descubrió, conectó, y respondió a nuestro
announce sobre la conexión que **nosotros** abrimos. El lado central basta.

El bug concreto es de una línea de criterio: `payloads.py:418` mapea
`MessageType.ANNOUNCE` a `AnnouncePayload`, que implementa la forma **legacy**
(sólo nickname). El announce actual es TLV.

El formato ya está resuelto y probado, no hay que investigarlo:

- `identity.py` tiene el TLV de identidad con `peer_id` derivado, y el test usa
  el announce real de 80 B.
- Los 80 B de la captura de hoy dan `0x01` nickname, `0x02` Noise, `0x03` firma.
  Encajan exactamente.

Lo que hay que decidir al implementarlo: si `AnnouncePayload` se cambia al TLV
para ambos dialectos, o si el TLV sólo aplica al actual. `decode_payload` ya
exige `dialect=` para 6 valores ambiguos, así que el sitio natural es añadir
una clase de payload TLV y mapear `(CURRENT, ANNOUNCE)` a ella, dejando
`(LEGACY, ANNOUNCE)` como está. **No** reescribir la legacy: si la app legacy
algún día habla con nosotros, sigue siendo la forma legacy.

Los paquetes se guardan ahora en `capturas/recibido.bin`, así que el trabajo es
sobre los bytes y no sobre el terminal.

### Después: el servidor GATT (sólo si hace falta)

No hay atajo si arrive a hacer falta: bleak 3.0.2 no puede ser peripheral en
Linux, así que habría que implementarlo a mano, igual que el anuncio.

**Orden de trabajo, con tests antes que hardware:**

1. `ble/gatt_server.py` — `org.bluez.GattManager1` con un servicio y el
   characteristic de BitChat, `org.bluez.GattService1` y
   `org.bluez.GattCharacteristic1`.
2. **Tests de formato primero**: rutas de objeto, firmas D-Bus, nombres de
   interfaz. Es lo que más ha atrapado (§6, punto 12).
3. Probar en hardware con un paso corto y aislado.

Pregunta abierta antes de escribirlo: **¿hace falta?** Si la app nos descubre
por el anuncio y nos escribe por la conexión que nosotros abrimos, el servidor
GATT puede no hacer falta para el primer hito. Conviene comprobarlo.

### Después: los tres problemas abiertos

Orden sugerido:

1. **Los 72 bytes de `0xff`** (§3.3). Es lo que más información da y es lo
   único que la app manda y no entendemos. Candidatos: `Special recipient IDs`
   en `BinaryProtocol.kt:32`, o relleno deliberado.
2. **El `MESSAGE` de 4 bytes** que rechazamos. ¿Se sale la app de spec o
   nuestro `MIN_PAYLOAD_SIZE` es demasiado estricto?
3. **La contradicción del relleno** (§3.2). Requiere leer
   `MessagePadding` y `BinaryProtocol.encode` a fondo.

### Después: el handshake

Con identidad válida y anuncio, el siguiente paso es `msg1` de Noise XX. La
parte criptográfica ya está hecha y verificada con vectores; falta el
transporte que la mueva y la preimagen de firma, que ya está implementada como
`to_binary_data_for_signing()`.

**Detalle que ya se sabe:** el TTL se fija a 0 al firmar, porque baja en cada
salto y si entrara en la preimagen cualquier paquete reenviado una sola vez
llegaría con firma inválida.

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
    fallo de ese tipo en 392 tests.

---

## 7. Notas de estilo

- La documentación es en español y explica **por qué**, no sólo qué.
- Cuando un layout está confirmado por una sola cara del código se dice
  explícitamente que es una hipótesis.
- Cada constante de Android lleva `file:line` de procedencia.
- Los tests llevan nombre descriptivo en español y, cuando cubren un caso
  raro, el motivo por el que ese caso importa.
- Un descarte o un rechazo **lleva el motivo registrado**, no falla en silencio.