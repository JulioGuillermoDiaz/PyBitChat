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
| **Anuncio como peripheral** | 🔧 en prueba — commit `0c8c613` |
| Handshake Noise con la app real | ❌ **falta** |

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

### 3.2 Contradicción del relleno, sin resolver

`BLEPacketPaddingPolicy.shouldPadForBLE` dice que **sólo** se rellenan las
tramas Noise, y se usa de verdad (`BluetoothPacketBroadcaster.kt:215, 237, 350`).

Pero los paquetes capturados son un `ANNOUNCE` y un `MESSAGE`, ninguno Noise, y
**sí vienen rellenos** con PKCS#7 exacto:

| Paquete | Contenido | Relleno | Byte |
|---|---|---|---|
| ANNOUNCE | 166 B | 90 B | `0x5a` = 90 |
| filler | 96 B | 160 B | `0xa0` = 160 |

**No se cambió el comportamiento.** La función sigue reflejando el código, que
es lo verificable, y el conflicto está documentado en el docstring. Cambiarla
con una observación que no se explica sería sustituir una afirmación sin
verificar por otra igual de sin verificar.

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

### Primero: el resultado del announce

Si `probe_advertise.py` anuncia bien, el siguiente paso natural es el
**servidor GATT** (`org.bluez.GattManager1`). No hay atajo: bleak 3.0.2 no
puede ser peripheral en Linux, así que hay que implementarlo a mano, igual que
el anuncio.

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