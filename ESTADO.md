# Estado del proyecto — punto de reanudación

**Fecha de corte:** 2026-10-01
**Objetivo:** cliente BitChat en Python para **Android + Linux** (iOS fuera de
alcance). Es una **reimplementación**, no un port de `bitchat-tui`.

> ⚠️ **Antes de nada:** no se porta `bitchat-tui`. Habla un dialecto retirado, así
> que portarlo daría un cliente incapaz de hablar con ninguna app actual. Ver
> `EVALUACION-MIGRACION.md` §1 y §11.

---

## 1. Cómo arrancar

```powershell
cd C:\PyBitChat
$env:PYTHONIOENCODING='utf-8'
.\.venv\Scripts\python.exe tests\<fichero_de_test>.py
```

| Fichero | Tests | Cubre |
|---------|-------|-------|
| `tests/test_dialect.py` | 21 | Constantes Android con `file:line` |
| `tests/test_payloads.py` | 25 | `ANNOUNCE`, fragmentación, opacidad |
| `tests/test_golden_packets.py` | 19 | Los 21 paquetes reales, byte a byte |
| `tests/test_noise_vectors.py` | 39 | Handshake XX, framing, anti-replay |
| `tests/test_current_payloads.py` | 44 | `MESSAGE`, TLV, voz |
| `tests/test_dispatch.py` | 19 | Despacho por dialecto y ambigüedad |
| **Total** | **167** | **todos en verde** |

Detalle importante del entorno: **PowerShell destroza los `python -c` en línea
con llaves y comillas**. Para scripts de un solo uso, escribir un fichero y
ejecutarlo, o usar `tools/extract_vectors.py`.

`reference/` está en `.gitignore` porque es un clon de solo lectura de
`vaibhav-mattoo/bitchat-tui` (MIT, 2024). Si hace falta:

```powershell
git clone https://github.com/vaibhav-mattoo/bitchat-tui reference/bitchat-tui
```

Lo único que se conserva de esa fuente son los vectores ya extraídos, en
`tests/fixtures/vectors.json`, regenerables con `tools/extract_vectors.py`.

---

## 2. Qué está hecho

| Fase | Contenido | Estado |
|------|-----------|--------|
| 0 | Vectores reales + 3 oráculos independientes | ✅ |
| 1 | Codec de payloads | ✅ |
| 1.5 | Dialecto: constantes Android con procedencia | ✅ |
| 3 | Noise XX handshake + transporte + anti-replay | ✅ |
| — | Payloads del dialecto actual (`MESSAGE`, TLV, voz) | ✅ |
| 2 | **Integración BLE** | ❌ bloqueada, ver §4 |

Ficheros con el detalle de cada decisión:

- `src/pybitchat/protocol/types.py` — los dos enums (`MessageType` actual,
  `LegacyMessageType` retirado), constantes, vectores de Noise.
- `src/pybitchat/protocol/packet.py` — cabecera de **14** bytes.
- `src/pybitchat/protocol/payloads.py` — despacho y registro de huecos.
- `src/pybitchat/protocol/message.py`, `tlv.py`, `voice.py` — payloads actuales.
- `src/pybitchat/noise/session.py`, `framing.py`, `primitives.py` — Noise.
- `EVALUACION-MIGRACION.md` — informe de 795 líneas, 14 secciones.

---

## 3. Decisiones ya tomadas (no re-litigar)

1. **Motor de handshake = `noiseprotocol`**, no hecho a mano. BitChat usa Noise
   **rev 32/33** (`MixKey`: clave de cifrado = salida 2 de HKDF, sin
   `MixHash(temp)`), no rev 34. Una implementación a mano de rev 34 coincidía
   en msg1 pero divergía en el primer byte de msg2. `noiseprotocol` reproduce
   los vectores de `NoiseExternalVectorTest.kt` byte a byte.

2. **Dos enums, no uno.** Los dialectos se diferencian por **renumeración**, no
   por inclusión: `0x11` es `NOISE_HANDSHAKE_RESP` en el viejo y
   `NOISE_ENCRYPTED` en el actual. Mezclarlos no da error, da basura silenciosa.
   `decode_payload` exige `dialect=` para los 6 valores ambiguos
   (`0x02, 0x10, 0x11, 0x20, 0x21, 0x22`) y **se niega a adivinar**.

3. **Un payload desconocido se conserva `OpaquePayload`, byte-exacto.** Nunca se
   adivina. Es deliberado: es exactamente el error que tumbó al cliente Rust.

4. **El prefijo del transporte es big-endian; el nonce del AEAD es
   little-endian.** Son opuestos. Los dos casos están cubiertos por tests con
   nombre (`TestEndiannessDelPrefijo`).

5. **El transporte usa la clave dividida directamente, sin derivación de
   época** (`ChaChaPolyCipherState.setNonce` es sólo `n = nonce`).

6. **El prologue de producción va vacío** (`NoiseSession.kt:244` no llama a
   `setPrologue`). Ojo: `HandshakeState.java:512-516` siempre hace `mixHash`
   aunque el prologue sea vacío — es un no-op que **cambia `h`**, así que no se
   puede "optimizar" fuera.

7. **Android rellena sólo las tramas Noise** (`BLEPacketPaddingPolicy.kt`); el
   Rust rellenaba todo. PKCS#7 blocks256/512/1024/2048, saltando si el relleno
   pasa de 255 B. Compresión **DEFLATE** (`CompressionUtil.kt`), no LZ4.

8. La cabecera es de **14** bytes (`BinaryProtocol.kt:208-217`), no de 13 como
   dicen el README de Android y el propio `bitchat-tui`.

---

## 4. Qué queda abierto

| Hueco | Qué falta | Bloquea |
|-------|-----------|---------|
| **H1** | 7 paquetes que el Rust envió no tienen volcado hex. Sólo se capturó el tráfico entrante. | Nada crítico |
| **H2** | *Prologue* de producción sin confirmar contra captura real. | Fase 3 (resto hecho) |
| **Fase 2** | Integración BLE. | El camino a un cliente real |

### Por qué la Fase 2 está bloqueada aquí

Esta VM es un **guest de VirtualBox sin adaptador Bluetooth** y sin WSL.
Verificado: sólo `Intel PRO/1000 MT` Ethernet, cero dispositivos PnP de BT, y
no existen `bluetoothctl`, `btmon` ni `hciconfig`. Las fases 0, 1 y 3 se
pudieron hacer porque son criptografía y códec puros.

**Hace falta el portátil Linux con el teléfono Android asociado.** Al arrancar
con BLE, tener en cuenta:

- MTU: Android 14+ = **517**; BlueZ vía bleak = **23** salvo que se llame a
  `_acquire_mtu()`.
- `MAX_FRAGMENT_SIZE=469`, `FRAGMENT_SIZE_THRESHOLD=512`,
  `MAX_FRAGMENTS_PER_ID=256`.
- El fragmento corta el paquete **ya rellenado**, así que la cabecera de 14 B
  puede quedar partida entre dos fragmentos. El reensamblado concatena bytes a
  secas, sin interpretar nada.

### Por qué H3, H4 y H5 se descartaron

Eran la siguiente tarea propuesta, pero **ninguno de los tres existe ya en el
protocolo actual**:

| Hueco | Tipo | Valor | ¿En `MessageType`? |
|-------|------|-------|--------------------|
| H3 | `NOISE_IDENTITY_ANNOUNCE` | `0x13` | **No** |
| H4 | `HANDSHAKE_REQUEST` | `0x25` | **No** |
| H5 | `PROTOCOL_ACK` | `0x22` | Sí, pero es **`FILE_TRANSFER`** |

Son artefactos del dialecto retirado. En su lugar se cerraron los tipos **vivos**
que faltaban: H6 `REQUEST_SYNC`, H7 `FILE_TRANSFER`, H8 `VOICE_FRAME`, más el
`MESSAGE` completo. Ver `EVALUACION-MIGRACION.md` §12.7.

---

## 5. Bugs reales encontrados (no volver a introducirlos)

1. **`False is not None` es `True` en Python.** El cálculo de flags de
   `MessagePayload` trataba `is_relay` como campo opcional, así que
   `is_relay=False` activaba el bit `0x01` y contaminaba todos los mensajes.
   Los flags booleanos están separados de los campos opcionales (`BOOL_FLAGS`).

2. **Un registro indexado por valor crudo no puede representar dos dialectos.**
   `OPEN_QUESTIONS` usaba el valor crudo como clave, pero `PROTOCOL_ACK` (legacy)
   y `FILE_TRANSFER` (actual) son **ambos `0x22`**: una entrada pisaba a la
   otra. Ahora la clave es `(dialecto, valor_crudo)`, con las vistas derivadas
   `OPAQUE_BY_DIALECT` y `open_question_for()`. El bug no fallaba ruidosamente:
   devolvía una respuesta plausible y equivocada.

3. **`BitchatFilePacket.kt:14` miente.** El comentario dice *"Length field for
   TLV is 2 bytes for all TLVs"*, pero el código usa `buf.putInt` para `CONTENT`,
   o sea **u32** (`:87`, y `off += 4` en el decode `:120-123`). Fiarse del
   comentario rompe la interop sólo con ficheros grandes: intermitente y difícil
   de diagnosticar. **El código es el que manda.**

---

## 6. Sobre `msg1` y los tests verdes

`msg1` del handshake **no valida criptografía**: son 32 B efímeros más payload en
claro, porque todavía no hay clave. El primer dato real es **msg2** (111 B).

> Un `msg1` en verde no dice nada. No confundirlo con una verificación de
> seguridad.

---

## 7. Notas de estilo

- La documentación de los módulos es en español y explica **por qué**, no sólo
  qué. Cuando un layout está confirmado por una sola cara del código se
  dice explícitamente que es una hipótesis.
- Cada constante de Android lleva `file:line` de procedencia.
- Los tests llevan nombre descriptivo en español y, cuando cubren un caso
  raro, el motivo por el que ese caso importa.

---

## 8. Opcional: avisar al upstream

Los hallazgos corroboran el issue #12. El repo tiene 18 issues abiertos y 14
meses sin commits. Podría merecer la pena reportar, en particular:

- El comentario de `BitchatFilePacket.kt:14` contradice el código.
- La cabecera es de 14 B, no de 13 como dice el README.
- El dialecto de `bitchat-tui` está retirado.