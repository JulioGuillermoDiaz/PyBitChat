# Evaluación: migrar `bitchat-tui` de Rust a Python

**Fecha:** 2026-10-01
**Referencia analizada:** [`vaibhav-mattoo/bitchat-tui`](https://github.com/vaibhav-mattoo/bitchat-tui) @ `107a13c` (clon en `reference/bitchat-tui/`)
**Alcance:** evaluación de viabilidad. No se ha escrito código de producción.

---

## 1. Veredicto

**La migración es viable como reimplementación, pero `bitchat-tui` no es una base de la que partir: habla un dialecto de protocolo retirado.**

Cuando empezó este análisis la conclusión era "no portar, reimplementar". Tras
contrastar con el código de `permissionlesstech/bitchat-android` la conclusión
es más fuerte: **el dialecto que implementa `bitchat-tui` ya no lo habla ninguna
app actual** (§11). Portarlo, incluso corrigiendo sus 12 bugs, daría un cliente
incapaz de comunicarse con nada.

Lo que sí sobrevive del repositorio Rust: la estructura del paquete (cabecera de
14 B, flags dirigidos por bits, formato del payload de mensaje) y las trazas de
captura histórica de `debug.log`. Todo lo demás hay que tomarlo del dialecto
vigente.

### Bugs de `bitchat-tui` (todos con `file:line`)

| Bug | Evidencia | Efecto para el usuario |
|---|---|---|
| **Los DMs cifrados no pueden volver ni al propio emisor** | `message_handlers.rs:167-170` antepone un marcador de tipo de 1 byte (`0x04`) antes de cifrar; `notification_handlers.rs:1452-1455` hace `parse_bitchat_packet(&decrypted)` **sin** consumir ese marcador | **El round-trip de DM Noise está roto dentro del propio Rust.** Un port fiel reproduce un DM que el cliente no sabe descifrar. |
| Noise nunca se activa | `set_noise_manager` definido en `encryption.rs:184`, **0 llamadas**; `main.rs:357-361` es un `if` vacío con TODO. `encrypt()`/`decrypt()` hacen `.read()` del manager (no pueden obtener `&mut`), loguean *"falling back to legacy"* y **siempre** ejecutan AES-256-GCM | El E2E con Noise nunca ocurre. El fallback se dispara **en silencio** cuando Noise falla. |
| `store_peer_static_key` es un no-op | `noise_session.rs:1294-1308` valida y descarta (*"You might need to add a field to store these keys"*) | Las claves estáticas anunciadas nunca se reutilizan: **cada sesión re-handshakea** desde cero. |
| Canales sin cifrar no se enrutan | `MSG_FLAG_HAS_CHANNEL` (`0x40`) solo se setea en la ruta cifrada (`payload_handling.rs:263`); la ruta normal lo lee (`payload_handling.rs:154`) pero nunca lo escribe | Un mensaje a `#canal` sin contraseña llega a `#public`. |
| El handler de identity-anounce contradice a su propio serializer | `notification_handlers.rs:1589-1628` espera `staticKey(32)‖identityHash(32)‖nickname`; `binary_encoding.rs:488-570` espera `flags‖peerID(8)‖Data(32)‖Data(32)‖nick‖ts[‖prevID]‖sig` | Dos formatos de wire distintos para el mismo tipo. Confirmado roto en `noise_handler_debug.log:68`. |
| Firmas Ed25519 sin verificar | `encryption.rs` silencia `verify()` con `#[allow(dead_code)]` | Se generan firmas pero nadie las comprueba. |
| Validación de clave pública rota | `noise_protocol.rs:1307-1368` asume que `PublicKey::from([u8;32])` valida el punto de curva, pero en x25519-dalek 2.x es **infalible** → el `match` siempre retorna `Ok` y solo filtra 8 "bad points" hardcodeados. **Nunca se aplica a la clave efímera** (`:965-968`) | Sin validación de clave de curva. |
| Peer ID de solo 4 bytes | `main.rs:255-257` → 32 bits; el tie-breaker compara solo 8 chars hex | Colisiones plausibles en un entorno BLE denso. |
| Compresión LZ4 inactiva | `packet_creation.rs:125` → `// No compression for now`; `decompress_raw()` es reverse-engineering a ciegas (magic `bv41`/`bv4-`, skips de 0/2/4/12/16 B) | La compresión es *write-only*. Un port puede **descartar LZ4** y soportar solo recepción. |
| `/block` no persiste | `EncryptionService::new()` genera identidad efímera e ignora `app_state.identity_key`; los fingerprints bloqueados se derivan de esa clave | Los bloqueos se pierden al reiniciar. |
| `/exit` no guarda estado | `main.rs:625` cortocircuita `handle_exit_command` con un `break` previo | Nickname, canales y contraseñas se pierden al salir. |
| Padding inconsistente | `packet_creation.rs:46-55` usa bytes aleatorios; `command_handling.rs:326-328` y `message_handlers.rs:280-282` usan byte repetido. Además `pad_message_to_size` **no rellena** si el padding supera 255 B (`packet_creation.rs:39-41`) | Paquetes ≥~1793 B salen sin padding. |

**Conclusión operativa:** el repositorio sirve como **especificación de referencia** del formato binario y como fuente de contraste, **no como implementación a replicar**. No es que la migración sea difícil: es que portar de forma fiel significaría portar un cliente cuyos DMs cifrados no se descifran ni a sí mismo.

Corroboración externa — issues abiertas del repo, sin resolver desde hace ~14 meses:

| Issue | Reportado |
|---|---|
| #21 | `Failed to add peer public key: InvalidPublicKey` contra la última versión de Android |
| #11 | *"Messages not arriving to cellphone, but cellphone messages are arriving to linux"* |
| #9 | `Failed to encrypt private message: NoSharedSecret` |
| #8 | No puede conectarse con la última iOS |
| #12 | Un tercero (`spr-networks/bitchat-plugin`) **reimplementó desde cero con `snow-rs`** *"to avoid implementation errors from a rewrite"* y reporta *"reliability problems with the noise implementation"* |

Ese último issue es la señal más clara: **alguien independiente ya intentó esto y eligió una librería auditada en lugar de reimplementar Noise.** Es exactamente la estrategia que recomienda este informe.

La ruta recomendada es una reimplementación limpia en Python apoyada en librerías ya validadas, tomando de `bitchat-tui` únicamente los detalles de formato de bytes.

---

## 2. Métricas del proyecto

| Métrica | Valor |
|---|---|
| Lenguaje | Rust 2021, crate binario único (sin `lib.rs`) |
| LOC Rust | **11.057** en 29 ficheros |
| Licencia | MIT / Apache-2.0 (`Cargo.toml:5`) |
| Estrellas / forks | 376 / 32 |
| Último push | **2025-08-01** (≈14 meses de inactividad) |
| Issues abiertas | 18 |
| Tests automatizados | **4 `#[test]`** en todo el repo; ninguno de Noise ni de wire-format |
| Código muerto estimado | ~500 LOC (`binary_encoding.rs` entero sin usar) + 20 `#[allow(dead_code)]` + 3 stubs |
| Logging commiteado | **~1.100 LOC** dentro de `noise_protocol.rs`/`noise_session.rs` (86+76 llamadas `debug_full_println!`) + 4 ficheros `.log` con paquetes reales de iOS |
| Downloads crates.io | 1.303 acumulados |

Desglose por capa (de mayor a menor):

| Fichero | LOC | Capa |
|---|---|---|
| `notification_handlers.rs` | 1.811 | dominio (relay mesh, dedup, ACKs) |
| `noise_protocol.rs` | 1.217 | criptografía (Noise completo) |
| `noise_session.rs` | 1.211 | criptografía (gestión de sesiones) |
| `main.rs` | 797 | orquestación (mezcla red + UI) |
| `command_handling.rs` | 696 | comandos |
| `data_structures.rs` | 626 | dominio |
| `message_handlers.rs` | 546 | dominio |
| `tui/app.rs` | 540 | UI (estado puro, sin ratatui) |
| resto (`tui/widgets/*`, `encryption.rs`, `binary_*`, …) | ~2.500 | mixto |

---

## 3. Estado real de la implementación Rust

### 3.1 Lo que está bien

`noise_protocol.rs` es una **implementación estructuralmente correcta** del Noise Protocol Framework. Verificada contra la spec:

- **Perfil real: `Noise_XX_25519_ChaChaPoly_SHA256`** (no es `NNpsk0`). Solo se usa el patrón **XX** (`noise_session.rs:151-156, 215-220, 736-751, 1103-1108`); sin PSK, sin pre-shared key, prologue vacío.
- El nombre del protocolo (28 B) se copia en `h` sin hashear (`noise_protocol.rs:418-435`) — correcto según spec.
- **HKDF propio conforme** (`noise_protocol.rs:565-587`): `temp_key = HMAC(ck, ikm)`; `o1 = HMAC(temp_key, 0x01)`; `oi = HMAC(temp_key, o(i-1)‖i)`. Idéntico a la spec.
- Nonce ChaCha = 4 bytes cero ‖ u64 LE en `[4..12]` (`:271-273, 362-364`) — correcto.
- Asignación de cifrados post-`split()` (`:1237-1240`): initiator (send=c1, recv=c2), responder (send=c2, recv=c1) — correcto.
- Patrón XX (`:1265-1276`): `-> e`, `<- e,ee,s,es`, `-> s,se` — correcto.
- `use_extracted_nonce` (`:157`) imita la desviación real de la app oficial (etiquetada `BCH-01-010` en el Swift). Buen indicio de que el autor sí estudió el código Swift.

**Matiz sobre el tamaño real:** de las ~1.300 líneas de `noise_protocol.rs`, **~600 son logging** (76 llamadas `debug_full_println!`). La lógica criptográfica real es ~600 LOC. Esto refuerza el argumento de no portarla: incluso la parte "buena" es pequeña comparada con el coste de mantenerla.

### 3.2 Pero tiene 3 agujeros de seguridad reales

| # | Agujero | Ubicación |
|---|---|---|
| **A1** | **Anti-replay solo con `n>0`** → los mensajes con nonce 0 son reenviables indefinidamente | `noise_protocol.rs:346, 384-386` |
| **A2** | **`read_message` se traga el fallo de descifrado del payload** y continúa el handshake con `vec![]` (comentario: *"for debugging"*) → desincroniza `h` y anula la autenticación AEAD | `noise_protocol.rs:1193-1203` |
| **A3** | **`decrypt_and_hash` acepta ciphertext vacío** como plaintext vacío válido (excepción *hand-rolled*, contra la spec) | `noise_protocol.rs:499-506` |

A2 es el más serio: convierte el fallo de autenticación en un fallo silencioso que además corrompe el estado del handshake.

### 3.3 El estado final, según el historial

```
107a13c receiving noise protocol messages finally!!!!!!!!!!!!
facb676 now just fails to parse inner message
fc13102 works till utf-8 issue
599ed05 now noise detection and handshake works but issues with sending message
0201d09 lots of changes noise protocol still does not work
```

Traducción: **el módulo criptográfico funciona; la integración con el transporte y el parseo de mensajes no.** El fallo está en `notification_handlers.rs` (donde hay 4 bloques de ~35 líneas duplicados, comentados como `// NEW – wrap the Noise payload in a BitchatPacket`) y en que `set_noise_manager()` nunca se invoca.

**Matiz importante:** el último commit es un **hito de depuración, no un cierre**. En los logs commiteados solo hay 4 mensajes, todos en el mismo segundo; sin ACKs, sin identity announce funcional, sin cover traffic (`COVER_TRAFFIC_PREFIX` en `data_structures.rs:53` nunca se usa) y con la verificación de fingerprint desconectada de la UI (`TODO` en `main.rs:346,352`). Los ~2.400 LOC de `noise_protocol.rs` + `noise_session.rs` no son el activo más valioso del repositorio: son el más **voluminoso**, y buena parte es logging o código que nunca se ejecuta.

### 3.4 Arquitectura y concurrencia

El diseño tiene **más estructura de la que aparenta**, y esto juega a favor:

- **73% del código (~5.800 LOC) es dominio puro** — protocolo binario, criptografía, Noise, encoding — sin imports de `ratatui` ni de `btleplug`. Se traduce directamente.
- `tui/app.rs` **no importa `ratatui`**: es un struct plano de ~35 campos con `HashMap<String, Vec<Message>>` e `tui_input::Input`. Es estado, no presentación.
- Solo **7 ficheros (~900 LOC)** dependen de ratatui/crossterm: `ui.rs`, `event.rs`, `tui.rs`, `widgets/*.rs`.
- `notification_handlers.rs` (1.811 LOC) **no importa `tui`**: se comunica con la UI solo por canales `mpsc` de strings.

El problema es el **fan-in**, no la estructura: `main.rs` y 8 de los 14 handlers de `command_handling.rs` importan `crate::tui::app::App` directamente y lo mutan desde el dispatcher de red.

**Concurrencia — hallazgo relevante:** no existe `tokio::select!` en todo el repositorio. Es un **bucle cooperativo de una sola tarea** con 7 fases secuenciales:

| # | Fase | Mecanismo |
|---|---|---|
| 1 | Drenar `ui_rx` | `while let Ok(msg) = ui_rx.try_recv()` |
| 2 | Init post-conexión | ~110 líneas inline, corre 1 vez |
| 3 | Notificación BLE | `timeout(1ms, notification_stream.next())` → **máx. 1 paquete por iteración** |
| 4 | Teclado | `crossterm_event::poll()` **bloqueante síncrono** dentro de la tarea async |
| 5 | Drenar `input_rx` | cadena de ~15 `if handler(...).await` |
| 6 | Render | redibujo completo sin diff, ~10 FPS |
| 7 | `should_quit` | |

El IPC entre backend y UI es un **protocolo de strings sin tipar** parseado con regex (`app.rs:211-344`): `__DM__:…`, `__CHANNEL__:…`, `"{name} connected"`, `"system: …"`. En sentido inverso, outbox con 5 flags `pending_*`.

**Consecuencia para el port:** es *más* fácil de lo que parece. No hay que reproducir un `select!` complejo; se traduce a **1 `asyncio.Task` para BLE + 2 `asyncio.Queue`**. Los `Arc<Mutex<>>` son innecesarios (el código usa `tokio::sync::Mutex` en un contexto de una sola tarea) y los `RwLock` de `EncryptionService` igual.

---

## 4. Portabilidad por capa

| Capa | LOC | Portabilidad | Nota |
|---|---|---|---|
| `data_structures.rs` | 626 | **Muy alta** | `MessageType` (24 variantes), flags, `BitchatPacket`. Solo reimplementar codificación binaria. |
| `binary_encoding.rs` | 555 | Muy alta | Solo `HandshakeRequest` está vivo; ~500 LOC muertos. No portar. |
| `binary_protocol_utils.rs` | 252 | Muy alta | Hex + helpers de lectura/escritura. Trivial en Python. |
| `packet_creation.rs` / `packet_parser.rs` | 437 | Muy alta | Incluye padding PKCS#7 a 256/512/1024/2048. |
| `payload_handling.rs` | 253 | Muy alta | ⚠️ contiene el bug de orden de campos; **no portar tal cual**. |
| `compression.rs` | 128 | Muy alta | ⚠️ Path de envío inactivo; `decompress_raw()` es reverse-engineering a ciegas. Usar `lz4` de Python solo en recepción. |
| `encryption.rs` | 375 | **No portar** | X25519/Ed25519/AES-GCM/HKDF/PBKDF2 → `cryptography` + `PyNaCl`. |
| `noise_protocol.rs` | 1.217 | **No portar** | → librería para el handshake + framing de transporte propio (§5.1). |
| `noise_session.rs` | 1.211 | **No portar** | → reimplementar sobre la librería + el wrapper `NoiseMessage`. |
| `notification_handlers.rs` | 1.811 | Alta (lógica) | Dominio real, pero acoplado por strings. Reimplementar con eventos tipados. |
| `fragmentation.rs` | 273 | Alta | ⚠️ La API pública está muerta y **contradice** la lógica inline: usa 500 B mientras el código real trocea a **150 B** del paquete ya paddado (`main.rs:141-264`). Usar 150 B y revalidar contra los `.log`. |
| `tui/app.rs` | 540 | Muy alta | Estado puro. Reutilizable casi literal. |
| `tui/ui.rs` + `widgets/*` + `event.rs` | ~900 | Media | Sustituir por Textual. |
| `command_handling.rs` | 696 | Media | ⚠️ 8 de 14 handlers atados a `App`. Refactor previo necesario. |
| `main.rs` | 797 | **Baja** | El peor offender: mezcla red y UI. Reescribir. |

**Balance: ~5.800 LOC (73%) son dominio puro traducible; ~1.700 LOC de UI se reconstruyen con Textual; ~2.400 LOC de criptografía se eliminan sustituyéndolas.**

### 4.1 Refactor previo necesario

Para desbloquear el port hay que extraer `AppState` (dominio) de `UiState` (presentación) y reemplazar los strings-centinela por un enum `Event` tipado. Coste: **~600 líneas**. Es la tarea que más riesgo tiene y la que conviene hacer en el propio Rust antes de traducir, para tener una suite de pruebas que sirvan de oráculo.

---

## 5. Mapeo al ecosistema Python

| Necesidad | Rust | Python | Estado |
|---|---|---|---|
| TUI | `ratatui` 0.26 + `crossterm` + `tui-input` | **`textual`** | ✅ Excelente. `Tree`→sidebar, `RichLog`→chat, `Input`→cursor y wrap multilínea nativos, `Footer`→keybindings, `@work`→tareas asyncio. BITTOR-TUI ya valida el combo. |
| BLE | `btleplug` 0.11 + `dbus` (Linux) | **`bleak`** ≥0.22 | ⚠️ Funcional pero con salvedades (ver §6). |
| Noise | `x25519-dalek`, `chacha20poly1305`, `sha2`, `hkdf` (2.400 LOC) | **`noiseframework`** o **`noiseprotocol`** | ✅ `noiseframework` (311 tests, asyncio); `noiseprotocol` (spec rev. 32/33). Ambos cubren `Noise_XX_25519_ChaChaPoly_SHA256`. |
| Simétricos | `chacha20poly1305`, `aes-gcm`, `hmac` | `cryptography`, `PyNaCl` | ✅ |
| Firmas | `ed25519-dalek` | `cryptography` | ✅ |
| Compresión | `lz4_flex` | `lz4` | ✅ |
| Bloom filter | `bloomfilter` | `pybloomlive` / reimplementar (es trivial) | ✅ |
| Persistencia | `serde` + `serde_json` | `json` nativo / `pydantic` | ✅ |
| Concurrencia | `tokio` + `mpsc` | `asyncio` + `asyncio.Queue` | ✅ |

### 5.1 Interoperabilidad: verificada y favorable

Datos extraídos del código Swift de `permissionlesstech/bitchat`:

| Parámetro | Valor |
|---|---|
| Servicio GATT (mainnet) | `F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C` |
| Servicio GATT (testnet) | `F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5A` |
| Característica | `A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D` |
| Propiedades | Read, Write, Notify · seguridad abierta |
| Perfil Noise | **`Noise_XX_25519_ChaChaPoly_SHA256`** (patrón XX, DH 25519, ChaCha20-Poly1305, SHA-256) |

Coincide **exactamente** con las constantes de `bitchat-tui`:

```
data_structures.rs:48  BITCHAT_SERVICE_UUID        = 0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5C
data_structures.rs:50  BITCHAT_CHARACTERISTIC_UUID = 0xA1B2C3D4_E5F6_4A5B_8C9D_0E1F2A3B4C5D
```

El **handshake** es Noise estándar y las librerías Python lo cubren sin fork. Pero **el transporte no lo es**, y esto es un detalle que decide la arquitectura:

| Capa | Compatible con librería estándar |
|---|---|
| Handshake XX (mix_key, mix_hash, DH, `split()`) | ✅ Sí, sin cambios |
| `CipherState` de transporte | ❌ **No.** BitChat antepone un **prefijo de nonce de 4 bytes LE** al ciphertext, y usa ChaCha20-Poly1305 con nonce `00000000‖u64LE(n)` (`noise_protocol.rs:216-246, 271-274, 296-310, 362-364`) |

**Consecuencia práctica:** cualquier implementación Noise estándar (`noiseframework`, `noiseprotocol`, `snow`) **producirá y leerá bytes distintos** en la fase de transporte. Hay que usar la librería **solo para el handshake** y reimplementar una capa de framing propia encima. No es difícil (son ~40 líneas), pero es un requisito de diseño, no un detalle de implementación.

A esto se suman dos desviaciones propias de BitChat:

- **Wrapper `NoiseMessage`**: tipo `UInt8` + `sessionID` UUID + payload (`NoiseEncryptionService.swift`).
- **Desviación de nonce `BCH-01-010`** / `useExtractedNonce`, ya presente en el código Rust (`:157`), lo que confirma que el autor la había identificado.

⚠️ **Cuidado con un error fácil de cometer:** el markdown de `bitchat4agents` afirma *"Official Noise XX session primitives validated against the macOS app's test vectors"*. Eso valida el **handshake**, no necesariamente el framing de transporte. Confirmar ambas cosas por separado antes de fiarse.

### 5.2 Parámetros criptográficos concretos (extraídos del código)

Estos son los valores exactos que hay que reproducir. Errar en cualquiera rompe la interop:

| Qué | Algoritmo | Parámetros |
|---|---|---|
| Noise static key | X25519 | persistida **en texto plano** en `~/.bitchat/state.json`, 32 B crudos (`persistence.rs:31`) |
| Noise transport | HKDF-Noise(ck, "", 2) | 2×32 B: initiator-send / responder-send (`noise_protocol.rs:543-562`) |
| ECDH legacy → AES | HKDF-SHA256 | **salt = ASCII `"bitchat-v1"`** (11 B), info = vacío, L=32 → AES-256-GCM, nonce 12 B, wire = `nonce‖ct‖tag(16)` (`encryption.rs:140-143`) |
| Blob de key exchange | — | 96 B = X25519 pub(32) ‖ Ed25519 verify(32) ‖ Ed25519 identity verify(32) (`encryption.rs:77-83`) |
| **Password de canal** | PBKDF2-HMAC-SHA256 | **salt = bytes UTF-8 crudos del nombre del canal** (sin quitar `#`, sin normalizar), **100.000 iteraciones**, dkLen=32 (`encryption.rs:285-294`) |
| Password en disco | SHA-256 | `SHA256(b"bitchat-password-encryption" ‖ identity_key)` — pese al comentario *"HKDF-like"*, **es SHA-256 plano**, sin salt ni iteraciones (`persistence.rs:115-123`) |
| Fingerprint (2 definiciones) | SHA-256 | `SHA256(static_pub)` → **64 hex** (`noise_session.rs:633`); `SHA256(identity_key)[:16]` → **32 hex** (`encryption.rs:161`). La blocked-list usa la de 32. |
| Fragmentación | — | umbral `len > 500`; **chunk real de 150 B del paquete YA paddado**; delay 20 ms; `WriteType::WithoutResponse`. Los fragmentos cortan el paquete padded en fronteras de 150 B, así que **el header de 13 B puede quedar partido entre dos fragmentos** (`fragmentation.rs:129-262`). |

### 5.3 El wire format (la parte realmente portable)

`~2.100 LOC` de protocolo binario puro, **sin `transmute`, sin `unsafe`, sin FFI**, todo big-endian salvo 3 puntos documentados. Trivial de replicar byte-a-byte en Python.

> **Corrección tras Fase 0 (2026-10-01):** la cabecera es de **14 bytes**, no de 13. Desglose verificado byte a byte contra 21 paquetes reales de iOS:
> ```
> [0] version=1 │ [1] type │ [2] ttl │ [3:11] timestamp u64 BE │ [11] flags │ [12:14] payload_len u16 BE
> ```
> Son 1+1+1+8+1+2 = **14**. El `sender_id` empieza en el offset 14 y el `timestamp` es epoch Unix en **milisegundos** (comprobado: los vectores caen en agosto de 2025).

```
Header 14 B: version(1)=1 | type(1) | ttl(1) | timestamp u64 BE (epoch ms)
             | flags(1) | payloadLen u16 BE
flags: 0x01 hasRecipient | 0x02 hasSignature | 0x04 isCompressed
senderID 8 B | [recipientID 8 B] | payload | [signature 64 B Ed25519] | padding

Payload de mensaje:
  flags(1) | ts u64 BE ms | idLen u8 + id | senderLen u8 + sender
  | contentLen u16 BE + content | campos opcionales dirigidos por flags
```

Los **campos opcionales están dirigidos por flags, no en posición fija**. Confirmado empíricamente: el mensaje "hi" lleva `flags=0x10` (`HAS_SENDER_PEER_ID`) y su `payload_len=76` sólo cuadra si el `peer_id` va detrás del contenido:

```
1 + 8 + (1+36) + (1+8) + (2+2) + (1+16) = 76 ✓
```

Esto **corrige** el diagnóstico del bug de §1: no es un orden de campos invertido, sino que **se escribe el nombre de canal siempre pero nunca se pone `MSG_FLAG_HAS_CHANNEL` (0x40)**, con lo que el receptor lo ignora. También explica por qué la variante *cifrada* sí funciona: `payload_handling.rs:263` sí pone el flag.

### 5.4 Precedente: ya existe un cliente BitChat en Python

| Proyecto | Qué es | Nota legal |
|---|---|---|
| [`kaganisildak/bitchat-python`](https://github.com/kaganisildak/bitchat-python) | Cliente BLE completo sobre `bleak`. 259 ★, 45 forks. UUIDs reales, cifrado, fragmentación, bloom filter, comandos. | ⚠️ **Sin licencia declarada** (`license: null`). Sin licencia = todos los derechos reservados. **No reutilizable legalmente.** |
| [`bitchat4agents`](https://pypi.org/project/bitchat4agents/) (PyPI) | CLI "clean-room" de BitChat. BLE mesh + Nostr/geohash, Noise XX, *test vectors de la app macOS*, fragmentos, relay multi-salto, periférico BLE en macOS. Deps: `bleak`, `coincurve`, `cryptography`. | ✅ **Unlicense** (dominio público). Reutilizable. |
| [`aadi121205/BITTOR-TUI`](https://github.com/aadi121205/BITTOR-TUI) | TUI de BitChat en **Python + Textual**. Pero sobre Nostr/Tor, no BLE. | ⚠️ Sin licencia declarada. Serviría como referencia de *arquitectura UI*, no de código. |

**Implicación:** el núcleo de protocolo en Python está **ya demostrado y verificado contra vectores de la app oficial**. El hueco que `bitchat-tui` ocupa (mesh BLE **+** TUI) es la única pieza que falta, y es precisamente la más fácil.

---

## 6. Riesgos

| # | Riesgo | Severidad | Mitigación |
|---|---|---|---|
| R1 | **`bleak` en Linux (BlueZ) reporta siempre MTU 23**, el mínimo, salvo hack de `_acquire_mtu()`. `fragmentation.rs:9` asume MTU 512 y `MAX_FRAGMENT_SIZE = 500` | 🔴 Alta | Detectar backend y fijar MTU negociado real; si es 23, usar `bleDefaultFragmentSize` como el Swift. Sin esto, fragmentos de 20 B. |
| R2 | **BlueZ impose intervalo de conexión por defecto de 50 ms** y hay pérdida de paquetes documentada con varios periféricos en un adaptador ([bleak #1502](https://github.com/hbldh/bleak/issues/1502)) | 🔴 Alta | Es un problema de app *mesh*: duty-cycling, colas acotadas, backoff exponencial. Precedente: `bitchat4agents` lo resolvió así. |
| R3 | **macOS Sonoma redujo el throughput 3×** (intervalo de conexión 11,25 → 30 ms, [bleak #1436](https://github.com/hbldh/bleak/issues/1436)) | 🟡 Media | Aceptable para chat. Medir y documentar. |
| R4 | Sin tests de vectores en el código actual → portar a ciegas | 🔴 Alta | **Hay vectores dorados ocultos en el propio repo:** los 4 ficheros `.log` commiteados contienen dumps hex de paquetes reales de iOS (p.ej. `debug.log:13` es un paquete `Message` completo de 256 B). `noise_handler_debug.log` contiene un handshake XX completo con ciphertexts `NoiseCipherState`. Derivarlos + los vectores de `bitchat4agents`. **Prerrequisito absoluto.** |
| R9 | **El framing de transporte Noise no es estándar** (§5.1): prefijo de nonce de 4 B LE | 🔴 Alta | Librería solo para el handshake; capa de framing propia (~40 LOC) verificada contra los dumps de los `.log`. |
| R10 | La identidad Noise usa 4 bytes aleatorios (32 bits) y el tie-breaker compara 8 chars hex | 🟡 Media | Considerar 8 bytes para el Peer ID en el port (el header lo permite: `senderID 8 B`). Evaluar compatibilidad. |
| R11 | `hex_decode` acepta `+`/`-` (`u8::from_str_radix`) e indexa `[..8]` sobre `unwrap_or(vec![0;8])` → **panic** si el hex no decodifica a 8 B exactos (`binary_encoding.rs:216-220, 277-278`) | 🟡 Media | No reproduce: usar `bytes.fromhex()` de Python, que es estricto y no hace panic. |
| R12 | `payload.len() as u16` trunca en silencio por encima de 65535 (`packet_creation.rs:129`) | 🟢 Baja | Validar explícitamente. |
| R5 | Glitches de `bleak` al reconectar y estados `GATT` parciales | 🟡 Media | Máquina de estados explícita, lo que `bitchat-tui` no tiene (`TuiPhase` sólo tiene `Connecting/Connected/Error`). |
| R6 | El bucle Rust procesa **1 paquete BLE por iteración** con `timeout(1ms)` y `sleep(10..50ms)` por relay **dentro** de la tarea principal | 🟡 Media | **Oportunidad**: en asyncio, ejecutar el handler de cada paquete en una task propia evita el congelamiento de UI que sufre en Rust. No reproducir este defecto. |
| R7 | `debug.log` y 4 logs más commiteados en el repo, escritos de forma síncrona en el hot path | 🟢 Baja | No reproducir. `logging` con niveles. |
| R8 | `pub static mut DEBUG_LEVEL` leído con `unsafe {}` en ~100 sitios | 🟢 Baja | No reproducir. En Python es un `logging.getLogger().level`. |

---

## 7. Estrategias

### Opción A — Port fiel de `bitchat-tui` ❌ No recomendada
Traducir las 11.057 líneas. **Heredaría los 12 bugs de §1**, entre ellos un DM Noise que no se descifra ni a sí mismo, el E2E sin activar, 3 agujeros de seguridad criptográfica y los canales que no enrutan. El resultado sería un cliente que parece funcionar pero cuya característica central —el E2E con Noise— no está activa. Coste el más alto de las tres, valor el más bajo.

### Opción B — Reimplementación limpia sobre el spec oficial ✅ Recomendada
Construir desde cero el protocolo en Python, usando:
- `noiseframework` para Noise XX (verificado, 311 tests)
- `bleak` para BLE, con trabajo explícito sobre MTU y backoff
- `textual` para la TUI
- Los vectores de test de `bitchat4agents` como oráculo de interop
- `bitchat-tui` **solo** como referencia del formato binario de paquetes

Es la opción con mejor relación esfuerzo/resultado: elimina ~2.400 LOC de criptografía ya sustituidas, y sale sin bugs heredados.

### Opción C — Reutilizar un núcleo Python existente y añadir la TUI ⚠️ Alternativa rápida
Fork de `bitchat4agents` (Unlicense) o de la arquitectura de `BITTOR-TUI` (sin licencia → solo como referencia de diseño), y añadir la capa Textual. Entrega una TUI funcional en poco tiempo, pero hereda su alcance deliberadamente estrecho (`bitchat4agents` declara explícitamente no cubrir todo el protocolo) y obliga a mantener un fork.

---

## 8. Esfuerzo estimado (Opción B)

| Fase | Contenido | LOC Python | Tiempo |
|---|---|---|---|
| 0 | **Vectores dorados de los `.log` + arnés de test + `pyproject.toml`** | ~200 | 2-3 días |
| 1 | Codec binario: `BitchatPacket`, flags, payload, padding PKCS#7 | ~900 | 3-4 días |
| 2 | BLE: escaneo, GATT, MTU real, notify/write, backoff, estado | ~600 | 4-5 días |
| 3 | Noise XX: `noiseframework` + wrapper `NoiseMessage` + sesiones por par | ~500 | 3-4 días |
| 4 | Legacy: AES-GCM, Ed25519 (firmar **y** verificar), PBKDF2 para canales | ~300 | 2 días |
| 5 | Fragmentación + LZ4 + relay mesh (TTL, bloom, dedup) + ACKs | ~700 | 4-5 días |
| 6 | Persistencia JSON + estado de sesión | ~200 | 1 día |
| 7 | Comandos (17) + orquestación asyncio | ~750 | 3-4 días |
| 8 | TUI Textual: sidebar, panel, input, popup, help bar | ~700 | 4-5 días |
| | **Total** | **~4.850** | **~5-7 semanas** |

Hitos verificables:
- **F1** (≈2 sem.): Discovery + handshake Noise XX **interoperando con la app iOS/Android real**, validado con vectores. Es el riesgo principal (R4) y el que decide el proyecto.
- **F2** (≈4 sem.): chat público y canales con contraseña, extremo a extremo.
- **F3** (≈6 sem.): DMs, relay multi-salto, persistencia.
- **F4** (≈7 sem.): TUI pulida y empaquetado.

Con la Opción C, un equivalente funcional de F1+F2 puede lograrse en **1-2 semanas**.

---

## 9. Recomendación

1. **Antes de escribir una línea de Python**, construir la Fase 0: extraer los vectores dorados de los 4 `.log` commiteados (paquetes reales de iOS, handshake XX completo) y construir un test que los reproduzca byte a byte. Es el único modo de que esto no se convierta en depuración a ciegas por BLE.
2. **Opción B**, salvo que el objetivo sea tener un cliente usable ya mismo — entonces Opción C sobre `bitchat4agents`.
3. **No portar** `noise_protocol.rs` ni `noise_session.rs`. No solo porque haya librerías: también porque tienen 3 agujeros de seguridad reales (§3.1.b) y ~1.100 LOC de logging commiteado.
4. **Usar la librería de Noise solo para el handshake.** El transporte necesita framing propio por el prefijo de nonce de 4 B LE (§5.1). Es un requisito de diseño, no un detalle.
5. **Reimplementar el wire format desde el Swift oficial**, no desde `payload_handling.rs`, que tiene el orden de campos invertido (§5.3).
6. **No reproducir** el bucle de una sola tarea: usar `asyncio` con handlers de paquete en tasks separadas, lo que además elimina el congelamiento de UI (§R6).
7. Fijar el backend de BLE y el MTU real en el primer commit; es la decisión que más afecta a la experiencia en Linux.
8. **Vale la pena avisar al upstream.** Con 14 meses sin commits y 18 issues abiertos, este informe (bugs concretos con `file:line`, 3 agujeros de seguridad, un round-trip de DM roto y los vectores dorados en los `.log`) es material útil para quien mantenga el proyecto.

---

## 10. Alcance: Android + Linux

**Objetivo de producto: interoperar con la app Android de BitChat en Linux. iOS queda fuera de alcance.**

### 10.1 Qué cambia y qué no

| Elemento | ¿Afectado? | Motivo |
|---|---|---|
| Formato de paquete (cabecera 14 B, flags, payload) | **No** | `permissionlesstech/bitchat-android` declara ser *"fully protocol-compatible with the iOS version"*: mismos tipos de paquete, mismo enrutado, mismos UUID. El codec validado en Fase 0/1 sirve igual. |
| UUIDs GATT | **No** | `F47B5E2D-…B5C` (mainnet) / `…B5A` (testnet), característica `A1B2C3D4-…4C5D`. Compartidos. |
| MTU / fragmentación | **Sí, a favor** | Ver §10.2. |
| Ruido de bleak en Linux | **Sí, es el problema principal** | Ver §6 R1/R2. |
| H2 (longitud del mensaje Noise) | **Se mantiene abierto** | Ver §10.3. |

### 10.2 MTU: el problema es de Linux, no de Android

| Plataforma | MTU | Consecuencia |
|---|---|---|
| **Android 14+** | **517** por defecto del stack | El primer cliente GATT solicita 517 y se ignoran solicitudes posteriores. Caben 514 B de ATT. |
| iOS | 185 negociado | Por eso el Rust trocea a **150 B** (*"conservative for iOS BLE"*, `fragmentation.rs:151`). |
| **Linux (BlueZ vía bleak)** | **23** salvo hack | `bleak` siempre devuelve 23. Con `_acquire_mtu()` se puede forzar. |

Esto tiene una consecuencia favorable y cuantificada: con MTU 514 útil, el chunk de fragmento puede pasar de **150 B a 514 B**, y el dato útil por fragmento de **137 B a 501 B**. Un mensaje de 1024 B pasa de **8 fragmentos a 3**. Está cubierto por `test_chunk_size_para_android`.

Corolario: **el valor de 150 B heredado de iOS es subóptimo para un objetivo Android+Linux.** Debe parametrizarse según el MTU real negociado, con 150 B como valor conservador de reserva.

### 10.3 Precisión sobre los vectores: la plataforma es desconocida

Los logs **no mencionan ninguna plataforma** (cero coincidencias de `android`/`iphone`/`apple`/`google`/`swift`). Los etiquetar como "iOS" fue una suposición mía **sin evidencia**, y hay que corregirlo:

| Peer id | Identidad |
|---|---|
| `234de4e300000000` | **El propio cliente Rust.** `main.rs:255-257` genera 4 bytes aleatorios, de ahí los 4 ceros finales. |
| `8b7f0cb466d3f967` | **El par remoto.** 8 bytes reales. |

Así que los vectores muestran tráfico en **dirección par → cliente**, con un emisor cuya plataforma **no se puede determinar** con los datos disponibles. Dado que Android e iOS comparten protocolo, la validación del codec se mantiene; pero **H2 no se puede descartar** hasta saber de qué plataforma vinieron los bytes.

---

## 11. Hallazgo decisivo: `bitchat-tui` habla un dialecto RETIRADO

**Este es el resultado más importante del análisis, y lo invalida la premise de "migrar".**

El código de `permissionlesstech/bitchat-android` define el protocolo vigente. Su `MessageType` **renumera** los tipos respecto a `bitchat-tui`, y donde el número se solapa **el significado cambia**:

| Valor | `bitchat-tui` (legacy) | Android (actual) | Consecuencia |
|-------|------------------------|-------------------|--------------|
| `0x02` | `KeyExchange` | **`MESSAGE`** | El `MESSAGE` de Android se lee como intercambio de claves |
| `0x10` | `NoiseHandshakeInit` | **`NOISE_HANDSHAKE`** | — |
| `0x11` | `NoiseHandshakeResp` | **`NOISE_ENCRYPTED`** | Un handshake se descifra como transporte, y viceversa |
| `0x12` | `NoiseEncrypted` | *no definido* | — |
| `0x20` | `ProtocolAck` | **`FRAGMENT`** | Un acuse se interpreta como fragmento |
| `0x21` | `ProtocolAck`/negociación | **`REQUEST_SYNC`** | — |
| `0x22` | `ProtocolNack` | **`FILE_TRANSFER`** | — |
| `0x05-0x07` | `FragmentStart/Continue/End` | *no existen* | Hay un único `FRAGMENT` en `0x20` |

El error es **silencioso**: no hay excepción, sólo bytes válidos interpretados como otro tipo de mensaje. Un cliente portado del Rust emitiría paquetes que ninguna app actual entiende.

### Otros desfases confirmados en el código Android

| Aspecto | `bitchat-tui` | Android actual |
|---------|----------------|----------------|
| Cabecera | 13 B (documentado; en realidad 14) | **`HEADER_SIZE_V1 = 14`**, v2 = 16 |
| Flag `HAS_ROUTE` | no existe | **`0x08`**, sólo en v2 |
| Relleno | **todo** a cubos 256/512/1024/2048 | **sólo tramas Noise** (`BLEPacketPaddingPolicy`) |
| Fragmentación | 150 B, umbral 500 | **469 B, umbral 512** |
| Tope de fragmentos | — | **256 por conjunto**, se rechaza |
| Compresión | LZ4 (inactiva) | **DEFLATE** |
| Tipos de protocolo | 24 | 9, más-holder de `route` en v2 |

### 11.1 H2 RESUELTO — el handshake sí es Noise XX estándar

Los vectores de Cacophony/Noise-C publicados en
`app/src/test/kotlin/com/bitchat/android/noise/NoiseExternalVectorTest.kt`
dan la respuesta definitiva, y la aritmética cuadra exactamente:

| Mensaje | Payload | Cifrado | Estructura Noise XX | ✓ |
|---------|---------|---------|---------------------|---|
| `msg1` `-> e` | 16 B | **48 B** | `e`(32) + payload **en claro** | ✓ |
| `msg2` `<- e,ee,s,es` | 15 B | **111 B** | `e`(32) + `s` cifrada(48) + payload+tag(31) | ✓ |
| `msg3` `-> s,se` | 11 B | **75 B** | `s` cifrada(48) + payload+tag(27) | ✓ |
| transporte ×3 | 11/17/20 B | +16 B | sólo crece el tag AEAD | ✓ |

Y contra eso, lo observado en los vectores de `debug.log`:

| Observado | Estructura | ✓ |
|-----------|------------|---|
| `NOISE_HANDSHAKE_INIT` 32 B | `msg1` con payload vacío | ✓ |
| `NOISE_HANDSHAKE_RESP` **96 B** | `msg2` con payload vacío (32+48+16) | ✓ |
| `NOISE_HANDSHAKE_RESP` **64 B** | `msg3` con payload vacío (48+16) | ✓ |

**Conclusión:** el handshake es Noise XX estándar. El 96 B era `msg2` y el 64 B era `msg3`; el error era del cliente Rust, que etiqueta ambos como `0x11` e ignora `0x04`. Con el dialecto actual hay un único tipo `NOISE_HANDSHAKE (0x10)` y el rol se decide por estado de sesión.

**No existía desviación de protocolo en Noise.** El prefijo de nonce de 4 B sigue siendo propietario de BitChat, pero sólo en el transporte (`0x11`).

---

## 12. Registro de Fases 0 y 1

### Fase 0 — vectores y arnés ✅

**17 tests.** Ver el detalle en §12.2.

### Fase 1 — codec de payloads ✅ (parcial)

**20 tests.** Fichero nuevo: `src/pybitchat/protocol/payloads.py` (~330 LOC).

| Payload | Estado | Evidencia |
|---|---|---|
| `ANNOUNCE` (0x01) | ✅ **Decodificado y validado** | 4 vectores. El payload es **sólo el nickname UTF-8, sin prefijo de longitud**; la longitud la da `payload_len`. Valores: `"anonymous"` (9 B), `"anon6328"` (8 B). |
| `MESSAGE` (0x04) | ✅ Decodificado (Fase 0) | 2 vectores |
| `NOISE_ENCRYPTED` (0x12) | 🟡 Framing confirmado | 7 vectores. `nonce u32 LE` (4 B) ‖ ciphertext. El nonce little-endian está probado con `0x01020304 → 04 03 02 01`. |
| `FRAGMENT_*` (0x05-0x07) | 📐 Según spec, round-trip probado | Sin vectores reales. `fragment_id(8) ‖ index u16 BE ‖ total u16 BE ‖ original_type u8 ‖ data`. Reensamblado byte-exacto verificado para 512/1024/2048 B. |
| resto | 🚧 Pendiente | — |

**Decisión de diseño importante:** los payloads que no sabemos decodificar se conservan en `OpaquePayload`, **byte-exactos y sin interpretar**, con una referencia al caso abierto que los cubre. No se adivinan. Es exactamente el error que hizo fracasar al cliente Rust, y hay un test que verifica la propiedad general: *decodificar y re-codificar cualquier payload de cualquier vector devuelve los bytes originales*.

### Tres correcciones al informe

1. **La cabecera es de 14 bytes, no de 13.** Verificado numéricamente: leer el `sender_id` en el offset 14 coincide **21/21** vectores; en el offset 13 coincide **0/21**. El "13-byte header" que afirma el README de Android (y que mi borrador recogía) es incorrecto.
2. **El bug de los canales no es un orden de campos invertido**, sino que falta poner `MSG_FLAG_HAS_CHANNEL` (0x40) al escribir. Ver §5.3.
3. **Los vectores no son "de iOS"**, son de un par remoto de plataforma desconocida. Ver §10.3.

### Hallazgo colateral: la fragmentación es más agresiva de lo que parece

Con `chunk_size=150` el dato útil por fragmento es `150 - 13 = 137 B`. Como el **menor cubo de relleno de BitChat es 256 B**, *todo* mensaje rellenado necesita **al menos 2 fragmentos**, incluso un "hola" de 106 B. Está documentado y testeado en `test_paquete_pequeno_aun_necesita_dos_fragmentos`.

### H2 refinado — sigue abierto y es el bloqueo principal

Los datos reales del handshake Noise:

| Mensaje | Longitud observada | Noise XX estándar |
|---|---|---|
| `NOISE_HANDSHAKE_INIT` | **32 B** | 32 B (`e`) ✅ coincide |
| `NOISE_HANDSHAKE_RESP` | **96 B** (sesión 1) | 80 B (`e` 32 + estática cifrada 48) ❌ |
| `NOISE_HANDSHAKE_RESP` | **64 B** (sesión 2) | 80 B ❌ |

Dos hechos nuevos y incómodos:

1. **Ni 96 ni 64 son 80.** El handshake de BitChat se desvía estructuralmente de Noise XX estándar, más allá del framing de 4 B del transporte.
2. **El mismo par remoto envía dos longitudes distintas** (96 y 64). O hay variosWAP etapas del handshake etiquetadas con el mismo tipo, o existen dos variantes de patrón.

El log del Rust registra *"response length: 64"*, así que el propio Rust tampoco cuadra con lo que recibió.

**Implicación:** Fase 3 no es "usar una librería y pegar 40 líneas de framing". Hay que entender primero qué intercambia exactamente el par remoto. Es el riesgo que decide el proyecto y requiere captura con hardware.

### Casos abiertos tras Fase 1

| # | Qué falta | Bloquea |
|---|---|---|
| **H1** | Bytes de 7 paquetes que el cliente Rust envió (quedan en 116 B sin relleno). Necesita captura con `write_debug_log` activo. | Nada crítico |
| **H2** | Layout de `NOISE_HANDSHAKE_RESP` (64 y 96 B). Contradice el estándar. | **Fase 3** |
| **H3** | ~~Layout de `NOISE_IDENTITY_ANNOUNCE`~~ **Descartado**: `0x13` no existe en `MessageType`. No hay nada que decodificar. | Nada |
| **H4** | ~~Layout de `HANDSHAKE_REQUEST`~~ **Descartado**: `0x25` no existe en `MessageType`. No hay nada que decodificar. | Nada |
| **H5** | ~~Layout de `PROTOCOL_ACK`~~ **Descartado**: `0x22` es `FILE_TRANSFER` en el dialecto actual, resuelto como H7 (§12.7). | Nada |

---

### 12.6 Fase 3 — Noise XX ✅

**27 tests**, todos contra los vectores oficiales de
`NoiseExternalVectorTest.kt` (`permissionlesstech/bitchat-android`).

Ficheros nuevos:

| Fichero | LOC | Función |
|---|---|---|
| `noise/session.py` | ~250 | Handshake sobre `noiseprotocol`, con nuestra API |
| `noise/framing.py` | ~170 | Framing propietario: prefijo de nonce de 4 B |
| `noise/primitives.py` | ~150 | HKDF de Noise, X25519 y AEAD sobre `cryptography` |
| `noise/state_errors.py` | ~25 | Errores propios, para no filtrar la librería |
| `tests/test_noise_vectors.py` | ~380 | 27 tests |

Dependencias (`requirements.txt`): `cryptography>=45`, `noiseprotocol>=0.3`.

#### El hallazgo importante: BitChat usa Noise rev. 32/33, no rev. 34

La especificación cambió `MixKey` entre revisiones:

| Revisión | `MixKey` | Clave de cifrado |
|---|---|---|
| **32/33** (BitChat, `noiseprotocol`) | `ck, temp = HKDF(ck, ikm, 2)`, **sin** `MixHash(temp)` | salida **2** |
| 34 (spec actual, `snow`) | `ck, temp_h = HKDF(...)`, con `MixHash(temp_h)` | salida **1** |

Ambas son Noise válido, pero producen claves distintas. Se comprobó
empíricamente: una implementación propia siguiendo la rev. 34 **coincide en msg1
(48 B) y diverge en msg2, desde el primer byte de la estática cifrada**.

Y msg1 dando "verde" es engañoso: son 32 B de clave pública en claro más el
payload también en claro, porque a esas alturas no hay clave de cifrado. **msg1
no valida nada criptográfico.** El primer dato real es msg2, donde las 111
bytes del vector obligan a acertar en `MixKey`, `HKDF` y `AD`.

Por eso el motor del handshake es `noiseprotocol` (verificado byte a byte) y no
una implementación propia. Es exactamente lo que recomendaba §5.1 y §7, y la
prueba es que sin esa decisión no habría interop.

#### Lo que sí escribimos a mano

El **framing de transporte**, que es lo único propietario de BitChat:

```
┌──────────────┬───────────────────────────────┐
│ nonce  4 B   │  ciphertext ChaCha20-Poly1305 │
│ u32 LE       │  (+ tag de 16 B)               │
└──────────────┴───────────────────────────────┘
```

`NoiseTransportCipher` fuerza `SetNonce()` antes de cada operación
(`k = HMAC(k, n_le_64)`). El nonce explícito de la trama manda sobre cualquier
contador interno: es lo que evita reutilizar clave con el mismo nonce al
reanudar una sesión, que es justo para lo que está el prefijo.

Un detalle que parecía inocuo y no lo era: sin clave, `HMAC(b"", n)` produce 32
bytes válidos y el canal **funcionaría** cifrando con material derivado de la
nada. `_epoch_key` comprueba la clave vacía y falla.

#### Bug de diseño encontrado y cerrado

El test `test_el_prefijo_lleva_el_contador` destapó que `noiseprotocol` **borra**
`symmetric_state`, `hash_fn` y `handshake_state` del `NoiseProtocol` en
`handshake_done()`. Pedir el `split()` otra vez revienta con `AttributeError`.
La sesión captura el par `(c1, c2)` que devuelve el propio `write_message` en el
último mensaje, que es el único momento en que existe.

#### Verificación end-to-end

```
msg1  48 B  OK
msg2 111 B  OK
msg3  75 B  OK
handshake hash idéntico en ambos lados: True
ida y vuelta por el framing propietario: OK
```

Con payload vacío (que es el tráfico real de BitChat): **32, 96 y 64 bytes**,
que es exactamente lo que se observó en los vectores de `debug.log`.

#### Lo que sigue abierto

El **prologue de producción** sigue siendo desconocido. Los vectores usan
`"John Galt"`, que es material de test de Cacophony. Si BitChat usara un
prologue no vacío en producción, nuestro handshake no interoperaría aunque
todos los vectores passasen. La app oficial deja el prologue vacío por defecto,
pero **no está confirmado para BitChat**: es la siguiente comprobación
prioritaria y requiere una captura real o leer `NoiseSession.kt`.

### 12.7 H6, H7 y H8 RESUELTOS — los tres payloads vivos del dialecto actual

Al revisar los "huecos" H3, H4 y H5 pendientes apareció que **ninguno de los
tres existe ya en el protocolo actual**. Son artefactos del dialecto retirado:

| Hueco | Tipo declarado | Valor | ¿Existe en `MessageType`? |
|-------|----------------|-------|---------------------------|
| H3 | `NOISE_IDENTITY_ANNOUNCE` | `0x13` | **No** |
| H4 | `HANDSHAKE_REQUEST` | `0x25` | **No** |
| H5 | `PROTOCOL_ACK` | `0x22` | Sí, pero es **`FILE_TRANSFER`** |

Decodificar el layout de `HANDSHAKE_REQUEST` no aportaría nada: ninguna app
Android actual envía ese tipo. Lo útil era cerrar los tipos vivos que aún
desconocíamos, que son los que de verdad bloquean la interoperación.

Todos se cerraron leyendo **las dos caras** del código Kotlin — el `encode` y el
`decode` de cada clase — porque un layout confirmado por una sola cara es una
hipótesis, no un hecho.

| Caso | Tipo | Fichero autoritativo |
|------|------|----------------------|
| H6 | `REQUEST_SYNC` `0x21` | `model/RequestSyncPacket.kt` |
| H7 | `FILE_TRANSFER` `0x22` | `model/BitchatFilePacket.kt` |
| H8 | `VOICE_FRAME` `0x29` | `features/voice/VoiceBurstPacket.kt` |

#### `MESSAGE` (0x02): cerrado por completo

El layout ya validado con los vectores resultaba ser **un subconjunto** del
real. Faltaban cuatro campos opcionales, todos con flag:

    flags      u8
    timestamp  u64 big-endian
    id         u8 len + bytes
    sender     u8 len + bytes
    content    u16 big-endian len + bytes   (o `encrypted_content` si 0x80)
    [0x04] original_sender    u8 len + bytes
    [0x08] recipient_nickname u8 len + bytes
    [0x10] sender_peer_id      u8 len + bytes
    [0x20] mentions   u8 count + (u8 len + bytes) x count
    [0x40] channel     u8 len + bytes

Dos detalles que importan y no son evidentes:

- **El orden de los campos opcionales es el orden ascendente de sus flags**
  (0x04, 0x08, 0x10, 0x20, 0x40). No es una convención: si se escribieran en
  otro orden, el receptor leería longitudes equivocadas y todo lo posterior
  sería basura.
- El `ByteBuffer` se crea con `order(ByteOrder.BIG_ENDIAN)` explícito
  (`BitchatMessage.kt:190`). Todos los enteros son big-endian, incluido el
  `timestamp`.

#### H6 — `REQUEST_SYNC`: TLV de longitud u16

GCS (conjuntos ordenados comprimidos), **no** un listado de mensajes:

    [tipo u8][longitud u16 big-endian][valor]

con `0x01` = P (parámetro Golomb-Rice, u8), `0x02` = M (rango, u32
big-endian) y `0x03` = bitstream.

#### H7 — `FILE_TRANSFER`: TLV con una excepción que rompe la interop

Misma estructura, pero **el TLV `CONTENT` (`0x04`) usa longitud u32
big-endian** mientras que los demás usan u16. Confirmado en las dos
direcciones:

    encode  BitchatFilePacket.kt:86-88   buf.putInt(content.size)
    decode  BitchatFilePacket.kt:118-128  if (t == TLVType.CONTENT) off += 4

⚠️ El comentario de cabecera del propio fichero afirma *"Length field for TLV
is 2 bytes for all TLVs"*, y **es falso**: está desactualizado respecto al
código. Fiarse del comentario rompe la interop en cuanto llega contenido, y
sólo con ficheros grandes, lo que lo hace un fallo intermitente y difícil de
diagnosticar.

#### Regla de compatibilidad hacia delante

El decoder oficial **salta los tags desconocidos en lugar de rechazarlos**
(`BitchatFilePacket.kt:130-141`), porque un par puede rellenar un paquete con
TLVs que el otro no conoce. Se replica exactamente.

#### H8 — `VOICE_FRAME`: `flags` por igualdad exacta

`flags` **no es acumulable**. El decoder hace `when (flags)` con coincidencia
exacta, así que un valor combinado como `0x03` no casa con ningún caso y se
rechaza:

    burst_id   8 B
    sequence   u16 big-endian
    flags      u8        0x00 | 0x01 | 0x02 | 0x04
    0x01 START     -> codec u8
    0x02 END       -> total_data_packets u16 BE, duration_ms u32 BE
    0x04 CANCELED  -> (nada)
    0x00 FRAMES    -> (frame_len u16 BE ‖ frame) * N

El códec **sólo viaja en el mensaje de inicio**; los paquetes de datos llevan
`flags = 0` y no lo repiten.

#### Bugs reales encontrados y cerrados al implementar

1. **`False is not None` es `True` en Python.** El cálculo de flags trataba
   `is_relay` e `is_private` como campos opcionales, así que
   `is_relay=False` activaba el bit 0x01 y contaminaba todos los mensajes. Se
   separaron los flags booleanos de los campos opcionales.

2. **`OPEN_QUESTIONS` no distinguía dialecto.** El registro estaba indexado por
   el valor crudo, pero `PROTOCOL_ACK` (legacy) y `FILE_TRANSFER` (actual) son
   **ambos `0x22`**: una entrada pisaba a la otra y se perdía una de las dos
   respuestas. Ahora la clave es `(dialecto, valor_crudo)`, con las vistas
   derivadas `OPAQUE_BY_DIALECT` y `open_question_for()`.

El segundo es exactamente la clase de error que este proyecto evita por
diseño: no fallaba ruidosamente, sino que devolvía una respuesta plausible y
equivocada.

#### Estado tras esta fase

167 tests, todos en verde:

| Fichero | Tests | Cubre |
|---------|-------|-------|
| `test_dialect.py` | 21 | Constantes Android con `file:line` |
| `test_payloads.py` | 25 | `ANNOUNCE`, fragmentación, opacidad |
| `test_golden_packets.py` | 19 | Los 21 paquetes reales, byte a byte |
| `test_noise_vectors.py` | 39 | Handshake XX, framing, anti-replay |
| `test_current_payloads.py` | 44 | `MESSAGE`, TLV, voz (nuevo) |
| `test_dispatch.py` | 19 | Despacho por dialecto y ambigüedad (nuevo) |

### 12.8 Fase 2a — la capa que no necesita Bluetooth ✅

La Fase 2 (integración BLE) estaba bloqueada por una VM sin adaptador
Bluetooth. Al revisar el código se vio que **la mayor parte de esa fase no
necesita hardware**: el transporte es la única pieza que lo necesita, y todo lo
demás es lógica pura que se puede probar con un enlace en memoria.

Ficheros nuevos:

| Fichero | Contenido |
|---------|-----------|
| `protocol/compression.py` | DEFLATE crudo, heurística de entropía, guardas anti zip-bomb |
| `protocol/reassembly.py` | Receptor de fragmentos con los límites de `AppConstants` |
| `ble/gatt.py` | UUIDs GATT y constantes de ciclo de vida de pares |
| `mesh/transport.py` | Abstracción de transporte + `MockTransport` |

Modificados: `protocol/packet.py` (compresión y `WirePayload`),
`protocol/payloads.py` (cálculo del tamaño de fragmento).

Resultado: **238 tests en verde**, de los que 71 son nuevos.

#### La bomba de interoperabilidad más importante del proyecto

`BinaryProtocol.kt:38-57` explica por qué existe `WirePayload`, y es un detalle
que no se puede pasar por alto:

> *DEFLATE output is not canonical and clients use different encoders (java.util.zip.Deflater here, Apple's compression_encode_buffer on iOS), so re-compressing can change the preimage and reject a valid packet.*

El `Deflater` de Java y el `zlib` de Python **no producen los mismos bytes** para
la misma entrada. Como la verificación de firma re-codifica el paquete para
reconstruir lo que se firmó, re-comprimir un payload ajeno cambiaría la
preimagen y **haría que una firma válida dejara de validar**.

Android lo evita guardando los bytes originales del cable en `WirePayload` y
reusándolos al re-codificar (`BinaryProtocol.kt:527-530` y `:246-250`). El
mismo mecanismo evita que un relé que decrementa el TTL sustituya la codificación
de quien originó el paquete (`:46`).

**Sin esto, el fallo sólo aparecería con mensajes largos y en un relé real**:
intermitente, y atribuible al ruido de la red en lugar de a la implementación.

Implementado como `WirePayload` en `protocol/packet.py`, con `matches()` que
comprueba que el payload sigue siendo el mismo antes de reusar los bytes.

#### DEFLATE crudo, y por qué importa

`CompressionUtil.kt:48` usa `Deflater(DEFAULT_COMPRESSION, true)`: raw deflate,
sin cabeceras zlib. En Python, `wbits=-15`. Con el valor por defecto de `zlib`
(`wbits=15`) se producirían 2 bytes de cabecera que el receptor no puede
descomprimir.

Para **leer** sí se toleran ambas formas, igual que la app
(`decompressExact`, `:117-125`): si los bytes parecen zlib, se prueba ese
formato primero y, si no cuadra exactamente, se cae a raw.

#### Guardas de descompresión

Replicadas de `BinaryProtocol.kt:501-539`, en este orden:

| Guarda | Valor | Qué evita |
|--------|-------|-----------|
| Tamaño original en `1..MAX_PAYLOAD_LENGTH` | 1 B – 10 MiB | Reservar memoria absurda |
| Ratio ≤ 50 000:1 | `MAX_COMPRESSION_RATIO` | Bomba de compresión |
| La expansión debe medir **exactamente** lo declarado | — | Stream truncado o sobredeclarado |
| `eof` debe ser cierto | — | Queda salida sin colocar (tamaño subdeclarado) |
| `unused_data` vacío | — | Bytes basura tras el final del stream |

El ratio se comprueba **antes** de desinflar: es la única barrera útil, porque
comprobarlo después ya es tarde.

#### Tamaño del fragmento: no es `MAX_FRAGMENT_SIZE`

`FragmentManager.createFragments` (`:106-108`) calcula:

    overhead = cabecera + sender + [recipient] + [ruta]
              + cabecera_de_fragmento + margen_de_relleno
    datos = min(512 - overhead, MAX_FRAGMENT_SIZE)

El margen de relleno no es opcional: `MessagePadding.optimalBlockSize` mete el
paquete en el siguiente cubo, y sin reservarlo el fragmento se pasa de largo.

Sin destinatario ni ruta, el total queda en 469 y sobra margen. El problema
aparece con la **ruta**: cada salto añade `1 + 8 × saltos` bytes de sobre, y
`MAX_FRAGMENT_SIZE` es una constante fija que no los contempla. Con seis saltos
el fragmento mide 548 B y el relleno lo empuja al cubo de 1024, con lo que cada
fragmento pasa a costar el doble de lo previsto. Implementado como
`max_fragment_data_size()` y `max_fragment_payload_size()`, con `has_recipient`
y `hops`.

**Inconsistencia detectada en el propio Android:** `FragmentManager.kt:98` usa
`headerSize = 13` para v1 y `15` para v2, cuando la cabecera real es 14 y 16
(`BinaryProtocol.kt:208-209`). Se usa 14 aquí: un byte de más de margen sólo hace
el fragmento más conservador; equivocarse al revés sí desbordaría el bloque.

> De paso, esto explica probablemente el "13-byte header" del README de Android:
> alguien leyó esta constante en vez del formato de cable.

#### Validación cruzada de los UUID GATT

Los mismos tres UUID aparecen en dos implementaciones independientes:

- `BLEService.swift` de `permissionlesstech/bitchat` y `data_structures.rs:48`.
- `util/AppConstants.kt`, sección `Mesh.Gatt`, en la app Android.

Que coincidan no es casualidad: es el mismo protocolo visto desde dos sitios. Se
documenta en `ble/gatt.py`, que **no los redefine** sino que los toma de
`protocol/types.py`, y hay un test que compara ambas fuentes para que no se
separen sin que nadie se entere.

#### Reensamblado de fragmentos

Semántica exacta de `FragmentManager.handleFragment`:

- El reensamblado es **siempre por índice**, nunca por orden de llegada
  (`:264`). El primer fragmento puede perderse y aun así el resultado debe ser
  idéntico al original.
- Si un `fragment_id` llega con otro `total` u otro `originalType` del que se
  había registrado, se rechaza el fragmento **y se borra el conjunto entero**
  (`:198-203`). Dos emisores distintos con el mismo id harían que cualquier
  reensamblado fuese inventado.
- Un reenvío del mismo índice **sustituye**, no suma: el tamaño acumulado
  descuenta lo que ya había en esa posición (`:237-238`). Sin esto, un par que
  reenvía mucho consumiría el límite de 1 MiB sin motivo.
- `FragmentPayload.isValid()` valida `index < total` (`:127`), que es lo que
  impide que un índice fuera de rango complete el conjunto con un resultado
  truncado.

El reloj del reensamblador es inyectable, de modo que el timeout de 30 s se
prueba sin dormir.

#### Lo que queda para 2b

Hace falta hardware Bluetooth y la máquina Linux con el teléfono asociado.
Lo pendiente:

- `ble/bleak_transport.py`: `Transport` sobre `bleak` (escaneo, advertisings,
  GATT con `SERVICE_UUID` y `CHARACTERISTIC_UUID`, escritura al CCCD).
- Política de reenvío y descubrimiento de pares.
- Emparejamiento BLE con Android, que es la parte más frágil de toda la
  operación.

---

### 12.9 Conformidad con los tests de la app, y v2 implementado

Sin adaptador Bluetooth no se puede probar la interoperabilidad en vivo. Lo que
sí se puede es comprobar nuestro códec contra **los tests que el propio autor del
protocolo escribió sobre su propia implementación**:
`app/src/test/java/com/bitchat/android/protocol/BinaryProtocolTest.kt`, 54 casos.

Portados 48 a `tests/test_conformance.py`, con el nombre original del test entre
comillas en cada caso para poder rastrearlo.

> ⚠️ Esto **no sustituye** a la interoperabilidad en vivo. Nada offline la
> sustituye. Demuestra que nuestro códec coincide con la especificación tal y
> como la implementa la app; no que la app acepte lo que emitimos.

#### Tres bugs reales que sólo aparecen al portar

**1. `sender_id` no se normalizaba a 8 bytes.** La app rellena con ceros lo que
sobra corto y trunca lo que sobra largo (`BinaryProtocol.kt:311-315`). Nosotros lo
emitíamos tal cual, así que un `sender_id` de 4 bytes producía un paquete 4 bytes
corto que **nadie podía decodificar**.

Ahora se rellena, pero **no se trunca**: truncar la identidad de un par es
dirección incorrecta, y un id demasiado largo debe descubrirse aquí en vez de
convertirse en otro par distinto. Es una divergencia deliberada respecto a la app.

**2. `zlib.error` se propagaba en vez de rechazarse.** Este es el más grave. En
Python, datos comprimidos malformados no dan un resultado vacío: `decompress()`
lanza `zlib.error`. Sin capturarla, **un par que mandase un payload comprimido
corrupto tumbaría el bucle de recepción**, en vez de que se descartara el paquete.

La app lo captura explícitamente (`CompressionUtil.kt:121-124`) para que la
comprobación zlib pueda fallar y caer a raw sin romper nada. Corregido igual.

**3. v2 no estaba implementado.** El header de 16 bytes, la longitud u32 y la
ruta opcional eran un `UnsupportedVersionError`. Ahora están implementados.

Android nunca *emite* v2 (`BitchatPacket.version = 1u`), pero su suite de tests lo
cubre a fondo, así que dejarlo fuera descartaba unos 25 vectores de conformidad.

#### El vector más valioso: el codificador ajeno

`re-encoding preserves a foreign encoder's compressed payload` construye a mano
un bloque *stored* de DEFLATE: bytes que **el `zlib` de Python jamás generaría**
para ese payload. Comprueba que re-codificar reproduce los bytes del originator.

Portado tal cual, y con un testextra que demuestra el riesgo por el otro lado:
descartando el `WirePayload` y comprimiendo de nuevo, la salida cambia. Eso es
justo lo que haría que una firma válida dejara de verificar.

#### La preimagen de firma, que nos faltaba

`toBinaryDataForSigning` quita la firma y **fija el TTL a 0**
(`SYNC_TTL_HOPS`). La razón está en el propio test de la app, y merece citarse:

> *If TTL leaks into the signed data, a packet relayed even once would fail
> signature verification at the recipient.*

El TTL baja en cada salto, así que un paquete reenviado *una sola vez* llega con
un TTL distinto del firmado. Implementado como
`Packet.to_binary_data_for_signing()`, con un test que comprueba que la firma no
depende de los saltos dados.

#### El off-by-one de la cabecera resulta estar propagado

`FragmentManager.kt:98` usa 13 y 15 donde los reales son 14 y 16. El mismo error
aparece en el comentario de un test de la app (*"v2 header size (15 bytes)"*). No
fue un descuido puntual: está repetido, y de ahí procede el "13-byte header" del
README.

#### Estado

286 tests en verde. `test_conformance.py` aporta 48.

---

## 13. Anexo: los tres oráculos de validación

### 13.1 Definición

| Oráculo | Origen | Resultado |
|---|---|---|
| 1. Round-trip byte a byte | Los propios bytes del log | **21/21** idénticos, relleno incluido |
| 2. Longitud sin relleno | `packet_debug.log` | **21/21** coinciden con nuestro parser |
| 3. Valores en claro | Lectura manual del hex | `anonymous`, `anon6328`, `hi`, peer_id, id de 36 chars |

El oráculo 2 reproduce la aritmética de la cabecera de forma independiente:

| Paquete | `packet_debug.log` | Nuestro parser |
|---|---|---|
| Announce | 39 | 14+8+8+9 = **39** |
| Message | 106 | 14+8+8+76 = **106** |
| HandshakeRequest | 72 | 14+8+50 = **72** |
| NoiseHandshakeResp | 126 | 14+8+8+96 = **126** |
| NoiseEncrypted (x7) | 306 | 14+8+8+276 = **306** |

### 13.2 Qué validan y qué no

| Validan | No validan |
|---|---|
| Estructura de la cabecera de 14 B | Numeración de tipos (los vectores son legacy) |
| Flags dirigidos por bits | Política de relleno (el par rellenaba todo) |
| Longitud y orden del payload de `Message` | Layouts de `NoiseIdentityAnnounce`, `HandshakeRequest`, `ProtocolAck` |
| `Announce` = nickname sin prefijo | Tope de fragmentos y DEFLATE |
| Framing de 4 B del transporte Noise | Rutas explícitas de la v2 |

Esta distinción la verifica `test_dialect.py`: los vectores se analizan
siempre con `dialect=LEGACY` y `decode_payload` se niega a adivinar en los 6
valores ambiguos.

### 13.3 Limitación del entorno

Esta VM es un guest de VirtualBox **sin adaptador Bluetooth** y sin WSL. Todo lo
anterior es criptografía y códec puros, así que se validó aqui. La Fase 2
(integración BLE) necesita la máquina Linux donde el teléfono está asociado.

---

## 14. Decisiones que corresponden al usuario

- **Objetivo**: ¿cliente nuevo desde cero, o continuacion de itchat-tui? El upstream lleva 14 meses sin commits y 18 issues abiertos.
- **Opcion A/B/C** según §7. Con Fase 0 y 1 ya hechas, la B va por delante.
- **Plataformas**: Android + Linux, confirmado. §10.2 define el MTU a usar.
- **Alcance del protocolo**: ¿sólo mesh BLE, o también Nostr/geohash como itchat4agents? Lo segundo duplica el esfuerzo y no es necesario para hablar con Android por BLE.
- **Disponibilidad de hardware**: ¿hay un teléfono Android con la app de BitChat disponible para capturar tráfico? Es lo que desbloquea H1 y H2 (§12.7: H3-H5 eran tipos del dialecto retirado y ya no son útiles). También es el requisito de la Fase 2, que esta VM no puede ejecutar por no tener adaptador Bluetooth.
- **Siguiente paso entre dos**: (a) Fase 2 BLE, que necesita el portátil Linux con el teléfono asociado, o (b) seguir cerrando huecos de códec, que se pueden hacer aquí. Ninguno bloquea al otro.
- **Prologue de Noise**: el de producción sigue sin confirmar. La app oficial no lo fija (`NoiseSession.kt:244` no llama a `setPrologue`) y los vectores usan material de test de Cacophony. Es la comprobación prioritaria que queda dentro de la Fase 3.
- **Licencia**: itchat-tui es MIT/Apache-2.0, asi que portar su formato es legal. itchat4agents es Unlicense. kaganisildak/bitchat-python NO tiene licencia y no es reutilizable.
