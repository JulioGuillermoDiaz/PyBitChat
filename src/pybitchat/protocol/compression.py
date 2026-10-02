"""Compresión de payloads: DEFLATE crudo, tal y como lo hace BitChat.

Fuente: `protocol/CompressionUtil.kt` de `permissionlesstech/bitchat-android`.

## Formato

BitChat comprime el **payload** del paquete, no el paquete entero. Cuando lo
hace, activa `IS_COMPRESSED` (0x04) en la cabecera y antepone el tamaño original
al stream DEFLATE:

    payload_len (u16 BE) = 2 + len(comprimido)          -- para v1
    payload = original_size (u16 BE) ‖ datos DEFLATE

⚠️ Para **v1** el tamaño original es **u16**, no u32. El u32 es sólo de v2
(`BinaryProtocol.kt:343` usa `putShort`; el `putInt` de `:341` está en la rama
de v2). Es un detalle fácil de invertir y rompe la descompresión en silencio.

## DEFLATE sin cabeceras

`CompressionUtil.kt:48`:

    val deflater = Deflater(Deflater.DEFAULT_COMPRESSION, true)
                                        // ^^^^ true = raw, sin cabeceras

En Python es `wbits=-15`. Con `wbits=15` (el valor por defecto de `zlib`) se
producirían las cabeceras zlib de 2 bytes y **el receptor no podría
descomprimirlo**. La app lo hace así por compatibilidad con iOS, que también
produce raw deflate bajo el nombre engañoso de `COMPRESSION_ZLIB`.

## ⚠️ La salida de DEFLATE no es canónica

El `Deflater` de Java y el `zlib` de Python **no producen los mismos bytes** para
la misma entrada, aunque los dos sean DEFLATE correcto. Esto no es un detalle
teórico: la verificación de firma de BitChat re-codifica el paquete para
reconstruir lo que se firmó, así que

> *re-compressing can change the preimage and reject a valid packet*
> — `BinaryProtocol.kt:43-45`

Es decir: si re-comprimiéramos un payload que acabamos de recibir, la firma de
quien lo envió dejaría de validar. Android lo evita guardando los bytes
originales del cable en `WirePayload` y reusándolos al re-codificar; también se
usa para que un relé que decrementa el TTL no sustituya la codificación de otro.

**Consecuencia para nosotros:** al decodificar hay que conservar los bytes
comprimidos tal cual llegaron (ver `WirePayload` en `packet.py`) y no
re-comprimir nunca un payload ajeno.
"""

from __future__ import annotations

import zlib

#: Tamaño a partir del cual se considera comprimir (`AppConstants.Protocol`).
#: `COMPRESSION_THRESHOLD_BYTES`
COMPRESSION_THRESHOLD_BYTES = 100

#: Tope del payload ya expandido (`AppConstants.Protocol.MAX_PAYLOAD_LENGTH`).
MAX_PAYLOAD_LENGTH = 10_485_760  # 10 MiB

#: Ratio máximo de expansión tolerado (`BinaryProtocol.kt:518`). Por encima se
#: trata como bomba de compresión y se rechaza sin desinflar.
MAX_COMPRESSION_RATIO = 50_000

#: Proporción máxima de bytes distintos por debajo de la cual se comprime
#: (`CompressionUtil.kt:34`).
UNIQUE_BYTE_RATIO_THRESHOLD = 0.9

#: `wbits` de DEFLATE crudo: sin cabeceras zlib.
RAW_DEFLATE = -15

#: `wbits` de zlib con cabeceras, sólo para *leer* datos de otros que sí las
#: añadan. BitChat nunca emite esto, pero `decompressExact` lo tolera.
ZLIB_WRAPPED = 15


class CompressionError(ValueError):
    """Los datos comprimidos no son válidos o no son seguros de expandir."""


# --------------------------------------------------------------------------
# Decisión: ¿comprimir?
# --------------------------------------------------------------------------


def unique_byte_ratio(data: bytes) -> float:
    """Proporción de bytes distintos, según `CompressionUtil.kt:31-35`.

    El denominador es `min(len(data), 256)`, no `len(data)`: con menos de 256
    bytes no puede haber más de 256 distintos, y el ratio se satura en 1.0
    justo cuando todos los bytes son diferentes, que es el peor caso para
    comprimir.
    """
    distintos = len(set(data))
    return distintos / min(len(data), 256)


def should_compress(data: bytes) -> bool | None:
    """¿Merece la pena comprimir este payload?

    Reproduce `CompressionUtil.shouldCompress` exactamente:

    - menos de 100 bytes: nunca (`:25`)
    - ratio de bytes distintos ≥ 0.9: no (`:35`)

    Devuelve `None` para payloads por debajo del umbral, que es como la app
    comunica "no comprimir" sin llegar a evaluar la entropía. Distinguirlo de
    `False` permite a quien llama distinguir "no procede" de "no conviene".
    """
    if len(data) < COMPRESSION_THRESHOLD_BYTES:
        return None
    return unique_byte_ratio(data) < UNIQUE_BYTE_RATIO_THRESHOLD


# --------------------------------------------------------------------------
# Compresión
# --------------------------------------------------------------------------


def compress(data: bytes) -> bytes | None:
    """Comprime con DEFLATE crudo. Devuelve `None` si no conviene.

    Las mismas condiciones que la app (`:44` y `:64`): por debajo del umbral se
    devuelve `None`, y si el resultado no es **estrictamente** menor que la
    entrada también. Un payload que no se reduce no se manda comprimido: se
    pagarían 2 bytes de tamaño original y el receptor no ganaría nada.
    """
    if len(data) < COMPRESSION_THRESHOLD_BYTES:
        return None

    # level=-1 es Z_DEFAULT_COMPRESSION, equivalente a Deflater.DEFAULT_COMPRESSION.
    co = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, RAW_DEFLATE)
    comprimido = co.compress(data) + co.flush()

    if comprimido and len(comprimido) < len(data):
        return comprimido
    return None


# --------------------------------------------------------------------------
# Descompresión
# --------------------------------------------------------------------------


def looks_like_zlib(data: bytes) -> bool:
    """Comprobación de cabecera RFC 1950 (`CompressionUtil.kt:147-154`).

    Un stream raw puede empezar por dos bytes que *parezcan* una cabecera zlib
    válida, así que esto sólo decide **cuál formato se prueba primero**. No es
    una decisión de confianza.
    """
    if len(data) < 2:
        return False
    cmf, flg = data[0], data[1]
    return (
        (cmf & 0x0F) == 8
        and (cmf >> 4) <= 7
        and ((cmf << 8) | flg) % 31 == 0
    )


def _inflate_exact(data: bytes, original_size: int, wbits: int) -> bytes | None:
    """Infla un stream completo hasta *exactamente* `original_size` bytes.

    Traducción de `CompressionUtil.inflateExact` (`:168-194`), incluidas las
    tres rechazos que la app considera obligatorias:

    1. `written != originalSize` -> el stream está truncado o es más corto de
       lo declarado.
    2. La sonda de desbordamiento: si el inflater produce **un solo byte más**
       de los declarados, el tamaño real es mayor. En Python queda cubierto por
       `eof`: si quedara salida pendiente, el stream no habría terminado.
    3. `remaining != 0` -> sobran bytes sin consumir tras el final del stream.

    Devolver `None` en vez de raise: quien llama decide si es un paquete
    descartable o un error de programación.
    """
    d = zlib.decompressobj(wbits)
    salida = d.decompress(data, original_size)

    if len(salida) != original_size:
        return None
    # Cubre a la vez el stream truncado y el tamaño subdeclarado.
    if not d.eof:
        return None
    # Bytes sobrantes despues del final del stream.
    if d.unused_data:
        return None
    return salida


def check_expansion(compressed_size: int, original_size: int) -> None:
    """Valida la petición de expansión antes de desinflar nada.

    De `BinaryProtocol.decode` (`:501-521`) y `isValidRequest` (`:100-114`):

    - payload comprimido no vacío
    - tamaño original en `1..MAX_PAYLOAD_LENGTH`
    - ratio ≤ 50 000

    El ratio se comprueba **antes** de reservar memoria: es la barrera contra
    una bomba de compresión, y comprobarla después ya no sirve de nada.
    """
    if compressed_size <= 0:
        raise CompressionError("payload comprimido vacío")
    if not 1 <= original_size <= MAX_PAYLOAD_LENGTH:
        raise CompressionError(
            f"tamaño expandido fuera de rango: {original_size} "
            f"(se admite 1..{MAX_PAYLOAD_LENGTH})"
        )
    ratio = original_size / compressed_size
    if ratio > MAX_COMPRESSION_RATIO:
        raise CompressionError(
            f"ratio de compresión sospechoso: {ratio:.0f}:1 "
            f"(máximo {MAX_COMPRESSION_RATIO}:1)"
        )


def decompress(compressed: bytes, original_size: int) -> bytes:
    """Descomprime un payload de BitChat a su tamaño declarado.

    Acepta **raw deflate** (lo que emite BitChat) y, como red de seguridad,
    zlib con cabeceras: `decompressExact` (`:117-125`) prueba el formato que
    parezca zlib primero y si no cuadra exactamente cae a raw. Se replica para
    no ser más estrictos que el otro extremo del enlace.

    A diferencia de la app, esto **lanza** en lugar de devolver `None`: en
    Python es más útil que el error se propague, y el decodificador de
    cabecera lo convierte en "paquete descartable". No hay un `try/except`
    silencioso escondiendo nada.
    """
    check_expansion(len(compressed), original_size)

    # Mismo orden que la app: el formato que *parece* zlib se prueba primero.
    if looks_like_zlib(compressed):
        resultado = _inflate_exact(compressed, original_size, ZLIB_WRAPPED)
        if resultado is not None:
            return resultado

    resultado = _inflate_exact(compressed, original_size, RAW_DEFLATE)
    if resultado is None:
        raise CompressionError(
            f"no se pudo descomprimir a exactamente {original_size} bytes; "
            "el stream está truncado, sobredeclarado o lleva bytes sobrantes"
        )
    return resultado


__all__ = [
    "COMPRESSION_THRESHOLD_BYTES",
    "MAX_COMPRESSION_RATIO",
    "MAX_PAYLOAD_LENGTH",
    "RAW_DEFLATE",
    "UNIQUE_BYTE_RATIO_THRESHOLD",
    "ZLIB_WRAPPED",
    "CompressionError",
    "check_expansion",
    "compress",
    "decompress",
    "looks_like_zlib",
    "should_compress",
    "unique_byte_ratio",
]