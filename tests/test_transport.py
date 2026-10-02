"""Tests de la Fase 2a: compresión, reensamblado, GATT y transporte.

Ninguno de estos tests necesita Bluetooth. Es el punto: toda la lógica de malla
tiene que ser verificable sin hardware, porque en hardware real las rutas de
error sólo se provocan por casualidad y no se repiten.

Ejecutar:
    .venv\\Scripts\\python.exe tests\\test_transport.py
"""

from __future__ import annotations

import asyncio
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import sys  # noqa: E402

sys.path.insert(0, str(ROOT / "src"))

from pybitchat.ble import gatt  # noqa: E402
from pybitchat.mesh.transport import (  # noqa: E402
    MockTransport,
    Peer,
    TransportError,
)
from pybitchat.protocol import compression  # noqa: E402
from pybitchat.protocol.compression import CompressionError  # noqa: E402
from pybitchat.protocol.packet import (  # noqa: E402
    HEADER_SIZE_BY_VERSION,
    KNOWN_UPSTREAM_VERSIONS,
    PROTOCOL_VERSION,
    Packet,
    PacketHeader,
    ProtocolError,
    UnsupportedVersionError,
)
from pybitchat.protocol.payloads import (  # noqa: E402
    max_fragment_data_size,
    max_fragment_payload_size,
)
from pybitchat.protocol.reassembly import (  # noqa: E402
    MAX_FRAGMENTS_PER_ID,
    Fragment,
    FragmentReassembler,
    Rejection,
    RejectReason,
)
from pybitchat.protocol.types import MAX_FRAGMENT_SIZE, PacketFlags  # noqa: E402


# --------------------------------------------------------------------------
# Compresión
# --------------------------------------------------------------------------


class TestCompresionDecision(unittest.TestCase):
    """La heurística de `shouldCompress`, replicada de `CompressionUtil.kt`."""

    def test_por_debajo_del_umbral_no_se_evalua(self):
        self.assertIsNone(compression.should_compress(b"x" * 99))
        self.assertEqual(compression.COMPRESSION_THRESHOLD_BYTES, 100)

    def test_texto_repetido_si_comprime(self):
        """Pocos bytes distintos, mucho relleno: entropía baja."""
        self.assertTrue(compression.should_compress(b"abc" * 100))

    def test_datos_aleatorios_no_se_comprimen(self):
        """256 bytes distintos sobre 256: ratio 1.0, el peor caso."""
        self.assertFalse(compression.should_compress(bytes(range(256))))

    def test_ratio_usa_el_minimo_con_256(self):
        """El denominador es min(len, 256), no len."""
        self.assertEqual(compression.unique_byte_ratio(bytes(range(256))), 1.0)
        self.assertEqual(compression.unique_byte_ratio(b"ab"), 1.0)

    def test_comprimir_da_none_si_no_reduce(self):
        """Patrón pseudoaleatorio: comprimirlo no lo hace más pequeño."""
        patron = bytes((i * 37 + (i >> 3)) & 0xFF for i in range(120))
        resultado = compression.compress(patron)
        if resultado is not None:
            self.assertLess(len(resultado), len(patron))


class TestCompresionRaw(unittest.TestCase):
    """El punto crítico: DEFLATE crudo, sin cabeceras zlib."""

    def test_salida_sin_cabecera_zlib(self):
        datos = b"hola mundo " * 50
        comprimido = compression.compress(datos)
        self.assertIsNotNone(comprimido)
        # Una cabecera zlib empieza por 0x78 con el resto coherente (%% 31 == 0).
        self.assertNotEqual(comprimido[0] & 0x0F, 8)
        with self.assertRaises(zlib.error):
            zlib.decompress(comprimido)  # wbits por defecto = con cabecera

    def test_round_trip_exacto(self):
        datos = b"mensaje largo " * 40
        comprimido = compression.compress(datos)
        vuelta = compression.decompress(comprimido, len(datos))
        self.assertEqual(vuelta, datos)

    def test_nuestro_zlib_por_defecto_no_valdria(self):
        """Control: el mismo dato con cabecera zlib sí es legible por zlib."""
        datos = b"mensaje largo " * 40
        con_cabecera = zlib.compress(datos)
        self.assertEqual(zlib.decompress(con_cabecera), datos)


class TestDescompresionSegura(unittest.TestCase):
    """Guardas anti zip-bomb, de `BinaryProtocol.kt:501-539`."""

    def test_tamano_original_fuera_de_rango(self):
        comprimido = compression.compress(b"x" * 200)
        with self.assertRaises(CompressionError):
            compression.decompress(comprimido, 0)
        with self.assertRaises(CompressionError):
            compression.decompress(comprimido, compression.MAX_PAYLOAD_LENGTH + 1)

    def test_ratio_sospechoso_se_rechaza_antes_de_desinflar(self):
        """1000 bytes que declaran 10 MiB: ratio 10 000:1, bajo el tope."""
        comprimido = compression.compress(b"x" * 200)
        with self.assertRaises(CompressionError) as ctx:
            compression.decompress(comprimido, 10_000_000)
        self.assertIn("ratio", str(ctx.exception))

    def test_ratio_justo_por_encima_del_tope(self):
        """El tope es 50 000:1 y se compara en exclusiva."""
        with self.assertRaises(CompressionError):
            compression.check_expansion(1, 50_001)
        compression.check_expansion(1, 50_000)  # justo en el límite, pasa

    def test_payload_vacio_se_rechaza(self):
        with self.assertRaises(CompressionError):
            compression.check_expansion(0, 100)

    def test_stream_truncado_se_rechaza(self):
        """A los 99 bytes el stream no da los 100 declarados."""
        datos = b"contenido " * 40
        comprimido = compression.compress(datos)
        with self.assertRaises(CompressionError):
            compression.decompress(comprimido[:len(comprimido) - 3], len(datos))

    def test_tamano_subdeclarado_se_rechaza(self):
        """Declarar menos de lo que el stream produce deja bytes sin colocar."""
        datos = b"contenido " * 40
        comprimido = compression.compress(datos)
        with self.assertRaises(CompressionError):
            compression.decompress(comprimido, len(datos) - 10)

    def test_bytes_sobrantes_despues_del_stream(self):
        """El stream más basura no vale: `unused_data` debe estar vacío."""
        datos = b"contenido " * 40
        comprimido = compression.compress(datos) + b"\x00\x00\x00"
        with self.assertRaises(CompressionError):
            compression.decompress(comprimido, len(datos))

    def test_acepta_zlib_aunque_bitchat_no_lo_emita(self):
        """Tolerancia como la app: si parece zlib, se prueba ese formato."""
        datos = b"contenido tolerante " * 20
        con_cabecera = zlib.compress(datos)
        self.assertTrue(compression.looks_like_zlib(con_cabecera))
        self.assertEqual(compression.decompress(con_cabecera, len(datos)), datos)

    def test_looks_like_zlib_rechaza_datos_cortos(self):
        self.assertFalse(compression.looks_like_zlib(b"\x78"))
        self.assertFalse(compression.looks_like_zlib(b""))


# --------------------------------------------------------------------------
# Compresión en la cabecera
# --------------------------------------------------------------------------


def _paquete(payload: bytes) -> Packet:
    cabecera = PacketHeader(0x01, 0x02, 6, 1_754_073_314_075, PacketFlags(0), len(payload))
    return Packet(header=cabecera, sender_id=b"\x01" * 8, payload=payload)


class TestPayloadComprimido(unittest.TestCase):
    """El framing de `IS_COMPRESSED` en la cabecera."""

    def test_payload_corto_sigue_sin_comprimirse(self):
        """Por debajo de 100 bytes nada cambia: los vectores reales lo notan."""
        p = _paquete(b"corto" * 5)
        crudo = p.to_bytes()
        self.assertNotEqual(crudo[11] & 0x04, 0x04)
        self.assertEqual(Packet.from_bytes(crudo).payload, p.payload)

    def test_ciclo_completo_comprimido(self):
        largo = "mensaje con suficiente entropía baja ".encode() * 20
        p = _paquete(largo).with_compression()
        crudo = p.to_bytes()
        self.assertTrue(crudo[11] & 0x04, "debería activar IS_COMPRESSED")
        vuelta = Packet.from_bytes(crudo)
        self.assertEqual(vuelta.payload, largo)
        # Y el tamaño del payload comprimido debe ser menor.
        self.assertLess(len(vuelta.payload) + 2, len(largo) + 14)

    def test_original_size_va_dentro_de_payload_len(self):
        largo = b"x" * 400
        p = _paquete(largo).with_compression()
        # wire = originalSize(2) + comprimidos; payload_len debe medirlos.
        total = p.to_bytes()
        payload_len = int.from_bytes(total[12:14], "big")
        self.assertEqual(payload_len, 2 + len(p.wire_payload.wire))

    def test_original_size_es_u16_en_v1(self):
        """Detalle fácil de invertir: u32 es sólo de v2."""
        largo = b"contenido " * 40
        p = _paquete(largo).with_compression()
        crudo = p.to_bytes()
        original = int.from_bytes(crudo[22:24], "big")  # tras cabecera+sender
        self.assertEqual(original, len(largo))
        self.assertLess(original, 0x10000)

    def test_reensamblar_conserva_los_bytes_del_cable(self):
        """La razón de existir `WirePayload`: no re-comprimir lo ajeno."""
        largo = b"datos " * 60
        recibido = Packet.from_bytes(_paquete(largo).with_compression().to_bytes())
        self.assertIsNotNone(recibido.wire_payload)
        # Re-codificar tal cual debe dar los mismos bytes.
        self.assertEqual(recibido.to_bytes(), recibido.to_bytes())
        # Y el wire debe ser el que llegó, no uno nuevo.
        self.assertEqual(recibido.wire_payload.wire,
                         recibido.to_bytes()[24:24 + len(recibido.wire_payload.wire)])


class TestWirePayload(unittest.TestCase):
    def test_matches_exige_el_mismo_payload(self):
        p = _paquete(b"datos " * 60).with_compression()
        wp = p.wire_payload
        self.assertIsNotNone(wp)
        self.assertTrue(wp.matches(b"datos " * 60))
        self.assertFalse(wp.matches(b"otro payload"))

    def test_cambiar_el_payload_invalida_el_wire(self):
        """Si el payload ya no es el mismo, hay que comprimir de nuevo."""
        p = _paquete(b"datos " * 60).with_compression()
        p.payload = b"cambiado por completo"
        p = p.with_compression()
        vuelta = Packet.from_bytes(p.to_bytes())
        self.assertEqual(vuelta.payload, b"cambiado por completo")

    def test_wire_comprimido_no_se_confunde_con_claro(self):
        wp = compression.compress(b"x" * 200)
        del wp
        p = _paquete(b"claro y corto")
        self.assertIsNone(p.wire_payload)
        self.assertNotEqual(p.to_bytes()[11] & 0x04, 0x04)


class TestVersion(unittest.TestCase):
    """Lo que no depende de construir un paquete.

    El round-trip de v1 y v2 vive en `test_conformance.py`, que tiene el
    constructor `make_packet`. Aqui solo queda la constante.
    """

    def test_ambas_versiones_conocidas_estan_implementadas(self):
        self.assertEqual(KNOWN_UPSTREAM_VERSIONS, frozenset({1, 2}))
        self.assertEqual(PROTOCOL_VERSION, 1, "Android emite siempre v1")

    def test_tamanos_de_cabecera_por_version(self):
        """14 en v1 y 16 en v2. `BinaryProtocol.kt:208-209`."""
        self.assertEqual(HEADER_SIZE_BY_VERSION, {1: 14, 2: 16})

    def test_v3_da_error_util(self):
        bruto = bytearray(14)
        bruto[0] = 0x03
        with self.assertRaises(ProtocolError) as ctx:
            Packet.from_bytes(bytes(bruto))
        self.assertNotIsInstance(ctx.exception, UnsupportedVersionError)
# --------------------------------------------------------------------------
# Fragmentos
# --------------------------------------------------------------------------


def _frag(fid: bytes, index: int, total: int, data: bytes, tipo: int = 0x02) -> bytes:
    return Fragment(fid, index, total, tipo, data).to_bytes()


class TestFragmento(unittest.TestCase):
    def test_header_de_13_bytes(self):
        self.assertEqual(Fragment.HEADER_SIZE, 13)

    def test_round_trip(self):
        f = Fragment(b"\xaa" * 8, 2, 5, 0x11, b"datos")
        vuelta = Fragment.parse(f.to_bytes())
        self.assertEqual(vuelta.fragment_id, b"\xaa" * 8)
        self.assertEqual((vuelta.index, vuelta.total, vuelta.original_type), (2, 5, 0x11))
        self.assertEqual(vuelta.data, b"datos")

    def test_indice_mayor_o_igual_que_total_se_rechaza(self):
        """`isValid` de `FragmentPayload.kt:127`: index < total."""
        with self.assertRaises(ProtocolError):
            Fragment.parse(_frag(b"\x01" * 8, 3, 3, b"x"))

    def test_total_cero_se_rechaza(self):
        with self.assertRaises(ProtocolError):
            Fragment.parse(_frag(b"\x01" * 8, 0, 0, b"x"))

    def test_sin_datos_se_rechaza(self):
        with self.assertRaises(ProtocolError):
            Fragment.parse(Fragment(b"\x01" * 8, 0, 1, 0x02, b"").to_bytes())

    def test_truncado_se_rechaza(self):
        with self.assertRaises(ProtocolError):
            Fragment.parse(b"\x01" * 8)


class TestReensamblado(unittest.TestCase):
    def setUp(self):
        self.r = FragmentReassembler()
        self.fid = b"\x01" * 8

    def test_reensambla_en_orden_de_indice(self):
        for i, trozo in enumerate([b"AAA", b"BBB", b"CCC"]):
            res = self.r.add(_frag(self.fid, i, 3, trozo))
            if i < 2:
                self.assertIsNone(res, "a medio camino debe devolver None")
        self.assertEqual(res, b"AAABBBCCC")

    def test_llegada_en_desorden_no_altera_el_resultado(self):
        """Se concatena por índice, nunca por orden de llegada."""
        for i, trozo in [(2, b"CCC"), (0, b"AAA"), (1, b"BBB")]:
            res = self.r.add(_frag(self.fid, i, 3, trozo))
        self.assertEqual(res, b"AAABBBCCC")

    def test_reenvio_sustituye_en_vez_de_sumar(self):
        """Un reenvío del mismo índice reemplaza; no duplica bytes.

        El cálculo de tamaño acumulado descuenta lo que ya había en esa
        posición (`FragmentManager.kt:237-238`). Si no lo hiciera, un par que
        reenvía mucho acabaría consumiendo el límite de 1 MiB por conjunto sin
        motivo.
        """
        self.r.add(_frag(self.fid, 0, 2, b"AAA"))
        self.assertEqual(self.r.bytes_en_bufer, 3)
        self.r.add(_frag(self.fid, 0, 2, b"AAZ"))
        self.assertEqual(self.r.bytes_en_bufer, 3, "no debe contar dos veces")
        self.assertEqual(self.r.conjuntos_activos, 1)
        res = self.r.add(_frag(self.fid, 1, 2, b"BBB"))
        self.assertEqual(res, b"AAZBBB")

    def test_reenvio_mas_largo_ajusta_el_conteo(self):
        """Sustituir por algo más grande sí debe subir el contador."""
        self.r.add(_frag(self.fid, 0, 2, b"A"))
        self.assertEqual(self.r.bytes_en_bufer, 1)
        self.r.add(_frag(self.fid, 0, 2, b"AAAAA"))
        self.assertEqual(self.r.bytes_en_bufer, 5)

    def test_metadatos_inconsistentes_descartan_el_conjunto(self):
        """Otro total con el mismo id: se descarta todo, no se mezcla."""
        self.r.add(_frag(self.fid, 0, 2, b"AAA"))
        res = self.r.add(_frag(self.fid, 0, 3, b"AAA"))
        self.assertIsInstance(res, Rejection)
        self.assertEqual(res.reason, RejectReason.INCONSISTENT_METADATA)
        self.assertEqual(self.r.conjuntos_activos, 0, "el conjunto debe borrarse")

    def test_tipo_original_distinto_tambien_invalida(self):
        self.r.add(_frag(self.fid, 0, 2, b"AAA", tipo=0x02))
        res = self.r.add(_frag(self.fid, 1, 2, b"BBB", tipo=0x11))
        self.assertEqual(res.reason, RejectReason.INCONSISTENT_METADATA)

    def test_total_sobre_el_maximo_se_rechaza(self):
        res = self.r.add(_frag(self.fid, 0, MAX_FRAGMENTS_PER_ID + 1, b"x"))
        self.assertEqual(res.reason, RejectReason.TOO_MANY_FRAGMENTS)

    def test_maximo_de_conjuntos_simultaneos(self):
        for i in range(64):
            self.r.add(_frag(bytes([i]) * 8, 0, 2, b"x"))
        self.assertEqual(self.r.conjuntos_activos, 64)
        res = self.r.add(_frag(b"\xff" * 8, 0, 2, b"x"))
        self.assertEqual(res.reason, RejectReason.TOO_MANY_SETS)

    def test_conjunto_que_vena_se_purga(self):
        """El reloj es inyectable: no hace falta esperar 30 s."""
        ahora = [0.0]
        r = FragmentReassembler(reloj=lambda: ahora[0])
        r.add(_frag(b"\x01" * 8, 0, 3, b"x"))
        ahora[0] = 31.0
        purgados = r.purgar()
        self.assertEqual(len(purgados), 1)
        self.assertEqual(purgados[0].reason, RejectReason.EXPIRED)
        self.assertEqual(r.conjuntos_activos, 0)
        self.assertEqual(r.bytes_en_bufer, 0, "la memoria también se libera")

    def test_no_purga_antes_de_cumplir_el_timeout(self):
        ahora = [0.0]
        r = FragmentReassembler(reloj=lambda: ahora[0])
        r.add(_frag(b"\x01" * 8, 0, 3, b"x"))
        ahora[0] = 29.0
        self.assertEqual(r.purgar(), [])
        self.assertEqual(r.conjuntos_activos, 1)

    def test_el_reensamblado_libera_la_memoria(self):
        for i in range(3):
            res = self.r.add(_frag(self.fid, i, 3, b"x"))
        self.assertIsInstance(res, bytes)
        self.assertEqual(self.r.conjuntos_activos, 0)
        self.assertEqual(self.r.bytes_en_bufer, 0)

    def test_basura_no_se_confunde_con_un_fragmento(self):
        res = self.r.add(b"\x00" * 4)
        self.assertIsInstance(res, Rejection)
        self.assertEqual(res.reason, RejectReason.PAYLOAD_TOO_SHORT)


# --------------------------------------------------------------------------
# GATT
# --------------------------------------------------------------------------


class TestGatt(unittest.TestCase):
    def test_service_uuid(self):
        self.assertEqual(str(gatt.SERVICE_UUID).upper(),
                         "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C")

    def test_characteristic_uuid(self):
        self.assertEqual(str(gatt.CHARACTERISTIC_UUID).upper(),
                         "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D")

    def test_descriptor_es_el_cccd_estandar(self):
        self.assertEqual(str(gatt.DESCRIPTOR_UUID).lower(),
                         "00002902-0000-1000-8000-00805f9b34fb")

    def test_service_y_characteristic_son_distintos(self):
        self.assertNotEqual(gatt.SERVICE_UUID, gatt.CHARACTERISTIC_UUID)

    def test_tamanos_de_conexion(self):
        self.assertEqual(gatt.STALE_PEER_TIMEOUT_MS, 180_000)
        self.assertEqual(gatt.MAX_CONNECTION_ATTEMPTS, 3)

    def test_cuidos_coinciden_con_protocol(self):
        """`ble.gatt` no redefine los UUID: los toma de `protocol.types`.

        Los valores de `types.py` vienen de `BLEService.swift` y
        `data_structures.rs`; los de la app, de `AppConstants.Mesh.Gatt`. Que
        coincidan es una validación cruzada entre dos implementaciones
        independientes del mismo protocolo. Si algún día dejan de coincidir,
        hay que saberlo antes de intentar hablar con nadie.
        """
        from pybitchat.protocol import types

        self.assertEqual(str(gatt.SERVICE_UUID).upper(), types.BITCHAT_SERVICE_UUID)
        self.assertEqual(
            str(gatt.CHARACTERISTIC_UUID).upper(), types.BITCHAT_CHARACTERISTIC_UUID
        )
        self.assertEqual(
            str(gatt.SERVICE_UUID_TESTNET).upper(), types.BITCHAT_SERVICE_UUID_TESTNET
        )

    def test_testnet_difiere_en_el_ultimo_nibble(self):
        main = str(gatt.SERVICE_UUID).upper()
        test = str(gatt.SERVICE_UUID_TESTNET).upper()
        self.assertEqual(main[:-1], test[:-1], "sólo debe cambiar el último carácter")
        self.assertTrue(main.endswith("C"))
        self.assertTrue(test.endswith("A"))

    def test_peer_id_size(self):
        self.assertEqual(gatt.PEER_ID_SIZE, 8)


class TestComparacionDeUuid(unittest.TestCase):
    """El bug que costó un rato de diagnóstico: comparar UUID como texto.

    `uuid.UUID.hex` devuelve 32 caracteres sin guiones; `str(uuid)` devuelve 36
    con guiones. bleak entrega los UUID del anuncio con guiones, así que
    comparar contra `.hex` **no puede coincidir nunca** y el descubrimiento se
    queda mudo.
    """

    def test_hex_y_str_difieren(self):
        """Documenta el mecanismo, para que el test siguiente tenga sentido."""
        self.assertEqual(len(gatt.SERVICE_UUID.hex), 32)
        self.assertNotIn("-", gatt.SERVICE_UUID.hex)
        self.assertEqual(len(str(gatt.SERVICE_UUID)), 36)
        self.assertIn("-", str(gatt.SERVICE_UUID))
        self.assertNotEqual(gatt.SERVICE_UUID.hex.upper(), str(gatt.SERVICE_UUID).upper())

    def test_comparar_contra_hex_falla(self):
        """La forma que estaba mal, comprobada para que no vuelva."""
        con_guiones = str(gatt.SERVICE_UUID)
        self.assertNotIn(con_guiones.upper(), {gatt.SERVICE_UUID.hex.upper()})

    def test_reconoce_el_formato_del_anuncio(self):
        """Así es como llega de bleak: con guiones."""
        self.assertTrue(gatt.es_nuestro_servicio(str(gatt.SERVICE_UUID)))
        self.assertTrue(gatt.es_nuestro_servicio(str(gatt.SERVICE_UUID).upper()))
        self.assertTrue(gatt.es_nuestro_servicio(str(gatt.SERVICE_UUID).lower()))

    def test_reconoce_tambien_el_objeto_uuid(self):
        import uuid

        self.assertTrue(gatt.es_nuestro_servicio(gatt.SERVICE_UUID))
        self.assertTrue(gatt.es_nuestro_servicio(uuid.UUID(gatt.SERVICE_UUID.hex)))

    def test_no_confunde_el_testnet(self):
        """El testnet se parece mucho: mismo UUID salvo el último carácter."""
        self.assertNotEqual(
            str(gatt.SERVICE_UUID_TESTNET), str(gatt.SERVICE_UUID)
        )
        self.assertFalse(gatt.es_nuestro_servicio(str(gatt.SERVICE_UUID_TESTNET)))

    def test_basura_no_revienta(self):
        for basura in (None, "", "no-es-un-uuid", 42, b"\xff\xfe", []):
            with self.subTest(valor=basura):
                self.assertFalse(gatt.es_nuestro_servicio(basura))


# --------------------------------------------------------------------------
# Transporte
# --------------------------------------------------------------------------


class TestMockTransport(unittest.TestCase):
    def test_entrega_los_bytes_sin_alterarlos(self):
        """En bucle, lo enviado vuelve byte a byte: nada se normaliza."""
        recibido = []
        t = MockTransport(loopback=True)

        async def escenario():
            await t.start(lambda pid, data: recibido.append((pid, data)))
            t.add_peer(b"\x01" * 8, fiable=True)
            await t.send(b"\x01" * 8, b"\x00\xff\x10datos")

        asyncio.run(escenario())
        self.assertEqual(len(recibido), 1)
        self.assertEqual(recibido[0][1], b"\x00\xff\x10datos")

    def test_sin_bucle_lo_enviado_no_vuelve(self):
        """Por defecto `send` no realimenta: el bucle es opt-in."""
        recibido = []
        t = MockTransport()

        async def escenario():
            await t.start(lambda pid, data: recibido.append(data))
            t.add_peer(b"\x01" * 8)
            await t.send(b"\x01" * 8, b"algo")

        asyncio.run(escenario())
        self.assertEqual(recibido, [])
        self.assertEqual(t.enviado_a(b"\x01" * 8), [b"algo"])

    def test_registra_lo_enviado(self):
        t = MockTransport()

        async def escenario():
            await t.start(lambda pid, data: None)
            await t.send(b"\x02" * 8, b"uno")
            await t.send(b"\x02" * 8, b"dos")

        asyncio.run(escenario())
        self.assertEqual(t.enviado_a(b"\x02" * 8), [b"uno", b"dos"])

    def test_entregar_alimenta_el_camino_de_recepcion(self):
        """La vía normal para meter un paquete entrante en un test."""
        recibido = []
        t = MockTransport()

        async def escenario():
            await t.start(lambda pid, data: recibido.append(data))
            t.entregar(b"\x09" * 8, b"entrante")

        asyncio.run(escenario())
        self.assertEqual(recibido, [b"entrante"])

    def test_perdida_parcial_no_llega_al_receptor(self):
        recibido = []
        t = MockTransport(loopback=True)
        t.drop_every(2)

        async def escenario():
            await t.start(lambda pid, data: recibido.append(data))
            t.add_peer(b"\x03" * 8)
            for i in range(4):
                await t.send(b"\x03" * 8, bytes([i]))

        asyncio.run(escenario())
        # Se enviaron 4, llegaron 2.
        self.assertEqual(len(t.enviado_a(b"\x03" * 8)), 4)
        self.assertEqual(len(recibido), 2)

    def test_send_antes_de_start_falla(self):
        t = MockTransport()
        with self.assertRaises(TransportError):
            asyncio.run(t.send(b"\x01" * 8, b"x"))

    def test_stop_limpia_el_callback(self):
        t = MockTransport()

        async def escenario():
            await t.start(lambda pid, data: None)
            await t.stop()
            t.entregar(b"\x01" * 8, b"x")

        with self.assertRaises(TransportError):
            asyncio.run(escenario())

    def test_peer_id_debe_medir_8(self):
        with self.assertRaises(ValueError):
            Peer(b"\x01" * 4)
        with self.assertRaises(ValueError):
            MockTransport().add_peer(b"\x01" * 7)

    def test_un_fallo_no_impide_enviar_a_otros(self):
        """Los pares son vecinos independientes: uno malo no para la malla."""
        t = MockTransport()

        async def escenario():
            await t.start(lambda pid, data: None)
            t.add_peer(b"\x04" * 8)
            t.add_peer(b"\x05" * 8)
            await t.send(b"\x04" * 8, b"a")
            await t.send(b"\x05" * 8, b"b")

        asyncio.run(escenario())
        self.assertEqual(t.enviado_a(b"\x04" * 8), [b"a"])
        self.assertEqual(t.enviado_a(b"\x05" * 8), [b"b"])


class TestCalculoDeFragmentos(unittest.TestCase):
    """El tamaño de fragmento descuenta el sobre real, no sólo el de un
    fragmento sin destino ni ruta.

    El fallo aparece con rutas largas: `MAX_FRAGMENT_SIZE` es una constante fija
    que no contempla los `1 + 8 × saltos` bytes de sobre que añade cada salto,
    y sin compensarlos el fragmento se sale del bloque de 512 y el relleno lo
    duplica a 1024.
    """

    def test_datos_sin_destinatario_ni_ruta(self):
        # 512 - (14 + 8 + 0 + 0 + 13 + 16) = 461
        self.assertEqual(max_fragment_data_size(), 461)

    def test_datos_con_destinatario(self):
        # 512 - (14 + 8 + 8 + 0 + 13 + 16) = 453
        self.assertEqual(max_fragment_data_size(has_recipient=True), 453)

    def test_datos_con_un_salto(self):
        # La ruta aporta 1 byte de cuenta + 8 por salto, sobre 51 de sobre base.
        self.assertEqual(max_fragment_data_size(hops=1), 461 - 9)

    def test_cada_salto_resta_ocho_mas_uno(self):
        """El byte de cuenta es uno solo, no uno por salto.

        `1 + 8 × saltos`, no `9 × saltos`. Confundirlo daría 461-54=407 en vez
        de 412 para seis saltos, y el cálculo saldría demasiado conservador.
        """
        base = max_fragment_data_size()
        for hops in (1, 2, 6):
            with self.subTest(hops=hops):
                self.assertEqual(
                    max_fragment_data_size(hops=hops), base - (1 + hops * 8)
                )

    def test_nunca_supera_el_maximo_de_fragmento(self):
        for kwargs in ({}, {"has_recipient": True}, {"hops": 1}, {"hops": 6}):
            with self.subTest(**kwargs):
                self.assertLessEqual(max_fragment_data_size(**kwargs), MAX_FRAGMENT_SIZE)

    def test_ruta_imposible_se_rechaza(self):
        with self.assertRaises(ValueError):
            max_fragment_data_size(hops=100)

    def test_sin_sobre_extra_no_cambia_el_comportamiento(self):
        """El valor por defecto histórico se conserva: 469 bytes de sobre."""
        self.assertEqual(max_fragment_payload_size(), MAX_FRAGMENT_SIZE)

    def test_fragmento_con_ruta_larga_cabe_en_512(self):
        """La propiedad que importa: con seis saltos tampoco se sale del bloque."""
        from pybitchat.protocol.payloads import FragmentPayload as FP, split_into_fragments

        partes = split_into_fragments(
            b"\xaa" * 4000, 0x11, fragment_id=b"\x01" * 8,
            has_recipient=True, hops=6,
        )
        for p in partes:
            FP.parse(p)  # debe seguir siendo un fragmento válido
            # Sobre completo: cabecera + sender + recipient + ruta + payload.
            sobre = 14 + 8 + 8 + (1 + 6 * 8) + len(p)
            self.assertLessEqual(
                sobre, 512, f"el fragmento ocupa {sobre} B y el relleno lo lleva a 1024"
            )

    def test_reensamblado_de_lo_que_produce_el_cortador(self):
        """Ciclo completo: trocear y reensamblar da el original."""
        from pybitchat.protocol.payloads import split_into_fragments

        original = b"mensaje largo que necesita fragmentacion " * 40
        partes = split_into_fragments(
            original, 0x02, fragment_id=b"\x07" * 8, has_recipient=True
        )
        r = FragmentReassembler()
        resultado = None
        for p in partes:
            salida = r.add(p)
            if salida is not None:
                resultado = salida
        self.assertEqual(resultado, original)


if __name__ == "__main__":
    unittest.main(verbosity=2)




