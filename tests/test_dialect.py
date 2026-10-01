"""Guardarraíles del dialecto de protocolo.

Existe un test por cada forma en que se puede reintroducir el error más grave
posible en este proyecto: **confundir el dialecto retirado de `bitchat-tui` con
el dialecto actual de la app Android.**

El riesgo es silencioso. Donde los valores numéricos se solapan, el significado
cambia:

    0x02  legacy KEY_EXCHANGE  vs  actual MESSAGE
    0x11  legacy NOISE_HANDSHAKE_RESP  vs  actual NOISE_ENCRYPTED
    0x20  legacy PROTOCOL_ACK  vs  actual FRAGMENT

Un cliente que mezcle ambos enums no lanza ningún error: emite bytes válidos que
la otra parte interpreta como otro tipo de mensaje.

Ejecutar:
    python tests/test_dialect.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol import (  # noqa: E402
    BITCHAT_SERVICE_UUID,
    BITCHAT_SERVICE_UUID_TESTNET,
    HEADER_SIZE,
    HEADER_SIZE_V2,
    MAX_FRAGMENT_SIZE,
    MAX_FRAGMENTS_PER_ID,
    NOISE_C_VECTORS,
    NOISE_PROTOCOL_NAME,
    PacketFlags,
)
from pybitchat.protocol.types import (  # noqa: E402
    FRAGMENT_SIZE_THRESHOLD,
    BLE_MTU_ANDROID_14,
    BLE_MTU_BLUEZ_DEFAULT,
    LEGACY_FRAGMENT_CHUNK_SIZE,
    LegacyMessageType,
    MessageType,
    should_pad_for_ble,
)


class TestLosDialectosNoCoinciden(unittest.TestCase):
    """Cada valor solapado debe significar algo distinto en cada dialecto."""

    #: Valores donde ambos dialectos definen el mismo número con distinto
    #: propósito. Se compara contra `AMBIGUOUS_VALUES`, que lo calcula el
    #: propio código, para que la lista no pueda desviarse en silencio.
    TRAMPAS = {
        0x02: ("KEY_EXCHANGE", "MESSAGE"),
        0x10: ("NOISE_HANDSHAKE_INIT", "NOISE_HANDSHAKE"),
        0x11: ("NOISE_HANDSHAKE_RESP", "NOISE_ENCRYPTED"),
        0x20: ("VERSION_HELLO", "FRAGMENT"),
        0x21: ("VERSION_ACK", "REQUEST_SYNC"),
        0x22: ("PROTOCOL_ACK", "FILE_TRANSFER"),
    }

    def test_la_lista_de_trampas_coincide_con_el_codigo(self):
        """`AMBIGUOUS_VALUES` debe ser exactamente el conjunto de `TRAMPAS`."""
        from pybitchat.protocol.payloads import AMBIGUOUS_VALUES

        self.assertEqual(
            set(AMBIGUOUS_VALUES),
            set(self.TRAMPAS),
            "el conjunto de valores ambiguos cambió: revisa el análisis de dialecto",
        )

    def test_valores_solapados_tienen_significado_distinto(self):
        for valor, (nombre_legacy, nombre_actual) in self.TRAMPAS.items():
            with self.subTest(valor=hex(valor)):
                self.assertIn(valor, LegacyMessageType._value2member_map_)
                self.assertIn(valor, MessageType._value2member_map_)
                self.assertNotEqual(
                    LegacyMessageType(valor).name,
                    MessageType(valor).name,
                    f"{hex(valor)} significa lo mismo en ambos dialectos: "
                    "la tabla de trampas está desactualizada",
                )

    def test_los_nombres_de_las_trampas_son_los_esperados(self):
        """Si upstream renumera, este test obliga a revisar el análisis."""
        for valor, (nombre_legacy, nombre_actual) in self.TRAMPAS.items():
            with self.subTest(valor=hex(valor)):
                self.assertEqual(LegacyMessageType(valor).name, nombre_legacy)
                self.assertEqual(MessageType(valor).name, nombre_actual)

    def test_el_dialecto_legacy_tiene_tipos_inexistentes_en_el_actual(self):
        """0x04/0x05-0x07/0x12 no existen en el dialecto actual."""
        for valor in (0x04, 0x05, 0x06, 0x07, 0x12, 0x13, 0x25):
            with self.subTest(valor=hex(valor)):
                self.assertIn(
                    valor,
                    LegacyMessageType._value2member_map_,
                    f"{hex(valor)} ya no existe en el dialecto legacy",
                )
                self.assertNotIn(
                    valor,
                    MessageType._value2member_map_,
                    f"{hex(valor)} no debería existir en el dialecto actual",
                )

    def test_el_actual_es_mas_pequeno_que_el_legacy(self):
        """El dialecto actual colapsa tipos; el legacy los expande."""
        self.assertLess(len(list(MessageType)), len(list(LegacyMessageType)))


class TestConstantesDelDialectoActual(unittest.TestCase):
    """Valores tomados del código de `permissionlesstech/bitchat-android`."""

    def test_header_sizes(self):
        # BinaryProtocol.kt:208-209
        self.assertEqual(HEADER_SIZE, 14)
        self.assertEqual(HEADER_SIZE_V2, 16)

    def test_has_route_no_existe_en_el_legacy(self):
        """`BinaryProtocol.kt:217` define HAS_ROUTE; el Rust no lo tiene."""
        self.assertEqual(PacketFlags.HAS_ROUTE, 0x08)

    def test_constantes_de_fragmentacion_android(self):
        # AppConstants.Fragmentation
        self.assertEqual(FRAGMENT_SIZE_THRESHOLD, 512)
        self.assertEqual(MAX_FRAGMENT_SIZE, 469)
        self.assertEqual(MAX_FRAGMENTS_PER_ID, 256)

    def test_fragmentacion_legacy_es_un_valor_distinto(self):
        """150 B (iOS, MTU 185) es un tercer valor, no el de Android."""
        self.assertEqual(LEGACY_FRAGMENT_CHUNK_SIZE, 150)
        self.assertNotEqual(LEGACY_FRAGMENT_CHUNK_SIZE, MAX_FRAGMENT_SIZE)

    def test_mtus_conocidas(self):
        self.assertEqual(BLE_MTU_ANDROID_14, 517)
        self.assertEqual(BLE_MTU_BLUEZ_DEFAULT, 23)


class TestPoliticaDeRelleno(unittest.TestCase):
    """`BLEPacketPaddingPolicy.kt`: sólo se rellenan las tramas Noise."""

    def test_solo_noise_se_rellena(self):
        self.assertTrue(should_pad_for_ble(int(MessageType.NOISE_ENCRYPTED)))
        self.assertTrue(should_pad_for_ble(int(MessageType.NOISE_HANDSHAKE)))

        for mt in (
            MessageType.ANNOUNCE,
            MessageType.MESSAGE,
            MessageType.LEAVE,
            MessageType.FRAGMENT,
            MessageType.REQUEST_SYNC,
            MessageType.FILE_TRANSFER,
        ):
            with self.subTest(mtype=mt.name):
                self.assertFalse(
                    should_pad_for_ble(int(mt)),
                    f"{mt.name} no debería rellenarse según la política actual",
                )

    def test_tipo_desconocido_no_rellena(self):
        self.assertFalse(should_pad_for_ble(0xFF))


class TestVectoresNoiseC(unittest.TestCase):
    """Vectores canónicos publicados por la app Android."""

    def test_esta_el_perfil_correcto(self):
        self.assertEqual(NOISE_PROTOCOL_NAME, b"Noise_XX_25519_ChaChaPoly_SHA256")

    def test_los_seis_vectores_estan(self):
        self.assertEqual(
            set(NOISE_C_VECTORS),
            {"msg1", "msg2", "msg3", "transport_a", "transport_b", "transport_c"},
        )

    def test_longitudes_de_hex_validas(self):
        for nombre, (payload, ciphertext) in NOISE_C_VECTORS.items():
            with self.subTest(vector=nombre):
                for etiqueta, valor in (("payload", payload), ("ciphertext", ciphertext)):
                    self.assertEqual(
                        len(valor) % 2,
                        0,
                        f"{nombre}/{etiqueta} tiene longitud hex impar",
                    )
                    int(valor, 16)  # lanza si no es hex válido

    def test_longitudes_de_handshake_coherentes(self):
        """Las longitudes siguen exactamente la aritmética de Noise XX.

        Fórmula de Noise: si la clave de cifrado aún está vacía,
        `EncryptWithAd` devuelve el texto plano sin cifrar (regla de la spec,
        §5.2). Por eso msg1 lleva el payload **en claro**.

            msg1 = e(32) + payload            (aún no hay clave)
            msg2 = e(32) + s_cifrada(48) + payload + tag(16)
            msg3 = s_cifrada(48) + payload + tag(16)
        """
        longitudes = {
            nombre: (len(bytes.fromhex(p)), len(bytes.fromhex(c)))
            for nombre, (p, c) in NOISE_C_VECTORS.items()
        }

        p1, c1 = longitudes["msg1"]
        self.assertEqual(c1, 32 + p1, "msg1 debe llevar el payload en claro")
        self.assertEqual((p1, c1), (16, 48))  # "Ludwig von Mises"

        p2, c2 = longitudes["msg2"]
        self.assertEqual(c2, 32 + 48 + p2 + 16)
        self.assertEqual((p2, c2), (15, 111))  # "Murray Rothbard"

        p3, c3 = longitudes["msg3"]
        self.assertEqual(c3, 48 + p3 + 16)
        self.assertEqual((p3, c3), (11, 75))  # "F. A. Hayek"

    def test_payload_de_transporte_solo_lleva_el_tag(self):
        """En transporte la clave ya existe: ciphertext = payload + 16 (tag)."""
        for nombre in ("transport_a", "transport_b", "transport_c"):
            with self.subTest(vector=nombre):
                p, c = NOISE_C_VECTORS[nombre]
                self.assertEqual(
                    len(bytes.fromhex(c)),
                    len(bytes.fromhex(p)) + 16,
                    "en transporte sólo debe crecer el tag AEAD",
                )

    def test_payloads_son_texto_imprimible(self):
        """Los vectores usan nombres de autopsia; el último va en latin-1."""
        for nombre, (p, _) in NOISE_C_VECTORS.items():
            with self.subTest(vector=nombre):
                crudo = bytes.fromhex(p)
                self.assertTrue(
                    all(32 <= b < 127 or b >= 0xA0 for b in crudo),
                    f"{nombre} debería ser texto imprimible",
                )

    def test_ultimo_vector_no_es_utf8(self):
        """'Eugene Böhm von Bawerk' viene en latin-1: 0xF6, no U+00F6.

        Es un recordatorio de no asumir UTF-8 en los payloads.
        """
        crudo = bytes.fromhex(NOISE_C_VECTORS["transport_c"][0])
        self.assertIn(0xF6, crudo)
        with self.assertRaises(UnicodeDecodeError):
            crudo.decode("utf-8")
        self.assertIn("Böhm", crudo.decode("latin-1"))


class TestGatt(unittest.TestCase):
    def test_mainnet_y_testnet_se_diferencian_en_un_caracter(self):
        self.assertEqual(BITCHAT_SERVICE_UUID[:-1], BITCHAT_SERVICE_UUID_TESTNET[:-1])
        self.assertEqual(BITCHAT_SERVICE_UUID[-1], "C")
        self.assertEqual(BITCHAT_SERVICE_UUID_TESTNET[-1], "A")

    def test_scan_debe_usar_el_uuid_correcto(self):
        """Recordatorio: mainnet termina en C, no en B5B ni en B5E."""
        self.assertTrue(BITCHAT_SERVICE_UUID.endswith("B5C"))
        self.assertTrue(BITCHAT_SERVICE_UUID_TESTNET.endswith("B5A"))


if __name__ == "__main__":
    unittest.main(verbosity=2)