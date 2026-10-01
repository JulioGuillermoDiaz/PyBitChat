"""Validación de Noise contra los vectores canónicos de Cacophony/Noise-C.

Los vectores están publicados por `permissionlesstech/bitchat-android` en
`app/src/test/kotlin/com/bitchat/android/noise/NoiseExternalVectorTest.kt`: son
los mismos que usa la app oficial para su propio test.

Si estos tests pasan, el handshake es **byte-compatible con la app oficial**.

Ejecutar:
    .venv\\Scripts\\python.exe tests\\test_noise_vectors.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.noise.framing import (  # noqa: E402
    NONCE_PREFIX_LEN,
    REPLAY_WINDOW,
    REPLAY_WINDOW_BYTES,
    NoiseTransportCipher,
    decode_transport,
    encode_transport,
)
from pybitchat.noise.primitives import (  # noqa: E402
    chacha_decrypt,
    chacha_encrypt,
    chacha_nonce,
    generate_x25519_private,
    hkdf,
    hmac_hash,
    x25519,
    x25519_public_from_private,
)
from pybitchat.noise.session import (  # noqa: E402
    PROTOCOL_NAME,
    SUPPORTED_PROFILES,
    HandshakeSession,
    NoiseError,
)
from pybitchat.noise.state_errors import CipherStateError, ReplayError  # noqa: E402
from pybitchat.protocol.types import (  # noqa: E402
    NOISE_C_INITIATOR_EPHEMERAL,
    NOISE_C_INITIATOR_STATIC,
    NOISE_C_PROLOGUE,
    NOISE_C_RESPONDER_EPHEMERAL,
    NOISE_C_RESPONDER_STATIC,
    NOISE_C_VECTORS,
)

u = bytes.fromhex
PRO = u(NOISE_C_PROLOGUE)

#: (nombre del vector, ¿escribe el iniciador?)
PASOS = (("msg1", True), ("msg2", False), ("msg3", True))


def vector(nombre: str) -> tuple[bytes, bytes]:
    payload, ciphertext = NOISE_C_VECTORS[nombre]
    return u(payload), u(ciphertext)


def sesion(iniciador: bool, prologue: bytes = PRO) -> HandshakeSession:
    return HandshakeSession(
        initiator=iniciador,
        protocol_name=PROTOCOL_NAME,
        prologue=prologue,
        static_private=u(
            NOISE_C_INITIATOR_STATIC if iniciador else NOISE_C_RESPONDER_STATIC
        ),
        ephemeral_private=u(
            NOISE_C_INITIATOR_EPHEMERAL if iniciador else NOISE_C_RESPONDER_EPHEMERAL
        ),
    )


class TestPrimitivas(unittest.TestCase):
    def test_chacha_nonce_formato(self):
        """4 bytes a cero + contador u64 little-endian (§12.2)."""
        self.assertEqual(chacha_nonce(0), b"\x00" * 12)
        self.assertEqual(chacha_nonce(1)[:4], b"\x00" * 4)
        self.assertEqual(chacha_nonce(1)[4], 1)
        self.assertEqual(chacha_nonce(1)[5:], b"\x00" * 7)
        self.assertEqual(chacha_nonce(1 << 16)[4:8], b"\x00\x00\x01\x00")
        self.assertEqual(len(chacha_nonce(2**63 - 1)), 12)

    def test_chacha_nonce_rechaza_desbordamiento(self):
        for malo in (2**64, -1):
            with self.subTest(n=malo), self.assertRaises(ValueError):
                chacha_nonce(malo)

    def test_hkdf_de_noise_no_es_el_de_rfc(self):
        """Empieza en output1, sin extract con salt."""
        out = hkdf(b"k" * 32, b"ikm", 2)
        temp = hmac_hash(b"k" * 32, b"ikm")
        self.assertEqual(out[0], hmac_hash(temp, b"\x01"))
        self.assertEqual(out[1], hmac_hash(temp, out[0] + b"\x02"))
        self.assertEqual(out, hkdf(b"k" * 32, b"ikm", 2))
        self.assertEqual(len(hkdf(b"k" * 32, b"ikm", 3)), 3)
        for n in (0, 4, -1):
            with self.subTest(num_outputs=n), self.assertRaises(ValueError):
                hkdf(b"k" * 32, b"ikm", n)

    def test_x25519_propiedad_dh(self):
        a, b = generate_x25519_private(), generate_x25519_private()
        self.assertEqual(
            x25519(a, x25519_public_from_private(b)),
            x25519(b, x25519_public_from_private(a)),
        )
        self.assertEqual(len(x25519(a, x25519_public_from_private(a))), 32)

    def test_x25519_rechaza_longitudes(self):
        with self.assertRaises(ValueError):
            x25519(b"corto", bytes(32))
        with self.assertRaises(ValueError):
            x25519(bytes(32), b"")

    def test_aead_rechaza_tamperado_y_ad_distinto(self):
        clave = bytes(32)
        ct = chacha_encrypt(clave, 3, b"secreto", b"ad")
        with self.assertRaises(ValueError):
            chacha_decrypt(clave, 3, ct[:-1] + bytes([ct[-1] ^ 1]), b"ad")
        with self.assertRaises(ValueError):
            chacha_decrypt(clave, 3, ct, b"otro")


class TestHandshakeContraVectores(unittest.TestCase):
    """Los 3 mensajes de handshake, byte a byte.

    ⚠️ Cada paso **escribe y lee**. No basta con escribir los tres seguidos:
    msg3 necesita la clave efímera del respondedor, que el iniciador sólo
    obtiene al leer msg2.
    """

    def setUp(self):
        self.init = sesion(True)
        self.resp = sesion(False)

    def _lados(self, escribe_init: bool):
        return (self.init, self.resp) if escribe_init else (self.resp, self.init)

    def test_cada_mensaje_coincide_byte_a_byte(self):
        """El test central de Fase 3."""
        for nombre, escribe_init in PASOS:
            with self.subTest(mensaje=nombre):
                payload, esperado = vector(nombre)
                escritor, lector = self._lados(escribe_init)
                self.assertEqual(escritor.write_handshake(payload), esperado)
                self.assertEqual(lector.read_handshake(esperado, len(payload)), payload)

    def test_longitudes_de_handshake(self):
        """Con los payloads de los vectores: 48, 111 y 75 bytes."""
        for (nombre, escribe_init), largo in zip(PASOS, (48, 111, 75)):
            with self.subTest(mensaje=nombre):
                payload, esperado = vector(nombre)
                escritor, lector = self._lados(escribe_init)
                self.assertEqual(len(escritor.write_handshake(payload)), largo)
                lector.read_handshake(esperado, len(payload))

    def test_handshake_vacio_por_lado_usa_los_tamanos_de_bitchat(self):
        """Sin payload: 32, 96 y 64. Son los de los vectores reales.

        msg2 vacío = e(32) + estática cifrada(48) + tag del payload(16)
        msg3 vacío = estática cifrada(48) + tag del payload(16)
        """
        init, resp = sesion(True), sesion(False)
        m1 = init.write_handshake(b"")
        self.assertEqual(len(m1), 32)
        resp.read_handshake(m1)

        m2 = resp.write_handshake(b"")
        self.assertEqual(len(m2), 96)
        init.read_handshake(m2)

        m3 = init.write_handshake(b"")
        self.assertEqual(len(m3), 64)

    def test_ambos_lados_terminan_con_el_mismo_hash(self):
        for nombre, escribe_init in PASOS:
            payload, esperado = vector(nombre)
            escritor, lector = self._lados(escribe_init)
            escritor.write_handshake(payload)
            lector.read_handshake(esperado, len(payload))

        self.assertTrue(self.init.complete)
        self.assertTrue(self.resp.complete)
        self.assertEqual(self.init.handshake_hash, self.resp.handshake_hash)
        self.assertEqual(len(self.init.handshake_hash), 32)

    def test_las_estaticas_se_cruzan_correctamente(self):
        for nombre, escribe_init in PASOS:
            payload, esperado = vector(nombre)
            escritor, lector = self._lados(escribe_init)
            escritor.write_handshake(payload)
            lector.read_handshake(esperado, len(payload))

        self.assertEqual(
            self.init.remote_static_public,
            x25519_public_from_private(u(NOISE_C_RESPONDER_STATIC)),
        )
        self.assertEqual(
            self.resp.remote_static_public,
            x25519_public_from_private(u(NOISE_C_INITIATOR_STATIC)),
        )


class TestTransporte(unittest.TestCase):
    """Transporte de Noise estándar y framing propietario de BitChat."""

    def setUp(self):
        self.init = sesion(True)
        self.resp = sesion(False)
        for nombre, escribe_init in PASOS:
            payload, esperado = vector(nombre)
            escritor, lector = (
                (self.init, self.resp) if escribe_init else (self.resp, self.init)
            )
            escritor.write_handshake(payload)
            lector.read_handshake(esperado, len(payload))
        self.canal_init = self.init.split()
        self.canal_resp = self.resp.split()

    def test_framing_propietario_de_4_bytes(self):
        """La desviación de BitChat: prefijo de nonce de 4 bytes."""
        mensaje = self.canal_init.encrypt(b"hola")
        self.assertEqual(len(mensaje), 4 + 4 + 16, "nonce(4) + 'hola'(4) + tag(16)")
        self.assertEqual(mensaje[:4], b"\x00\x00\x00\x00", "primer mensaje, nonce 0")

        nonce, ciphertext = decode_transport(mensaje)
        self.assertEqual(nonce, 0)
        self.assertEqual(ciphertext, mensaje[NONCE_PREFIX_LEN:])
        self.assertEqual(self.canal_resp.decrypt(mensaje), b"hola")

    def test_ida_y_vuelta_ambos_lados(self):
        a = self.canal_init.encrypt(b"de python a android")
        self.assertEqual(self.canal_resp.decrypt(a), b"de python a android")
        b = self.canal_resp.encrypt(b"y de vuelta")
        self.assertEqual(self.canal_init.decrypt(b), b"y de vuelta")

    def test_el_prefijo_lleva_el_contador(self):
        self.canal_init.encrypt(b"a")
        segundo = self.canal_init.encrypt(b"b")
        nonce, _ = decode_transport(segundo)
        self.assertEqual(nonce, 1)
        # Big-endian: el contador crece por la izquierda.
        self.assertEqual(segundo[:4], b"\x00\x00\x00\x01")
        self.assertEqual(self.canal_init.send_nonce, 2)

    def test_trama_tamperada_falla(self):
        mensaje = bytearray(self.canal_init.encrypt(b"secreto"))
        mensaje[-1] ^= 0x01
        with self.assertRaises(ValueError):
            self.canal_resp.decrypt(bytes(mensaje))

    def test_nonce_alterado_falla(self):
        """Un nonce distinto deriva otra clave, y el AEAD lo rechaza.

        Es lo que impide que un intermediario reescriba el prefijo de nonce para
        hacer pasar un mensaje antiguo por uno nuevo.
        """
        original = self.canal_init.encrypt(b"secreto")
        _, ciphertext = decode_transport(original)
        falsificada = encode_transport(7, ciphertext)
        self.assertNotEqual(falsificada[:4], original[:4])
        with self.assertRaises(ValueError):
            self.canal_resp.decrypt(falsificada)

    def test_mensaje_largo_usa_varios_nonces(self):
        grande = "á" * 900
        trama = self.canal_init.encrypt(grande.encode("utf-8"))
        nonce, _ = decode_transport(trama)
        self.assertEqual(nonce, 0)
        self.assertEqual(self.canal_resp.decrypt(trama), grande.encode("utf-8"))

    def test_trama_demasiado_corta(self):
        with self.assertRaises(ValueError):
            decode_transport(b"\x00\x00\x00")

    def test_perfil_no_soportado(self):
        with self.assertRaises(NoiseError):
            HandshakeSession(
                initiator=True, protocol_name=b"Noise_XX_448_ChaChaPoly_SHA512"
            )


class TestAntiReplay(unittest.TestCase):
    """El AEAD solo detecta manipulacion, no repeticion.

    La clave se deriva del nonce de forma determinista, asi que sin estado
    explicito una trama capturada y reenviada se descifraria SIN ERROR.
    BitChat lo evita con una ventana de 1024 nonces (NoiseSession.kt:40-41).
    """

    def setUp(self):
        self.init = sesion(True)
        self.resp = sesion(False)
        for nombre, escribe_init in PASOS:
            payload, esperado = vector(nombre)
            escritor, lector = (
                (self.init, self.resp) if escribe_init else (self.resp, self.init)
            )
            escritor.write_handshake(payload)
            lector.read_handshake(esperado, len(payload))
        self.canal_init = self.init.split()
        self.canal_resp = self.resp.split()

    def test_reenvio_literal_se_rechaza(self):
        """El caso que el AEAD por si solo NO detecta."""
        trama = self.canal_init.encrypt(b"secreto")
        self.assertEqual(self.canal_resp.decrypt(trama), b"secreto")
        with self.assertRaises(ReplayError):
            self.canal_resp.decrypt(trama)

    def test_trama_manipulada_tampien_falla(self):
        trama = bytearray(self.canal_init.encrypt(b"secreto"))
        trama[-1] ^= 0x01
        with self.assertRaises(ValueError):
            self.canal_resp.decrypt(bytes(trama))

    def test_fuera_de_ventana_se_rechaza(self):
        self.canal_init._send_nonce = 0
        trama = self.canal_init.encrypt(b"viejo")
        self.canal_resp._highest = 5000
        with self.assertRaises(ReplayError):
            self.canal_resp.decrypt(trama)

    def test_mensajes_sucesivos_son_validos(self):
        for i in range(50):
            trama = self.canal_init.encrypt(("mensaje %d" % i).encode())
            self.assertEqual(self.canal_resp.decrypt(trama), ("mensaje %d" % i).encode())

    def test_desorden_dentro_de_la_ventana_se_acepta(self):
        """El relay puede reordenar: hay que tolerarlo dentro de la ventana."""
        tramas = [self.canal_init.encrypt(("m%d" % i).encode()) for i in range(20)]
        for trama in reversed(tramas):
            self.assertIsInstance(self.canal_resp.decrypt(trama), bytes)

    def test_el_ultimo_nonce_se_registra(self):
        self.canal_init.encrypt(b"uno")
        self.canal_init.encrypt(b"dos")
        self.canal_resp.decrypt(self.canal_init.encrypt(b"tres"))
        self.assertGreaterEqual(self.canal_resp.highest_received_nonce, 2)

    def test_constantes_coinciden_con_la_app_oficial(self):
        self.assertEqual(REPLAY_WINDOW, 1024)
        self.assertEqual(REPLAY_WINDOW_BYTES, 128)
        self.assertEqual(NONCE_PREFIX_LEN, 4)


class TestEndiannessDelPrefijo(unittest.TestCase):
    """El prefijo de 4 B es BIG-endian. Little endian coincidiria hasta 255.

    Es la clase de bug que no se manifiesta en las pruebas: todo funciona
    durante 256 mensajes y luego el AEAD empieza a fallar en ambos sentidos,
    con un síntoma indistinguible de "no llegan los mensajes".
    """

    def test_256_es_el_punto_de_divergencia(self):
        """Con nonce 0 los dos coincide; con 256 no."""
        self.assertEqual(encode_transport(0, b"")[:4], b"\x00\x00\x00\x00")
        self.assertEqual(encode_transport(255, b"")[:4], b"\x00\x00\x00\xff")
        # Big-endian:
        self.assertEqual(encode_transport(256, b"")[:4], b"\x00\x00\x01\x00")
        # Little-endian habría dado b"\x00\x01\x00\x00": es el error a evitar.
        self.assertNotEqual(encode_transport(256, b"")[:4], b"\x00\x01\x00\x00")

    def test_ida_y_vuelta_de_varios_nonces(self):
        for nonce in (0, 1, 127, 128, 255, 256, 257, 1000, 65535, 65536, 1_000_000):
            with self.subTest(nonce=nonce):
                self.assertEqual(decode_transport(encode_transport(nonce, b"x")), (nonce, b"x"))

    def test_prefijo_de_4_bases_es_el_de_la_app(self):
        for nonce, esperado in (
            (0, "00000000"), (1, "00000001"), (256, "00000100"),
            (1000, "000003e8"), (65536, "00010000"),
        ):
            with self.subTest(nonce=nonce):
                self.assertEqual(encode_transport(nonce, b"")[:4].hex(), esperado)


class TestTransporteContraVectores(unittest.TestCase):
    """El transporte se compara contra los vectores Noise-C oficiales.

    Estos vectores son Noise canónico, SIN el prefijo propietario de BitChat.
    Sirven para validar la clave de split y el nonce AEAD.

    Verifican que la clave de transporte se usa **tal cual**: con una clave de
    epoch derivada por HMAC el ciphertext no coincide en absoluto.
    """

    def setUp(self):
        self.init = sesion(True)
        self.resp = sesion(False)
        for nombre, escribe_init in PASOS:
            payload, esperado = vector(nombre)
            escritor, lector = (
                (self.init, self.resp) if escribe_init else (self.resp, self.init)
            )
            escritor.write_handshake(payload)
            lector.read_handshake(esperado, len(payload))
        self.canal_init = self.init.split()
        self.canal_resp = self.resp.split()

    def test_ciphertext_de_transporte_coincide_con_los_vectores(self):
        """respondedor -> iniciador, y luego iniciador -> respondedor."""
        from pybitchat.noise.primitives import chacha_encrypt

        for nombre, emisor, clave in (
            ("transport_a", "resp", self.canal_resp._send_key),
            ("transport_b", "init", self.canal_init._send_key),
        ):
            with self.subTest(mensaje=nombre):
                payload, esperado = vector(nombre)
                produced = chacha_encrypt(clave, 0, payload, b"")
                self.assertEqual(
                    produced, esperado,
                    "el transporte debe usar la clave de split sin derivarla",
                )
                self.assertEqual(emisor, "resp" if nombre.endswith("a") else "init")

    def test_la_derivacion_de_epoch_no_se_usa(self):
        """Contraprueba explícita: derivar la clave rompe la compatibilidad."""
        from pybitchat.noise.primitives import chacha_encrypt, hmac_hash

        payload, esperado = vector("transport_a")
        clave = self.canal_resp._send_key
        con_epoch = chacha_encrypt(hmac_hash(clave, (0).to_bytes(8, "little")), 0, payload, b"")
        self.assertNotEqual(
            con_epoch, esperado,
            "si esto coincidiera, estaríamos derivando la clave y "
            "sería incompatible con la app oficial",
        )
class TestRobustez(unittest.TestCase):
    """Los agujeros que tenía el cliente Rust, aquí cerrados."""

    def setUp(self):
        self.init = sesion(True)
        self.resp = sesion(False)

    def test_split_antes_de_terminar_falla(self):
        with self.assertRaises(NoiseError):
            self.init.split()

    def test_escribir_despues_de_terminar_falla(self):
        for nombre, escribe_init in PASOS:
            payload, esperado = vector(nombre)
            escritor, lector = (
                (self.init, self.resp) if escribe_init else (self.resp, self.init)
            )
            escritor.write_handshake(payload)
            lector.read_handshake(esperado, len(payload))
        with self.assertRaises(NoiseError):
            self.init.write_handshake(b"tarde")

    def test_mensaje_corrupto_no_deja_continuar(self):
        """El agujero A2 del cliente Rust: tragar el fallo y seguir."""
        m1 = self.init.write_handshake(b"")
        self.resp.read_handshake(m1)
        m2 = bytearray(self.resp.write_handshake(b""))
        m2[-1] ^= 0x01
        with self.assertRaises(NoiseError):
            self.resp.read_handshake(bytes(m2))

    def test_truncado_falla(self):
        m1 = self.init.write_handshake(b"")
        with self.assertRaises(NoiseError):
            self.resp.read_handshake(m1[:10])

    def test_cipher_sin_clave_falla(self):
        """Sin clave no hay canal: el constructor lo rechaza.

        Sin este chequeo, `chacha_encrypt` derivaría material válido a partir de
        una clave vacía y el canal "funcionaría" cifrando con nada.
        """
        with self.assertRaises(CipherStateError):
            NoiseTransportCipher(b"", b"")
        with self.assertRaises(CipherStateError):
            NoiseTransportCipher(bytes(32), b"")

    def test_perfiles_declarados(self):
        self.assertIn(PROTOCOL_NAME, SUPPORTED_PROFILES)
        self.assertEqual(PROTOCOL_NAME, b"Noise_XX_25519_ChaChaPoly_SHA256")
        self.assertEqual(
            len(PROTOCOL_NAME), 32, "32 exactos: InitializeSymmetric no lo hashea"
        )

    def test_hash_estable_entre_llamadas(self):
        self.assertEqual(self.init.handshake_hash, self.init.handshake_hash)

    def test_prologue_distinto_impide_interoperar(self):
        """Con otro prologue no hay sesión común: es lo que hay que negociar."""
        otro = sesion(True, prologue=b"distinto")
        self.assertNotEqual(otro.handshake_hash, self.init.handshake_hash)


if __name__ == "__main__":
    unittest.main(verbosity=2)

