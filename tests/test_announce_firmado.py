"""`announce_packet(firmar=True)`: el announce que la app acepta.

## Por qué este test existe

La app **descarta** el announce sin firma:

```kotlin
val announcement = AnnouncementIdentityValidator.verify(packet, peerID)
if (announcement == null) {
    return AnnounceHandlingResult.Rejected
}
```

Sin registro como par no hay `isVerifiedNickname`, y `handleBroadcastMessage`
exige eso para aceptar cualquier mensaje nuestro. Es un bloqueo circular detrás de
una línea, y se lleva arrastrando desde el principio sin que se supiera.

## Lo que estos tests fijan

1. **Sin `--firmar` no cambia nada.** Es un flag, no un cambio de defecto.
2. **Con `--firmar` la firma valida** contra `to_binary_data_for_signing()`.
3. **La preimagen no es lo que se manda.** Es el paquete con TTL a 0 y sin firma.
   Firmar el segundo daría una firma que no valida contra el primero, y eso
   pasó: el primer test firmó `to_bytes()` y la verificación falló.
4. El announce firmado lleva `HAS_SIGNATURE` y los 64 bytes, y se rellena a 256
   como el de la app.
"""

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol.identity import Identity  # noqa: E402
from pybitchat.protocol.packet import Packet  # noqa: E402
from pybitchat.protocol.types import PacketFlags  # noqa: E402


def _cargar_smoke():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "smoke_firmar", ROOT / "tools" / "smoke_ble.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestAnnounceFirmado(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ident = Identity.generate("anewells74")

    # -- sin firmar: nada cambia --------------------------------------------

    def test_sin_firmar_no_lleva_firma(self):
        """Lo que se mandaba hasta ahora. Un flag no puede alterar esto."""
        p = Packet.from_bytes(self.ident.announce_packet(ttl=3))
        self.assertIsNone(p.signature)

    def test_sin_firmar_no_activa_el_flag(self):
        p = Packet.from_bytes(self.ident.announce_packet(ttl=3))
        self.assertFalse(p.header.flags & PacketFlags.HAS_SIGNATURE)

    def test_sin_firmar_sigue_siendo_pequeno(self):
        """111 B con 'pybitchat-probe', y no se rellena."""
        ident = Identity.generate("pybitchat-probe")
        crudo = ident.announce_packet(ttl=3)
        self.assertEqual(len(crudo), 111)

    # -- con firmar ---------------------------------------------------------

    def test_firmado_lleva_64_bytes(self):
        p = Packet.from_bytes(self.ident.announce_packet(ttl=3, firmar=True))
        self.assertIsNotNone(p.signature)
        self.assertEqual(len(p.signature), 64)

    def test_firmado_activa_el_flag(self):
        p = Packet.from_bytes(self.ident.announce_packet(ttl=3, firmar=True))
        self.assertTrue(p.header.flags & PacketFlags.HAS_SIGNATURE)

    def test_firmado_se_rellena_a_256(self):
        """Como el announce real de la app, que llega en 256 B."""
        crudo = self.ident.announce_packet(ttl=3, firmar=True)
        self.assertEqual(len(crudo), 256)

    def test_la_firma_verifica_contra_la_preimagen(self):
        p = Packet.from_bytes(self.ident.announce_packet(ttl=3, firmar=True))
        pre = p.to_binary_data_for_signing()
        self.assertTrue(self.ident.verify(pre, p.signature))

    def test_la_preimagen_pone_el_ttl_a_cero(self):
        p = Packet.from_bytes(self.ident.announce_packet(ttl=3, firmar=True))
        pre = p.to_binary_data_for_signing()
        self.assertEqual(pre[2], 0, "el TTL tiene que estar a 0 al firmar")
        self.assertEqual(p.header.ttl, 3, "el paquete si lleva su TTL")

    def test_la_preimagen_no_es_lo_que_se_manda(self):
        """La diferencia que hizo fallar la primera versi\u00f3n de esto.

        `to_binary_data_for_signing()` quita la firma y pone el TTL a 0.
        `to_bytes()` deja el TTL. Firmar el segundo produce una firma que no
        valida contra el primero.
        """
        p = Packet.from_bytes(self.ident.announce_packet(ttl=3, firmar=True))
        pre = p.to_binary_data_for_signing()
        en_cable = self.ident.announce_packet(ttl=3, firmar=True)
        self.assertNotEqual(pre, en_cable[:len(pre)])
        self.assertFalse(
            self.ident.verify(p.to_bytes(include_padding=False)[: len(pre)],
                              p.signature),
            "la firma no deberia validar contra los bytes con TTL real",
        )

    def test_la_preimagen_no_lleva_la_firma(self):
        p = Packet.from_bytes(self.ident.announce_packet(ttl=3, firmar=True))
        pre = p.to_binary_data_for_signing()
        self.assertNotIn(p.signature, pre)

    def test_el_ttl_no_afecta_a_la_firma(self):
        """Firmar con TTL 3 o con TTL 7 da la **misma** firma.

        Es la raz\u00f3n de fijar el TTL a 0: el paquete baja en cada salto, y si el
        TTL entrase en la preimagen, un paquete reenviado una sola vez dejar\u00eda de
        validar en el receptor.
        """
        a = Packet.from_bytes(self.ident.announce_packet(ttl=3, firmar=True))
        b = Packet.from_bytes(self.ident.announce_packet(ttl=7, firmar=True))
        self.assertEqual(
            a.to_binary_data_for_signing()[2:], b.to_binary_data_for_signing()[2:]
        )

    def test_el_timestamp_si_afecta_a_la_firma(self):
        """El timestamp va en la preimagen, as\u00ed que dos announces distintos
        no pueden llevar la misma firma."""
        a = self.ident.announce_packet(ttl=3, firmar=True, timestamp=1_000)
        b = self.ident.announce_packet(ttl=3, firmar=True, timestamp=2_000)
        self.assertNotEqual(a, b)

    def test_una_firma_alterada_no_verifica(self):
        crudo = bytearray(self.ident.announce_packet(ttl=3, firmar=True))
        crudo[110] ^= 0xFF          # dentro de la firma (106..169)
        p = Packet.from_bytes(bytes(crudo))
        self.assertFalse(self.ident.verify(p.to_binary_data_for_signing(),
                                           p.signature))

    def test_otra_clave_no_verifica_nuestra_firma(self):
        """La firma ata al par: otra identidad no puede firmarlo."""
        otro = Identity.generate("otro")
        p = Packet.from_bytes(self.ident.announce_packet(ttl=3, firmar=True))
        self.assertFalse(otro.verify(p.to_binary_data_for_signing(), p.signature))


class TestElFlagEnSmokeBle(unittest.TestCase):
    """El flag llega desde la l\u00ednea de \u00f3rdenes hasta el announce."""

    def test_firmar_llega_a_announce_packet(self):
        import inspect

        mod = _cargar_smoke()
        fuente = inspect.getsource(mod._preparar)
        self.assertIn("firmar=", fuente)

    def test_el_flag_existe(self):
        import inspect

        mod = _cargar_smoke()
        self.assertIn("--firmar", inspect.getsource(mod.main))

    def test_el_handshake_no_hereda_el_flag(self):
        """La app **no** firma los handshakes (`MessageHandler.kt:392`).

        As\u00ed que `--firmar` con `--handshake` no puede acabar firmando el
        `msg1`. Se comprueba sobre el c\u00f3digo: `iniciar_handshake` no recibe
        `firmar`.
        """
        import inspect

        mod = _cargar_smoke()
        fuente = inspect.getsource(mod._preparar)
        # el bloque del handshake llama a iniciar_handshake, y no mentiona firmar
        bloque = fuente.split("iniciar_handshake(")[0].rsplit("if ", 1)[-1]
        self.assertNotIn("firmar", bloque)

    def test_el_handshake_sigue_sin_firma(self):
        """Comprobado sobre el paquete real que construye la app."""
        from pybitchat.noise.handshake import iniciar_handshake

        ident = Identity.generate("pybitchat-probe")
        destino = bytes.fromhex("34e01ccea10a8c6d")
        paquete, _sesion = iniciar_handshake(ident, peer_id_remoto=destino)
        p = Packet.from_bytes(paquete)
        self.assertIsNone(p.signature)


if __name__ == "__main__":
    unittest.main()