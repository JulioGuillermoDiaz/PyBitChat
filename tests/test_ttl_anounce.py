"""El TTL del announce: por qué tenía que ser 7 y no 3.

## El síntoma

El announce se aceptaba, la firma valía, y el móvil **no nos contaba en el mesh**
(`mesh [0 personas]`). Ni un solo rechazo en ninguna de las cinco condiciones de
`AnnouncementIdentityValidator`. El par no salía por un motivo que no estaba en
el validador.

## La causa

`DirectLinkAnnouncementPolicy.observationFor`, en la app:

```kotlin
fun observationFor(routed: RoutedPacket, maxTtl: UByte): Observation? {
    if (routed.packet.ttl != maxTtl) return null
    return Observation(
        peerID = routed.peerID ?: return null,
        relayAddress = routed.relayAddress ?: return null,
        ingressLinkID = routed.ingressLinkID ?: return null
    )
}
```

Y lo que se hace con ese `null` es lo importante. En
`BluetoothMeshService.handleAnnounce`:

```kotlin
DirectLinkAnnouncementPolicy.observationFor(routed, MAX_TTL)?.let { observation ->
    connectionManager.observePeerIfCurrent(observation.relayAddress, ...)
    gossipSyncManager.scheduleInitialSyncToPeer(observation.peerID, 1_000)
}
```

Y `isPeerDirectlyConnected` **solo** mira ese mapa:

```kotlin
peerManager.isPeerDirectlyConnected = { peerID ->
    connectionManager.addressPeerMap.containsValue(peerID)
}
```

O sea, la cadena entera:

    ttl != 7
      -> observationFor() = null
      -> observePeerIfCurrent() nunca se llama
      -> addressPeerMap vacia
      -> isPeerDirectlyConnected = false
      -> no aparecemos, y no llega el sync inicial

El TTL es la señal de "me llegó sin reenviar". Ours iba con 3, que significa
"me reenviaron dos veces" — y una observación de alcanzabilidad no sobrevive a
eso. El announce se aceptaba y el par se registraba; como par **no directo**.

## Por qué nadie lo detectó antes

Porque todo lo demás estaba bien. La firma, el reloj, el TLV, el `peerID`
derivado, el relleno de la preimagen. Y el fallo no es un rechazo: es una
ausencia. Un announce con TTL bajo es *válido*, se acepta, y no hace nada.

Por eso el test de aquí no comprueba "que el TTL valga 7". Comprueba **que la
regla de la app acepta nuestro announce**, que es lo que importa y lo que
fallaba.
"""

import io
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol.identity import Identity  # noqa: E402
from pybitchat.protocol.packet import (  # noqa: E402
    MESSAGE_TTL_HOPS,
    Packet,
    PacketHeader,
)

#: `AppConstants.MESSAGE_TTL_HOPS`. Declarado aquí aparte del módulo a
#: propósito: si alguien cambia la constante de producción, este test se
#: levanta solo. La app no la va a cambiar, pero la nuestra sí la tiene.
TTL_DE_LA_APP = 7


@dataclass
class _Routed:
    """Lo mínimo de `RoutedPacket` que mira `observationFor`."""

    packet: Packet
    peer_id: str | None
    relay_address: str | None
    ingress_link_id: str | None


def _observation_for(routed: _Routed, max_ttl: int):
    """Traducción literal de `DirectLinkAnnouncementPolicy.observationFor`."""
    if routed.packet.header.ttl != max_ttl:
        return None
    if routed.packet is None or routed.peer_id is None:
        return None
    if routed.relay_address is None:
        return None
    if routed.ingress_link_id is None:
        return None
    return (routed.peer_id, routed.relay_address, routed.ingress_link_id)


class TestTtlDelAnnounce(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ident = Identity.generate("pybitchat-probe")
        cls.paquete = Packet.from_bytes(cls.ident.announce_packet(ttl=MESSAGE_TTL_HOPS))

    # -- la constante -------------------------------------------------------

    def test_la_constante_es_la_de_la_app(self):
        self.assertEqual(MESSAGE_TTL_HOPS, TTL_DE_LA_APP)

    # -- el paquete real ---------------------------------------------------

    def test_el_announce_lleva_el_ttl_de_la_app(self):
        """El byte 2 de la cabecera. No el valor por defecto de la función."""
        crudo = self.ident.announce_packet(ttl=MESSAGE_TTL_HOPS)
        self.assertEqual(crudo[2], TTL_DE_LA_APP)
        self.assertEqual(self.paquete.header.ttl, TTL_DE_LA_APP)

    def test_el_default_ya_no_es_tres(self):
        """El 3 era un valor inventado en `identity.py`, no de la app."""
        p = Packet.from_bytes(self.ident.announce_packet())
        self.assertEqual(p.header.ttl, TTL_DE_LA_APP)

    def test_todas_las_versiones_del_announce_llevan_7(self):
        """Firmado y sin firmar, con y sin TTL explícito."""
        for firmar in (False, True):
            with self.subTest(firmar=firmar):
                p = Packet.from_bytes(self.ident.announce_packet(firmar=firmar))
                self.assertEqual(p.header.ttl, TTL_DE_LA_APP)

    # -- la regla de la app, aplicada a nuestro paquete ----------------------

    def test_la_app_acepta_nuestro_announce_como_directo(self):
        """El test que habría pillado el bug.

        Se ejecuta la regla de la app sobre **nuestro announce real**, con los
        tres identificadores que el servidor GATT le pasa de verdad. Antes de
        arreglarlo devolvía `None`, y con ello se caía la observación entera.
        """
        observation = _observation_for(
            _Routed(
                packet=self.paquete,
                peer_id=self.paquete.sender_id.hex(),
                relay_address="77:ED:36:22:4A:29",
                ingress_link_id="link-1",
            ),
            max_ttl=TTL_DE_LA_APP,
        )
        self.assertIsNotNone(
            observation,
            "con TTL distinto de 7 la app descarta la observacion y no nos "
            "anota en addressPeerMap, que es de donde sale isDirectConnection",
        )
        # `Identity.peer_id` son 8 bytes crudos; en el cable viajan como hex.
        self.assertEqual(observation[0], self.ident.peer_id.hex())
        # El servidor GATT saca el peerID del propio paquete, en hex. Que
        # coincida con el nuestro es lo que hace pasar la segunda mitad de
        # `AnnouncementIdentityValidator`: `claimedPeerID != derivedPeerID`.
        self.assertEqual(observation[0], self.paquete.sender_id.hex())

    def test_un_ttl_menor_no_llegaria_nunca(self):
        """Por qué 3 no vale, en el test que lo demuestra al revés.

        Con el mismo announce y los mismos identificadores, un TTL de 3 hace que
        la regla devuelva `None`. Es la definición de "no directo".
        """
        paquete = Packet.from_bytes(self.ident.announce_packet(ttl=3))
        self.assertIsNone(
            _observation_for(
                _Routed(paquete, paquete.sender_id.hex(), "AA:BB", "link-1"),
                max_ttl=TTL_DE_LA_APP,
            )
        )

    def test_faltando_el_link_tambien_se_cae(self):
        """El otro `return null`, y por el mismo motivo: no hay whence que mirar.

        El `relayAddress` lo pone el `BluetoothDevice` del servidor GATT, así
        que en nuestra posición siempre viene. Se deja constancia de que la
        regla tiene tres puertas, no una.
        """
        self.assertIsNone(
            _observation_for(
                _Routed(self.paquete, self.ident.peer_id, None, "link-1"),
                max_ttl=TTL_DE_LA_APP,
            )
        )


class TestNoVuelveElLiteral(unittest.TestCase):
    """Que el 3 no pueda volver colado en la ruta del announce.

    El bug no fue escribir `ttl != 7`; fue tener un **3 como valor por defecto**
    en dos sitios distintos, con tests que pasaban.
    """

    def _fuente(self, relativa: str) -> str:
        return io.open(ROOT / relativa, encoding="utf-8").read()

    def test_identity_no_tiene_un_ttl_tres(self):
        fuente = self._fuente("src/pybitchat/protocol/identity.py")
        self.assertNotIn("ttl: int = 3", fuente)

    def test_smoke_ble_no_tiene_un_ttl_tres(self):
        fuente = self._fuente("tools/smoke_ble.py")
        self.assertNotIn("ttl=3", fuente)
        self.assertNotIn("ttl: int = 3", fuente)

    def test_smoke_ble_usa_la_constante(self):
        """No basta con no tener el 3: tiene que usar el 7 de la app."""
        fuente = self._fuente("tools/smoke_ble.py")
        self.assertIn("ttl=MESSAGE_TTL_HOPS", fuente)

    def test_la_constante_dice_de_donde_sale(self):
        """Un 7 sin procedencia es un 3 esperando aWQiche nadie mire."""
        fuente = self._fuente("src/pybitchat/protocol/packet.py")
        self.assertIn("MESSAGE_TTL_HOPS = 7", fuente)
        i = fuente.index("MESSAGE_TTL_HOPS = 7")
        comentario = fuente[max(0, i - 700):i]
        self.assertIn("DirectLinkAnnouncementPolicy", comentario)
        self.assertIn("MESSAGE_TTL_HOPS", comentario)


if __name__ == "__main__":
    unittest.main()
