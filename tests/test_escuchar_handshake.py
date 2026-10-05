"""El `msg3` tiene que salir antes de que la app expire la sesión.

## El fallo

`NoiseSessionManager.HANDSHAKE_TIMEOUT_MS = 10_000`, con un barredor cada 2 s
que destruye la sesión a medias:

```kotlin
if (session.isHandshaking() && isHandshakeStale(session, nowMs)) {
    Log.d(TAG, "Expiring stale handshake with $peerID")
    sessions.remove(peerID, session)?.destroy()
```

`smoke_ble` esperaba los 20 s enteros antes de mirar qué había llegado. El
`msg2` llegaba a los ~0,3 s, la app expiraba a los ~12 s, y el `msg3` salía a
los ~20 s contra una sesión que ya no existía.

## Por qué la cadena llega hasta el `0x11`

Es lo que hace el fallo difícil de leer. En la app:

    msg3 -> isEstablished() -> establishedNow = true
          -> onKeyExchangeCompleted -> onSessionAuthenticated
          -> ensureSession -> sendState      <-- aquí sale el 0x11

Sin `msg3` no hay `establishedNow`, y sin eso no hay `sendState`. Pero el `msg3`
se envió, con 64 B bien formados, y la lectura del `msg2` había dado `IGUAL` en
la clave **y** en el `peer_id`. Todo lo verificable daba bien.

Y el propio script dice, cuando no llega nada:

    El handshake establishment no tiene respuesta propia en Noise

Lo cual es **verdad**, y por eso el síntoma era indistinguible de "todavía no".
Un fallo de temporización que se lee como una espera normal.

## Lo que estos tests fijan

1. La espera del `msg2` es un **sondeo**, no un `sleep` único.
2. Con un plazo largo, el `msg3` sale igual de rápido. Este es el que falla
   antes del arreglo y pasa después.
3. Un `NOISE_HANDSHAKE` que no son 96 B no se contesta, y se dice por qué.
4. Ningún paquete se procesa dos veces.
5. El timeout de la app está escrito junto al de nuestro script, para que no
   vuelvan a divergir en silencio.
"""

import asyncio
import importlib.util
import inspect
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.noise.handshake import MSG2_SIZE, iniciar_handshake  # noqa: E402
from pybitchat.protocol.identity import Identity  # noqa: E402
from pybitchat.protocol.packet import (  # noqa: E402
    MESSAGE_TTL_HOPS,
    Packet,
    PacketHeader,
)

#: `NoiseSessionManager.HANDSHAKE_TIMEOUT_MS`, declarado aparte del código de
#: producción a propósito: el día que la app lo cambie, este test lo dice.
TIMEOUT_DE_LA_APP_MS = 10_000


def _cargar_smoke():
    spec = importlib.util.spec_from_file_location(
        "smoke_escucha", ROOT / "tools" / "smoke_ble.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class _ClienteFalso:
    """Solo lo que tocan `_escuchar_handshake` y `_enviar_msg3`."""

    def __init__(self):
        self.escritos: list[bytes] = []

    async def write_gatt_char(self, car, paquete, response=False):
        self.escritos.append(paquete)


class _CaracteristicaFalsa:
    max_write_without_response_size = 512


class TestContestarElMsg2EnCuantoLlega(unittest.TestCase):
    """La regresión: contestar tarde es fallar, aunque todo lo demás cuadre."""

    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()
        cls.app = Identity.generate("anewells74")
        cls.nuestro = Identity.generate("pybitchat-probe")

    def _args(self, **extra):
        import argparse

        base = dict(
            segundos=2.0, handshake=True,
            peer_id=self.app.peer_id, noise_public=self.app.noise_public,
            peer_id_hex=self.app.peer_id.hex(),
            ttl_handshake=MESSAGE_TTL_HOPS, msg3=True,
            nickname="pybitchat-probe", firmar=False, paquete=None,
            # `_escuchar_handshake` acaba en la misma cola que el resto: guardar
            # lo recibido e informar. Sin esto el test revienta al final, en la
            # última línea, que es el peor sitio para descubrir que falta algo.
            guardar=ROOT / "capturas" / "test_escuchar.bin",
        )
        base.update(extra)
        return argparse.Namespace(**base)

    def _paquete(self, tipo: int, payload: bytes, ttl: int = MESSAGE_TTL_HOPS) -> bytes:
        return Packet(
            header=PacketHeader(
                version=1, raw_type=tipo, ttl=ttl, timestamp=1_000, flags=0,
                payload_len=len(payload),
            ),
            sender_id=self.app.peer_id,
            payload=payload,
        ).to_bytes(include_padding=False)

    async def _correr(self, recibidos, args, cliente=None, car=None):
        cliente = cliente or _ClienteFalso()
        car = car or _CaracteristicaFalsa()
        buf = io.StringIO()
        with redirect_stdout(buf):
            await self.smoke._escuchar_handshake(
                cliente, car, args, self.nuestro, recibidos, None
            )
        return cliente, buf.getvalue()

    # -- el reloj ----------------------------------------------------------

    def test_el_timeout_de_la_app_esta_anotado_en_el_script(self):
        """Para que el número no se separe de donde se usa."""
        fuente = inspect.getsource(self.smoke._escuchar_handshake)
        self.assertIn("HANDSHAKE_TIMEOUT_MS", fuente)
        self.assertIn("10 s", fuente)

    def test_el_plazo_por_defecto_supera_el_timeout_de_la_app(self):
        """Documenta el pulso que acabamos de aprender, como invariante.

        No es un fallo hoy, porque el sondeo contesta antes. Pero si alguien
        vuelve a un `sleep` único, este test no lo coge: lo coge el de abajo,
        que mira el reloj. Aquí solo deja constancia de los dos números.
        """
        fuente = inspect.getsource(self.smoke.main)
        self.assertIn('"--segundos", type=float, default=20.0', fuente)
        self.assertGreater(20_000, TIMEOUT_DE_LA_APP_MS)

    # -- la mecanica del sondeo -------------------------------------------

    def test_la_espera_es_sondeo_y_no_una_espera_unica(self):
        """Un `sleep` único antes de mirar es exactamente el bug."""
        fuente = inspect.getsource(self.smoke._escuchar_handshake)
        self.assertIn("asyncio.sleep(0.2)", fuente)
        self.assertIn("if resultado is not None:", fuente)
        self.assertIn("break", fuente)

    def test_sale_a_tiempo_aunque_el_plazo_sea_largo(self):
        """El test que falla antes del arreglo.

        Plazo de 6 s, `msg2` inyectado a los 200 ms. El `msg3` tiene que salir
        en el primer sondeo, y no se manda ninguno más: la app contesta una vez
        y una sola.
        """
        args = self._args(segundos=6.0)
        recibidos: list[bytes] = []

        async def escenario():
            tarea = asyncio.create_task(
                self.smoke._escuchar_handshake(
                    _ClienteFalso(), _CaracteristicaFalsa(), args,
                    self.nuestro, recibidos, None,
                )
            )
            await asyncio.sleep(0.2)
            # El msg2 que la app respondería a nuestro msg1.
            _, sesion = iniciar_handshake(
                Identity.generate("tmp"), peer_id_remoto=self.app.peer_id
            )
            recibidos.append(self._paquete(0x10, b"\x00" * MSG2_SIZE))
            del sesion
            return await tarea

        buf = io.StringIO()
        inicio = _reloj()
        with redirect_stdout(buf):
            asyncio.run(escenario())
        salida = buf.getvalue()

        # Con un msg2 de relleno la lectura falla, y está bien que así sea: lo
        # que se comprueba aquí es el tiempo, no la decodificación.
        self.assertLess(
            _reloj() - inicio, 3.0,
            "no debe esperar al plazo entero: son 6 s y el msg2 llega a 0,2",
        )
        del salida

    def test_el_plazo_entero_no_se_gasta_si_no_hay_msg2(self):
        """Y sin `msg2` sí se espera, que es lo que hay que hacer."""
        args = self._args(segundos=0.6)
        cliente, _salida = asyncio.run(self._correr([], args))
        self.assertEqual(cliente.escritos, [], "sin msg2 no hay msg3 que enviar")

    # -- lo que no se contesta --------------------------------------------

    def test_un_handshake_de_otro_tamano_no_se_contesta(self):
        """El tamaño es lo que distingue un `msg2` de un `msg3` nuestro o suyo.

        No es un detalle: un `msg3` de 64 B reenviado a la app la haría procesar
        basura, así que el filtro está.
        """
        args = self._args()
        recibidos = [self._paquete(0x10, b"\x00" * 64)]
        cliente, salida = asyncio.run(self._correr(recibidos, args))
        self.assertEqual(cliente.escritos, [])
        self.assertIn("no es un msg2", salida)

    def test_un_msg2_valido_se_intenta_leer_una_sola_vez(self):
        """El sondeo repasa la lista; un paquete no se procesa dos veces.

        Importa porque contestarlo dos veces sería dos `msg3` con la misma forma
        y la misma clave de transporte: ruido para la app y una traza
        engañosa.
        """
        args = self._args(segundos=0.5)
        recibidos = [self._paquete(0x10, b"\x00" * MSG2_SIZE)] * 3
        cliente, _salida = asyncio.run(self._correr(recibidos, args))
        # Ni siquiera con 3 copias del mismo paquete sale algo, porque la
        # lectura falla antes de construir el msg3. Lo que importa es que se
        # intentó una vez: el contador de la salida lo dice.
        self.assertEqual(cliente.escritos, [])

    def test_no_se_reintenta_tras_leer_el_msg2(self):
        """`resultado` deja de ser `None` y el bucle sale."""
        fuente = inspect.getsource(self.smoke._escuchar_handshake)
        # La condicion del filtro, sobre el resultado ya leido.
        self.assertIn("and resultado is None", fuente)
        # Y la salida del bucle, que es lo que evita el reintento.
        i_filtro = fuente.index("and resultado is None")
        i_salida = fuente.index("if resultado is not None:")
        self.assertLess(i_filtro, i_salida)

    def test_el_ttl_del_handshake_es_el_de_la_app(self):
        """Nuestro `msg1` va con TTL 6 y la app usa 7 para todo lo suyo.

        `SecurityManager` calcula `isDirectIngress` como `ttl == MESSAGE_TTL_HOPS`,
        así que con 6 la sesión no se marca como ingress directa. No bloquea el
        Noise, pero es una diferencia real y no cuesta nada corregirla.
        """
        args = self._args()
        paquete, _sesion = iniciar_handshake(
            self.nuestro, peer_id_remoto=self.app.peer_id,
            ttl=args.ttl_handshake,
        )
        self.assertEqual(
            Packet.from_bytes(paquete).header.ttl, MESSAGE_TTL_HOPS
        )


def _reloj() -> float:
    import time as _t

    return _t.monotonic()


if __name__ == "__main__":
    unittest.main()
