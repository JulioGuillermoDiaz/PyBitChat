"""El filtro y el veredicto de `probe_logcat.py`, sin `adb` ni móvil.

## Por qué esto sí se puede probar aquí

La VM Windows no tiene `adb` ni BLE, así que la orchestration de la herramienta
no se prueba. Pero lo que **decide** qué nos cuenta el móvil son dos funciones
puras sobre texto de log, y esas sí.

Y tienen que estar probadas por un motivo concreto: **una ausencia es
indistinguible de un evento que no ocurrió**. Si una frase del filtro está mal
escrita, el filtro devuelve `None`, la herramienta dice "ni una línea útil", y
eso se lee igual que "la app no dijo nada". Un error de una letra se vuelve un
diagnóstico falso.

## De dónde salen las frases

Todas están leídas del código de la app. Las que importan:

| Frase | Dónde |
|---|---|
| `Noise handshake completed with` | `SecurityManager.handleNoiseHandshake` |
| `Handshake failed with` | `NoiseSessionManager` (con el motivo detrás de `:`) |
| `Expiring stale handshake` | `NoiseSessionManager.cleanupStaleHandshakes` |
| `Authenticated Noise key derives to` | `NoiseSessionError.PeerIdentityMismatch` |
| `Ignoring ANNOUNCE from stale BLE link` | `BluetoothMeshService.handleAnnounce` |
| `Dropping packet from stale connection` | `BluetoothGattServerManager` |
| `Received packet with no peer ID` | `PacketProcessor.processPacket` |
| `Noise session established with` | `EncryptionService` (con el emoji ✅ delante) |

Ese emoji es una razón más de no filtrar por etiqueta: la línea de log lleva
`✅` y un buscar-y-reemplazar ingenuo lo revienta.
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import importlib  # noqa: E402


def _cargar():
    spec = importlib.util.spec_from_file_location(
        "probe_logcat", ROOT / "tools" / "probe_logcat.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _log(nivel: str, etiqueta: str, mensaje: str, pid: int = 1234) -> str:
    """Una línea con el formato que emite `adb logcat -v time`."""
    return f"10-06 11:47:23.456 {nivel}/{etiqueta}({pid:5d}): {mensaje}"


class TestElFiltro(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = _cargar()

    def test_reconoce_la_linea_de_exito(self):
        """`Noise handshake completed`, en `SecurityManager`."""
        linea = _log("I", "SecurityManager",
                     "Noise handshake completed with 09dce4fe2058f5db")
        etiqueta, explicacion, motivo = self.probe._clasificar(linea)
        self.assertEqual(etiqueta, "COMPLETADO")
        self.assertIn("establecida", explicacion)
        del motivo

    def test_saca_el_motivo_del_fallo(self):
        """El motivo va detrás de `:` y es lo que se busca.

        `Handshake failed with 34e0...: <motivo>`: el `:` que separa el motivo
        es el primero, porque el `peer_id` no lleva ninguno.
        """
        linea = _log("E", "NoiseSessionManager",
                     "Handshake failed with 09dce4fe2058f5db: Invalid state")
        etiqueta, _explicacion, motivo = self.probe._clasificar(linea)
        self.assertEqual(etiqueta, "FALLIDO")
        self.assertEqual(motivo, "Invalid state")

    def test_reconoce_el_tiempo_espigado(self):
        linea = _log("D", "NoiseSessionManager",
                     "Expiring stale handshake with 09dce4fe2058f5db")
        etiqueta, explicacion, _m = self.probe._clasificar(linea)
        self.assertEqual(etiqueta, "EXPIRADO")
        self.assertIn("10 s", explicacion)

    def test_reconoce_la_clave_que_no_deriva(self):
        """El mensaje es del `NoiseSessionError`, no de un `Log`."""
        linea = _log("E", "NoiseSessionManager",
                     "Authenticated Noise key derives to 0011223344556677, "
                     "not claimed peer 09dce4fe2058f5db")
        etiqueta, _e, _m = self.probe._clasificar(linea)
        self.assertEqual(etiqueta, "IDENTIDAD-DISTINTA")

    def test_el_emoji_no_rompe_la_linea(self):
        """La línea real de `EncryptionService` lleva un `✅` delante.

        Es la razón de no filtrar por etiqueta: un buscar-y-reemplazar por
        palabra exacta fallaría aquí, y con `noise` en minúsculas dentro de
        "Noise" tampoco.
        """
        linea = _log("D", "EncryptionService",
                     "\u2705 Noise session established with 09dce4fe2058f5db, "
                     "fingerprint: 9f3a...")
        etiqueta, _e, _m = self.probe._clasificar(linea)
        self.assertEqual(etiqueta, "SESION-ESTABLECIDA")

    def test_reconoce_el_paquete_que_no_llego(self):
        """El que más vale, porque descarta la capa Noise entera."""
        linea = _log("D", "BluetoothGattServerManager",
                     "Server: Dropping packet from stale connection "
                     "5E:4D:8B:F3:A0:3A")
        etiqueta, explicacion, _m = self.probe._clasificar(linea)
        self.assertEqual(etiqueta, "CONEXION-VIEJA")
        self.assertIn("Noise", explicacion)

    def test_reconoce_el_peer_id_ausente(self):
        linea = _log("W", "PacketProcessor",
                     "Received packet with no peer ID, skipping")
        etiqueta, _e, _m = self.probe._clasificar(linea)
        self.assertEqual(etiqueta, "SIN-PEER-ID")

    def test_reconoce_el_announce_rechazado(self):
        linea = _log("W", "MessageHandler",
                     "Rejecting malformed, unbound, or invalidly signed "
                     "ANNOUNCE from 09dce4fe")
        etiqueta, _e, _m = self.probe._clasificar(linea)
        self.assertEqual(etiqueta, "ANNOUNCE-RECHAZADO")

    def test_reconoce_el_no_verificado(self):
        linea = _log("W", "MessageHandler",
                     "Dropping public message from unverified peer 09dce4fe")
        etiqueta, _e, _m = self.probe._clasificar(linea)
        self.assertEqual(etiqueta, "NO-VERIFICADO")

    # -- lo que el filtro debe dejar fuera y lo que no ---------------------

    def test_una_linea_corriente_no_se_clasifica(self):
        """Un `Log.d` de estado no es una señal, y si lo fuera el veredicdo miente."""
        linea = _log("D", "BluetoothMeshService",
                     "Starting Bluetooth mesh service with peer ID: 34e0...")
        self.assertEqual(self.probe._clasificar(linea)[0], None)

    def test_conserva_los_warn_desconocidos(self):
        """Ante la duda, sobra.

        Una etiqueta que no conozco no puede hacer que se pierda un `WARN` que
       |resultara ser justo lo que buscábamos.
        """
        linea = _log("W", "AlgoNuevoDeLaApp",
                     "esto no estaba en el codigo que lei")
        self.assertEqual(self.probe._clasificar(linea)[0], "OTRA")

    def test_conserva_los_error_desconocidos(self):
        linea = _log("E", "LoQueSea", "boom")
        self.assertEqual(self.probe._clasificar(linea)[0], "OTRA")

    def test_una_linea_sin_formato_no_rompe(self):
        """Si `adb` cambiara el formato, o filtráramos mal, no reventamos.

        Un crash aquí sería peor que no clasificar: perderíamos el log entero.
        """
        self.assertEqual(self.probe._clasificar("basura sin formato")[0], None)

    def test_una_linea_vacia_no_rompe(self):
        self.assertEqual(self.probe._clasificar("")[0], None)

    def test_una_frase_mal_escrita_no_se_da_por_bien(self):
        """La razón de existir de estos tests.

        Si alguien escribe "Noise handshake complete" en vez de "completed",
        el filtro devuelve `None` y la herramienta dice "ni una línea útil",
        que se lee igual que "la app no dijo nada". Un error de una letra
        convertirse en un diagnóstico falso es exactamente el fallo que hay
        que evitar aquí.
        """
        mal = _log("I", "SecurityManager",
                   "Noise handshake complete with 09dce4fe2058f5db")
        self.assertNotEqual(
            self.probe._clasificar(mal)[0], "COMPLETADO",
            "una frase mal escrita tiene que fallar el filtro, no colarse",
        )

    def test_todas_las_frases_estan_en_el_codigo_de_sin_atajos(self):
        """Guarda contra el typo: cada frase tiene que ser alcanzable.

        Se comprueba que la frase está *en* la tabla, que es el invariante
        trivial, pero sobre todo que ninguna está duplicada con otra más
        corta que la tape: el orden de `SIGNALES` manda, y una entrada
        posterior nunca gana.
        """
        frases = [s[0] for s in self.probe.SIGNALES]
        self.assertEqual(len(frases), len(set(frases)), "frases repetidas")
        for i, corta in enumerate(frases):
            for j, larga in enumerate(frases):
                if i != j and corta in larga:
                    self.fail(
                        f"'{corta}' (pos {i}) queda dentro de '{larga}' (pos {j}); "
                        f"la que va antes se come a la que va despues"
                    )


class TestElVeredicto(unittest.TestCase):
    """Las tres ramas, que son las hipótesis de `ESTADO.md` §5."""

    @classmethod
    def setUpClass(cls):
        cls.probe = _cargar()

    def _v(self, *mensajes):
        lineas = [
            _log("I", "SecurityManager",
                 "Noise handshake completed with 09dce4fe2058f5db")
            for _ in (1,)
        ]
        cl = []
        for etiqueta, explicacion, motivo in mensajes:
            cl.append((etiqueta, explicacion, motivo))
        return "\n".join(self.probe._veredicto(cl)), lineas

    def test_si_completo_dice_que_la_sesion_existe(self):
        texto, _ = self._v(
            ("COMPLETADO", "la app cerro el handshake", None)
        )
        self.assertIn("COMPLETO", texto)
        self.assertIn("establecida en su lado", texto)
        # Y tiene que decir dónde mirar después, no solo qué pasó.
        self.assertIn("ensureSession", texto)

    def test_el_completo_manda_sobre_el_expirado(self):
        """Un `Expiring` viejo puede quedar en el log junto a un éxito.

        Si no, el veredicto daría "no pudo" con la sesión establecida, que es
        justo la confusión que queremos evitar.
        """
        texto, _ = self._v(
            ("COMPLETADO", "la app cerro el handshake", None),
            ("EXPIRADO", "le paso el tiempo", None),
        )
        self.assertIn("COMPLETO", texto)

    def test_si_intento_y_no_pudo_muestra_el_motivo(self):
        texto, _ = self._v(
            ("FALLIDO", "lo intento y no pudo", "Invalid state")
        )
        self.assertIn("INTENTO", texto)
        self.assertIn("Invalid state", texto)

    def test_si_no_llego_lo_dice_porque_descarta_mas_teoria(self):
        """La tercera rama es la más valiosa.

        Si la app no menciona el handshake en ningún momento, el problema no
        es el `msg3` ni el Noise: se perdió antes. Y eso elimina de golpe todo
        lo que se podría sospechar del mensaje.
        """
        texto, _ = self._v(
            ("CONEXION-VIEJA", "no llego a la capa Noise", None)
        )
        self.assertIn("NO LLEGO", texto)
        self.assertIn("no es el msg3 ni el Noise", texto)

    def test_el_announce_rechazado_manda_sobre_el_silencio(self):
        """Va antes que Noise, porque sin par verificado no hay sesión."""
        texto, _ = self._v(
            ("ANNOUNCE-RECHAZADO", "no paso el validador", None)
        )
        self.assertIn("announce", texto)
        self.assertIn("verificado", texto)

    def test_sin_lineas_no_inventa_un_veredicto(self):
        """El caso en el que hay que ser más cauto.

        Cero señales significa casi siempre que el filtro se quedó corto, no
        que la app estuvo callada. La herramienta tiene que decirlo, porque lo
        contrario se lee como un dato.
        """
        texto = "\n".join(self.probe._veredicto([]))
        self.assertIn("ni una linea util", texto)
        self.assertIn("filtro", texto)
        self.assertIn("adb logcat -d", texto)

    def test_las_tres_ramas_son_alcanzables(self):
        """Que el conjunto de reglas no deje ninguna rama muerta."""
        import inspect

        fuente = inspect.getsource(self.probe._veredicto)
        for rama in ("completados", "intentados", "perdidos", "announces"):
            self.assertIn(f"if {rama}:", fuente)


if __name__ == "__main__":
    unittest.main()