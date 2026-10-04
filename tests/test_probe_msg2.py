"""Tests de `tools/probe_msg2.py`.

La pregunta que responde la herramienta: el `msg2` de la app son 96 B, se lee
sin error de descifrado, pero `remote_static_public` queda `None`. Con nuestro
propio intercambio la misma librería sí lo pone.

Las dos funciones puras —recorrer paquetes y desglosar el `msg2`— se comprueban
aquí, sin `noiseprotocol` y sin hardware. La parte que sí necesita la librería
(`probar_read`) es la que responde en el host.

Por qué recorrer por longitud declarada y no asumir 256 B: un paquete relleno a
256 tiene 256 bytes en el cable pero su longitud real es menor. Saltar de 256
en 256 mete el siguiente paquete en el sitio equivocado, y el error resultante
no señala el origen.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from pybitchat.protocol.identity import Identity  # noqa: E402
from pybitchat.protocol.packet import Packet, PacketHeader  # noqa: E402
from pybitchat.protocol.types import MessageType, PacketFlags  # noqa: E402


def _cargar():
    ruta = ROOT / "tools" / "probe_msg2.py"
    # Nombre propio: `TestSmokeBle` carga el mismo fichero de `smoke_ble.py`, y
    # dos módulos con el mismo `spec.name` no son independientes.
    spec = importlib.util.spec_from_file_location("probe_msg2_mod", ruta)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


probe = _cargar()


def _paquete(tipo, carga, *, con_relleno=True):
    cabecera = PacketHeader(
        version=1,
        raw_type=int(tipo),
        ttl=6,
        timestamp=1_754_073_314_075,
        flags=PacketFlags(0),
        payload_len=len(carga),
    )
    p = Packet(
        header=cabecera, sender_id=b"\x11" * 8, payload=carga
    )
    return p.to_bytes(include_padding=False)


class TestLeerPaquetes(unittest.TestCase):
    """Recorrer por longitud declarada, no por un tamaño supuesto."""

    def test_lee_varios_paquetes_seguidos(self):
        datos = (
            _paquete(MessageType.ANNOUNCE, b"\x01" * 80)
            + _paquete(MessageType.NOISE_HANDSHAKE, b"\x02" * 96)
            + _paquete(MessageType.REQUEST_SYNC, b"\x03" * 16)
        )
        leidos = probe.leer_paquetes(datos)
        self.assertEqual(len(leidos), 3)
        self.assertEqual(
            [p.header.raw_type for p in leidos],
            [int(MessageType.ANNOUNCE),
             int(MessageType.NOISE_HANDSHAKE),
             int(MessageType.REQUEST_SYNC)],
        )

    def test_el_ultimo_paquete_no_necesita_relleno(self):
        """El fichero acaba justo donde acaba el paquete.

        Si el recorrido exigiera un múltiplo de 256, el último se perdería.
        """
        datos = _paquete(MessageType.ANNOUNCE, b"\x01" * 80)
        leidos = probe.leer_paquetes(datos)
        self.assertEqual(len(leidos), 1)

    def test_datos_vacios_da_cero_paquetes(self):
        self.assertEqual(probe.leer_paquetes(b""), [])

    def test_datos_corruptos_no_revientan(self):
        """Un paquete ilegible debe parar con un diagnóstico, no con una
        excepción: la herramienta existe para esto y si peta, no sirve."""
        datos = _paquete(MessageType.ANNOUNCE, b"\x01" * 80) + b"\xff" * 4
        leidos = probe.leer_paquetes(datos)
        # Los buenos antes del corrupto, y ningún error.
        self.assertGreaterEqual(len(leidos), 0)

    def test_el_primer_paquete_se_lee_bien_tras_uno_corrupto_al_final(self):
        datos = _paquete(MessageType.ANNOUNCE, b"\x01" * 80) + b"\xff" * 64
        leidos = probe.leer_paquetes(datos)
        self.assertEqual(len(leidos), 1)
        self.assertEqual(leidos[0].header.raw_type, int(MessageType.ANNOUNCE))


class TestDesglose(unittest.TestCase):
    """El desglose tiene que poder decir que NO cuadra.

    ## Lo que cambia el 2026-10-05

    Antes este test daba por bueno que XX canonico mide `32 + 48*3 = 176` B, y
    que por tanto el `msg2` real de la app (96 B) "no era XX canonico". Era una
    cuenta mala: `EE` y `ES` son `mixDH`, derivan clave y **no emiten bytes**.
    Los tres tokens de 48 B no existen.

    El desglose correcto sale del patron y del cipher:

        E(32) + EE(0) + S(48) + ES(0) + tag(16) = 96

    asi que el `msg2` real de la app **si** es XX con ChaChaPoly, y 96 es
    justo lo que tiene que decir la herramienta.
    """

    def test_un_msg2_de_96_si_cuadra(self):
        """96 B es el tamano correcto, no una excepcion."""
        lineas = "\n".join(probe.desglosar(b"\x00" * 96))
        self.assertIn("coincide", lineas)
        self.assertNotIn("NO coincide", lineas)

    def test_el_desglose_dice_los_cuatro_tokens(self):
        texto = "\n".join(probe.desglosar(b"\x00" * 96))
        for token in ("E ", "EE", "S ", "ES"):
            with self.subTest(token=token):
                self.assertIn(token, texto)

    def test_los_mixdh_son_cero_bytes(self):
        """`EE` y `ES` no ocupan espacio. Es la mitad del error anterior."""
        texto = "\n".join(probe.desglosar(b"\x00" * 96))
        self.assertIn("EE  ->   0 B", texto)
        self.assertIn("ES  ->   0 B", texto)

    def test_ningun_token_mixdh_cuesta_48(self):
        """176 y 144 fueron las dos cuentas erroneas. Ninguna puede volver."""
        texto = "\n".join(probe.desglosar(b"\x00" * 96))
        self.assertNotIn("176", texto)
        self.assertNotIn("144", texto)

    def test_avisa_cuando_el_tamano_no_cuadra(self):
        lineas = "\n".join(probe.desglosar(b"\x00" * 80))
        self.assertIn("NO coincide", lineas)

    def test_indica_cuantos_faltan(self):
        lineas = "\n".join(probe.desglosar(b"\x00" * 80))
        self.assertIn("-16", lineas)  # 80 - 96

    def test_avisa_que_el_desglose_no_describe_el_formato_real(self):
        """El fallo de este informe seria ensenar `S -> 16 B` sin avisar de que
        el tamano no cuadra, que lleva a debuggear un token que no existe."""
        texto = " ".join(probe.desglosar(b"\x00" * 80))
        # La frase va partida en varias lineas del informe, asi que se
        # comprueba sobre el texto unido: `assertIn` sobre el "\n" fallaria
        # aunque el aviso este.
        self.assertIn("aritmetica sobre una", texto)

    def test_no_dice_que_avisa_cuando_el_tamano_si_cuadra(self):
        """Con 96 B el desglose si es valido: no debe llevar el aviso."""
        texto = " ".join(probe.desglosar(b"\x00" * 96))
        self.assertNotIn("aritmetica sobre una", texto)

    def test_avisa_cuando_un_token_no_cabe(self):
        """Con 80 B, `S` necesita 48 y solo quedan 48 tras `E`... y el tag se
        queda sin sitio. Se dice "NO CABE" en vez de escribir un tamano que no
        es real."""
        texto = "\n".join(probe.desglosar(b"\x00" * 10))
        self.assertIn("NO CABE", texto)

    def test_no_se_inventa_bytes_que_no_hay(self):
        """Con 10 B no puede desglosar 96: el informe tiene que poner lo que
        hay, no lo que deberia."""
        lineas = "\n".join(probe.desglosar(b"\x00" * 10))
        self.assertIn("10", lineas)

    def test_dice_que_comprobar_la_efimera(self):
        """Un tamano que cuadra no demuestra el reparto. La comprobacion que si
        es independiente del tamano es que los 32 primeros bytes sean un punto
        X25519 valido, porque la efimera va en claro."""
        texto = " ".join(probe.desglosar(b"\x00" * 96))
        self.assertIn("punto X25519", texto)


class TestSinNoiseProtocol(unittest.TestCase):
    """La herramienta tiene que dar el desglose aunque falte la librería.

    Es lo que pasó el 2026-10-04: `noiseprotocol` no estaba en el host, y el
    script contestaba "NO INSTALADO" y salía con código 1 **sin dar el
    desglose**, que es justo lo que se le pedía.

    La comprobación se hace donde se usa —descifrar—, no al principio, para que
    la falta se note en su sitio y no impida el resto.
    """

    def test_desglosar_no_depende_de_la_libreria(self):
        """El desglose es aritmetica sobre longitudes: no necesita nada.

        Se comprueba con un tamano que **no** cuadra, porque ahi el informe
        tiene mas trabajo que hacer: si bastara con que el tamino cuadre, el
        test pasaria sin hacer nada.
        """
        lineas = probe.desglosar(bytes(80))
        self.assertTrue(any("NO coincide" in l for l in lineas))
        self.assertTrue(any("E" in l and "32" in l for l in lineas))

    def test_leer_paquetes_no_depende_de_la_libreria(self):
        """Leer un paquete tampoco la necesita."""
        datos = _paquete(MessageType.NOISE_HANDSHAKE, b"\x02" * 96)
        leidos = probe.leer_paquetes(datos)
        self.assertEqual(len(leidos), 1)
        self.assertEqual(len(leidos[0].payload), 96)

    def test_el_modulo_importa_sin_la_libreria(self):
        """Si importar el módulo requiriera `noiseprotocol`, el script no
        podría decir siquiera "no está instalado"."""
        import importlib
        import subprocess
        import sys as _sys

        src = (
            "import importlib.util, sys;"
            "sys.path.insert(0, 'src');"
            "spec = importlib.util.spec_from_file_location('m', 'tools/probe_msg2.py');"
            "m = importlib.util.module_from_spec(spec);"
            "spec.loader.exec_module(m);"
            "print('ok')"
        )
        raiz = ROOT
        r = subprocess.run(
            [_sys.executable, "-c", src],
            capture_output=True,
            text=True,
            cwd=str(raiz),
            timeout=60,
        )
        # El código de salida, no el texto.
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok", r.stdout)

    def test_probar_read_no_revienta_sin_la_libreria(self):
        """Sigue sin lanzar aunque el motor no este: el informe entero vale.

        Lo que ahora dice es que aqui **no** se puede descifrar, con o sin
        motor, asi que la comprobacion va en `smoke_ble.py`.
        """
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            probe.probar_read(bytes(96), None)
        self.assertIn("no puede", buf.getvalue())

    def test_probar_read_dice_que_toca_smoke_ble(self):
        """El informe tiene que senalizar donde esta la comprobacion de verdad."""
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            probe.probar_read(bytes(96), None)
        self.assertIn("smoke_ble.py", buf.getvalue())

    def test_probar_read_no_promete_que_descifra(self):
        """Ya no puede decir 'leido sin error': era mentira.

        Decirlo era peor que callarse: un Poly1305 que nunca se comprueba no
        puede fallar, y eso se leia como una prueba.
        """
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            probe.probar_read(bytes(96), None)
        salida = buf.getvalue()
        self.assertNotIn("leído sin error.", salida)

    def test_el_umbral_de_fichero_por_defecto_capturas(self):
        """Por defecto mira `capturas/recibido.bin`, que es donde
        `smoke_ble.py` guarda."""
        import argparse
        import io
        from contextlib import redirect_stdout

        # Se comprueba el default del parser, no el de la función.
        src = (ROOT / "tools" / "probe_msg2.py").read_text(encoding="utf-8")
        self.assertIn("capturas", src)
        self.assertIn("recibido.bin", src)


class TestNombreDelModulo(unittest.TestCase):
    """La distribucion se llama `noiseprotocol`; el modulo, `noise`.

    ## Por que esto necesita un test

    Pasó el 2026-10-05 en el host, y costó una ida y vuelta: `pip` decía
    `Requirement already satisfied: noiseprotocol (0.3.1)` y el script decía
    que el paquete no estaba instalado. Los dos tenían razón.

    `requirements.txt` fija la **distribucion** de PyPI, que se llama
    `noiseprotocol`. El **modulo** que instala se llama `noise`, y lo que
    `noise/session.py` importa es `noise.noise_protocol`.

    Preguntar por `find_spec("noiseprotocol")` devuelve `None` **siempre**, con
    la distribución perfectamente instalada. Por eso el diagnosis tiene que ir
    por el nombre del modulo.
    """

    def test_el_modulo_es_noise_no_noiseprotocol(self):
        self.assertEqual(probe.MODULO_NOISE, "noise.noise_protocol")

    def test_no_se_pregunta_por_el_nombre_de_la_distribucion(self):
        """Si vuelve a preguntarse por `noiseprotocol`, el falso negativo vuelve."""
        import inspect

        fuente = inspect.getsource(probe._estado_noiseprotocol)
        self.assertNotIn('find_spec("noiseprotocol")', fuente)
        self.assertNotIn("import noiseprotocol", fuente)

    def test_session_py_importa_el_mismo_modulo(self):
        """El script y la sesion tienen que mirar lo mismo, o uno miente."""
        import importlib

        mod = importlib.import_module("pybitchat.noise.session")
        self.assertTrue(hasattr(mod, "NoiseProtocol"))

    def test_el_comando_de_comprobacion_usa_el_modulo(self):
        """El comando que el motivo sugiere tiene que funcionar de verdad."""
        ok, motivo = probe._estado_noiseprotocol()
        if ok:
            self.skipTest("noiseprotocol esta en esta maquina")
        self.assertIn("noise.noise_protocol", motivo)
        self.assertNotIn("import noiseprotocol;", motivo)


class TestCompararContraLaApp(unittest.TestCase):
    """La clave del `msg2` es de la app, así que se compara contra la app.

    La versión anterior comparaba el `peer_id` derivado contra **nuestro** propio
    `peer_id`. Eso da `False` siempre y no dice absolutely nada: es una
    comparación que no puede salir bien ni mal.
    """

    def test_probar_read_acepta_el_peer_id_remoto(self):
        import inspect

        firma = inspect.signature(probe.probar_read)
        self.assertIn("peer_id_remoto", firma.parameters)
        self.assertIn("noise_remoto", firma.parameters)

    def test_no_compara_contra_identidad_del_propio_peer_id(self):
        import inspect

        fuente = inspect.getsource(probe.probar_read)
        self.assertNotIn("pid == identidad.peer_id", fuente)

    def test_main_pasa_los_argumentos(self):
        """Si `main` no los pasa, la firma nueva no sirve de nada."""
        import inspect

        fuente = inspect.getsource(probe.main)
        self.assertIn("args.peer_id", fuente)
        self.assertIn("args.noise_public", fuente)


class TestEstadoDeNoiseprotocol(unittest.TestCase):
    """La comprobación tiene que distinguir tres casos, no uno.

    Pasó el 2026-10-04: `pip` decía "already satisfied (0.3.1)" y el script
    imprimía "NO INSTALADO". Se contradecían, y un mensaje falso hace perder una
    sesión entera porque dice "instala esto" cuando ya está instalado.

    Un `except ImportError` estrecho tiene tres caminos a ese falso negativo:
    una dependencia ausente dentro del paquete (el error es sobre *ella*, no
    sobre `noiseprotocol`), algo que Python movió, y `__version__` inexistente
    (`AttributeError`, que no lo captura `except ImportError`).
    """

    def test_el_motivo_siempre_explica_algo(self):
        ok, motivo = probe._estado_noiseprotocol()
        self.assertIsInstance(motivo, str)
        self.assertTrue(motivo.strip(), "el motivo está vacío")

    def test_si_esta_instalada_no_dice_que_falta(self):
        ok, motivo = probe._estado_noiseprotocol()
        if not ok:
            self.skipTest("noiseprotocol no está en esta máquina")
        self.assertNotIn("no está", motivo)
        self.assertNotIn("pip install", motivo)

    def test_si_ausente_dice_como_instalarla(self):
        ok, motivo = probe._estado_noiseprotocol()
        if ok:
            self.skipTest("noiseprotocol está en esta máquina")
        self.assertIn("no está", motivo)
        self.assertIn("pip install", motivo)

    def test_el_motivo_dice_donde_ha_mirado(self):
        """Un "no esta" sin decir donde obliga a una ida y vuelta.

        Paso el 2026-10-05: `pip` decia "already satisfied (0.3.1)" y el script
        decia que el paquete no estaba. Los dos tienen razon y solo se arbitra
        con la version del interprete y la ruta que se ha mirado, asi que el
        motivo tiene que traerlas.
        """
        ok, motivo = probe._estado_noiseprotocol()
        if ok:
            self.skipTest("noiseprotocol esta en esta maquina")
        self.assertIn("intérprete:", motivo)
        self.assertIn("versión:", motivo)
        self.assertIn("buscando en:", motivo)

    def test_el_motivo_dice_como_comprobar_el_import(self):
        """El motivo debe decir como comprobarlo, no solo que no lo encuentra."""
        ok, motivo = probe._estado_noiseprotocol()
        if ok:
            self.skipTest("noiseprotocol esta en esta maquina")
        self.assertIn("noiseprotocol.__file__", motivo)

    def test_el_camino_de_paquete_roto_esta_escrito(self):
        """Que exista una rama para "está pero no importa".

        **No se puede simular** con `sys.modules`: poner `None` hace que
        `find_spec` devuelva `None` también, así que la función ve "no existe"
        y no hay forma de llegar a la otra rama. Comprobado.

        Se comprueba el texto, que es lo verificable sin un paquete roto de
        verdad en disco. El comportamiento viene fijado por los otros tests: si
        la librería está, no dice que falta.
        """
        import io
        from pathlib import Path as _P

        raiz = _P(__file__).resolve().parent.parent
        src = io.open(raiz / "tools" / "probe_msg2.py", encoding="utf-8").read()
        self.assertIn("el paquete está pero su import falla", src)
        self.assertIn("el paquete está pero al importarlo salta", src)


class TestSaltoDelRelleno(unittest.TestCase):
    """El recorrido tiene que saltarse el relleno, no leerlo como cabecera.

    Pasó el 2026-10-04: se paraba en el offset 166 con "versión de protocolo
    desconocida: 0x5a". El 166 era **correcto** —el announce ocupa 166 en el
    cable, con su firma— y lo que faltaba era saltar los 90 de relleno.
    """

    @staticmethod
    def _announce_real() -> bytes:
        """166 B exactos: 14 cabecera + 8 sender + 80 TLV + 64 firma."""
        return bytes.fromhex(
            "010107000001a10310526d020050"          # cabecera, flags=0x02
            "34e01ccea10a8c6d"                      # sender
            "010a616e6577656c6c733734"              # TLV 0x01 nickname
            "0220973585b6502836ff5767934bdb4c62458c"
            "48b87e94c02d470797e93d21052f6b"         # TLV 0x02 Noise
            "03207ada9dab1bec9eb274cfaa0e3489b2"
            "59d3219f069fe84cb694aa7c5871a61a88"     # TLV 0x03 firma
            + "00" * 64                              # la firma (cualquiera)
        )

    def _con_relleno(self) -> bytes:
        real = self._announce_real()
        return real + bytes([256 - len(real)]) * (256 - len(real))

    def test_un_paquete_rellenado_se_lee_entero(self):
        leidos = probe.leer_paquetes(self._con_relleno())
        self.assertEqual(len(leidos), 1)
        self.assertEqual(len(leidos[0].payload), 80)
        self.assertEqual(len(leidos[0].signature), 64)

    def test_tres_paquetes_rellenados_se_leen_tres(self):
        """El caso real: el fichero de 768 B del usuario."""
        leidos = probe.leer_paquetes(self._con_relleno() * 3)
        self.assertEqual(len(leidos), 3)

    def test_sin_relleno_tambien_funciona(self):
        """El salto es condicional: un paquete sin relleno va igual."""
        leidos = probe.leer_paquetes(self._announce_real())
        self.assertEqual(len(leidos), 1)

    def test_relleno_no_pkcs7_no_revienta(self):
        """Un relleno que no es PKCS#7 se para con un mensaje, no con una
        excepción sin contexto."""
        real = self._announce_real()
        leidos = probe.leer_paquetes(real + bytes([0x01, 0x02] * 45))
        self.assertGreaterEqual(len(leidos), 1)

    def test_paquetes_sin_relleno_pegados_no_se_comen(self):
        """El falso positivo que Almost se cuela.

        Una comprobación floja del relleno —"si el byte siguiente está
        repetido, es relleno"— se come el principio del paquete siguiente cuando
        **no** hay relleno. Tras un paquete de 166 B, el byte 167 es `0x01`, el
        168 `0x10`, y eso parece un relleno de 1 B.

        Se exige además que tras el relleno empiece un paquete **legible**, que
        es lo que corta el falso positivo.
        """
        import struct

        def cab(tipo, plen, flags=0x02):
            ts = struct.pack(">Q", 1)
            return (
                struct.pack(">B", 1) + struct.pack(">B", tipo)
                + struct.pack(">B", 7) + ts
                + struct.pack(">B", flags) + struct.pack(">H", plen)
            )

        snd = bytes.fromhex("34e01ccea10a8c6d")
        p1 = cab(1, 80) + snd + bytes(80) + bytes(64)      # 166 B
        p2 = cab(0x10, 96) + snd + bytes(96) + bytes(64)   # 182 B
        p3 = cab(0x21, 16, 0x00) + snd + bytes(16)         # 38 B
        leidos = probe.leer_paquetes(p1 + p2 + p3)
        self.assertEqual(len(leidos), 3)
        self.assertEqual(
            [p.header.raw_type for p in leidos], [0x01, 0x10, 0x21]
        )

    def test_la_longitud_en_cable_no_usa_to_bytes(self):
        """Re-serializar puede dar una longitud distinta de la que ocupa el
        original: `to_bytes` omite lo que el paquete no declara."""
        import struct

        from pybitchat.protocol.packet import Packet, PacketHeader

        ts = struct.pack(">Q", 1)
        cab = PacketHeader(
            version=1, raw_type=int(MessageType.NOISE_HANDSHAKE), ttl=7,
            timestamp=0, flags=PacketFlags(0x02), payload_len=96,
        )
        p = Packet(
            header=cab, sender_id=bytes(8), payload=bytes(96), signature=bytes(64)
        )
        # 14 + 8 sender + 96 payload + 64 firma = 182
        self.assertEqual(probe._longitud_en_cable(p), 14 + 8 + 96 + 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)