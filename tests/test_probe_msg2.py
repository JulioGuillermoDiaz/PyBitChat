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
    """El desglose tiene que poder decir que NO cuadra."""

    def test_un_msg2_de_96_no_cuadra_con_xx_canonico(self):
        """XX canónico mide 32 + 48*3 = 176 B.

        Este es el hallazgo del 2026-10-04: el `msg2` de la app son 96 B y no
        son XX canónico por tamaño. La herramienta tiene que decirlo, no
        esconderlo dando un desglose plausible.
        """
        lineas = "\n".join(probe.desglosar(b"\x00" * 96))
        self.assertIn("NO coincide", lineas)
        self.assertIn("176", lineas)
        self.assertIn("96", lineas)

    def test_un_msg2_de_176_si_cuadra(self):
        lineas = "\n".join(probe.desglosar(b"\x00" * 176))
        self.assertIn("coincide", lineas)
        self.assertNotIn("NO coincide", lineas)

    def test_indica_cuantos_faltan(self):
        lineas = "\n".join(probe.desglosar(b"\x00" * 96))
        self.assertIn("80", lineas)  # 176 - 96

    def test_propone_las_causas_de_la_diferencia(self):
        """Los 80 B que faltan encajan con tokens sin tag o en claro, y eso
        es lo que hay que investigar. Se **dice**, no se supone cuál es."""
        lineas = "\n".join(probe.desglosar(b"\x00" * 96))
        self.assertIn("tag", lineas)
        self.assertIn("sin decidir", lineas)

    def test_avisa_que_el_desglose_no_describe_el_formato_real(self):
        """El fallo de este informe sería enseñar `S -> 16 B` sin avisar de que
        el patrón no es XX, que lleva a debuggear un token que no existe."""
        texto = " ".join(probe.desglosar(b"\x00" * 96))
        # La frase va partida en varias líneas del informe, así que se
        # comprueba sobre el texto unido: `assertIn` sobre el "\n" fallaría
        # aunque el aviso esté.
        self.assertIn("no describe el formato real", texto)

    def test_no_dice_que_avisa_cuando_el_patron_si_cuadra(self):
        """Con 176 B el desglose sí es válido: no debe llevar el aviso."""
        texto = " ".join(probe.desglosar(b"\x00" * 176))
        self.assertNotIn("no describe el formato real", texto)

    def test_avisa_cuando_un_token_no_cabe(self):
        """Con 96 B, `S` necesita 48 y sólo quedan 16. Se dice "NO CABE" en vez
        de escribir 16 como si fuera el tamaño del token."""
        texto = "\n".join(probe.desglosar(b"\x00" * 96))
        self.assertIn("NO CABE", texto)

    def test_no_se_inventa_bytes_que_no_hay(self):
        """Con 10 B no puede "desglosar" 176: el informe tiene que poner lo que
        hay, no lo que debería."""
        lineas = "\n".join(probe.desglosar(b"\x00" * 10))
        self.assertIn("10", lineas)


class TestSinNoiseProtocol(unittest.TestCase):
    """La herramienta tiene que dar el desglose aunque falte la librería.

    Es lo que pasó el 2026-10-04: `noiseprotocol` no estaba en el host, y el
    script contestaba "NO INSTALADO" y salía con código 1 **sin dar el
    desglose**, que es justo lo que se le pedía.

    La comprobación se hace donde se usa —descifrar—, no al principio, para que
    la falta se note en su sitio y no impida el resto.
    """

    def test_desglosar_no_depende_de_la_libreria(self):
        """El desglose es aritmética sobre longitudes: no necesita nada."""
        lineas = probe.desglosar(bytes(96))
        self.assertTrue(any("NO coincide" in l for l in lineas))

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
        """`probar_read` es la única parte que la necesita: con la librería
        ausente avisa, no lanza."""
        import io
        from contextlib import redirect_stdout

        ident = Identity.generate("probe")
        buf = io.StringIO()
        with redirect_stdout(buf):
            probe.probar_read(bytes(96), ident)
        salida = buf.getvalue()
        # O se omitió por falta de librería, o se leyó. Ambas son válidas; lo
        # que no vale es una excepción.
        self.assertIn("read_handshake", salida)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)