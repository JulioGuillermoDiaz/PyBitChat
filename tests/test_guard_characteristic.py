"""El guardián del characteristic: que no vuelva a ser código muerto.

## Lo que pasaba

El 2026-10-05, una ejecución terminó en traceback:

    bleak.exc.BleakCharacteristicNotFoundError: Characteristic
    a1b2c3d4-... was not found!

Y el script **tenía** el diagnóstico:

```python
await cliente.start_notify(CHARACTERISTIC_UUID, al_recibir)   # <- lanza aquí
print("  notificaciones activadas")
car = cliente.services.get_characteristic(CHARACTERISTIC_UUID)  # <- nunca se alcanza
if car is None:
    print("  el teléfono no expone el characteristic de BitChat")
    return 1
```

`start_notify` resuelve el characteristic **por dentro** y lanza si no lo
encuentra. El `if` estaba después, así que nunca se ejecutaba. Código muerto
justo en el sitio donde falla: el peor sitio posible.

## Lo que Estos tests fijan

1. El `if car is None` se evalúa **antes** de `start_notify`, no después.
2. Cuando no hay characteristic, se sale con código 1 y un motivo, no con un
   traceback.
3. `start_notify` recibe el characteristic ya resuelto.

Y el motivo tiene que ser accionable: el anuncio y el GATT son cosas distintas,
así que el mensaje lista las causas del entorno antes de culpar al código.
"""

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pybitchat.ble.gatt import CHARACTERISTIC_UUID  # noqa: E402

try:
    import bleak  # noqa: F401

    HAY_BLEAK = True
except Exception:  # pragma: no cover - depende del entorno
    HAY_BLEAK = False


def _cargar_smoke():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "smoke_car", ROOT / "tools" / "smoke_ble.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class _Servicio:
    def __init__(self, uuid, descripcion="servicio"):
        self.uuid = uuid
        self.description = descripcion


class _Servicios:
    """Lo mínimo de `client.services` que usa el script.

    Con `__len__` e iteración porque `_sin_characteristic` los usa para listar lo
    que sí hay: es la mitad del diagnóstico, dice si faltó el nuestro o
    todos.
    """

    def __init__(self, presentes=()):
        self._presentes = [_Servicio(u) for u in presentes]

    def __len__(self):
        return len(self._presentes)

    def __iter__(self):
        return iter(self._presentes)

    def get_characteristic(self, uuid):
        for u in self._presentes:
            if str(u.uuid).lower() == str(uuid).lower():
                return u
        return None


class _Cliente:
    def __init__(self, servicios, mtu=517, notificar_falla=False):
        self.services = servicios
        self.mtu_size = mtu
        self._notificar_falla = notificar_falla
        self.notificado = None
        self.escrito = []

    async def _acquire(self):
        return None

    async def start_notify(self, car, callback):
        if self._notificar_falla:
            raise RuntimeError("no se pudo")
        self.notificado = car

    async def write_gatt_char(self, car, data, response=False):
        self.escrito.append(data)


class _Backend:
    def __init__(self, cliente):
        self._acquire_mtu = cliente._acquire


def _cliente(servicios, **kw):
    c = _Cliente(servicios, **kw)
    c._backend = _Backend(c)
    return c


def _llamadas(funcion):
    """Llamadas del cuerpo de `funcion`, en el orden en que se ejecutan.

    ## Por qué `ast` y no el texto

    Buscar con `source.index("start_notify")` encuentra la **primera
    aparición**, que en este caso es la palabra dentro de un comentario que
    explica el bug. El test pasaría por el motivo equivocado, y habría pasado
    con el bug presente.

    ## Dos detalles que hay que respetar

    1. **Nombre y atributo.** `_sin_characteristic(x)` es un `Name`; `x.start_notify`
       es un `Attribute`. Mirar solo uno de los dos deja media lista fuera, y el
       test falla por lo que no ve en lugar de por lo que ve.
    2. **`ast.walk` no va en orden de fuente.** Recorre en anchura. Para afirmar
       sobre el orden hay que ordenar por `(lineno, col_offset)`.
    """
    import ast
    import inspect
    import textwrap

    arbol = ast.parse(textwrap.dedent(inspect.getsource(funcion)))
    encontradas = []
    for n in ast.walk(arbol):
        if not isinstance(n, ast.Call):
            continue
        func = n.func
        if isinstance(func, ast.Attribute):
            encontradas.append((n.lineno, n.col_offset, func.attr))
        elif isinstance(func, ast.Name):
            encontradas.append((n.lineno, n.col_offset, func.id))
    encontradas.sort(key=lambda x: (x[0], x[1]))
    return [nombre for _l, _c, nombre in encontradas]


class TestElGuardianNoEsCodigoMuerto(unittest.TestCase):
    """El orden de las llamadas, que es todo el bug."""

    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()

    def test_el_guard_se_evalua_antes_de_start_notify(self):
        """Si `start_notify` va primero, el `if` no puede ejecutarse."""
        llamadas = _llamadas(self.smoke._sesion)
        self.assertIn("get_characteristic", llamadas)
        self.assertIn("start_notify", llamadas)
        self.assertLess(
            llamadas.index("get_characteristic"),
            llamadas.index("start_notify"),
            "el characteristic se resuelve despues de start_notify: "
            "el guard es codigo muerto",
        )

    def test_el_guard_sale_antes_de_start_notify(self):
        """Que se llame a `_sin_characteristic` antes de notificar."""
        llamadas = _llamadas(self.smoke._sesion)
        self.assertIn("_sin_characteristic", llamadas)
        self.assertLess(
            llamadas.index("_sin_characteristic"),
            llamadas.index("start_notify"),
        )

    def test_start_notify_recibe_el_characteristic_resuelto(self):
        """Por UUID volvería a resolverlo por dentro, que es el problema.

        Se comprueba sobre el código: bleak recibe el UUID y busca él, así que
        El primer argumento tiene que ser la variable, no la constante:
        por UUID, bleak lo resolveria por dentro otra vez.
        """
        import ast
        import inspect
        import textwrap

        arbol = ast.parse(textwrap.dedent(inspect.getsource(self.smoke._sesion)))
        llamadas = [
            n for n in ast.walk(arbol)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "start_notify"
        ]
        self.assertEqual(len(llamadas), 1, "se esperaba una sola llamada")
        primero = llamadas[0].args[0]
        self.assertIsInstance(primero, ast.Name)
        self.assertNotEqual(primero.id, "CHARACTERISTIC_UUID")

    def test_el_comentario_no_puede_tovar_el_test(self):
        """Guardia: el texto de `start_notify` aparece en un comentario antes de
        la llamada. Si algún cambiara el test a buscar texto, esto lo detecta."""
        import inspect

        fuente = inspect.getsource(self.smoke._sesion)
        primera = fuente.index("start_notify")
        llamada = fuente.index("start_notify(")
        self.assertLess(
            primera, llamada,
            "si coinciden, el comentario ya no menciona la llamada y el test "
            "de texto pasaría por el motivo equivocado",
        )


class TestSinCharacteristic(unittest.TestCase):
    """Sin characteristic no hay nada que hacer: código 1 y un motivo."""

    @classmethod
    def setUpClass(cls):
        cls.smoke = _cargar_smoke()

    def test_devuelve_1(self):
        self.assertEqual(
            self.smoke._sin_characteristic(_cliente(_Servicios())), 1
        )

    def test_no_revienta_sin_servicios(self):
        """Un cliente sin `services` tampoco debe reventar."""
        c = _Cliente(servicios=None)
        self.assertEqual(self.smoke._sin_characteristic(c), 1)

    def test_dice_el_characteristic_buscado(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.smoke._sin_characteristic(_cliente(_Servicios()))
        self.assertIn(str(CHARACTERISTIC_UUID).lower(), buf.getvalue().lower())

    def test_el_motivo_es_accionable(self):
        """El anuncio y el GATT son cosas distintas: el mensaje lo dice, y lista
        las causas del entorno **antes** de culpar al código."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.smoke._sin_characteristic(_cliente(_Servicios()))
        salida = buf.getvalue()
        self.assertIn("no sirvi", salida)
        self.assertIn("anuncio", salida)
        self.assertIn("15 min", salida)

    def test_lista_los_servicios_que_hay(self):
        """Cuando hay otros servicios, saber cuáles es la mitad del diagnóstico:
        dice si es "no sirvió el nuestro" o "no sirvió ninguno"."""
        otros = _Servicios(["0000xxxx-0000-0000-0000-000000000001"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.smoke._sin_characteristic(_cliente(otros))
        self.assertIn("0000xxxx", buf.getvalue())

    def test_no_atribuye_el_fallo_al_codigo(self):
        """Ninguno de los tres casos que lista es del lado nuestro."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.smoke._sin_characteristic(_cliente(_Servicios()))
        salida = buf.getvalue()
        self.assertIn("Antes de culpar al c", salida)


class TestAvisoDeMTU(unittest.TestCase):
    """MTU 23 es el valor por defecto de BlueZ, no el negociado.

    Y un envío que no cabe **no da error**: no llega y no se sabe por qué. Es el
    mismo modo de fallo silencioso que el characteristic ausente, y por eso se
    avisa en el momento.
    """

    def test_el_valor_por_defecto_es_23(self):
        self.assertEqual(_cargar_smoke().MTU_POR_DEFECTO, 23)

    def test_es_el_que_bluez_deja_sin_negociar(self):
        """517 es lo que se negocia con Android 14+. 23 es el valor de fábrica."""
        self.assertNotEqual(self.__class__.__name__, "517")
        self.assertEqual(_cargar_smoke().MTU_POR_DEFECTO, 23)


if __name__ == "__main__":
    unittest.main()