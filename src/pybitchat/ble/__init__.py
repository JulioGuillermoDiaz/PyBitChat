"""Capa BLE de PyBitChat.

`gatt.py` tiene los UUID y las constantes: datos puros, sin dependencias.
`bleak_transport.py` implementa `mesh.transport.Transport` sobre el adaptador
real, y es la única parte del proyecto que necesita hardware y `bleak`.

La separación no es purismo. Permite probar toda la lógica de malla —
codificación, fragmentación, reensamblado, Noise— contra un enlace en memoria,
sin Bluetooth y sin tests de temporización que fallen por casualidad.

`bleak_transport.py` importa `bleak` en el momento de importarse, así que este
paquete **no** lo reexporta: el código que sólo necesita los UUID no debe
arrastrar la dependencia ni necesitar hardware para importarse.
"""