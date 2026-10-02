"""Capa BLE de PyBitChat.

Aquí sólo hay datos y abstracciones. Nada en este paquete importa `bleak` ni
toca un adaptador: el transporte real vive en `ble/bleak_transport.py`, que es
la Fase 2b y necesita hardware.

La separación no es purismo. Permite probar toda la lógica de malla —codificación,
fragmentación, reensamblado, Noise— contra un transporte en memoria, sin
Bluetooth y sin flaky tests de temporización.
"""