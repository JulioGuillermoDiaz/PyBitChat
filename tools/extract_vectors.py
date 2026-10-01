"""Extrae vectores de prueba dorados de los ficheros `.log` del proyecto Rust.

Los ficheros `.log` están commiteados en `reference/bitchat-tui/` y contienen
volcados hex completos de paquetes reales enviados por la app oficial de iOS.
Son la única fuente de verdad disponible para validar el codec, ya que el
proyecto Rust no tiene ni un solo test de wire-format.

Uso:
    python tools/extract_vectors.py

Salida:
    tests/fixtures/vectors.json

Los metadatos que el cliente Rust interpretó (`Successfully parsed packet: ...`)
se guardan aparte, como anotación, y NO se usan como verdad: el código Rust tiene
bugs documentados (ver EVALUACION-MIGRACION.md §1), así que su interpretación no
es autoritativa. Lo autoritativo son los bytes.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "reference" / "bitchat-tui"
OUT_PATH = ROOT / "tests" / "fixtures" / "vectors.json"

#: `Raw notification data: 256 bytes`
RE_DECLARED = re.compile(r"Raw notification data:\s*(\d+)\s*bytes")

#: `Raw bytes: [1, 1, 6, 0, ...]`
RE_RAW_BYTES = re.compile(r"Raw bytes:\s*\[([0-9,\s]*)\]")

#: `Successfully parsed packet: type=Announce, sender_id='x', recipient_id='None'`
RE_PARSED = re.compile(
    r"Successfully parsed packet:\s*type=(?P<type>\w+),\s*"
    r"sender_id='(?P<sender>[^']*)',\s*"
    r"recipient_id='(?P<recipient>[^']*)'"
)

#: `Packet payload length: 276`
RE_PAYLOAD_LEN = re.compile(r"Packet payload length:\s*(\d+)")

#: `Packet first 16 bytes: [0, 0, 0, 0, ...]`
RE_FIRST_16 = re.compile(r"Packet first 16 bytes:\s*\[([0-9,\s]*)\]")

#: `[1754073307] After unpadding, data length: 39`
RE_UNPADDED = re.compile(r"After unpadding,\s*data length:\s*(\d+)")

#: `[1754073307] Starting packet parsing, data length: 256`
RE_PARSING = re.compile(r"Starting packet parsing,\s*data length:\s*(\d+)")

#: `[1754073307] Sender ID as hex: '234de4e300000000'`
RE_SENDER_HEX = re.compile(r"Sender ID as hex:\s*'([0-9a-fA-F]*)'")

#: Líneas de error que valen como casos negativos.
RE_IGNORED = re.compile(r"Ignoring unknown packet type:\s*(\w+)")
RE_ERROR = re.compile(
    r"(Failed to [^\n]*?|Ignoring [^\n]*?)"
)


def parse_byte_list(raw: str) -> list[int]:
    """Convierte `1, 2, 3` en `[1, 2, 3]`, tolerando elipsis de truncado."""
    text = raw.strip()
    if text.endswith("..."):
        text = text[:-3]
    return [int(part) for part in text.split(",") if part.strip()]


def extract_from_log(path: Path) -> list[dict]:
    """Extrae los vectores de un fichero de log."""
    vectors: list[dict] = []
    current: dict | None = None

    for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        m = RE_DECLARED.search(line)
        if m:
            current = {
                "source_file": path.name,
                "source_line": lineno,
                "declared_length": int(m.group(1)),
            }
            continue

        m = RE_RAW_BYTES.search(line)
        if m and current is not None:
            data = parse_byte_list(m.group(1))
            current["byte_count"] = len(data)
            current["raw_hex"] = bytes(data).hex()
            # El log parseado y las notas de ruido siguen al volcado.
            current["_tail"] = []
            vectors.append(current)
            current["_source_line_of_hex"] = lineno
            continue

        if current is not None and "_tail" in current:
            m = RE_PARSED.search(line)
            if m:
                recipient = m.group("recipient")
                current["rust_parsed"] = {
                    "type": m.group("type"),
                    "sender_id": m.group("sender"),
                    "recipient_id": None
                    if recipient == "None"
                    else recipient.removeprefix('Some("').removesuffix('")'),
                }
                continue

            m = RE_PAYLOAD_LEN.search(line)
            if m:
                current["rust_reported_payload_len"] = int(m.group(1))
                continue

            m = RE_FIRST_16.search(line)
            if m:
                current["rust_reported_first_16"] = parse_byte_list(m.group(1))
                continue

            m = RE_IGNORED.search(line)
            if m:
                current.setdefault("rust_behaviour", []).append(
                    f"ignored: {m.group(1)}"
                )
                continue

            err = RE_ERROR.search(line)
            if err and "Successfully" not in line:
                current.setdefault("rust_behaviour", []).append(err.group(1).strip())
                continue

            if line.strip() and not line.startswith("["):
                continue

    for v in vectors:
        v.pop("_tail", None)
    return vectors


def extract_unpadding_oracle(path: Path) -> list[dict]:
    """Extrae las longitudes "tras quitar el relleno" de `packet_debug.log`.

    Este es un oráculo independiente y muy valioso: permite comprobar la
    aritmética de la cabecera (14 bytes) y de los identificadores dirigidos por
    flags sin depender de la *interpretación* del cliente Rust, que tiene bugs.
    """
    entries: list[dict] = []
    pending: dict | None = None

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = RE_PARSING.search(line)
        if m:
            pending = {"declared_length": int(m.group(1))}
            continue

        if pending is None:
            continue

        m = RE_UNPADDED.search(line)
        if m:
            pending["unpadded_length"] = int(m.group(1))
            continue

        m = RE_SENDER_HEX.search(line)
        if m:
            pending["sender_id"] = m.group(1)
            if "unpadded_length" in pending:
                entries.append(pending)
            pending = None

    return entries


def extract_noise_lengths(path: Path) -> list[dict]:
    """Extrae longitudes de mensaje Noise de `noise_handler_debug.log`.

    Cubre por ahora sólo los mensajes con longitud explícita. Sirven para
    contrastar el handshake contra lo que realmente envió iOS.
    """
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        for pattern, key in (
            (re.compile(r"Handshake initiated,\s*data length:\s*(\d+)"), "handshake_init_len"),
            (re.compile(r"Handshake response processed,\s*response length:\s*(\d+)"), "handshake_resp_len"),
        ):
            m = pattern.search(line)
            if m:
                out.append({"key": key, "value": int(m.group(1)), "line": line.strip()})
    return out


def main() -> int:
    if not LOG_DIR.is_dir():
        print(f"ERROR: no existe {LOG_DIR}", file=sys.stderr)
        return 1

    all_vectors: list[dict] = []
    per_file: dict[str, int] = {}

    for log in sorted(LOG_DIR.glob("*.log")):
        found = extract_from_log(log)
        per_file[log.name] = len(found)
        all_vectors.extend(found)

    oracle = extract_unpadding_oracle(LOG_DIR / "packet_debug.log")
    noise_lengths = extract_noise_lengths(LOG_DIR / "noise_handler_debug.log")

    doc = {
        "_generated_by": "tools/extract_vectors.py",
        "_source": "reference/bitchat-tui/*.log (commiteados en el repo upstream)",
        "_note": (
            "Los bytes son verdad. Los campos rust_* son anotaciones del "
            "cliente Rust y NO son autoritativos: sus parsers tienen bugs "
            "documentados."
        ),
        "vectors_per_file": per_file,
        "total": len(all_vectors),
        "vectors": all_vectors,
        "unpadding_oracle": oracle,
        "noise_lengths": noise_lengths,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print(f"Extraídos {len(all_vectors)} vectores brutos de {len(per_file)} ficheros:")
    for name, count in per_file.items():
        print(f"  {name}: {count}")
    print(f"\nOráculo de unpadding (packet_debug.log): {len(oracle)} entradas")
    print(f"Longitudes Noise (noise_handler_debug.log): {len(noise_lengths)} entradas")
    print(f"\nEscritos en {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())