"""Tail command — live substrate or log stream tailing."""

from __future__ import annotations

import json
import sys
import time

from securecore.cli.common import (
    LOG_STREAM_NAMES,
    SUBSTRATE_NAMES,
    log_stream_path,
    substrate_path,
    tail_log_stream,
    tail_substrate,
)
from securecore.substrates.base import SubstrateRecord


def _colorize(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    codes = {
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "reset": "\033[0m",
    }
    return f"{codes.get(color, '')}{text}{codes.get('reset', '')}"


def _format_record(record: SubstrateRecord) -> str:
    payload_str = json.dumps(record.payload, separators=(",", ":"))
    if len(payload_str) > 120:
        payload_str = payload_str[:117] + "..."
    cell_tag = f" cell={record.cell_id}" if record.cell_id else ""
    return (
        f"  {_colorize(str(record.sequence), 'dim'):>8s}  "
        f"{record.timestamp[:19]}  "
        f"{_colorize(record.record_type, 'cyan'):30s}"
        f"{cell_tag}  "
        f"{payload_str}"
    )


def _format_log_entry(entry: dict) -> str:
    ts = entry.get("timestamp", "?")[:19]
    stream = entry.get("stream", "?")
    cell_tag = f" cell={entry.get('cell_id', '')}" if entry.get("cell_id") else ""
    details = entry.get("details", entry.get("event_type", ""))
    if not details:
        details = json.dumps(entry, separators=(",", ":"))
        if len(details) > 100:
            details = details[:97] + "..."
    return f"  {ts}  {_colorize(stream, 'cyan'):20s}{cell_tag}  {details}"


def run(target: str, n: int, cell_id: str, follow: bool) -> None:
    if target in SUBSTRATE_NAMES:
        _tail_substrate(target, n, cell_id, follow)
        return
    if target in LOG_STREAM_NAMES:
        _tail_log_stream(target, n, follow)
        return

    print(f"\n  Unknown target: {target}")
    print(f"  Substrates: {', '.join(SUBSTRATE_NAMES)}")
    print(f"  Log streams: {', '.join(LOG_STREAM_NAMES)}")


def _tail_substrate(name: str, n: int, cell_id: str, follow: bool) -> None:
    print()
    print(f"  {_colorize(f'TAIL: {name}', 'bold')}  (last {n} records)")
    print(f"  {_colorize('-' * 60, 'dim')}")

    records = tail_substrate(name, limit=n, cell_id=cell_id)
    for record in records:
        print(_format_record(record))
    if not records:
        print("  (no records)")

    if follow:
        print(f"\n  {_colorize('Following...', 'yellow')} (Ctrl+C to stop)")
        _follow_substrate_file(name, cell_id)

    print()


def _follow_substrate_file(name: str, cell_id: str) -> None:
    jsonl_path = substrate_path(name)
    file_position = jsonl_path.stat().st_size if jsonl_path.exists() else 0
    try:
        while True:
            time.sleep(1.0)
            if not jsonl_path.exists():
                continue
            current_size = jsonl_path.stat().st_size
            if current_size < file_position:
                file_position = 0
            if current_size == file_position:
                continue
            with open(jsonl_path, "r", encoding="utf-8") as handle:
                handle.seek(file_position)
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = SubstrateRecord.from_dict(json.loads(line))
                    except Exception:
                        continue
                    if cell_id and record.cell_id != cell_id:
                        continue
                    print(_format_record(record))
                file_position = handle.tell()
    except KeyboardInterrupt:
        print(f"\n  {_colorize('Stopped.', 'dim')}")


def _tail_log_stream(name: str, n: int, follow: bool) -> None:
    print()
    print(f"  {_colorize(f'TAIL: {name} (log stream)', 'bold')}  (last {n} entries)")
    print(f"  {_colorize('-' * 60, 'dim')}")

    entries = tail_log_stream(name, n)
    for entry in entries:
        print(_format_log_entry(entry))
    if not entries:
        print("  (no entries)")

    if follow:
        print(f"\n  {_colorize('Following...', 'yellow')} (Ctrl+C to stop)")
        _follow_log_file(name)

    print()


def _follow_log_file(name: str) -> None:
    jsonl_path = log_stream_path(name)
    file_position = jsonl_path.stat().st_size if jsonl_path.exists() else 0
    try:
        while True:
            time.sleep(1.0)
            if not jsonl_path.exists():
                continue
            current_size = jsonl_path.stat().st_size
            if current_size < file_position:
                file_position = 0
            if current_size == file_position:
                continue
            with open(jsonl_path, "r", encoding="utf-8") as handle:
                handle.seek(file_position)
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    print(_format_log_entry(entry))
                file_position = handle.tell()
    except KeyboardInterrupt:
        print(f"\n  {_colorize('Stopped.', 'dim')}")
