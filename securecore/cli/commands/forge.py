"""Forge command — forge store inspection and verification."""

from __future__ import annotations

import json
import sys

from securecore.cli.common import SUBSTRATE_NAMES, forge_dir, forge_reader, forge_store_stats


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


def run(substrate: str, verify: str, tail: int) -> None:
    target = verify or substrate
    if not target:
        _show_overview()
        return

    if verify:
        _verify_substrate(verify)
    elif tail > 0:
        _tail_substrate(substrate, tail)
    else:
        _show_substrate_stats(substrate)


def _show_overview() -> None:
    root = forge_dir()

    print()
    print(_colorize("  FORGE OVERVIEW", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    if not root.exists():
        print(f"    forge dir:  {root}")
        print(f"    status:     {_colorize('NOT ACTIVE', 'yellow')}")
        print()
        return

    for name in SUBSTRATE_NAMES:
        stats = forge_store_stats(name)
        if not stats["exists"]:
            print(f"    {name:20s}  {_colorize('no forge store', 'dim')}")
            continue
        last_ts = (stats.get("last_timestamp", "") or "?")[:19]
        print(f"    {name:20s}  records={stats['count']:>6d}  last={last_ts}")

    print()


def _show_substrate_stats(name: str) -> None:
    stats = forge_store_stats(name)

    print()
    print(_colorize(f"  FORGE: {name}", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    if not stats["exists"]:
        print(f"    {_colorize('No forge store found.', 'yellow')}")
        print(f"    Expected at: {forge_dir() / name}")
        print()
        return

    print(f"    records_path:  {stats['records_path']}")
    print(f"    wal_path:      {stats['wal_path']}")
    print(f"    index_path:    {stats['index_path']}")
    print(f"    total_records: {stats['count']}")
    print(f"    index_entries: {stats['index_count']}")
    print(f"    last_record:   {stats['last_record_id'] or '(none)'}")
    print(f"    last_sequence: {stats['last_sequence']}")
    print()


def _verify_substrate(name: str) -> None:
    sub_dir = forge_dir() / name

    print()
    print(_colorize(f"  FORGE VERIFY: {name}", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    if not sub_dir.exists():
        print(f"    {_colorize('No forge store found.', 'yellow')}")
        print()
        return

    result = forge_reader(name).verify()
    if result.get("intact"):
        print(f"    status:  {_colorize('INTACT', 'green')}")
        print(f"    records: {result.get('total_records', 0)}")
        print(f"    last_seq:{result.get('last_sequence', -1)}")
    else:
        print(f"    status:  {_colorize('BROKEN', 'red')}")
        print(f"    error:   {result.get('error', '?')}")
        print(f"    at_seq:  {result.get('sequence', '?')}")
    print()


def _tail_substrate(name: str, n: int) -> None:
    sub_dir = forge_dir() / name

    print()
    print(_colorize(f"  FORGE TAIL: {name} (last {n})", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    if not sub_dir.exists():
        print(f"    {_colorize('No forge store found.', 'yellow')}")
        print()
        return

    records = forge_reader(name).tail(n)
    if not records:
        print(f"    {_colorize('(no records)', 'dim')}")
    else:
        for record in records:
            payload_str = json.dumps(record.payload, separators=(",", ":"))
            if len(payload_str) > 80:
                payload_str = payload_str[:77] + "..."
            cell_tag = f" cell={record.cell_id}" if record.cell_id else ""
            print(f"    seq={record.sequence:>4d}  {record.timestamp[:19]}  {record.record_type:20s}{cell_tag}  {payload_str}")
    print()
