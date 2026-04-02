"""Cells command — mirror cell inspection."""

from __future__ import annotations

import json
import sys

from securecore.cli.common import stream_substrate, verify_evidence_cell_chain

ESCALATION_NAMES = {0: "OBSERVED", 1: "TRACKING", 2: "ENGAGED", 3: "LOCKED", 4: "TRAPPED", 5: "BURNING"}


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


def run(cell_id: str, locked_only: bool, include_evidence: bool) -> None:
    if cell_id:
        _show_cell_detail(cell_id, include_evidence)
    else:
        _list_cells(locked_only)


def _list_cells(locked_only: bool) -> None:
    cells = {}

    for record in stream_substrate("mirror"):
        cid = record.cell_id
        if not cid:
            continue

        if record.record_type == "cell_created":
            cells[cid] = {
                "cell_id": cid,
                "source_ip": record.payload.get("source_ip", ""),
                "fingerprint": record.payload.get("attacker_fingerprint", "")[:16],
                "first_seen": record.timestamp,
                "last_seen": record.timestamp,
                "interactions": 0,
                "escalation_level": 0,
                "locked": False,
                "tools": set(),
            }
        elif cid in cells:
            cells[cid]["last_seen"] = record.timestamp
            if record.record_type == "interaction":
                cells[cid]["interactions"] = record.payload.get("interaction_count", 0)
                tool = record.payload.get("tool_signature", "")
                if tool and tool != "unknown":
                    cells[cid]["tools"].add(tool)
            elif record.record_type == "escalation":
                cells[cid]["escalation_level"] = record.payload.get("new_level", 0)
            elif record.record_type == "cell_locked":
                cells[cid]["locked"] = True

    if locked_only:
        cells = {k: v for k, v in cells.items() if v.get("locked")}

    if not cells:
        print("\n  No mirror cells found.")
        return

    print()
    print(_colorize(f"  MIRROR CELLS ({len(cells)} cell(s))", "bold"))
    print(_colorize("  " + "=" * 70, "dim"))
    print()

    for cell in cells.values():
        level = cell["escalation_level"]
        level_name = ESCALATION_NAMES.get(level, "?")
        lock_tag = _colorize(" [LOCKED]", "red") if cell["locked"] else ""
        level_color = "red" if level >= 3 else "yellow" if level >= 1 else "dim"
        print(f"    {_colorize(cell['cell_id'], 'cyan')}  IP={cell['source_ip']}")
        print(
            f"      level={_colorize(f'{level}({level_name})', level_color)}{lock_tag}  "
            f"interactions={cell['interactions']}  tools={','.join(cell['tools']) or 'none'}"
        )
        print(f"      first={cell['first_seen'][:19]}  last={cell['last_seen'][:19]}")
        print()


def _show_cell_detail(cell_id: str, include_evidence: bool) -> None:
    print()
    print(_colorize(f"  CELL REPORT: {cell_id}", "bold"))
    print(_colorize("  " + "=" * 60, "dim"))

    mirror_records = [record for record in stream_substrate("mirror") if record.cell_id == cell_id]
    if not mirror_records:
        print(f"\n  Cell {cell_id} not found in mirror substrate.")
        return

    print(f"\n  {_colorize('MIRROR TIMELINE', 'cyan')} ({len(mirror_records)} records)")
    for record in mirror_records:
        payload_str = json.dumps(record.payload, separators=(",", ":"))
        if len(payload_str) > 80:
            payload_str = payload_str[:77] + "..."
        print(f"    seq={record.sequence:>4d}  {record.timestamp[:19]}  {record.record_type:20s}  {payload_str}")

    if include_evidence:
        evidence_records = [record for record in stream_substrate("evidence") if record.cell_id == cell_id][:500]
        print(f"\n  {_colorize('EVIDENCE TIMELINE', 'cyan')} ({len(evidence_records)} records)")

        if evidence_records:
            chain = verify_evidence_cell_chain(cell_id)
            chain_status = _colorize("INTACT", "green") if chain.get("intact", False) else _colorize("BROKEN", "red")
            print(f"    chain: {chain_status}")
            for record in evidence_records:
                payload = record.payload
                print(
                    f"    seq={payload.get('cell_sequence', '?'):>4}  "
                    f"{record.timestamp[:19]}  "
                    f"{payload.get('evidence_type', '?'):22s}  "
                    f"{payload.get('method', '?'):6s} {payload.get('path', '?')}"
                )
        else:
            print("    (no evidence)")

    print()
