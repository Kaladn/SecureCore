"""Shared helpers for the SecureCore CLI command center."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Iterator

from securecore.config import load_settings
from securecore.forge.index import ForgeIndex
from securecore.forge.reader import ForgeReader
from securecore.substrates.base import SubstrateRecord

SUBSTRATE_NAMES = [
    "ingress",
    "mirror",
    "evidence",
    "telemetry",
    "agent_decisions",
    "operator",
    "hid",
]

LOG_STREAM_NAMES = [
    "raw_ingress",
    "normalized",
    "forensic",
    "agent_decision",
    "operator",
    "health",
    "chain_anchor",
]


def _settings() -> dict:
    return load_settings()


def securecore_root() -> Path:
    return Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    return securecore_root() / _settings().get("DATA_DIR", "data")


def substrates_dir() -> Path:
    return data_dir() / "substrates"


def logs_dir() -> Path:
    return securecore_root() / _settings().get("LOG_DIR", "logs")


def forge_dir() -> Path:
    configured = os.getenv("SECURECORE_FORGE_DIR", "").strip()
    if configured:
        return Path(configured)
    return data_dir() / "forge"


def control_bus_dir() -> Path:
    return data_dir() / "runtime" / "control_bus"


def substrate_path(name: str) -> Path:
    return substrates_dir() / f"{name}.jsonl"


def log_stream_path(name: str) -> Path:
    return logs_dir() / f"{name}.jsonl"


def iter_jsonl(path: Path) -> Iterator[dict]:
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def stream_substrate(name: str, since_sequence: int = 0) -> Iterator[SubstrateRecord]:
    for payload in iter_jsonl(substrate_path(name)):
        if payload.get("sequence", 0) >= since_sequence:
            yield SubstrateRecord.from_dict(payload)


def tail_substrate(name: str, limit: int = 20, cell_id: str = "") -> list[SubstrateRecord]:
    records = list(stream_substrate(name))
    if cell_id:
        records = [record for record in records if record.cell_id == cell_id]
    return records[-limit:]


def tail_log_stream(name: str, limit: int = 20) -> list[dict]:
    entries = list(iter_jsonl(log_stream_path(name)))
    return entries[-limit:]


def count_jsonl_records(path: Path) -> int:
    return sum(1 for _ in iter_jsonl(path))


def count_substrate_records(name: str) -> int:
    return count_jsonl_records(substrate_path(name))


def count_log_entries(name: str) -> int:
    return count_jsonl_records(log_stream_path(name))


def verify_substrate_chain(name: str) -> dict:
    expected_prev = "GENESIS"
    count = 0
    last_timestamp = None

    for record in stream_substrate(name):
        if record.previous_hash != expected_prev:
            return {
                "substrate": name,
                "intact": False,
                "broken_at_sequence": record.sequence,
                "error": "previous_hash mismatch",
                "expected": expected_prev,
                "found": record.previous_hash,
            }

        recomputed_input = "|".join([
            record.record_id,
            record.substrate,
            str(record.sequence),
            record.timestamp,
            record.cell_id,
            record.record_type,
            json.dumps(record.payload, sort_keys=True),
            record.previous_hash,
        ])
        recomputed = hashlib.sha256(recomputed_input.encode("utf-8")).hexdigest()
        if recomputed != record.chain_hash:
            return {
                "substrate": name,
                "intact": False,
                "broken_at_sequence": record.sequence,
                "error": "chain_hash tampered",
                "expected": recomputed,
                "found": record.chain_hash,
            }

        expected_prev = record.chain_hash
        count += 1
        last_timestamp = record.timestamp

    return {
        "substrate": name,
        "intact": True,
        "total_records": count,
        "last_timestamp": last_timestamp,
    }


def verify_evidence_cell_chain(cell_id: str) -> dict:
    expected_prev = "GENESIS"
    count = 0
    found = False

    for record in stream_substrate("evidence"):
        if record.cell_id != cell_id:
            continue
        found = True
        payload = record.payload
        stored_prev = payload.get("previous_cell_hash", "GENESIS")
        if stored_prev != expected_prev:
            return {
                "cell_id": cell_id,
                "intact": False,
                "broken_at_cell_sequence": payload.get("cell_sequence", -1),
                "error": "previous_cell_hash mismatch",
                "expected": expected_prev,
                "found": stored_prev,
            }

        chain_input = "|".join([
            cell_id,
            str(payload.get("cell_sequence", 0)),
            payload.get("evidence_type", ""),
            payload.get("method", ""),
            payload.get("path", ""),
            payload.get("headers_hash", ""),
            payload.get("body_hash", ""),
            payload.get("source_ip", ""),
            stored_prev,
        ])
        recomputed = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()
        stored_hash = payload.get("cell_chain_hash", "")
        if recomputed != stored_hash:
            return {
                "cell_id": cell_id,
                "intact": False,
                "broken_at_cell_sequence": payload.get("cell_sequence", -1),
                "error": "cell_chain_hash tampered",
                "expected": recomputed,
                "found": stored_hash,
            }

        expected_prev = stored_hash
        count += 1

    return {
        "cell_id": cell_id,
        "intact": True,
        "entries": count if found else 0,
    }


def forge_reader(name: str) -> ForgeReader:
    return ForgeReader(forge_dir() / name)


def forge_store_stats(name: str) -> dict:
    base_dir = forge_dir() / name
    reader = ForgeReader(base_dir)
    index = ForgeIndex(base_dir / "records.index.jsonl")

    if not base_dir.exists() or not reader.exists():
        return {
            "exists": False,
            "records_path": str(base_dir / "records.bin"),
            "wal_path": str(base_dir / "records.wal"),
            "index_path": str(base_dir / "records.index.jsonl"),
            "count": 0,
            "index_count": index.count(),
            "last_record_id": "",
            "last_sequence": -1,
        }

    last = reader.last_record()
    return {
        "exists": True,
        "records_path": str(base_dir / "records.bin"),
        "wal_path": str(base_dir / "records.wal"),
        "index_path": str(base_dir / "records.index.jsonl"),
        "count": reader.count(),
        "index_count": index.count(),
        "last_record_id": last.record_id if last else "",
        "last_sequence": last.sequence if last else -1,
        "last_timestamp": last.timestamp if last else "",
    }


def request_live_command(command: str, args: dict | None = None, timeout: float = 3.0) -> dict | None:
    bus_root = control_bus_dir()
    commands_dir = bus_root / "commands"
    responses_dir = bus_root / "responses"
    heartbeat_path = bus_root / "heartbeat.json"
    if not commands_dir.exists() or not responses_dir.exists() or not heartbeat_path.exists():
        return None
    if time.time() - heartbeat_path.stat().st_mtime > 1.5:
        return None

    command_id = uuid.uuid4().hex
    payload = {
        "command_id": command_id,
        "command": command,
        "args": args or {},
        "created_at": time.time(),
    }
    command_path = commands_dir / f"{command_id}.json"
    temp_path = command_path.with_suffix(".json.tmp")
    temp_path.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    temp_path.replace(command_path)

    response_path = responses_dir / f"{command_id}.json"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if response_path.exists():
            try:
                data = json.loads(response_path.read_text(encoding="utf-8"))
            except Exception:
                data = {"ok": False, "error": "invalid response payload"}
            try:
                response_path.unlink()
            except FileNotFoundError:
                pass
            return data
        time.sleep(0.1)

    try:
        command_path.unlink()
    except FileNotFoundError:
        pass
    return None
