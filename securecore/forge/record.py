"""Binary record format for SecureCore Forge."""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass


MAGIC = b"SCFG"
VERSION = 1
PREFIX = struct.Struct("<4sBII32s")


@dataclass(slots=True)
class ForgeRecord:
    """Binary-encoded companion representation of a substrate record."""

    record_id: str
    substrate: str
    sequence: int
    timestamp: str
    cell_id: str
    record_type: str
    payload: dict
    chain_hash: str
    previous_hash: str

    @classmethod
    def from_substrate_dict(cls, data: dict) -> "ForgeRecord":
        return cls(
            record_id=data["record_id"],
            substrate=data["substrate"],
            sequence=int(data["sequence"]),
            timestamp=data["timestamp"],
            cell_id=data.get("cell_id", ""),
            record_type=data["record_type"],
            payload=data["payload"],
            chain_hash=data["chain_hash"],
            previous_hash=data["previous_hash"],
        )

    def header_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "substrate": self.substrate,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "cell_id": self.cell_id,
            "record_type": self.record_type,
            "chain_hash": self.chain_hash,
            "previous_hash": self.previous_hash,
        }

    def to_dict(self) -> dict:
        data = self.header_dict()
        data["payload"] = self.payload
        return data

    def encode(self) -> bytes:
        header_blob = json.dumps(
            self.header_dict(),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        payload_blob = json.dumps(
            self.payload,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        body = header_blob + payload_blob
        checksum = hashlib.sha256(body).digest()
        prefix = PREFIX.pack(MAGIC, VERSION, len(header_blob), len(payload_blob), checksum)
        return prefix + body

    @classmethod
    def decode(cls, raw: bytes) -> "ForgeRecord":
        prefix_size = PREFIX.size
        if len(raw) < prefix_size:
            raise ValueError("forge record too small")

        magic, version, header_len, payload_len, checksum = PREFIX.unpack(raw[:prefix_size])
        if magic != MAGIC:
            raise ValueError("invalid forge magic")
        if version != VERSION:
            raise ValueError(f"unsupported forge version: {version}")

        expected_size = prefix_size + header_len + payload_len
        if len(raw) != expected_size:
            raise ValueError("forge record size mismatch")

        body = raw[prefix_size:]
        if hashlib.sha256(body).digest() != checksum:
            raise ValueError("forge checksum mismatch")

        header_blob = body[:header_len]
        payload_blob = body[header_len:]
        header = json.loads(header_blob.decode("utf-8"))
        payload = json.loads(payload_blob.decode("utf-8"))

        return cls(
            record_id=header["record_id"],
            substrate=header["substrate"],
            sequence=int(header["sequence"]),
            timestamp=header["timestamp"],
            cell_id=header.get("cell_id", ""),
            record_type=header["record_type"],
            payload=payload,
            chain_hash=header["chain_hash"],
            previous_hash=header["previous_hash"],
        )
