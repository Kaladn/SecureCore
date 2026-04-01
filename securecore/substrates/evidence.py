"""Evidence Substrate - forensic-grade, hash-chained proof.

This is the courtroom-grade evidence layer. Every interaction an attacker
has with a mirror cell is recorded here with full fidelity:
  - raw headers (as-received)
  - raw body content
  - response that was served back
  - tool fingerprint
  - timing
  - source metadata

The hash chain in this substrate is SEPARATE from the base substrate chain.
This substrate carries TWO chains:
  1. The substrate-level chain (inherited from base, covers all records)
  2. Per-cell evidence chains (within each cell_id, records chain independently)

Both must be intact for evidence to be considered untampered.
"""

import hashlib
import json
from typing import Optional

from securecore.substrates.base import Substrate


class EvidenceSubstrate(Substrate):
    """Forensic evidence substrate with per-cell chaining."""

    name = "evidence"

    def __init__(self, data_dir: str):
        super().__init__(data_dir)
        # Track per-cell chain state: {cell_id: (sequence, last_hash)}
        self._cell_chains: dict[str, tuple[int, str]] = {}
        self._recover_cell_chains()

    def _recover_cell_chains(self) -> None:
        """Recover per-cell chain state from existing records."""
        for record in self.stream():
            cell_id = record.cell_id
            if cell_id:
                cell_seq = record.payload.get("cell_sequence", 0)
                cell_hash = record.payload.get("cell_chain_hash", "GENESIS")
                self._cell_chains[cell_id] = (cell_seq + 1, cell_hash)

    def _compute_cell_chain_hash(
        self,
        cell_id: str,
        cell_sequence: int,
        evidence_type: str,
        method: str,
        path: str,
        headers_hash: str,
        body_hash: str,
        source_ip: str,
        previous_cell_hash: str,
    ) -> str:
        """Compute the per-cell evidence chain hash."""
        chain_input = "|".join([
            cell_id,
            str(cell_sequence),
            evidence_type,
            method,
            path,
            headers_hash,
            body_hash,
            source_ip,
            previous_cell_hash,
        ])
        return hashlib.sha256(chain_input.encode("utf-8")).hexdigest()

    def record_evidence(
        self,
        cell_id: str,
        evidence_type: str,
        method: str,
        path: str,
        headers: dict,
        body: str,
        source_ip: str,
        source_port: Optional[int],
        user_agent: str,
        tool_signature: str,
        response_served: str,
    ) -> "SubstrateRecord":
        """Record a forensic evidence entry with per-cell chain integrity."""
        headers_json = json.dumps(headers, sort_keys=True, default=str)
        headers_hash = hashlib.sha256(headers_json.encode("utf-8")).hexdigest()
        body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        response_hash = hashlib.sha256(response_served.encode("utf-8")).hexdigest()

        # Get or initialize per-cell chain
        cell_seq, prev_cell_hash = self._cell_chains.get(cell_id, (0, "GENESIS"))

        cell_chain_hash = self._compute_cell_chain_hash(
            cell_id=cell_id,
            cell_sequence=cell_seq,
            evidence_type=evidence_type,
            method=method,
            path=path,
            headers_hash=headers_hash,
            body_hash=body_hash,
            source_ip=source_ip,
            previous_cell_hash=prev_cell_hash,
        )

        payload = {
            "evidence_type": evidence_type,
            "method": method,
            "path": path,
            "source_ip": source_ip,
            "source_port": source_port,
            "user_agent": user_agent,
            "tool_signature": tool_signature,
            "headers_hash": headers_hash,
            "body_hash": body_hash,
            "response_hash": response_hash,
            "raw_headers": headers_json,
            "raw_body": body[:10000],
            "response_served": response_served[:10000],
            "cell_sequence": cell_seq,
            "cell_chain_hash": cell_chain_hash,
            "previous_cell_hash": prev_cell_hash,
        }

        record = self.append(
            record_type="forensic_evidence",
            payload=payload,
            cell_id=cell_id,
        )

        # Update per-cell chain state
        self._cell_chains[cell_id] = (cell_seq + 1, cell_chain_hash)

        return record

    def verify_cell_chain(self, cell_id: str) -> dict:
        """Verify the per-cell evidence chain for a specific cell."""
        records = self.query(cell_id=cell_id, limit=100000)
        if not records:
            return {"cell_id": cell_id, "intact": True, "entries": 0}

        expected_prev = "GENESIS"
        count = 0

        for record in records:
            p = record.payload
            stored_prev = p.get("previous_cell_hash", "GENESIS")
            stored_hash = p.get("cell_chain_hash", "")

            if stored_prev != expected_prev:
                return {
                    "cell_id": cell_id,
                    "intact": False,
                    "broken_at_cell_sequence": p.get("cell_sequence", -1),
                    "error": "previous_cell_hash mismatch",
                    "expected": expected_prev,
                    "found": stored_prev,
                }

            recomputed = self._compute_cell_chain_hash(
                cell_id=cell_id,
                cell_sequence=p.get("cell_sequence", 0),
                evidence_type=p.get("evidence_type", ""),
                method=p.get("method", ""),
                path=p.get("path", ""),
                headers_hash=p.get("headers_hash", ""),
                body_hash=p.get("body_hash", ""),
                source_ip=p.get("source_ip", ""),
                previous_cell_hash=stored_prev,
            )

            if recomputed != stored_hash:
                return {
                    "cell_id": cell_id,
                    "intact": False,
                    "broken_at_cell_sequence": p.get("cell_sequence", -1),
                    "error": "cell_chain_hash tampered",
                    "expected": recomputed,
                    "found": stored_hash,
                }

            expected_prev = stored_hash
            count += 1

        return {
            "cell_id": cell_id,
            "intact": True,
            "entries": count,
        }

    def get_cell_evidence(self, cell_id: str) -> list[dict]:
        """Get all evidence records for a cell."""
        records = self.query(cell_id=cell_id, limit=100000)
        return [r.to_dict() for r in records]

    def export_evidence_bundle(self, cell_id: str) -> dict:
        """Export a complete evidence bundle for a cell.

        This is the package you hand to law enforcement or use
        for your own records. Includes chain verification.
        """
        records = self.query(cell_id=cell_id, limit=100000)
        chain_status = self.verify_cell_chain(cell_id)

        tools_seen = set()
        paths_probed = set()
        methods_used = set()
        evidence_types = {}

        entries = []
        for r in records:
            p = r.payload
            tools_seen.add(p.get("tool_signature", "unknown"))
            paths_probed.add(p.get("path", ""))
            methods_used.add(p.get("method", ""))
            et = p.get("evidence_type", "unknown")
            evidence_types[et] = evidence_types.get(et, 0) + 1
            entries.append(r.to_dict())

        return {
            "cell_id": cell_id,
            "evidence_count": len(entries),
            "chain_integrity": chain_status,
            "tools_observed": sorted(tools_seen),
            "paths_probed": sorted(paths_probed),
            "methods_used": sorted(methods_used),
            "evidence_type_counts": evidence_types,
            "entries": entries,
        }
