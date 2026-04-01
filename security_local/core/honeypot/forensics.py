"""Forensic evidence collector with tamper-evident hash chains.

Every interaction an attacker has with a mirror cell is recorded as a
ForensicEvidence entry. Each entry is chained to the previous one via
cryptographic hashing - tampering with any record breaks the chain.

This is the courtroom-grade evidence trail. If they touched it, it's here.
"""

import hashlib
import json
import logging
from datetime import datetime, UTC
from typing import Optional

from core.db import db
from core.models import ForensicEvidence, MirrorCellRecord, SecurityEvent
from core.honeypot.fingerprint import fingerprint_request, build_tool_report

logger = logging.getLogger("honeypot.forensics")


def _hash_content(content: str) -> str:
    """SHA-256 hash of arbitrary content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _compute_chain_hash(
    cell_id: str,
    sequence: int,
    timestamp: str,
    evidence_type: str,
    method: str,
    path: str,
    headers_hash: str,
    body_hash: str,
    source_ip: str,
    previous_hash: str,
) -> str:
    """Compute the chain hash for a forensic evidence entry.

    This links each evidence entry to the previous one. Changing any
    field in any entry invalidates all subsequent chain hashes.
    """
    chain_input = "|".join([
        cell_id,
        str(sequence),
        timestamp,
        evidence_type,
        method,
        path,
        headers_hash,
        body_hash,
        source_ip,
        previous_hash,
    ])
    return hashlib.sha256(chain_input.encode("utf-8")).hexdigest()


def record_evidence(
    cell_id: str,
    evidence_type: str,
    method: str,
    path: str,
    headers: dict,
    body: str,
    source_ip: str,
    source_port: Optional[int],
    response_served: str,
) -> ForensicEvidence:
    """Record a single forensic evidence entry with hash chain integrity.

    Each entry is cryptographically chained to the previous entry for
    this cell. The chain starts with GENESIS as the seed hash.
    """
    # Get the previous entry in this cell's chain
    prev = (
        ForensicEvidence.query
        .filter_by(cell_id=cell_id)
        .order_by(ForensicEvidence.sequence.desc())
        .first()
    )

    sequence = (prev.sequence + 1) if prev else 0
    previous_hash = prev.chain_hash if prev else "GENESIS"

    now = datetime.now(UTC)
    headers_json = json.dumps(headers, sort_keys=True, default=str)
    headers_hash = _hash_content(headers_json)
    body_hash = _hash_content(body)

    user_agent = headers.get("User-Agent", headers.get("user-agent", ""))
    tool_sig = fingerprint_request(headers)

    chain_hash = _compute_chain_hash(
        cell_id=cell_id,
        sequence=sequence,
        timestamp=now.isoformat(),
        evidence_type=evidence_type,
        method=method,
        path=path,
        headers_hash=headers_hash,
        body_hash=body_hash,
        source_ip=source_ip,
        previous_hash=previous_hash,
    )

    evidence = ForensicEvidence(
        cell_id=cell_id,
        sequence=sequence,
        timestamp=now,
        evidence_type=evidence_type,
        method=method,
        path=path,
        headers_hash=headers_hash,
        body_hash=body_hash,
        source_ip=source_ip,
        source_port=source_port,
        user_agent=user_agent,
        tool_signature=tool_sig,
        raw_headers=headers_json,
        raw_body=body[:10000],  # cap stored body size
        response_served=response_served[:10000],
        chain_hash=chain_hash,
        previous_hash=previous_hash,
    )

    db.session.add(evidence)
    db.session.commit()

    logger.info(
        "EVIDENCE cell=%s seq=%d type=%s tool=%s ip=%s path=%s",
        cell_id, sequence, evidence_type, tool_sig, source_ip, path,
    )

    return evidence


def verify_chain_integrity(cell_id: str) -> dict:
    """Verify the hash chain for a cell's evidence trail.

    Returns a report indicating whether the chain is intact or which
    entry has been tampered with.
    """
    entries = (
        ForensicEvidence.query
        .filter_by(cell_id=cell_id)
        .order_by(ForensicEvidence.sequence.asc())
        .all()
    )

    if not entries:
        return {"cell_id": cell_id, "intact": True, "entries": 0, "note": "no evidence"}

    expected_prev = "GENESIS"
    for entry in entries:
        # Verify previous hash linkage
        if entry.previous_hash != expected_prev:
            return {
                "cell_id": cell_id,
                "intact": False,
                "broken_at_sequence": entry.sequence,
                "error": "previous_hash mismatch",
                "expected": expected_prev,
                "found": entry.previous_hash,
            }

        # Recompute chain hash
        recomputed = _compute_chain_hash(
            cell_id=entry.cell_id,
            sequence=entry.sequence,
            timestamp=entry.timestamp.isoformat(),
            evidence_type=entry.evidence_type,
            method=entry.method,
            path=entry.path,
            headers_hash=entry.headers_hash,
            body_hash=entry.body_hash,
            source_ip=entry.source_ip,
            previous_hash=entry.previous_hash,
        )

        if recomputed != entry.chain_hash:
            return {
                "cell_id": cell_id,
                "intact": False,
                "broken_at_sequence": entry.sequence,
                "error": "chain_hash tampered",
                "expected": recomputed,
                "found": entry.chain_hash,
            }

        expected_prev = entry.chain_hash

    return {
        "cell_id": cell_id,
        "intact": True,
        "entries": len(entries),
        "first_timestamp": entries[0].timestamp.isoformat(),
        "last_timestamp": entries[-1].timestamp.isoformat(),
    }


def emit_security_event(cell_id: str, event_type: str, severity: str, details: str) -> None:
    """Emit a security event tied to honeypot activity."""
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        source=f"honeypot:mirror-cell:{cell_id}",
        details=details,
    )
    db.session.add(event)
    db.session.commit()


def get_cell_evidence_summary(cell_id: str) -> dict:
    """Build a complete forensic summary for a mirror cell."""
    cell = MirrorCellRecord.query.filter_by(cell_id=cell_id).first()
    if not cell:
        return {"error": "cell not found"}

    entries = (
        ForensicEvidence.query
        .filter_by(cell_id=cell_id)
        .order_by(ForensicEvidence.sequence.asc())
        .all()
    )

    chain_report = verify_chain_integrity(cell_id)

    # Aggregate tool signatures seen
    tools_seen = set()
    paths_probed = set()
    methods_used = set()
    evidence_types = {}

    for e in entries:
        tools_seen.add(e.tool_signature)
        paths_probed.add(e.path)
        methods_used.add(e.method)
        evidence_types[e.evidence_type] = evidence_types.get(e.evidence_type, 0) + 1

    return {
        "cell_id": cell_id,
        "attacker_fingerprint": cell.attacker_fingerprint,
        "source_ip": cell.source_ip,
        "first_seen": cell.first_seen.isoformat(),
        "last_seen": cell.last_seen.isoformat(),
        "escalation_level": cell.escalation_level,
        "total_interactions": cell.total_interactions,
        "locked": cell.locked,
        "status": cell.status,
        "evidence_count": len(entries),
        "chain_integrity": chain_report,
        "tools_observed": sorted(tools_seen),
        "paths_probed": sorted(paths_probed),
        "methods_used": sorted(methods_used),
        "evidence_type_counts": evidence_types,
    }
