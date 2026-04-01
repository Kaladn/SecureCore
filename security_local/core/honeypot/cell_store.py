"""Cell store - query and reporting interface for mirror cells.

Provides the API for the admin dashboard and CLI tools to inspect
active cells, locked attackers, and forensic evidence.
"""

import json
import logging
from datetime import datetime, UTC

from core.db import db
from core.models import MirrorCellRecord, ForensicEvidence
from core.honeypot.mirror_cell import cell_manager, ESCALATION_NAMES
from core.honeypot.forensics import verify_chain_integrity, get_cell_evidence_summary

logger = logging.getLogger("honeypot.cell_store")


def get_active_cells() -> list[dict]:
    """Get all active in-memory cells."""
    return cell_manager.get_all_cells()


def get_locked_cells() -> list[dict]:
    """Get all locked (committed attacker) cells."""
    return cell_manager.get_locked_cells()


def get_all_persisted_cells() -> list[dict]:
    """Get all cells from database, including those from previous runs."""
    records = (
        MirrorCellRecord.query
        .order_by(MirrorCellRecord.last_seen.desc())
        .all()
    )
    return [
        {
            "cell_id": r.cell_id,
            "attacker_fingerprint": r.attacker_fingerprint,
            "source_ip": r.source_ip,
            "first_seen": r.first_seen.isoformat(),
            "last_seen": r.last_seen.isoformat(),
            "escalation_level": r.escalation_level,
            "escalation_name": ESCALATION_NAMES.get(r.escalation_level, "UNKNOWN"),
            "total_interactions": r.total_interactions,
            "locked": r.locked,
            "status": r.status,
        }
        for r in records
    ]


def get_cell_full_report(cell_id: str) -> dict:
    """Generate a complete forensic report for a cell.

    This is the evidence package. Everything needed to identify
    the attacker, their tools, their methods, and their targets.
    """
    summary = get_cell_evidence_summary(cell_id)
    if "error" in summary:
        return summary

    # Get all evidence entries for timeline
    entries = (
        ForensicEvidence.query
        .filter_by(cell_id=cell_id)
        .order_by(ForensicEvidence.sequence.asc())
        .all()
    )

    timeline = []
    for e in entries:
        timeline.append({
            "sequence": e.sequence,
            "timestamp": e.timestamp.isoformat(),
            "evidence_type": e.evidence_type,
            "method": e.method,
            "path": e.path,
            "source_ip": e.source_ip,
            "source_port": e.source_port,
            "tool_signature": e.tool_signature,
            "user_agent": e.user_agent,
            "chain_hash": e.chain_hash,
        })

    summary["timeline"] = timeline

    return summary


def get_threat_dashboard() -> dict:
    """Build a threat overview dashboard."""
    active = cell_manager.get_all_cells()
    locked = cell_manager.get_locked_cells()

    # Persisted totals
    total_persisted = MirrorCellRecord.query.count()
    total_locked_persisted = MirrorCellRecord.query.filter_by(locked=True).count()
    total_evidence = ForensicEvidence.query.count()

    # Top attacked paths
    top_paths = (
        db.session.query(
            ForensicEvidence.path,
            db.func.count(ForensicEvidence.id).label("hit_count"),
        )
        .group_by(ForensicEvidence.path)
        .order_by(db.func.count(ForensicEvidence.id).desc())
        .limit(20)
        .all()
    )

    # Top tools observed
    top_tools = (
        db.session.query(
            ForensicEvidence.tool_signature,
            db.func.count(ForensicEvidence.id).label("count"),
        )
        .group_by(ForensicEvidence.tool_signature)
        .order_by(db.func.count(ForensicEvidence.id).desc())
        .limit(10)
        .all()
    )

    # Top source IPs
    top_ips = (
        db.session.query(
            ForensicEvidence.source_ip,
            db.func.count(ForensicEvidence.id).label("count"),
        )
        .group_by(ForensicEvidence.source_ip)
        .order_by(db.func.count(ForensicEvidence.id).desc())
        .limit(10)
        .all()
    )

    return {
        "active_cells": len(active),
        "locked_cells": len(locked),
        "total_cells_all_time": total_persisted,
        "total_locked_all_time": total_locked_persisted,
        "total_evidence_entries": total_evidence,
        "active_cell_summaries": active,
        "locked_cell_summaries": locked,
        "top_attacked_paths": [{"path": p, "hits": c} for p, c in top_paths],
        "top_tools_observed": [{"tool": t, "count": c} for t, c in top_tools],
        "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
    }
