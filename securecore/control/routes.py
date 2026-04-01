"""Control plane admin routes.

JWT-protected, role-enforced operator endpoints for:
  - Honeypot dashboard
  - Mirror cell inspection
  - Shun management
  - Evidence export
  - Chain integrity verification
  - Agent status
  - Substrate stats
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from securecore.core.auth import role_required

control_bp = Blueprint("control", __name__)

# These get set by the app factory after initialization
_substrates = {}
_agents = {}
_log_router = None
_reaper = None


def init_control_routes(substrates: dict, agents: dict, log_router=None, reaper=None):
    """Wire up control routes with substrate and agent references."""
    global _substrates, _agents, _log_router, _reaper
    _substrates = substrates
    _agents = agents
    _log_router = log_router
    _reaper = reaper


# ============================================================
# DASHBOARD
# ============================================================

@control_bp.get("/api/control/dashboard")
@jwt_required()
@role_required("admin")
def dashboard():
    """Full threat and system overview."""
    from securecore.control.shun import get_shun_list, get_shun_count

    data = {
        "substrates": {},
        "agents": {},
        "shun": {"count": get_shun_count(), "list": get_shun_list()},
    }

    for name, sub in _substrates.items():
        data["substrates"][name] = {
            "total_records": sub.count(),
            "jsonl_path": sub.jsonl_path,
        }

    for name, agent in _agents.items():
        data["agents"][name] = agent.stats

    if _log_router:
        data["log_streams"] = _log_router.stats()

    hid_sub = _substrates.get("hid")
    if hid_sub and hasattr(hid_sub, "get_recent_attestation"):
        data["hid"] = hid_sub.get_recent_attestation()

    return jsonify({"ok": True, "data": data})


# ============================================================
# SUBSTRATES
# ============================================================

@control_bp.get("/api/control/substrates")
@jwt_required()
@role_required("admin")
def substrate_stats():
    """Stats for all substrates."""
    stats = {}
    for name, sub in _substrates.items():
        stats[name] = {
            "total_records": sub.count(),
            "jsonl_path": sub.jsonl_path,
        }
    return jsonify({"ok": True, "substrates": stats})


@control_bp.get("/api/control/substrates/<name>/verify")
@jwt_required()
@role_required("admin")
def verify_substrate(name: str):
    """Verify hash chain integrity for a substrate."""
    sub = _substrates.get(name)
    if not sub:
        return jsonify({"ok": False, "error": f"unknown substrate: {name}"}), 404
    result = sub.verify_chain()
    return jsonify({"ok": True, "chain_integrity": result})


@control_bp.get("/api/control/substrates/<name>/tail")
@jwt_required()
@role_required("admin")
def substrate_tail(name: str):
    """Get the last N records from a substrate."""
    sub = _substrates.get(name)
    if not sub:
        return jsonify({"ok": False, "error": f"unknown substrate: {name}"}), 404

    limit = request.args.get("limit", 50, type=int)
    records = list(sub.stream())[-limit:]
    return jsonify({
        "ok": True,
        "substrate": name,
        "count": len(records),
        "records": [r.to_dict() for r in records],
    })


@control_bp.get("/api/control/hid")
@jwt_required()
@role_required("admin")
def hid_status():
    """Latest human-input-device attestation snapshot."""
    hid_sub = _substrates.get("hid")
    if not hid_sub or not hasattr(hid_sub, "get_recent_attestation"):
        return jsonify({"ok": False, "error": "hid substrate not available"}), 500
    return jsonify({"ok": True, "hid": hid_sub.get_recent_attestation()})


# ============================================================
# EVIDENCE
# ============================================================

@control_bp.get("/api/control/evidence/<cell_id>")
@jwt_required()
@role_required("admin")
def cell_evidence(cell_id: str):
    """Full evidence bundle for a cell."""
    evidence_sub = _substrates.get("evidence")
    if not evidence_sub:
        return jsonify({"ok": False, "error": "evidence substrate not available"}), 500

    bundle = evidence_sub.export_evidence_bundle(cell_id)
    return jsonify({"ok": True, "bundle": bundle})


@control_bp.get("/api/control/evidence/<cell_id>/verify")
@jwt_required()
@role_required("admin")
def verify_cell_evidence(cell_id: str):
    """Verify per-cell evidence chain."""
    evidence_sub = _substrates.get("evidence")
    if not evidence_sub:
        return jsonify({"ok": False, "error": "evidence substrate not available"}), 500

    result = evidence_sub.verify_cell_chain(cell_id)
    return jsonify({"ok": True, "chain_integrity": result})


# ============================================================
# AGENTS
# ============================================================

@control_bp.get("/api/control/agents")
@jwt_required()
@role_required("admin")
def agent_stats():
    """Status of all agents."""
    stats = {name: agent.stats for name, agent in _agents.items()}
    return jsonify({"ok": True, "agents": stats})


@control_bp.get("/api/control/agents/<name>/decisions")
@jwt_required()
@role_required("admin")
def agent_decisions(name: str):
    """Recent decisions from a specific agent."""
    decisions_sub = _substrates.get("agent_decisions")
    if not decisions_sub:
        return jsonify({"ok": False, "error": "agent_decisions substrate not available"}), 500

    limit = request.args.get("limit", 50, type=int)
    records = decisions_sub.get_decisions_by_agent(name, limit=limit)
    return jsonify({"ok": True, "agent": name, "decisions": records})


# ============================================================
# SHUN
# ============================================================

@control_bp.get("/api/control/shun")
@jwt_required()
@role_required("admin")
def shun_list():
    from securecore.control.shun import get_shun_list, get_shun_count
    return jsonify({"ok": True, "count": get_shun_count(), "shunned": get_shun_list()})


@control_bp.post("/api/control/shun")
@jwt_required()
@role_required("admin")
def manual_shun():
    from securecore.control.shun import shun_ip as do_shun
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "manual operator shun")
    if not ip:
        return jsonify({"ok": False, "error": "ip required"}), 400

    result = do_shun(
        ip=ip, reason=reason,
        operator_substrate=_substrates.get("operator"),
    )
    return jsonify(result), 200 if result["ok"] else 400


@control_bp.post("/api/control/unshun")
@jwt_required()
@role_required("admin")
def manual_unshun():
    from securecore.control.shun import unshun_ip as do_unshun
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "operator release")
    if not ip:
        return jsonify({"ok": False, "error": "ip required"}), 400

    result = do_unshun(
        ip=ip, reason=reason,
        operator_substrate=_substrates.get("operator"),
    )
    return jsonify(result), 200 if result["ok"] else 404


@control_bp.post("/api/control/shun/purge")
@jwt_required()
@role_required("admin")
def purge_shuns():
    from securecore.control.shun import purge_all_shun_rules
    result = purge_all_shun_rules()
    return jsonify({"ok": True, "purge_result": result})


# ============================================================
# CHAIN AUDIT
# ============================================================

@control_bp.post("/api/control/audit")
@jwt_required()
@role_required("admin")
def force_audit():
    """Force an immediate chain integrity audit across all substrates."""
    auditor = _agents.get("chain_auditor")
    if auditor and hasattr(auditor, "force_audit"):
        results = auditor.force_audit()
        return jsonify({"ok": True, "audit_results": results})
    return jsonify({"ok": False, "error": "chain_auditor agent not available"}), 500


# ============================================================
# LOG STREAMS
# ============================================================

@control_bp.get("/api/control/logs/<stream_name>")
@jwt_required()
@role_required("admin")
def log_stream_tail(stream_name: str):
    """Tail a specific log stream."""
    if not _log_router:
        return jsonify({"ok": False, "error": "log router not available"}), 500

    stream = _log_router.get_stream(stream_name)
    if not stream:
        return jsonify({"ok": False, "error": f"unknown stream: {stream_name}"}), 404

    n = request.args.get("n", 50, type=int)
    entries = stream.tail(n)
    return jsonify({"ok": True, "stream": stream_name, "entries": entries})


# ============================================================
# REAPER
# ============================================================

@control_bp.get("/api/control/reaper")
@jwt_required()
@role_required("admin")
def reaper_status():
    """Reaper status and statistics."""
    if not _reaper:
        return jsonify({"ok": False, "error": "reaper not available"}), 500
    return jsonify({"ok": True, "reaper": _reaper.stats})


@control_bp.post("/api/control/reaper/pause")
@jwt_required()
@role_required("admin")
def reaper_pause():
    """Pause the Reaper."""
    if not _reaper:
        return jsonify({"ok": False, "error": "reaper not available"}), 500
    _reaper.pause()
    return jsonify({"ok": True, "status": "paused"})


@control_bp.post("/api/control/reaper/resume")
@jwt_required()
@role_required("admin")
def reaper_resume():
    """Resume the Reaper."""
    if not _reaper:
        return jsonify({"ok": False, "error": "reaper not available"}), 500
    _reaper.resume()
    return jsonify({"ok": True, "status": "resumed"})
