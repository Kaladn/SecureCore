"""Admin routes for honeypot monitoring.

These are the REAL admin endpoints (JWT-protected, role-enforced)
that let the operator monitor active mirror cells, review forensic
evidence, verify chain integrity, and export evidence packages.
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from core.auth import role_required
from core.honeypot.cell_store import (
    get_active_cells,
    get_locked_cells,
    get_all_persisted_cells,
    get_cell_full_report,
    get_threat_dashboard,
)
from core.honeypot.forensics import verify_chain_integrity
from core.honeypot.shun_engine import (
    shun_ip,
    unshun_ip,
    get_shun_list,
    get_shun_count,
    is_shunned,
    list_firewall_shun_rules,
    purge_all_shun_rules,
)


honeypot_admin_bp = Blueprint("honeypot_admin", __name__)


@honeypot_admin_bp.get("/api/honeypot/dashboard")
@jwt_required()
@role_required("admin")
def dashboard():
    """Threat overview dashboard."""
    return jsonify({"ok": True, "data": get_threat_dashboard()})


@honeypot_admin_bp.get("/api/honeypot/cells")
@jwt_required()
@role_required("admin")
def list_cells():
    """List all active mirror cells."""
    return jsonify({"ok": True, "cells": get_active_cells()})


@honeypot_admin_bp.get("/api/honeypot/cells/locked")
@jwt_required()
@role_required("admin")
def list_locked_cells():
    """List only locked (committed attacker) cells."""
    return jsonify({"ok": True, "cells": get_locked_cells()})


@honeypot_admin_bp.get("/api/honeypot/cells/history")
@jwt_required()
@role_required("admin")
def list_historical_cells():
    """List all cells from database including previous runs."""
    return jsonify({"ok": True, "cells": get_all_persisted_cells()})


@honeypot_admin_bp.get("/api/honeypot/cells/<cell_id>")
@jwt_required()
@role_required("admin")
def cell_detail(cell_id: str):
    """Full forensic report for a specific cell."""
    report = get_cell_full_report(cell_id)
    if "error" in report:
        return jsonify({"ok": False, "error": report["error"]}), 404
    return jsonify({"ok": True, "report": report})


@honeypot_admin_bp.get("/api/honeypot/cells/<cell_id>/verify")
@jwt_required()
@role_required("admin")
def verify_cell_chain(cell_id: str):
    """Verify the tamper-evident hash chain for a cell's evidence."""
    result = verify_chain_integrity(cell_id)
    return jsonify({"ok": True, "chain_integrity": result})


# ============================================================
# SHUN ENGINE ROUTES
# ============================================================

@honeypot_admin_bp.get("/api/honeypot/shun")
@jwt_required()
@role_required("admin")
def shun_list():
    """List all currently shunned IPs."""
    return jsonify({
        "ok": True,
        "count": get_shun_count(),
        "shunned": get_shun_list(),
    })


@honeypot_admin_bp.post("/api/honeypot/shun")
@jwt_required()
@role_required("admin")
def manual_shun():
    """Manually shun an IP address."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "manual operator shun")

    if not ip:
        return jsonify({"ok": False, "error": "ip required"}), 400

    result = shun_ip(ip=ip, reason=reason)
    status_code = 200 if result["ok"] else 400
    return jsonify(result), status_code


@honeypot_admin_bp.post("/api/honeypot/unshun")
@jwt_required()
@role_required("admin")
def manual_unshun():
    """Remove an IP from the shun list."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "operator release")

    if not ip:
        return jsonify({"ok": False, "error": "ip required"}), 400

    result = unshun_ip(ip=ip, reason=reason)
    status_code = 200 if result["ok"] else 404
    return jsonify(result), status_code


@honeypot_admin_bp.get("/api/honeypot/shun/check/<ip>")
@jwt_required()
@role_required("admin")
def check_shun(ip: str):
    """Check if a specific IP is shunned."""
    return jsonify({"ok": True, "ip": ip, "shunned": is_shunned(ip)})


@honeypot_admin_bp.get("/api/honeypot/shun/firewall-rules")
@jwt_required()
@role_required("admin")
def firewall_rules():
    """List all active SecureCore firewall shun rules."""
    rules = list_firewall_shun_rules()
    return jsonify({"ok": True, "count": len(rules), "rules": rules})


@honeypot_admin_bp.post("/api/honeypot/shun/purge")
@jwt_required()
@role_required("admin")
def purge_shuns():
    """Emergency: remove ALL shun rules from firewall."""
    result = purge_all_shun_rules()
    return jsonify({"ok": True, "purge_result": result})
