"""Honeypot trap routes.

These are the bait endpoints. They look like real attack surface -
admin panels, exposed configs, API key endpoints, user databases.

Every request to these routes is intercepted by the mirror cell engine.
The attacker gets convincing fake data. We get forensic evidence.

Route categories:
  - Admin panel traps (fake login pages, dashboards)
  - Credential traps (fake API keys, tokens, passwords)
  - Data traps (fake user DBs, config dumps, backups)
  - Recon traps (fake server status, network maps)
  - Catch-all trap (anything that hits common scanner paths)
"""

import json
import logging
from flask import Blueprint, request, Response, make_response, current_app

from core.honeypot.mirror_cell import cell_manager
from core.honeypot.forensics import record_evidence
from core.honeypot.decoys import (
    fake_admin_panel,
    fake_api_keys_response,
    fake_user_database,
    fake_config_dump,
    fake_server_status,
    fake_backup_listing,
    fake_internal_network_map,
    fake_login_success,
    fake_error_with_stack,
)

logger = logging.getLogger("honeypot.traps")

trap_bp = Blueprint("traps", __name__)


def _extract_request_data() -> tuple[dict, str, str, int | None]:
    """Extract normalized request data for cell processing."""
    headers = dict(request.headers)
    body = request.get_data(as_text=True) or ""
    source_ip = request.remote_addr or "unknown"

    source_port = None
    if hasattr(request, "environ"):
        source_port = request.environ.get("REMOTE_PORT")

    return headers, body, source_ip, source_port


def _process_through_cell(
    method: str,
    path: str,
    headers: dict,
    body: str,
    source_ip: str,
    source_port: int | None,
    response_content: str,
    evidence_type: str = "trap_interaction",
) -> dict:
    """Run a request through the mirror cell engine and record evidence."""
    threshold = current_app.config.get("HONEYPOT_ESCALATION_THRESHOLD", 3)

    cell = cell_manager.get_or_create_cell(source_ip, headers)
    result = cell.process_request(
        method=method,
        path=path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        escalation_threshold=threshold,
    )

    # Record forensic evidence
    record_evidence(
        cell_id=cell.cell_id,
        evidence_type=result.get("evidence_type", evidence_type),
        method=method,
        path=path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_served=response_content[:5000],
    )

    # Persist cell state
    cell.persist()

    return result


# ============================================================
# ADMIN PANEL TRAPS
# ============================================================

@trap_bp.route("/admin", methods=["GET", "HEAD"])
@trap_bp.route("/admin/", methods=["GET", "HEAD"])
@trap_bp.route("/administrator", methods=["GET", "HEAD"])
@trap_bp.route("/admin/login", methods=["GET", "HEAD"])
@trap_bp.route("/admin/dashboard", methods=["GET", "HEAD"])
@trap_bp.route("/console", methods=["GET", "HEAD"])
@trap_bp.route("/manager", methods=["GET", "HEAD"])
@trap_bp.route("/wp-admin", methods=["GET", "HEAD"])
@trap_bp.route("/wp-admin/", methods=["GET", "HEAD"])
@trap_bp.route("/wp-login.php", methods=["GET", "HEAD"])
@trap_bp.route("/phpmyadmin", methods=["GET", "HEAD"])
@trap_bp.route("/phpmyadmin/", methods=["GET", "HEAD"])
def admin_panel_trap():
    headers, body, source_ip, source_port = _extract_request_data()
    cell = cell_manager.get_or_create_cell(source_ip, headers)
    content = fake_admin_panel(cell.cell_id)

    _process_through_cell(
        method=request.method,
        path=request.path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_content=content,
    )

    return Response(content, status=200, content_type="text/html")


@trap_bp.route("/admin/authenticate", methods=["POST"])
@trap_bp.route("/admin/login", methods=["POST"])
@trap_bp.route("/wp-login.php", methods=["POST"])
def admin_login_trap():
    """Fake login endpoint. Always 'succeeds' to keep them engaged."""
    headers, body, source_ip, source_port = _extract_request_data()
    cell = cell_manager.get_or_create_cell(source_ip, headers)

    # Extract whatever username they tried
    username = "admin"
    if request.is_json:
        data = request.get_json(silent=True) or {}
        username = data.get("username", data.get("user", "admin"))
    else:
        username = request.form.get("username", request.form.get("user", "admin"))

    content = json.dumps(fake_login_success(cell.cell_id, username))

    _process_through_cell(
        method=request.method,
        path=request.path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_content=content,
        evidence_type="credential_harvest",
    )

    return Response(content, status=200, content_type="application/json")


# ============================================================
# CREDENTIAL TRAPS
# ============================================================

@trap_bp.route("/api/keys", methods=["GET"])
@trap_bp.route("/api/tokens", methods=["GET"])
@trap_bp.route("/api/v1/keys", methods=["GET"])
@trap_bp.route("/api/v2/keys", methods=["GET"])
@trap_bp.route("/credentials", methods=["GET"])
@trap_bp.route("/.env", methods=["GET"])
def credential_trap():
    headers, body, source_ip, source_port = _extract_request_data()
    cell = cell_manager.get_or_create_cell(source_ip, headers)

    if request.path == "/.env":
        # Serve a fake .env file
        content = (
            f"# Production Environment\n"
            f"SECRET_KEY=sk_{cell.cell_id}a1b2c3d4e5f6\n"
            f"DATABASE_URL=postgresql://app:pg_{cell.cell_id}@db-primary:5432/prod\n"
            f"REDIS_URL=redis://:{cell.cell_id}_redis@cache:6379/0\n"
            f"AWS_ACCESS_KEY_ID=AKIA{cell.cell_id.upper()[:16]}\n"
            f"AWS_SECRET_ACCESS_KEY={cell.cell_id}secretkey1234567890\n"
            f"SMTP_PASSWORD=smtp_{cell.cell_id}\n"
            f"JWT_SECRET={cell.cell_id}_jwt_secret_key\n"
            f"ADMIN_PASSWORD=admin_{cell.cell_id[:8]}\n"
        )
        content_type = "text/plain"
    else:
        content = json.dumps(fake_api_keys_response(cell.cell_id), indent=2)
        content_type = "application/json"

    _process_through_cell(
        method=request.method,
        path=request.path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_content=content,
    )

    return Response(content, status=200, content_type=content_type)


# ============================================================
# DATA EXFILTRATION TRAPS
# ============================================================

@trap_bp.route("/api/users", methods=["GET"])
@trap_bp.route("/api/v1/users", methods=["GET"])
@trap_bp.route("/api/accounts", methods=["GET"])
@trap_bp.route("/users/export", methods=["GET"])
@trap_bp.route("/dump/users", methods=["GET"])
def user_data_trap():
    headers, body, source_ip, source_port = _extract_request_data()
    cell = cell_manager.get_or_create_cell(source_ip, headers)
    content = json.dumps(fake_user_database(cell.cell_id), indent=2)

    _process_through_cell(
        method=request.method,
        path=request.path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_content=content,
    )

    return Response(content, status=200, content_type="application/json")


@trap_bp.route("/config", methods=["GET"])
@trap_bp.route("/config.json", methods=["GET"])
@trap_bp.route("/api/config", methods=["GET"])
@trap_bp.route("/.git/config", methods=["GET"])
@trap_bp.route("/settings", methods=["GET"])
@trap_bp.route("/debug", methods=["GET"])
def config_trap():
    headers, body, source_ip, source_port = _extract_request_data()
    cell = cell_manager.get_or_create_cell(source_ip, headers)

    if request.path == "/.git/config":
        content = (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            "\tbare = false\n"
            "[remote \"origin\"]\n"
            "\turl = git@github.com:securecore-internal/platform.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            "[branch \"main\"]\n"
            "\tremote = origin\n"
            "\tmerge = refs/heads/main\n"
            "[user]\n"
            "\tname = deploy-bot\n"
            "\temail = deploy@securecore.local\n"
        )
        content_type = "text/plain"
    else:
        content = json.dumps(fake_config_dump(cell.cell_id), indent=2)
        content_type = "application/json"

    _process_through_cell(
        method=request.method,
        path=request.path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_content=content,
    )

    return Response(content, status=200, content_type=content_type)


@trap_bp.route("/backup", methods=["GET"])
@trap_bp.route("/backups", methods=["GET"])
@trap_bp.route("/api/backups", methods=["GET"])
@trap_bp.route("/dump", methods=["GET"])
@trap_bp.route("/database", methods=["GET"])
def backup_trap():
    headers, body, source_ip, source_port = _extract_request_data()
    cell = cell_manager.get_or_create_cell(source_ip, headers)
    content = json.dumps(fake_backup_listing(cell.cell_id), indent=2)

    _process_through_cell(
        method=request.method,
        path=request.path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_content=content,
    )

    return Response(content, status=200, content_type="application/json")


# ============================================================
# RECON TRAPS
# ============================================================

@trap_bp.route("/server-status", methods=["GET"])
@trap_bp.route("/status", methods=["GET"])
@trap_bp.route("/info", methods=["GET"])
@trap_bp.route("/api/status", methods=["GET"])
@trap_bp.route("/api/info", methods=["GET"])
@trap_bp.route("/version", methods=["GET"])
def status_trap():
    headers, body, source_ip, source_port = _extract_request_data()
    cell = cell_manager.get_or_create_cell(source_ip, headers)
    content = json.dumps(fake_server_status(cell.cell_id), indent=2)

    _process_through_cell(
        method=request.method,
        path=request.path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_content=content,
    )

    return Response(content, status=200, content_type="application/json")


@trap_bp.route("/network", methods=["GET"])
@trap_bp.route("/internal", methods=["GET"])
@trap_bp.route("/infrastructure", methods=["GET"])
@trap_bp.route("/api/network", methods=["GET"])
@trap_bp.route("/api/internal/hosts", methods=["GET"])
def network_trap():
    headers, body, source_ip, source_port = _extract_request_data()
    cell = cell_manager.get_or_create_cell(source_ip, headers)
    content = json.dumps(fake_internal_network_map(cell.cell_id), indent=2)

    _process_through_cell(
        method=request.method,
        path=request.path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_content=content,
    )

    return Response(content, status=200, content_type="application/json")


# ============================================================
# COMMON SCANNER PATHS - catch-all for known enumeration targets
# ============================================================

@trap_bp.route("/robots.txt", methods=["GET"])
def robots_trap():
    """Serve a robots.txt that reveals 'hidden' paths - all traps."""
    headers, body, source_ip, source_port = _extract_request_data()

    content = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /api/keys/\n"
        "Disallow: /api/users/\n"
        "Disallow: /backup/\n"
        "Disallow: /config/\n"
        "Disallow: /internal/\n"
        "Disallow: /api/internal/\n"
        "Disallow: /database/\n"
        "Disallow: /dump/\n"
        "Disallow: /credentials/\n"
        "Disallow: /private/\n"
        "Disallow: /secret/\n"
    )

    _process_through_cell(
        method=request.method,
        path=request.path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_content=content,
    )

    return Response(content, status=200, content_type="text/plain")


@trap_bp.route("/sitemap.xml", methods=["GET"])
def sitemap_trap():
    headers, body, source_ip, source_port = _extract_request_data()

    content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        '  <url><loc>/admin/</loc></url>\n'
        '  <url><loc>/api/status</loc></url>\n'
        '  <url><loc>/api/users</loc></url>\n'
        '  <url><loc>/api/config</loc></url>\n'
        '  <url><loc>/backup/</loc></url>\n'
        '</urlset>\n'
    )

    _process_through_cell(
        method=request.method,
        path=request.path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_content=content,
    )

    return Response(content, status=200, content_type="application/xml")


@trap_bp.route("/xmlrpc.php", methods=["GET", "POST"])
@trap_bp.route("/swagger", methods=["GET"])
@trap_bp.route("/swagger.json", methods=["GET"])
@trap_bp.route("/api-docs", methods=["GET"])
@trap_bp.route("/graphql", methods=["GET", "POST"])
@trap_bp.route("/.well-known/security.txt", methods=["GET"])
@trap_bp.route("/secret", methods=["GET"])
@trap_bp.route("/private", methods=["GET"])
def generic_probe_trap():
    """Catch-all for common scanner targets. Returns believable errors."""
    headers, body, source_ip, source_port = _extract_request_data()
    cell = cell_manager.get_or_create_cell(source_ip, headers)
    content = json.dumps(fake_error_with_stack(cell.cell_id, request.path), indent=2)

    _process_through_cell(
        method=request.method,
        path=request.path,
        headers=headers,
        body=body,
        source_ip=source_ip,
        source_port=source_port,
        response_content=content,
    )

    return Response(content, status=500, content_type="application/json")
