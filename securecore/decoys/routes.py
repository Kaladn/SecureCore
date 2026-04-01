"""Trap routes - bait endpoints that feed the substrate organism.

Every request to a trap route:
  1. Records raw ingress in the ingress substrate
  2. Gets or creates a mirror cell
  3. Records interaction in the mirror substrate
  4. Records forensic evidence in the evidence substrate
  5. Logs to all relevant log streams
  6. Serves a convincing decoy response

The trap routes are the mouth of the organism. Everything flows
from here into the substrates, and the agents interpret from there.
"""

import hashlib
import json
import time
from flask import Blueprint, request, Response, current_app

from securecore.core.fingerprint import (
    fingerprint_request, compute_attacker_fingerprint,
)
from securecore.decoys.content import (
    fake_admin_panel, fake_api_keys, fake_user_database,
    fake_config_dump, fake_server_status, fake_network_map,
    fake_backup_listing, fake_login_success, fake_error_with_stack,
    fake_env_file, fake_git_config,
)

trap_bp = Blueprint("traps", __name__)

# Set by app factory
_ingress_sub = None
_mirror_sub = None
_evidence_sub = None
_telemetry_sub = None
_log_router = None

# In-memory cell tracking (cell_id -> {fingerprint, ip, ...})
_cells: dict[str, dict] = {}
_cells_by_fingerprint: dict[str, str] = {}


def init_trap_routes(ingress_sub, mirror_sub, evidence_sub, telemetry_sub, log_router):
    global _ingress_sub, _mirror_sub, _evidence_sub, _telemetry_sub, _log_router
    _ingress_sub = ingress_sub
    _mirror_sub = mirror_sub
    _evidence_sub = evidence_sub
    _telemetry_sub = telemetry_sub
    _log_router = log_router


def _current_fingerprint() -> tuple[str, dict, str, str]:
    headers = dict(request.headers)
    source_ip = request.remote_addr or "unknown"
    user_agent = headers.get("User-Agent", headers.get("user-agent", ""))
    accept_lang = headers.get("Accept-Language", headers.get("accept-language", ""))
    accept_enc = headers.get("Accept-Encoding", headers.get("accept-encoding", ""))
    fingerprint = compute_attacker_fingerprint(source_ip, user_agent, accept_lang, accept_enc)
    return fingerprint, headers, source_ip, user_agent


def _ensure_cell(path: str = "") -> tuple[str, dict]:
    fingerprint, _, source_ip, user_agent = _current_fingerprint()
    cell_id = _cells_by_fingerprint.get(fingerprint)
    if not cell_id:
        cell_id = hashlib.sha256(f"{fingerprint}:{time.time()}".encode()).hexdigest()[:16]
        _cells_by_fingerprint[fingerprint] = cell_id
        _cells[cell_id] = {
            "fingerprint": fingerprint,
            "source_ip": source_ip,
            "interaction_count": 0,
            "escalation_level": 0,
            "created_at": time.time(),
        }
        if _mirror_sub:
            _mirror_sub.record_cell_created(
                cell_id=cell_id,
                attacker_fingerprint=fingerprint,
                source_ip=source_ip,
                user_agent=user_agent,
                trigger_path=path or request.path,
            )
    return cell_id, _cells[cell_id]


def _process_trap_request(decoy_content: str, content_type: str, status_code: int = 200) -> Response:
    """Universal trap request processor. Feeds all substrates."""
    start = time.time()
    headers = dict(request.headers)
    body = request.get_data(as_text=True) or ""
    source_ip = request.remote_addr or "unknown"
    source_port = request.environ.get("REMOTE_PORT") if hasattr(request, "environ") else None
    path = request.path
    method = request.method
    query_string = request.query_string.decode("utf-8", errors="replace")

    # Fingerprint
    ua = headers.get("User-Agent", headers.get("user-agent", ""))
    accept_lang = headers.get("Accept-Language", headers.get("accept-language", ""))
    accept_enc = headers.get("Accept-Encoding", headers.get("accept-encoding", ""))
    fingerprint = compute_attacker_fingerprint(source_ip, ua, accept_lang, accept_enc)
    tool_sig = fingerprint_request(headers)

    # Get or create cell
    cell_id, cell = _ensure_cell(path)
    cell["interaction_count"] += 1
    cell["last_seen"] = time.time()

    # 1. Record raw ingress
    if _ingress_sub:
        _ingress_sub.record_request(
            source_ip=source_ip, source_port=source_port,
            method=method, path=path, query_string=query_string,
            headers=headers, body=body, cell_id=cell_id,
        )

    # 2. Record mirror interaction
    if _mirror_sub:
        _mirror_sub.record_cell_interaction(
            cell_id=cell_id, interaction_count=cell["interaction_count"],
            escalation_level=cell["escalation_level"], path=path, tool_signature=tool_sig,
        )
        # Record decoy served
        response_hash = hashlib.sha256(decoy_content.encode()).hexdigest()[:16]
        _mirror_sub.record_decoy_served(
            cell_id=cell_id, decoy_type=content_type, path=path, response_hash=response_hash,
        )

    # 3. Record forensic evidence
    evidence_record = None
    if _evidence_sub:
        evidence_record = _evidence_sub.record_evidence(
            cell_id=cell_id, evidence_type=_classify_path(path, method),
            method=method, path=path, headers=headers, body=body,
            source_ip=source_ip, source_port=source_port,
            user_agent=ua, tool_signature=tool_sig,
            response_served=decoy_content[:5000],
        )

    # 4. Record telemetry
    if _telemetry_sub:
        duration = (time.time() - start) * 1000
        _telemetry_sub.record_timing("trap_request", duration, "decoys", cell_id=cell_id)

    # 5. Log to streams
    if _log_router:
        from securecore.log_streams.schemas import raw_ingress_entry, forensic_entry, normalized_event_entry
        _log_router.log(raw_ingress_entry(
            source_ip=source_ip, source_port=source_port, method=method, path=path,
            headers=headers, body_size=len(body),
            body_hash=hashlib.sha256(body.encode()).hexdigest(), cell_id=cell_id,
        ))
        _log_router.log(normalized_event_entry(
            event_type="trap_hit", severity="medium", source="decoys",
            cell_id=cell_id, details=f"{method} {path} from {source_ip} tool={tool_sig}",
            tags=[tool_sig, _classify_path(path, method)],
        ))
        _log_router.log(forensic_entry(
            cell_id=cell_id, evidence_type=_classify_path(path, method),
            method=method, path=path, source_ip=source_ip,
            tool_signature=tool_sig,
            chain_hash=evidence_record.chain_hash if evidence_record else "",
            sequence=evidence_record.sequence if evidence_record else 0,
        ))

    return Response(decoy_content, status=status_code, content_type=content_type)


def _classify_path(path: str, method: str) -> str:
    p = path.lower()
    if any(x in p for x in ["/admin", "/console", "/manager", "/wp-admin"]):
        return "admin_probe"
    if any(x in p for x in ["/.env", "/.git", "/config", "/secret", "/private"]):
        return "sensitive_file_probe"
    if any(x in p for x in ["/api/keys", "/api/tokens", "/credentials"]):
        return "credential_harvest"
    if any(x in p for x in ["/backup", "/dump", "/export", "/database"]):
        return "data_exfil_attempt"
    if any(x in p for x in ["/users", "/accounts"]):
        return "user_enumeration"
    if any(x in p for x in ["/network", "/internal", "/infrastructure"]):
        return "recon_internal"
    if any(x in p for x in ["/status", "/health", "/info", "/version"]):
        return "service_discovery"
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return "mutation_attempt"
    return "general_probe"


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
    cell_id, _ = _ensure_cell(request.path)
    return _process_trap_request(fake_admin_panel(cell_id), "text/html")


@trap_bp.route("/admin/authenticate", methods=["POST"])
@trap_bp.route("/admin/login", methods=["POST"])
@trap_bp.route("/wp-login.php", methods=["POST"])
def admin_login_trap():
    cell_id, _ = _ensure_cell(request.path)
    username = "admin"
    if request.is_json:
        data = request.get_json(silent=True) or {}
        username = data.get("username", "admin")
    else:
        username = request.form.get("username", "admin")
    content = json.dumps(fake_login_success(cell_id, username))
    return _process_trap_request(content, "application/json")


# ============================================================
# CREDENTIAL TRAPS
# ============================================================

@trap_bp.route("/api/keys", methods=["GET"])
@trap_bp.route("/api/tokens", methods=["GET"])
@trap_bp.route("/api/v1/keys", methods=["GET"])
@trap_bp.route("/credentials", methods=["GET"])
def credential_trap():
    fp = _get_cell_id()
    return _process_trap_request(json.dumps(fake_api_keys(fp), indent=2), "application/json")


@trap_bp.route("/.env", methods=["GET"])
def env_trap():
    fp = _get_cell_id()
    return _process_trap_request(fake_env_file(fp), "text/plain")


# ============================================================
# DATA TRAPS
# ============================================================

@trap_bp.route("/api/users", methods=["GET"])
@trap_bp.route("/api/v1/users", methods=["GET"])
@trap_bp.route("/api/accounts", methods=["GET"])
@trap_bp.route("/users/export", methods=["GET"])
@trap_bp.route("/dump/users", methods=["GET"])
def user_data_trap():
    fp = _get_cell_id()
    return _process_trap_request(json.dumps(fake_user_database(fp), indent=2), "application/json")


@trap_bp.route("/config", methods=["GET"])
@trap_bp.route("/config.json", methods=["GET"])
@trap_bp.route("/api/config", methods=["GET"])
@trap_bp.route("/settings", methods=["GET"])
@trap_bp.route("/debug", methods=["GET"])
def config_trap():
    fp = _get_cell_id()
    return _process_trap_request(json.dumps(fake_config_dump(fp), indent=2), "application/json")


@trap_bp.route("/.git/config", methods=["GET"])
def git_config_trap():
    return _process_trap_request(fake_git_config(), "text/plain")


@trap_bp.route("/backup", methods=["GET"])
@trap_bp.route("/backups", methods=["GET"])
@trap_bp.route("/api/backups", methods=["GET"])
@trap_bp.route("/dump", methods=["GET"])
@trap_bp.route("/database", methods=["GET"])
def backup_trap():
    fp = _get_cell_id()
    return _process_trap_request(json.dumps(fake_backup_listing(fp), indent=2), "application/json")


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
    fp = _get_cell_id()
    return _process_trap_request(json.dumps(fake_server_status(fp), indent=2), "application/json")


@trap_bp.route("/network", methods=["GET"])
@trap_bp.route("/internal", methods=["GET"])
@trap_bp.route("/infrastructure", methods=["GET"])
@trap_bp.route("/api/network", methods=["GET"])
@trap_bp.route("/api/internal/hosts", methods=["GET"])
def network_trap():
    fp = _get_cell_id()
    return _process_trap_request(json.dumps(fake_network_map(fp), indent=2), "application/json")


# ============================================================
# SCANNER BAIT
# ============================================================

@trap_bp.route("/robots.txt", methods=["GET"])
def robots_trap():
    content = (
        "User-agent: *\n"
        "Disallow: /admin/\nDisallow: /api/keys/\nDisallow: /api/users/\n"
        "Disallow: /backup/\nDisallow: /config/\nDisallow: /internal/\n"
        "Disallow: /database/\nDisallow: /credentials/\nDisallow: /secret/\n"
    )
    return _process_trap_request(content, "text/plain")


@trap_bp.route("/sitemap.xml", methods=["GET"])
def sitemap_trap():
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        '  <url><loc>/admin/</loc></url>\n<url><loc>/api/users</loc></url>\n'
        '  <url><loc>/api/config</loc></url>\n<url><loc>/backup/</loc></url>\n'
        '</urlset>\n'
    )
    return _process_trap_request(content, "application/xml")


@trap_bp.route("/xmlrpc.php", methods=["GET", "POST"])
@trap_bp.route("/swagger", methods=["GET"])
@trap_bp.route("/swagger.json", methods=["GET"])
@trap_bp.route("/api-docs", methods=["GET"])
@trap_bp.route("/graphql", methods=["GET", "POST"])
@trap_bp.route("/.well-known/security.txt", methods=["GET"])
@trap_bp.route("/secret", methods=["GET"])
@trap_bp.route("/private", methods=["GET"])
def generic_probe_trap():
    fp = _get_cell_id()
    content = json.dumps(fake_error_with_stack(fp, request.path), indent=2)
    return _process_trap_request(content, "application/json", status_code=500)


def _get_cell_id() -> str:
    cell_id, _ = _ensure_cell(request.path)
    return cell_id
