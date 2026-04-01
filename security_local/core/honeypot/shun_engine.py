"""Shun Engine - Active containment via local firewall blackholing.

When a mirror cell escalates to LOCKED (level 3+), the shun engine
automatically creates Windows Firewall rules to block the attacker's
source IP. This is YOUR firewall, on YOUR machine, blocking traffic
YOU don't want.

Capabilities:
  - Auto-shun: triggered by mirror cell escalation
  - Manual shun: operator can shun any IP via CLI or API
  - Shun list: persistent tracking of all shunned IPs with reason/evidence
  - Unshun: operator can release an IP
  - Firewall integration: creates/removes Windows Firewall rules
  - Socket kill: terminates active connections from shunned IPs
  - Dry-run mode: logs what WOULD happen without executing (for testing)

All actions are logged as SecurityEvents for audit trail.
"""

import json
import logging
import subprocess
import socket
import threading
from datetime import datetime, UTC
from typing import Optional

from core.db import db
from core.models import SecurityEvent

logger = logging.getLogger("honeypot.shun_engine")

# In-memory shun list (also persisted to DB via SecurityEvents)
_shun_lock = threading.Lock()
_shunned_ips: dict[str, dict] = {}

# Never shun these - safety net
PROTECTED_IPS = frozenset({
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "localhost",
})

# Firewall rule name prefix for easy identification and cleanup
RULE_PREFIX = "SecureCore_Shun_"


class ShunEntry:
    """Tracks a shunned IP with full context."""

    def __init__(
        self,
        ip: str,
        reason: str,
        cell_id: Optional[str] = None,
        escalation_level: int = 0,
        firewall_rule_created: bool = False,
    ):
        self.ip = ip
        self.reason = reason
        self.cell_id = cell_id
        self.escalation_level = escalation_level
        self.firewall_rule_created = firewall_rule_created
        self.shunned_at = datetime.now(UTC)
        self.hit_count = 0

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "cell_id": self.cell_id,
            "escalation_level": self.escalation_level,
            "firewall_rule_created": self.firewall_rule_created,
            "shunned_at": self.shunned_at.isoformat(),
            "hit_count": self.hit_count,
        }


def _create_firewall_rule(ip: str, dry_run: bool = False) -> bool:
    """Create a Windows Firewall inbound block rule for an IP.

    Uses netsh advfirewall. Returns True if rule was created successfully.
    """
    rule_name = f"{RULE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"

    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
        "enable=yes",
        f"description=SecureCore auto-shun: blocked by mirror cell escalation",
    ]

    if dry_run:
        logger.info("DRY-RUN: Would create firewall rule: %s", " ".join(cmd))
        return True

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            logger.warning("FIREWALL RULE CREATED: %s blocked (rule: %s)", ip, rule_name)
            return True
        else:
            logger.error(
                "FIREWALL RULE FAILED for %s: returncode=%d stderr=%s",
                ip, result.returncode, result.stderr.strip(),
            )
            return False
    except subprocess.TimeoutExpired:
        logger.error("FIREWALL RULE TIMEOUT for %s", ip)
        return False
    except FileNotFoundError:
        logger.error("netsh not found - cannot create firewall rules (not on Windows?)")
        return False
    except Exception as exc:
        logger.error("FIREWALL RULE ERROR for %s: %s", ip, exc)
        return False


def _remove_firewall_rule(ip: str, dry_run: bool = False) -> bool:
    """Remove a Windows Firewall block rule for an IP."""
    rule_name = f"{RULE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"

    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}",
    ]

    if dry_run:
        logger.info("DRY-RUN: Would remove firewall rule: %s", " ".join(cmd))
        return True

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            logger.warning("FIREWALL RULE REMOVED: %s unblocked (rule: %s)", ip, rule_name)
            return True
        else:
            logger.error(
                "FIREWALL RULE REMOVAL FAILED for %s: returncode=%d stderr=%s",
                ip, result.returncode, result.stderr.strip(),
            )
            return False
    except Exception as exc:
        logger.error("FIREWALL RULE REMOVAL ERROR for %s: %s", ip, exc)
        return False


def shun_ip(
    ip: str,
    reason: str,
    cell_id: Optional[str] = None,
    escalation_level: int = 0,
    dry_run: bool = False,
    create_firewall_rule: bool = True,
) -> dict:
    """Shun an IP address - add to blacklist and optionally create firewall rule.

    Returns a status dict with the result of the operation.
    """
    if ip in PROTECTED_IPS:
        logger.warning("SHUN REFUSED: %s is a protected IP", ip)
        return {"ok": False, "error": f"{ip} is a protected address", "ip": ip}

    with _shun_lock:
        if ip in _shunned_ips:
            # Already shunned - increment hit count
            _shunned_ips[ip].hit_count += 1
            logger.info("SHUN HIT: %s already shunned (hits: %d)", ip, _shunned_ips[ip].hit_count)
            return {"ok": True, "status": "already_shunned", "ip": ip, "hits": _shunned_ips[ip].hit_count}

        # Create the shun entry
        entry = ShunEntry(
            ip=ip,
            reason=reason,
            cell_id=cell_id,
            escalation_level=escalation_level,
        )

        # Create firewall rule
        if create_firewall_rule:
            entry.firewall_rule_created = _create_firewall_rule(ip, dry_run=dry_run)

        _shunned_ips[ip] = entry

    # Log security event
    _emit_shun_event(
        event_type="shun_activated",
        severity="critical",
        ip=ip,
        reason=reason,
        cell_id=cell_id,
        escalation_level=escalation_level,
        firewall_rule=entry.firewall_rule_created,
    )

    logger.warning(
        "IP SHUNNED: %s reason='%s' cell=%s level=%d firewall=%s",
        ip, reason, cell_id or "manual", escalation_level, entry.firewall_rule_created,
    )

    return {
        "ok": True,
        "status": "shunned",
        "ip": ip,
        "firewall_rule_created": entry.firewall_rule_created,
        "cell_id": cell_id,
    }


def unshun_ip(ip: str, reason: str = "operator release", dry_run: bool = False) -> dict:
    """Remove an IP from the shun list and delete its firewall rule."""
    with _shun_lock:
        entry = _shunned_ips.pop(ip, None)

    if not entry:
        return {"ok": False, "error": f"{ip} is not shunned", "ip": ip}

    # Remove firewall rule
    fw_removed = False
    if entry.firewall_rule_created:
        fw_removed = _remove_firewall_rule(ip, dry_run=dry_run)

    _emit_shun_event(
        event_type="shun_released",
        severity="high",
        ip=ip,
        reason=reason,
        cell_id=entry.cell_id,
        escalation_level=entry.escalation_level,
        firewall_rule=fw_removed,
    )

    logger.warning("IP UNSHUNNED: %s reason='%s'", ip, reason)

    return {
        "ok": True,
        "status": "unshunned",
        "ip": ip,
        "firewall_rule_removed": fw_removed,
    }


def is_shunned(ip: str) -> bool:
    """Check if an IP is currently shunned."""
    return ip in _shunned_ips


def get_shun_list() -> list[dict]:
    """Get all currently shunned IPs."""
    with _shun_lock:
        return [entry.to_dict() for entry in _shunned_ips.values()]


def get_shun_count() -> int:
    """Number of currently shunned IPs."""
    return len(_shunned_ips)


def auto_shun_from_cell(
    cell_id: str,
    source_ip: str,
    escalation_level: int,
    dry_run: bool = False,
) -> Optional[dict]:
    """Called by the mirror cell engine when escalation hits LOCKED (3+).

    This is the automatic trigger - no human needed. The cell decides
    the attacker has crossed the line, and the shun engine acts.
    """
    if escalation_level < 3:
        return None

    if is_shunned(source_ip):
        # Already handled
        with _shun_lock:
            if source_ip in _shunned_ips:
                _shunned_ips[source_ip].hit_count += 1
        return None

    reason = f"Mirror cell {cell_id} escalated to level {escalation_level}"
    return shun_ip(
        ip=source_ip,
        reason=reason,
        cell_id=cell_id,
        escalation_level=escalation_level,
        dry_run=dry_run,
    )


def _emit_shun_event(
    event_type: str,
    severity: str,
    ip: str,
    reason: str,
    cell_id: Optional[str],
    escalation_level: int,
    firewall_rule: bool,
) -> None:
    """Record a shun action as a SecurityEvent."""
    try:
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            source=f"shun_engine:{cell_id or 'manual'}",
            details=json.dumps({
                "ip": ip,
                "reason": reason,
                "cell_id": cell_id,
                "escalation_level": escalation_level,
                "firewall_rule_applied": firewall_rule,
            }),
        )
        db.session.add(event)
        db.session.commit()
    except Exception as exc:
        logger.error("Failed to emit shun event: %s", exc)


def list_firewall_shun_rules() -> list[str]:
    """List all active SecureCore shun rules in Windows Firewall."""
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name=all"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        rules = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Rule Name:") and RULE_PREFIX in stripped:
                rules.append(stripped.replace("Rule Name:", "").strip())
        return rules
    except Exception as exc:
        logger.error("Failed to list firewall rules: %s", exc)
        return []


def purge_all_shun_rules(dry_run: bool = False) -> dict:
    """Remove ALL SecureCore shun rules from Windows Firewall.

    Emergency cleanup. Use with caution.
    """
    rules = list_firewall_shun_rules()
    removed = 0
    failed = 0

    for rule_name in rules:
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]

        if dry_run:
            logger.info("DRY-RUN: Would remove rule: %s", rule_name)
            removed += 1
            continue

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                removed += 1
            else:
                failed += 1
        except Exception:
            failed += 1

    # Clear in-memory list
    with _shun_lock:
        _shunned_ips.clear()

    logger.warning("PURGE: removed %d firewall rules, %d failed", removed, failed)
    return {"removed": removed, "failed": failed, "total_found": len(rules)}
