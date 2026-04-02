"""Shun Engine - active containment via local firewall.

The control plane's enforcement arm. When the containment advisor
recommends a shun, this module executes it on YOUR firewall.

The shun engine:
  - Creates Windows Firewall inbound block rules
  - Maintains an in-memory + substrate-backed shun list
  - Records every action in the operator substrate
  - Supports manual shun/unshun by admin
  - Never shuns protected IPs (127.0.0.1, ::1)
  - Provides emergency purge capability
"""

import json
import logging
import subprocess
import threading
from datetime import datetime, UTC
from typing import Optional

logger = logging.getLogger("control.shun")

_shun_lock = threading.Lock()
_shunned_ips: dict[str, dict] = {}

PROTECTED_IPS = frozenset({"127.0.0.1", "::1", "0.0.0.0", "localhost"})
RULE_PREFIX = "SecureCore_Shun_"


def _create_firewall_rule(ip: str, dry_run: bool = False) -> bool:
    rule_name = f"{RULE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=block",
        f"remoteip={ip}", "enable=yes",
        "description=SecureCore auto-shun: blocked by mirror cell escalation",
    ]

    if dry_run:
        logger.info("DRY-RUN: Would create firewall rule: %s", " ".join(cmd))
        return True

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.warning("FIREWALL RULE CREATED: %s blocked (rule: %s)", ip, rule_name)
            return True
        logger.error("FIREWALL RULE FAILED for %s: %s", ip, result.stderr.strip())
        return False
    except FileNotFoundError:
        logger.error("netsh not found - not on Windows?")
        return False
    except Exception as exc:
        logger.error("FIREWALL RULE ERROR for %s: %s", ip, exc)
        return False


def _remove_firewall_rule(ip: str, dry_run: bool = False) -> bool:
    rule_name = f"{RULE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]

    if dry_run:
        logger.info("DRY-RUN: Would remove firewall rule: %s", " ".join(cmd))
        return True

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.warning("FIREWALL RULE REMOVED: %s unblocked", ip)
            return True
        logger.error("FIREWALL REMOVAL FAILED for %s: %s", ip, result.stderr.strip())
        return False
    except Exception as exc:
        logger.error("FIREWALL REMOVAL ERROR for %s: %s", ip, exc)
        return False


def shun_ip(
    ip: str,
    reason: str,
    cell_id: str = "",
    escalation_level: int = 0,
    operator_writer=None,
    dry_run: bool = False,
) -> dict:
    if ip in PROTECTED_IPS:
        return {"ok": False, "error": f"{ip} is protected"}

    with _shun_lock:
        if ip in _shunned_ips:
            _shunned_ips[ip]["hit_count"] += 1
            return {"ok": True, "status": "already_shunned", "ip": ip}

        fw_created = _create_firewall_rule(ip, dry_run=dry_run)

        _shunned_ips[ip] = {
            "ip": ip,
            "reason": reason,
            "cell_id": cell_id,
            "escalation_level": escalation_level,
            "firewall_rule_created": fw_created,
            "shunned_at": datetime.now(UTC).isoformat(),
            "hit_count": 0,
        }

    if operator_writer:
        operator_writer.record_shun(
            ip=ip, reason=reason, cell_id=cell_id, firewall_rule=fw_created,
        )

    logger.warning("IP SHUNNED: %s reason='%s' cell=%s fw=%s", ip, reason, cell_id or "manual", fw_created)
    return {"ok": True, "status": "shunned", "ip": ip, "firewall_rule_created": fw_created}


def unshun_ip(ip: str, reason: str = "operator release", operator_writer=None, dry_run: bool = False) -> dict:
    with _shun_lock:
        entry = _shunned_ips.pop(ip, None)

    if not entry:
        return {"ok": False, "error": f"{ip} is not shunned"}

    fw_removed = False
    if entry.get("firewall_rule_created"):
        fw_removed = _remove_firewall_rule(ip, dry_run=dry_run)

    if operator_writer:
        operator_writer.record_unshun(ip=ip, reason=reason, cell_id=entry.get("cell_id", ""))

    logger.warning("IP UNSHUNNED: %s reason='%s'", ip, reason)
    return {"ok": True, "status": "unshunned", "ip": ip, "firewall_rule_removed": fw_removed}


def is_shunned(ip: str) -> bool:
    return ip in _shunned_ips


def get_shun_list() -> list[dict]:
    with _shun_lock:
        return list(_shunned_ips.values())


def get_shun_count() -> int:
    return len(_shunned_ips)


def list_firewall_shun_rules() -> list[str]:
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True, timeout=15,
        )
        return [
            line.strip().replace("Rule Name:", "").strip()
            for line in result.stdout.splitlines()
            if line.strip().startswith("Rule Name:") and RULE_PREFIX in line
        ]
    except Exception:
        return []


def purge_all_shun_rules(dry_run: bool = False) -> dict:
    rules = list_firewall_shun_rules()
    removed = failed = 0
    for rule_name in rules:
        if dry_run:
            removed += 1
            continue
        try:
            r = subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                removed += 1
            else:
                failed += 1
        except Exception:
            failed += 1

    with _shun_lock:
        _shunned_ips.clear()

    return {"removed": removed, "failed": failed, "total_found": len(rules)}
