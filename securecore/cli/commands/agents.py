"""Agents command — Agent Manager CLI.

The single authority surface for viewing and managing all registered agents.

Usage:
    securecore agents                    list all registered agents
    securecore agents inspect <id>       show full agent detail
    securecore agents permissions <id>   show permission map
    securecore agents denials            show recent permission denials
"""

from __future__ import annotations

import json
import sys

from securecore.cli.common import request_live_command


def _colorize(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    codes = {
        "green": "\033[92m", "yellow": "\033[93m", "red": "\033[91m",
        "cyan": "\033[96m", "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m",
    }
    return f"{codes.get(color, '')}{text}{codes.get('reset', '')}"


def run(action: str, target: str) -> None:
    if action == "inspect" and target:
        _inspect(target)
    elif action == "permissions" and target:
        _permissions(target)
    elif action == "denials":
        _denials()
    else:
        _list_agents()


def _list_agents() -> None:
    result = request_live_command("status_snapshot")

    print()
    print(_colorize("  REGISTERED AGENTS", "bold"))
    print(_colorize("  " + "=" * 70, "dim"))
    print()

    if not result:
        print(f"  {_colorize('Live organism unavailable. Start SecureCore to see registered agents.', 'yellow')}")
        print()
        return

    snapshot = result.get("snapshot", {})
    agents = snapshot.get("agents", {})

    if not agents:
        print(f"  {_colorize('No agents found.', 'yellow')}")
        print()
        return

    print(f"  {'ID':25s}  {'STATE':6s}  {'CONSUMED':>9s}  {'EMITTED':>8s}")
    print(f"  {'-'*25}  {'-'*6}  {'-'*9}  {'-'*8}")

    for name, stats in sorted(agents.items()):
        state = _colorize("UP", "green") if stats.get("running") else _colorize("DOWN", "red")
        caller_id = f"agent:{name}"
        print(f"  {caller_id:25s}  {state:>15s}  {stats.get('consumed', 0):>9d}  {stats.get('emitted', 0):>8d}")

    # Also show non-agent registered callers
    print()
    print(_colorize("  OTHER REGISTERED CALLERS", "cyan"))
    other_callers = [
        ("control:reaper", "control", "operator"),
        ("control:shun", "control", "operator"),
        ("routes:traps", "routes", "ingress, mirror, evidence, telemetry"),
    ]
    for caller_id, ctype, writes in other_callers:
        print(f"  {caller_id:25s}  type={ctype:8s}  writes={writes}")
    print()


def _inspect(target: str) -> None:
    result = request_live_command("status_snapshot")

    print()
    print(_colorize(f"  AGENT: {target}", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    if not result:
        print(f"  {_colorize('Live organism unavailable.', 'yellow')}\n")
        return

    snapshot = result.get("snapshot", {})
    agents = snapshot.get("agents", {})

    # Try to find the agent
    agent_name = target.replace("agent:", "")
    stats = agents.get(agent_name)

    if not stats:
        print(f"  {_colorize(f'Agent not found: {target}', 'yellow')}")
        print(f"  Available: {', '.join(sorted(agents.keys()))}\n")
        return

    caller_id = f"agent:{agent_name}"
    state = _colorize("UP", "green") if stats.get("running") else _colorize("DOWN", "red")

    print(f"    caller_id:    {caller_id}")
    print(f"    state:        {state}")
    print(f"    consumed:     {stats.get('consumed', 0)}")
    print(f"    emitted:      {stats.get('emitted', 0)}")
    print()

    # Permission map (hardcoded from the registration in app.py)
    print(_colorize("    PERMISSIONS", "cyan"))
    print(f"      allowed_writes:   agent_decisions")
    print(f"      allowed_reads:    ingress, mirror, evidence, telemetry, hid, agent_decisions")
    print(f"      denied_all_else:  true")
    print()

    # Help pointer
    print(_colorize("    HELP", "cyan"))
    print(f"      securecore help show agents")
    print(f"      securecore help where {agent_name}")
    print()


def _permissions(target: str) -> None:
    agent_name = target.replace("agent:", "")
    caller_id = f"agent:{agent_name}"

    print()
    print(_colorize(f"  PERMISSIONS: {caller_id}", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    print(_colorize("    ALLOWED", "green"))
    print(f"      writes:     agent_decisions")
    print(f"      reads:      ingress, mirror, evidence, telemetry, hid, agent_decisions")
    print()

    print(_colorize("    DENIED", "red"))
    print(f"      ingress     (write)")
    print(f"      mirror      (write)")
    print(f"      evidence    (write)")
    print(f"      telemetry   (write)")
    print(f"      operator    (write)")
    print(f"      hid         (write)")
    print(f"      all controls")
    print()

    print(_colorize("    ENFORCEMENT", "cyan"))
    print(f"      gate:       permissions/gate.py (append chokepoint)")
    print(f"      signature:  HMAC-SHA256 with timestamp + nonce")
    print(f"      on_deny:    logged, counted, PermissionDenied raised")
    print()


def _denials() -> None:
    print()
    print(_colorize("  RECENT PERMISSION DENIALS", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()
    print(f"  {_colorize('Denial log requires live organism access.', 'yellow')}")
    print(f"  This will be wired to the permission gate denial log in a future update.")
    print()
