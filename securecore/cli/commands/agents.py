"""Agents command — Agent Manager CLI.

The single authority surface for viewing and managing all registered agents.
Reads from the live registry via control bus — no hardcoded permission tables.

Usage:
    securecore agents                    list all registered callers
    securecore agents inspect <id>       show full caller detail
    securecore agents permissions <id>   show permission map
    securecore agents denials            show recent permission denials
"""

from __future__ import annotations

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


def _get_registry() -> dict:
    """Pull live registry from organism via control bus."""
    result = request_live_command("registry_snapshot")
    if not result:
        return {}
    return result.get("registry", {})


def _list_agents() -> None:
    registry = _get_registry()
    status_result = request_live_command("status_snapshot") or {}
    snapshot = status_result.get("snapshot", {})
    live_agents = snapshot.get("agents", {})

    print()
    print(_colorize("  REGISTERED CALLERS", "bold"))
    print(_colorize("  " + "=" * 70, "dim"))
    print()

    if not registry:
        print(f"  {_colorize('Live organism unavailable. Start SecureCore to see registered callers.', 'yellow')}")
        print()
        return

    callers = registry.get("callers", {})
    if not callers:
        print(f"  {_colorize('No callers registered.', 'yellow')}")
        print()
        return

    print(f"  {'CALLER_ID':25s}  {'TYPE':8s}  {'WRITES':>7s}  {'DENIED':>7s}  {'STATE':6s}")
    print(f"  {'-'*25}  {'-'*8}  {'-'*7}  {'-'*7}  {'-'*6}")

    for caller_id, entry in sorted(callers.items()):
        ctype = entry.get("caller_type", "?")
        writes = entry.get("total_writes", 0)
        denied = entry.get("denied_count", 0)
        denied_str = _colorize(str(denied), "red") if denied > 0 else str(denied)

        # Check live state for agents
        agent_name = caller_id.replace("agent:", "") if caller_id.startswith("agent:") else ""
        if agent_name and agent_name in live_agents:
            state = _colorize("UP", "green") if live_agents[agent_name].get("running") else _colorize("DOWN", "red")
        else:
            state = _colorize("REG", "dim")

        print(f"  {caller_id:25s}  {ctype:8s}  {writes:>7d}  {denied_str:>16s}  {state}")

    print(f"\n  Total registered: {registry.get('total_registered', 0)}")
    print()


def _inspect(target: str) -> None:
    registry = _get_registry()

    print()
    print(_colorize(f"  CALLER: {target}", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    if not registry:
        print(f"  {_colorize('Live organism unavailable.', 'yellow')}\n")
        return

    callers = registry.get("callers", {})
    entry = callers.get(target)

    # Try with agent: prefix if not found
    if not entry and not target.startswith("agent:"):
        entry = callers.get(f"agent:{target}")
        if entry:
            target = f"agent:{target}"

    if not entry:
        print(f"  {_colorize(f'Caller not found: {target}', 'yellow')}")
        print(f"  Available: {', '.join(sorted(callers.keys()))}\n")
        return

    print(f"    caller_id:      {target}")
    print(f"    caller_type:    {entry.get('caller_type', '?')}")
    print(f"    module_path:    {entry.get('module_path', '?')}")
    print(f"    registered_at:  {entry.get('registered_at', '?')}")
    print(f"    total_writes:   {entry.get('total_writes', 0)}")
    denied = entry.get("denied_count", 0)
    if denied:
        print(f"    denied_count:   {_colorize(str(denied), 'red')}")
        print(f"    last_denied:    {entry.get('last_denied_at', '?')} -> {entry.get('last_denied_target', '?')}")
    else:
        print(f"    denied_count:   0")
    print()

    print(_colorize("    PERMISSIONS", "cyan"))
    allowed_w = entry.get("allowed_write", [])
    allowed_r = entry.get("allowed_read", [])
    print(f"      writes:  {', '.join(allowed_w) if allowed_w else '(none)'}")
    print(f"      reads:   {', '.join(allowed_r) if allowed_r else '(none)'}")
    print(f"      deny_all_else: true")
    print()

    print(_colorize("    HELP", "cyan"))
    print(f"      securecore help show agents")
    agent_name = target.replace("agent:", "").replace("control:", "").replace("routes:", "")
    print(f"      securecore help where {agent_name}")
    print()


def _permissions(target: str) -> None:
    registry = _get_registry()

    if not registry:
        print(f"\n  {_colorize('Live organism unavailable.', 'yellow')}\n")
        return

    callers = registry.get("callers", {})
    entry = callers.get(target) or callers.get(f"agent:{target}")

    if not entry:
        print(f"\n  {_colorize(f'Caller not found: {target}', 'yellow')}\n")
        return

    all_substrates = {"ingress", "mirror", "evidence", "telemetry", "agent_decisions", "operator", "hid"}
    allowed_w = set(entry.get("allowed_write", []))
    allowed_r = set(entry.get("allowed_read", []))
    denied_w = all_substrates - allowed_w

    print()
    print(_colorize(f"  PERMISSIONS: {target}", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    print(_colorize("    ALLOWED", "green"))
    print(f"      writes:  {', '.join(sorted(allowed_w)) if allowed_w else '(none)'}")
    print(f"      reads:   {', '.join(sorted(allowed_r)) if allowed_r else '(none)'}")
    print()

    print(_colorize("    DENIED (write)", "red"))
    for sub in sorted(denied_w):
        print(f"      {sub}")
    print()

    print(_colorize("    ENFORCEMENT", "cyan"))
    print(f"      gate:       permissions/gate.py (append chokepoint)")
    print(f"      signature:  HMAC-SHA256 with timestamp + nonce")
    print(f"      payload:    bound for direct writes, identity-only for delegated")
    print(f"      on_deny:    logged, counted, PermissionDenied raised")
    print()


def _denials() -> None:
    result = request_live_command("gate_denials")

    print()
    print(_colorize("  RECENT PERMISSION DENIALS", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    if not result:
        print(f"  {_colorize('Live organism unavailable.', 'yellow')}\n")
        return

    denials = result.get("denials", [])
    if not denials:
        print(f"  {_colorize('No denials recorded.', 'green')}\n")
        return

    for d in denials[-20:]:
        print(f"  {d.get('timestamp', '?')[:19]}  "
              f"{_colorize(d.get('caller_id', '?'), 'red'):30s}  "
              f"-> {d.get('substrate', '?'):20s}  "
              f"{d.get('reason', '?')}")
    print()
