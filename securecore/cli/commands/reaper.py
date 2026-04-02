"""Reaper command — status, control, and shun management."""

from __future__ import annotations

import sys

from securecore.cli.common import request_live_command


def _colorize(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    codes = {
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "reset": "\033[0m",
    }
    return f"{codes.get(color, '')}{text}{codes.get('reset', '')}"


def run(pause: bool, resume: bool, shun_ip: str, unshun_ip: str) -> None:
    if pause:
        result = request_live_command("reaper_pause")
        if not result:
            _unavailable()
            return
        print(f"\n  {_colorize('REAPER PAUSED', 'yellow')}\n")
        return

    if resume:
        result = request_live_command("reaper_resume")
        if not result:
            _unavailable()
            return
        print(f"\n  {_colorize('REAPER RESUMED', 'green')}\n")
        return

    if shun_ip:
        result = request_live_command("reaper_shun", {"ip": shun_ip, "reason": "manual CLI shun"})
        if not result:
            _unavailable()
            return
        if result.get("ok"):
            print(f"\n  {_colorize(f'SHUNNED: {shun_ip}', 'red')}")
            print(f"  firewall_rule: {result.get('firewall_rule_created', False)}\n")
        else:
            err = result.get("error", "unknown")
            print(f"\n  {_colorize(f'FAILED: {err}', 'yellow')}\n")
        return

    if unshun_ip:
        result = request_live_command("reaper_unshun", {"ip": unshun_ip, "reason": "manual CLI unshun"})
        if not result:
            _unavailable()
            return
        if result.get("ok"):
            print(f"\n  {_colorize(f'UNSHUNNED: {unshun_ip}', 'green')}\n")
        else:
            err = result.get("error", "unknown")
            print(f"\n  {_colorize(f'FAILED: {err}', 'yellow')}\n")
        return

    result = request_live_command("status_snapshot")
    if not result:
        _unavailable()
        return
    _show_status(result.get("snapshot", {}).get("reaper", {}))


def _unavailable() -> None:
    print(f"\n  {_colorize('live organism unavailable', 'yellow')}")
    print("  start SecureCore first, then retry the control command.\n")


def _show_status(stats: dict) -> None:
    print()
    print(_colorize("  REAPER STATUS", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    if not stats:
        state = _colorize("OFFLINE", "red")
    elif stats.get("paused"):
        state = _colorize("PAUSED", "yellow")
    else:
        state = _colorize("ALIVE", "green")

    print(f"    state:            {state}")
    print(f"    actions_taken:    {stats.get('actions_taken', 0)}")
    print(f"    actions_skipped:  {stats.get('actions_skipped', 0)}")
    print()

    ips = stats.get("ips_shunned", [])
    print(f"    {_colorize('SHUNNED IPs', 'cyan')} ({len(ips)})")
    if ips:
        for ip in ips:
            print(f"      {_colorize(ip, 'red')}")
    else:
        print(f"      {_colorize('(none)', 'dim')}")
    print()

    cells = stats.get("cells_locked", [])
    print(f"    {_colorize('LOCKED CELLS', 'cyan')} ({len(cells)})")
    if cells:
        for cell in cells:
            print(f"      {_colorize(cell, 'red')}")
    else:
        print(f"      {_colorize('(none)', 'dim')}")
    print()

    consensus = stats.get("last_consensus", {})
    if consensus:
        print(f"    {_colorize('LAST CONSENSUS', 'cyan')}")
        print(f"      score:      {consensus.get('score', 0):.3f}")
        print(f"      tier:       {consensus.get('tier', 'none')}")
        print(f"      actionable: {consensus.get('actionable', False)}")
        for contributor in consensus.get("contributors", []):
            print(f"      {contributor['name']:15s}  score={contributor['score']:.3f}  weight={contributor['weight']:.2f}")
        print()

    policy = stats.get("policy", {})
    print(f"    {_colorize('POLICY', 'cyan')}")
    print(f"      min_confidence:      {policy.get('min_confidence', '?')}")
    print(f"      shun_cooldown:       {policy.get('shun_cooldown_seconds', '?')}s")
    print(f"      auto_shun:           {policy.get('auto_shun_enabled', '?')}")
    print(f"      auto_lock:           {policy.get('auto_lock_enabled', '?')}")
    print(f"      auto_preserve:       {policy.get('auto_preserve_enabled', '?')}")
    print(f"      dry_run:             {policy.get('dry_run', '?')}")
    print()
