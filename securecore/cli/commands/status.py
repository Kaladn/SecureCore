"""Status command — organism health overview."""

from __future__ import annotations

import sys

from securecore.cli.common import (
    LOG_STREAM_NAMES,
    SUBSTRATE_NAMES,
    count_log_entries,
    count_substrate_records,
    forge_store_stats,
    request_live_command,
    verify_substrate_chain,
)


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


def run() -> None:
    live = request_live_command("status_snapshot") or {}
    snapshot = live.get("snapshot", {})
    live_agents = snapshot.get("agents", {})
    live_reaper = snapshot.get("reaper", {})
    live_substrates = snapshot.get("substrates", {})
    live_logs = snapshot.get("log_streams", {})

    print()
    print(_colorize("  SECURECORE ORGANISM STATUS", "bold"))
    print(_colorize("  " + "=" * 50, "dim"))
    print()

    print(_colorize("  SUBSTRATES", "cyan"))
    all_intact = True
    total_records = 0
    for name in SUBSTRATE_NAMES:
        count = count_substrate_records(name)
        total_records += count
        chain = verify_substrate_chain(name)
        intact = chain.get("intact", False)
        if not intact:
            all_intact = False
        status = _colorize("INTACT", "green") if intact else _colorize("BROKEN", "red")
        forge_live = live_substrates.get(name, {}).get("forge", {})
        forge_disk = forge_store_stats(name)
        forge_tag = ""
        if forge_live.get("enabled"):
            forge_tag = f"  forge={forge_live.get('writes', 0)}w/{forge_live.get('failures', 0)}f"
        elif forge_disk.get("exists"):
            forge_tag = f"  forge=disk:{forge_disk.get('count', 0)}"
        print(f"    {name:20s}  records={count:>6d}  chain={status}{forge_tag}")

    substrate_line = _colorize("ALL INTACT", "green") if all_intact else _colorize("VIOLATIONS DETECTED", "red")
    print(f"\n    chains: {substrate_line}")
    print()

    print(_colorize("  AGENTS", "cyan"))
    total_consumed = 0
    total_emitted = 0
    if live_agents:
        for name, stats in live_agents.items():
            running = _colorize("UP", "green") if stats["running"] else _colorize("DOWN", "red")
            total_consumed += stats["consumed"]
            total_emitted += stats["emitted"]
            print(f"    {name:20s}  {running}  consumed={stats['consumed']:>6d}  emitted={stats['emitted']:>4d}")
    else:
        print(f"    {_colorize('live organism unavailable', 'yellow')}")
    print()

    print(_colorize("  REAPER", "cyan"))
    if live_reaper:
        state = _colorize("PAUSED", "yellow") if live_reaper.get("paused") else _colorize("ALIVE", "green")
        print(f"    status:           {state}")
        print(f"    actions_taken:    {live_reaper['actions_taken']}")
        print(f"    actions_skipped:  {live_reaper['actions_skipped']}")
        print(f"    ips_shunned:      {len(live_reaper['ips_shunned'])}")
        print(f"    cells_locked:     {len(live_reaper['cells_locked'])}")
        if live_reaper.get("last_consensus"):
            last_consensus = live_reaper["last_consensus"]
            print(f"    last_consensus:   score={last_consensus.get('score', 0):.3f}  tier={last_consensus.get('tier', 'none')}")
    else:
        print(f"    status:           {_colorize('OFFLINE', 'red')}")
    print()

    print(_colorize("  LOG STREAMS", "cyan"))
    for name in LOG_STREAM_NAMES:
        count = live_logs.get(name, count_log_entries(name))
        print(f"    {name:20s}  writes={count:>6d}")
    print()

    print(_colorize("  SUMMARY", "bold"))
    print(f"    substrates:    {len(SUBSTRATE_NAMES)}/7")
    print(f"    agents:        {len(live_agents) if live_agents else 0}/7")
    print(f"    total_records: {total_records}")
    print(f"    total_consumed:{total_consumed}")
    print(f"    total_emitted: {total_emitted}")
    print()
