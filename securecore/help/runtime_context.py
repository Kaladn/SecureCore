"""Runtime context builder for help bot grounding.

Pulls live organism state from the control bus (if available)
and formats it as context for the help LLM.
"""

from __future__ import annotations

import json
from securecore.cli.common import (
    SUBSTRATE_NAMES,
    count_substrate_records,
    verify_substrate_chain,
    forge_store_stats,
    request_live_command,
)


def build_runtime_context() -> str:
    """Build a compact runtime context string for the help bot."""
    sections = []

    # Live organism state (if available)
    live = request_live_command("status_snapshot") or {}
    snapshot = live.get("snapshot", {})

    if snapshot:
        sections.append("LIVE ORGANISM: running")
        agents = snapshot.get("agents", {})
        if agents:
            agent_lines = []
            for name, stats in agents.items():
                state = "UP" if stats.get("running") else "DOWN"
                agent_lines.append(f"  {name}: {state} consumed={stats.get('consumed',0)} emitted={stats.get('emitted',0)}")
            sections.append("AGENTS:\n" + "\n".join(agent_lines))

        reaper = snapshot.get("reaper", {})
        if reaper:
            state = "PAUSED" if reaper.get("paused") else "ALIVE"
            sections.append(
                f"REAPER: {state} actions={reaper.get('actions_taken',0)} "
                f"skipped={reaper.get('actions_skipped',0)} "
                f"shunned={len(reaper.get('ips_shunned',[]))} "
                f"locked={len(reaper.get('cells_locked',[]))}"
            )
    else:
        sections.append("LIVE ORGANISM: offline or unreachable")

    # Substrate health (from disk)
    sub_lines = []
    for name in SUBSTRATE_NAMES:
        count = count_substrate_records(name)
        chain = verify_substrate_chain(name)
        intact = "INTACT" if chain.get("intact") else "BROKEN"
        sub_lines.append(f"  {name}: records={count} chain={intact}")
    sections.append("SUBSTRATES:\n" + "\n".join(sub_lines))

    # Forge status (from disk)
    forge_lines = []
    for name in SUBSTRATE_NAMES:
        stats = forge_store_stats(name)
        if stats.get("exists"):
            forge_lines.append(f"  {name}: records={stats.get('count',0)}")
    if forge_lines:
        sections.append("FORGE:\n" + "\n".join(forge_lines))
    else:
        sections.append("FORGE: not active")

    return "\n\n".join(sections)
