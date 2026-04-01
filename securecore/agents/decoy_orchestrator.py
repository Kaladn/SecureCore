"""Decoy Orchestrator Agent - manages which decoys to serve.

The orchestrator watches mirror and agent_decisions substrates to
decide which decoy content to serve each attacker. It adapts the
deception strategy based on the attacker's behavior:

  - Script kiddie hitting /wp-admin? Serve basic admin panel.
  - Sophisticated scanner enumerating APIs? Serve deeper decoys.
  - Attacker harvesting credentials? Serve fake key stores.
  - Attacker exfiltrating data? Serve fake databases and backups.

The orchestrator maintains a decoy assignment map per cell.
It never serves decoys directly - it recommends, and the trap
routes read the recommendation.
"""

import time
from typing import Optional

from securecore.agents.base import Agent, AgentDecision
from securecore.substrates.base import Substrate, SubstrateRecord


class DecoyStrategy:
    """Decoy strategy for a single cell."""

    def __init__(self, cell_id: str):
        self.cell_id = cell_id
        self.depth_level = 0  # 0=surface, 1=moderate, 2=deep
        self.focus_areas: set[str] = set()
        self.served_decoys: list[str] = []
        self.last_path: str = ""
        self.interaction_count = 0

    @property
    def next_decoy_hints(self) -> dict:
        """Suggest what kind of decoys to serve next."""
        hints = {
            "depth": self.depth_level,
            "focus": sorted(self.focus_areas),
            "strategy": "surface",
        }

        if self.depth_level == 0:
            hints["strategy"] = "surface"
            hints["serve"] = ["admin_panel", "server_status", "robots"]
        elif self.depth_level == 1:
            hints["strategy"] = "moderate"
            hints["serve"] = ["api_keys", "user_database", "config_dump"]
        else:
            hints["strategy"] = "deep"
            hints["serve"] = ["network_map", "backup_listing", "config_dump", "internal_apis"]

        # Adjust based on focus areas
        if "credentials" in self.focus_areas:
            hints["serve"].insert(0, "api_keys")
            hints["credential_richness"] = "high"
        if "data_exfil" in self.focus_areas:
            hints["serve"].insert(0, "user_database")
            hints["serve"].insert(0, "backup_listing")
        if "recon" in self.focus_areas:
            hints["serve"].insert(0, "network_map")
            hints["serve"].insert(0, "server_status")

        return hints


class DecoyOrchestratorAgent(Agent):
    """Manages decoy selection strategy per cell."""

    name = "decoy_orchestrator"

    def __init__(self, decision_substrate: Substrate):
        super().__init__(decision_substrate)
        self._strategies: dict[str, DecoyStrategy] = {}

    def _get_strategy(self, cell_id: str) -> DecoyStrategy:
        if cell_id not in self._strategies:
            self._strategies[cell_id] = DecoyStrategy(cell_id)
        return self._strategies[cell_id]

    def consume(self, record: SubstrateRecord) -> None:
        if not record.cell_id:
            return

        strategy = self._get_strategy(record.cell_id)

        if record.substrate == "mirror":
            if record.record_type == "interaction":
                strategy.interaction_count = record.payload.get(
                    "interaction_count", strategy.interaction_count + 1
                )
                path = record.payload.get("path", "")
                strategy.last_path = path

                # Classify focus area from path
                path_lower = path.lower()
                if any(p in path_lower for p in ["/api/keys", "/credentials", "/.env", "/tokens"]):
                    strategy.focus_areas.add("credentials")
                elif any(p in path_lower for p in ["/users", "/dump", "/backup", "/database", "/export"]):
                    strategy.focus_areas.add("data_exfil")
                elif any(p in path_lower for p in ["/network", "/internal", "/infrastructure", "/status"]):
                    strategy.focus_areas.add("recon")
                elif any(p in path_lower for p in ["/admin", "/console", "/manager", "/wp-admin"]):
                    strategy.focus_areas.add("admin_access")

            elif record.record_type == "decoy_served":
                strategy.served_decoys.append(record.payload.get("decoy_type", ""))

            elif record.record_type == "escalation":
                new_level = record.payload.get("new_level", 0)
                if new_level >= 2:
                    strategy.depth_level = 1
                if new_level >= 4:
                    strategy.depth_level = 2

        # Process escalation agent decisions
        elif record.substrate == "agent_decisions":
            p = record.payload
            if p.get("agent_name") == "escalation" and p.get("decision_type") == "escalation_recommendation":
                ctx = p.get("context", {})
                new_level = ctx.get("new_level", 0)
                if new_level >= 2:
                    strategy.depth_level = max(strategy.depth_level, 1)
                if new_level >= 4:
                    strategy.depth_level = max(strategy.depth_level, 2)

        # Emit strategy update every 5 interactions
        if strategy.interaction_count > 0 and strategy.interaction_count % 5 == 0:
            hints = strategy.next_decoy_hints
            self.emit(AgentDecision(
                agent_name=self.name,
                decision_type="decoy_strategy_update",
                confidence=0.8,
                cell_id=record.cell_id,
                reasoning=(
                    f"Depth={strategy.depth_level} "
                    f"focus={sorted(strategy.focus_areas)} "
                    f"interactions={strategy.interaction_count}"
                ),
                recommended_action=f"serve_{hints['strategy']}_decoys",
                context=hints,
            ))

    def get_strategy(self, cell_id: str) -> Optional[dict]:
        """Get current decoy strategy for a cell."""
        strategy = self._strategies.get(cell_id)
        if not strategy:
            return None
        return {
            "cell_id": strategy.cell_id,
            "depth_level": strategy.depth_level,
            "focus_areas": sorted(strategy.focus_areas),
            "interaction_count": strategy.interaction_count,
            "served_count": len(strategy.served_decoys),
            "hints": strategy.next_decoy_hints,
        }
