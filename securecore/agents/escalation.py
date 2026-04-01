"""Escalation Agent - decides when to escalate threat levels.

The escalation agent watches agent_decisions and mirror substrates
to make escalation recommendations. It aggregates signals from
multiple agents (watcher, profiler) and applies escalation policy.

Escalation policy:
  Level 0 -> 1: Any bait path hit (confirmed by watcher)
  Level 1 -> 2: Multiple tools or 3+ unique paths (confirmed by profiler)
  Level 2 -> 3: Injection attempt or sustained probing (LOCKS the cell)
  Level 3 -> 4: Continued engagement after lock
  Level 4 -> 5: Extensive interaction - evidence package complete

The escalation agent is the ONLY agent that recommends escalation.
Other agents provide signals. This agent synthesizes them.
"""

import time
from typing import Optional

from securecore.agents.base import Agent, AgentDecision
from securecore.substrates.base import Substrate, SubstrateRecord


class CellEscalationState:
    """Tracks escalation signals for a single cell."""

    def __init__(self, cell_id: str):
        self.cell_id = cell_id
        self.current_level = 0
        self.scanner_detected = False
        self.injection_detected = False
        self.sustained_probing = False
        self.rapid_fire = False
        self.bot_detected = False
        self.sophistication_score = 0.0
        self.watcher_signals = 0
        self.profiler_signals = 0
        self.interaction_count = 0
        self.bait_hits = 0
        self.unique_paths = 0
        self.last_escalation_time = 0.0

    @property
    def recommended_level(self) -> int:
        """Calculate what level this cell SHOULD be at based on accumulated signals."""
        level = 0

        # Level 1: any confirmed bait hit or scanner detection
        if self.bait_hits >= 1 or self.scanner_detected:
            level = max(level, 1)

        # Level 2: multiple tools, paths, or bot detection
        if self.unique_paths >= 3 or self.bot_detected or self.profiler_signals >= 2:
            level = max(level, 2)

        # Level 3: injection or sustained probing (THIS LOCKS THE CELL)
        if self.injection_detected or self.sustained_probing or self.rapid_fire:
            level = max(level, 3)

        # Level 4: continued engagement after significant interaction
        if level >= 3 and self.interaction_count >= 15:
            level = max(level, 4)

        # Level 5: extensive - they're fully committed
        if level >= 4 and self.interaction_count >= 30:
            level = max(level, 5)

        return level


class EscalationAgent(Agent):
    """Synthesizes signals and recommends escalation levels."""

    name = "escalation"

    def __init__(self, decision_substrate: Substrate):
        super().__init__(decision_substrate)
        self._cells: dict[str, CellEscalationState] = {}

    def _get_state(self, cell_id: str) -> CellEscalationState:
        if cell_id not in self._cells:
            self._cells[cell_id] = CellEscalationState(cell_id)
        return self._cells[cell_id]

    def consume(self, record: SubstrateRecord) -> None:
        if not record.cell_id:
            return

        state = self._get_state(record.cell_id)

        # Process watcher agent decisions
        if record.substrate == "agent_decisions":
            p = record.payload
            agent = p.get("agent_name", "")
            decision_type = p.get("decision_type", "")

            if agent == "watcher":
                state.watcher_signals += 1
                if decision_type == "scanner_detected":
                    state.scanner_detected = True
                elif decision_type == "injection_detected":
                    state.injection_detected = True
                elif decision_type == "sustained_probing":
                    state.sustained_probing = True
                    ctx = p.get("context", {})
                    state.bait_hits = ctx.get("bait_hits", state.bait_hits)
                elif decision_type == "rapid_fire":
                    state.rapid_fire = True

            elif agent == "profiler":
                state.profiler_signals += 1
                if decision_type == "bot_detected":
                    state.bot_detected = True
                elif decision_type == "profile_snapshot":
                    ctx = p.get("context", {})
                    state.sophistication_score = ctx.get("sophistication_score", 0.0)
                    state.unique_paths = ctx.get("unique_paths", 0)

        # Process mirror substrate events
        elif record.substrate == "mirror":
            if record.record_type == "interaction":
                state.interaction_count = record.payload.get(
                    "interaction_count", state.interaction_count + 1
                )

        # Evaluate escalation
        recommended = state.recommended_level
        if recommended > state.current_level:
            old_level = state.current_level
            state.current_level = recommended
            state.last_escalation_time = time.time()

            severity_map = {1: "low", 2: "medium", 3: "high", 4: "high", 5: "critical"}
            action_map = {
                1: "track",
                2: "engage_deeper_decoys",
                3: "lock_cell_and_shun",
                4: "full_forensic_capture",
                5: "evidence_package_complete",
            }

            self.emit(AgentDecision(
                agent_name=self.name,
                decision_type="escalation_recommendation",
                confidence=min(1.0, 0.5 + (state.watcher_signals + state.profiler_signals) * 0.1),
                cell_id=record.cell_id,
                reasoning=(
                    f"Level {old_level}->{recommended}: "
                    f"scanner={state.scanner_detected} "
                    f"injection={state.injection_detected} "
                    f"sustained={state.sustained_probing} "
                    f"rapid={state.rapid_fire} "
                    f"bot={state.bot_detected} "
                    f"sophistication={state.sophistication_score:.2f} "
                    f"interactions={state.interaction_count}"
                ),
                recommended_action=action_map.get(recommended, "track"),
                context={
                    "old_level": old_level,
                    "new_level": recommended,
                    "signals": {
                        "scanner": state.scanner_detected,
                        "injection": state.injection_detected,
                        "sustained_probing": state.sustained_probing,
                        "rapid_fire": state.rapid_fire,
                        "bot": state.bot_detected,
                        "sophistication": state.sophistication_score,
                    },
                },
            ))

    def get_cell_state(self, cell_id: str) -> Optional[dict]:
        state = self._cells.get(cell_id)
        if not state:
            return None
        return {
            "cell_id": state.cell_id,
            "current_level": state.current_level,
            "recommended_level": state.recommended_level,
            "interaction_count": state.interaction_count,
            "signals": {
                "scanner": state.scanner_detected,
                "injection": state.injection_detected,
                "sustained_probing": state.sustained_probing,
                "rapid_fire": state.rapid_fire,
                "bot": state.bot_detected,
            },
        }
