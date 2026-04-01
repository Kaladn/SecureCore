"""Profiler Agent - builds attacker behavioral profiles.

The profiler watches both ingress and mirror substrates to build
a comprehensive picture of each attacker:

  - Tool diversity: how many different tools are they using?
  - Path strategy: are they enumerating systematically or randomly?
  - Timing pattern: bot or human?
  - Sophistication: are they adapting their approach?
  - Session behavior: do they persist or hit-and-run?

The profiler emits profile snapshots that other agents use for
decision-making. It never takes action directly.
"""

import time
from typing import Optional

from securecore.agents.base import Agent, AgentDecision
from securecore.substrates.base import Substrate, SubstrateRecord


class AttackerProfile:
    """In-memory profile for a single attacker (keyed by cell_id)."""

    def __init__(self, cell_id: str):
        self.cell_id = cell_id
        self.tools: set[str] = set()
        self.paths: list[str] = []
        self.methods: set[str] = set()
        self.timestamps: list[float] = []
        self.evidence_types: dict[str, int] = {}
        self.injection_count: int = 0
        self.escalation_level: int = 0
        self.source_ip: str = ""
        self.user_agents: set[str] = set()
        self.last_update: float = time.time()

    def update_from_ingress(self, payload: dict) -> None:
        self.source_ip = payload.get("source_ip", self.source_ip)
        self.paths.append(payload.get("path", ""))
        self.methods.add(payload.get("method", ""))
        self.timestamps.append(time.time())
        ua = payload.get("user_agent", "")
        if ua:
            self.user_agents.add(ua)
        self.last_update = time.time()

    def update_from_mirror(self, payload: dict, record_type: str) -> None:
        if record_type == "escalation":
            self.escalation_level = payload.get("new_level", self.escalation_level)
            tools = payload.get("tools_seen", [])
            self.tools.update(tools)
            self.injection_count = payload.get("injection_attempts", self.injection_count)
        elif record_type == "interaction":
            tool = payload.get("tool_signature", "")
            if tool and tool != "unknown":
                self.tools.add(tool)
        self.last_update = time.time()

    @property
    def sophistication_score(self) -> float:
        """Estimate attacker sophistication (0.0 - 1.0)."""
        score = 0.0

        # Multiple tools = more sophisticated
        if len(self.tools) > 1:
            score += 0.2
        if len(self.tools) > 3:
            score += 0.2

        # Multiple user agents = tool switching
        if len(self.user_agents) > 1:
            score += 0.15

        # Systematic path coverage vs random
        unique_paths = len(set(self.paths))
        if unique_paths > 10:
            score += 0.15

        # Injection attempts = active exploitation
        if self.injection_count > 0:
            score += 0.15
        if self.injection_count > 3:
            score += 0.15

        return min(1.0, score)

    @property
    def timing_regularity(self) -> float:
        """How regular is the request timing? 0.0=irregular, 1.0=machine-perfect."""
        if len(self.timestamps) < 3:
            return 0.0

        intervals = [
            self.timestamps[i+1] - self.timestamps[i]
            for i in range(len(self.timestamps) - 1)
        ]
        avg = sum(intervals) / len(intervals)
        if avg == 0:
            return 1.0

        variance = sum((i - avg) ** 2 for i in intervals) / len(intervals)
        std = variance ** 0.5
        cv = std / avg if avg > 0 else 0

        return max(0.0, 1.0 - cv)

    def to_dict(self) -> dict:
        return {
            "cell_id": self.cell_id,
            "source_ip": self.source_ip,
            "tools": sorted(self.tools),
            "tool_count": len(self.tools),
            "unique_paths": len(set(self.paths)),
            "total_requests": len(self.paths),
            "methods": sorted(self.methods),
            "user_agents": sorted(self.user_agents),
            "injection_count": self.injection_count,
            "escalation_level": self.escalation_level,
            "sophistication_score": round(self.sophistication_score, 2),
            "timing_regularity": round(self.timing_regularity, 2),
            "is_likely_bot": self.timing_regularity > 0.85,
        }


class ProfilerAgent(Agent):
    """Builds and maintains attacker behavioral profiles."""

    name = "profiler"

    def __init__(self, decision_substrate: Substrate):
        super().__init__(decision_substrate)
        self._profiles: dict[str, AttackerProfile] = {}
        self._snapshot_interval = 10  # emit profile snapshot every N updates
        self._update_counts: dict[str, int] = {}

    def consume(self, record: SubstrateRecord) -> None:
        if not record.cell_id:
            return

        profile = self._profiles.get(record.cell_id)
        if not profile:
            profile = AttackerProfile(record.cell_id)
            self._profiles[record.cell_id] = profile

        if record.substrate == "ingress" and record.record_type == "http_request":
            profile.update_from_ingress(record.payload)

        elif record.substrate == "mirror":
            profile.update_from_mirror(record.payload, record.record_type)

        # Track updates and emit periodic snapshots
        self._update_counts[record.cell_id] = self._update_counts.get(record.cell_id, 0) + 1

        if self._update_counts[record.cell_id] % self._snapshot_interval == 0:
            self._emit_profile_snapshot(profile)

    def _emit_profile_snapshot(self, profile: AttackerProfile) -> None:
        """Emit a profile snapshot as a decision."""
        self.emit(AgentDecision(
            agent_name=self.name,
            decision_type="profile_snapshot",
            confidence=profile.sophistication_score,
            cell_id=profile.cell_id,
            reasoning=(
                f"Sophistication={profile.sophistication_score:.2f} "
                f"tools={len(profile.tools)} "
                f"paths={len(set(profile.paths))} "
                f"timing_regularity={profile.timing_regularity:.2f} "
                f"injections={profile.injection_count}"
            ),
            recommended_action="update_profile",
            context=profile.to_dict(),
        ))

        # Bot detection
        if profile.timing_regularity > 0.85 and len(profile.timestamps) >= 5:
            self.emit(AgentDecision(
                agent_name=self.name,
                decision_type="bot_detected",
                confidence=profile.timing_regularity,
                cell_id=profile.cell_id,
                reasoning=f"Timing regularity {profile.timing_regularity:.2f} indicates automated tool",
                recommended_action="flag_automated",
                context={"timing_regularity": profile.timing_regularity},
            ))

    def get_profile(self, cell_id: str) -> Optional[dict]:
        """Get current profile for a cell."""
        profile = self._profiles.get(cell_id)
        return profile.to_dict() if profile else None

    def get_all_profiles(self) -> list[dict]:
        """Get all active profiles."""
        return [p.to_dict() for p in self._profiles.values()]

    def tick(self) -> None:
        """Periodic: emit snapshots for profiles with high sophistication."""
        for profile in self._profiles.values():
            if profile.sophistication_score >= 0.6:
                self._emit_profile_snapshot(profile)
