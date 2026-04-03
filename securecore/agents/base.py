"""Base agent class.

An agent is an interpreter that sits on top of substrate truth.
Agents consume substrate records, maintain ephemeral internal state,
and emit decisions. Decisions are recorded in the agent_decisions
substrate - they become part of the audit trail but are NOT primary truth.

Hard rules:
  1. Agents NEVER mutate substrate records
  2. Agents NEVER write directly to evidence or ingress substrates
  3. Agent decisions are recorded separately and tagged with the agent's name
  4. Agents can READ any substrate but only WRITE to agent_decisions
  5. Agents can RECOMMEND actions (shun, escalate, contain) but the
     control plane decides whether to execute
  6. Agents must be deterministic given the same input sequence
  7. Agents must tolerate substrate replay (idempotent processing)

Lifecycle:
  - Agent is initialized with references to substrates it watches
  - Agent subscribes to substrate record streams
  - On each new record, agent.consume() is called
  - Agent accumulates state and periodically calls agent.decide()
  - Decisions are emitted via agent.emit() which writes to agent_decisions substrate
  - Agent can be ticked periodically via agent.tick() for time-based logic
"""

import logging
import threading
import time
from typing import Optional

from securecore.substrates.base import Substrate, SubstrateRecord


class AgentDecision:
    """A decision emitted by an agent."""

    __slots__ = (
        "agent_name", "decision_type", "confidence", "cell_id",
        "reasoning", "recommended_action", "context",
    )

    def __init__(
        self,
        agent_name: str,
        decision_type: str,
        confidence: float,
        cell_id: str = "",
        reasoning: str = "",
        recommended_action: str = "",
        context: Optional[dict] = None,
    ):
        self.agent_name = agent_name
        self.decision_type = decision_type
        self.confidence = min(1.0, max(0.0, confidence))
        self.cell_id = cell_id
        self.reasoning = reasoning
        self.recommended_action = recommended_action
        self.context = context or {}

    def to_dict(self) -> dict:
        return {
            "agent_name": self.agent_name,
            "decision_type": self.decision_type,
            "confidence": self.confidence,
            "cell_id": self.cell_id,
            "reasoning": self.reasoning,
            "recommended_action": self.recommended_action,
            "context": self.context,
        }


class Agent:
    """Base class for all SecureCore agents.

    Subclasses must implement:
      - name: agent identifier
      - consume(record): process a substrate record
      - tick(): periodic processing (called on interval)

    Subclasses may override:
      - on_start(): called when agent begins watching
      - on_stop(): called when agent stops
    """

    name: str = "base"

    def __init__(self, decision_substrate: Substrate):
        self._decision_substrate = decision_substrate
        self._running = False
        self._consumed_count = 0
        self._emitted_count = 0
        # Some agents watch `agent_decisions` and may emit follow-up decisions while
        # processing a prior decision. A re-entrant lock keeps that local recursion
        # from deadlocking the request path.
        self._lock = threading.RLock()
        self._logger = logging.getLogger(f"agent.{self.name}")

    def consume(self, record: SubstrateRecord) -> None:
        """Process a substrate record. Override in subclasses.

        This is called for every new record from watched substrates.
        Agents should update their internal state here and optionally
        call self.emit() to record a decision.
        """
        raise NotImplementedError

    def tick(self) -> None:
        """Periodic processing. Override in subclasses.

        Called on a regular interval for time-based logic like
        detecting inactivity, computing rollups, or re-evaluating
        confidence scores.
        """
        pass

    def on_start(self) -> None:
        """Called when the agent begins watching. Override for setup."""
        pass

    def on_stop(self) -> None:
        """Called when the agent stops. Override for cleanup."""
        pass

    def emit(self, decision: AgentDecision) -> SubstrateRecord:
        """Record a decision in the agent_decisions substrate.

        This is how agents communicate their interpretations.
        The decision becomes part of the audit trail.
        """
        record = self._decision_substrate.append(
            record_type=f"agent_decision:{decision.decision_type}",
            payload=decision.to_dict(),
            cell_id=decision.cell_id,
        )
        self._emitted_count += 1
        self._logger.info(
            "DECISION type=%s confidence=%.2f cell=%s action=%s",
            decision.decision_type, decision.confidence,
            decision.cell_id or "global", decision.recommended_action,
        )
        return record

    def watch(self, substrate: Substrate) -> None:
        """Subscribe to a substrate's record stream."""
        substrate.subscribe(self._on_record)

    def unwatch(self, substrate: Substrate) -> None:
        """Unsubscribe from a substrate."""
        substrate.unsubscribe(self._on_record)

    def _on_record(self, record: SubstrateRecord) -> None:
        """Internal callback from substrate subscription."""
        with self._lock:
            try:
                self.consume(record)
                self._consumed_count += 1
            except Exception as exc:
                self._logger.error("consume failed: %s", exc)

    def start(self) -> None:
        """Start the agent."""
        self._running = True
        self.on_start()
        self._logger.info("STARTED agent=%s", self.name)

    def stop(self) -> None:
        """Stop the agent."""
        self._running = False
        self.on_stop()
        self._logger.info("STOPPED agent=%s consumed=%d emitted=%d",
                         self.name, self._consumed_count, self._emitted_count)

    @property
    def stats(self) -> dict:
        return {
            "agent": self.name,
            "running": self._running,
            "consumed": self._consumed_count,
            "emitted": self._emitted_count,
        }
