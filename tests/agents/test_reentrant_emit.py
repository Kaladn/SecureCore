import shutil
import threading
import unittest
import uuid
from pathlib import Path

from securecore.agents.escalation import EscalationAgent
from securecore.substrates.agent_decisions import AgentDecisionsSubstrate
from securecore.substrates.mirror import MirrorSubstrate


def _make_repo_temp_dir() -> str:
    root = Path(__file__).resolve().parents[2] / ".test_tmp"
    root.mkdir(exist_ok=True)
    temp_dir = root / f"agent_reentrant_{uuid.uuid4().hex}"
    temp_dir.mkdir()
    return str(temp_dir)


class AgentReentrantEmitTests(unittest.TestCase):
    def test_agent_decisions_subscriber_can_emit_without_deadlocking(self):
        temp_dir = _make_repo_temp_dir()
        try:
            decisions = AgentDecisionsSubstrate(temp_dir)
            mirror = MirrorSubstrate(temp_dir)

            escalation = EscalationAgent(decisions)
            escalation.watch(decisions)
            escalation.watch(mirror)
            escalation.start()

            # Prime the cell with mirror context so escalation can update state.
            mirror.record_cell_interaction(
                cell_id="cell-1",
                interaction_count=1,
                escalation_level=0,
                path="/admin",
                tool_signature="nmap",
            )

            error: list[Exception] = []

            def _append_watcher_decision() -> None:
                try:
                    decisions.record_decision(
                        agent_name="watcher",
                        decision_type="scanner_detected",
                        confidence=0.9,
                        cell_id="cell-1",
                        context={"source_ip": "127.0.0.1", "path": "/admin", "user_agent": "nmap"},
                    )
                except Exception as exc:  # pragma: no cover - failure path asserted below
                    error.append(exc)

            worker = threading.Thread(target=_append_watcher_decision, daemon=True)
            worker.start()
            worker.join(timeout=2.0)

            self.assertFalse(worker.is_alive(), "agent decision append deadlocked")
            self.assertEqual(error, [])

            decisions_for_cell = decisions.get_decisions_for_cell("cell-1", limit=10)
            decision_types = [record["payload"]["decision_type"] for record in decisions_for_cell]
            self.assertIn("scanner_detected", decision_types)
            self.assertIn("escalation_recommendation", decision_types)

            escalation.stop()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
