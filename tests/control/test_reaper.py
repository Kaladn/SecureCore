import json
import shutil
import unittest
from unittest.mock import patch
import uuid
from pathlib import Path

from securecore.control.reaper import Reaper, ReaperPolicy
from securecore.substrates.agent_decisions import AgentDecisionsSubstrate
from securecore.substrates.hid import HIDSubstrate
from securecore.substrates.operator import OperatorSubstrate


def _make_repo_temp_dir() -> str:
    root = Path(__file__).resolve().parents[2] / ".test_tmp"
    root.mkdir(exist_ok=True)
    temp_dir = root / f"reaper_{uuid.uuid4().hex}"
    temp_dir.mkdir()
    return str(temp_dir)


class ReaperConsensusTests(unittest.TestCase):
    def test_reaper_executes_shun_when_consensus_is_actionable(self):
        temp_dir = _make_repo_temp_dir()
        try:
            decisions = AgentDecisionsSubstrate(temp_dir)
            operator = OperatorSubstrate(temp_dir)
            hid = HIDSubstrate(temp_dir)
            hid.record_session_state(session_locked=False, idle_seconds=5, foreground_app="SecureCore")
            hid.record_keyboard_activity(key_event_count=5, typing_variance=0.2, active_window="SecureCore")

            reaper = Reaper(
                decisions_substrate=decisions,
                operator_substrate=operator,
                hid_substrate=hid,
                policy=ReaperPolicy(min_confidence=0.7, dry_run=True),
            )

            with patch("securecore.control.reaper.is_shunned", return_value=False), patch(
                "securecore.control.reaper.shun_ip",
                return_value={"ok": True, "status": "shunned", "ip": "10.1.2.3", "firewall_rule_created": True},
            ) as shun_mock:
                reaper.start()
                decisions.record_decision(
                    agent_name="cognitive",
                    decision_type="cognitive_assessment",
                    confidence=0.92,
                    cell_id="cell-1",
                    context={
                        "confidence": 0.92,
                        "threat_score": 0.88,
                        "human_likelihood": 0.1,
                        "consensus_strength": 0.91,
                    },
                )
                decisions.record_decision(
                    agent_name="containment",
                    decision_type="shun_ip",
                    confidence=0.9,
                    cell_id="cell-1",
                    context={"ip": "10.1.2.3", "escalation_level": 4},
                )

                self.assertEqual(shun_mock.call_count, 1)
                self.assertIn("10.1.2.3", reaper.stats["ips_shunned"])
                self.assertTrue(reaper.stats["last_consensus"]["actionable"])
                self.assertEqual(reaper.stats["last_consensus"]["tier"], "review")
                contributor_names = {
                    contributor["name"] for contributor in reaper.stats["last_consensus"]["contributors"]
                }
                self.assertEqual(contributor_names, {"containment", "cognitive", "hid"})

                actions = operator.get_operator_history(limit=10)
                action_types = [record["payload"]["action"] for record in actions]
                self.assertIn("reaper_shun_execute", action_types)

                execute_record = next(
                    record for record in actions if record["payload"]["action"] == "reaper_shun_execute"
                )
                details = json.loads(execute_record["payload"]["details"])
                self.assertEqual(details["consensus"]["tier"], "review")

                reaper.stop()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_reaper_skips_shun_when_cognitive_signal_drags_consensus_below_review(self):
        temp_dir = _make_repo_temp_dir()
        try:
            decisions = AgentDecisionsSubstrate(temp_dir)
            operator = OperatorSubstrate(temp_dir)
            hid = HIDSubstrate(temp_dir)

            reaper = Reaper(
                decisions_substrate=decisions,
                operator_substrate=operator,
                hid_substrate=hid,
                policy=ReaperPolicy(min_confidence=0.7, dry_run=True),
            )

            with patch("securecore.control.reaper.is_shunned", return_value=False), patch(
                "securecore.control.reaper.shun_ip",
                return_value={"ok": True, "status": "shunned", "ip": "10.9.8.7", "firewall_rule_created": True},
            ) as shun_mock:
                reaper.start()
                decisions.record_decision(
                    agent_name="cognitive",
                    decision_type="cognitive_assessment",
                    confidence=0.2,
                    cell_id="cell-2",
                    context={
                        "confidence": 0.2,
                        "threat_score": 0.15,
                        "human_likelihood": 0.95,
                        "consensus_strength": 0.3,
                    },
                )
                decisions.record_decision(
                    agent_name="containment",
                    decision_type="shun_ip",
                    confidence=0.8,
                    cell_id="cell-2",
                    context={"ip": "10.9.8.7", "escalation_level": 3},
                )

                self.assertEqual(shun_mock.call_count, 0)
                self.assertEqual(reaper.stats["actions_taken"], 0)
                self.assertEqual(reaper.stats["last_consensus"]["tier"], "cautious")
                self.assertFalse(reaper.stats["last_consensus"]["actionable"])

                actions = operator.get_operator_history(limit=10)
                action_types = [record["payload"]["action"] for record in actions]
                self.assertIn("reaper_shun_skip", action_types)

                reaper.stop()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
