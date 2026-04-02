import json
import tempfile
import time
import unittest
from pathlib import Path

from securecore.control.command_bus import ControlBus


class _FakeSubstrate:
    def __init__(self, count: int = 0):
        self._count = count

    def count(self) -> int:
        return self._count

    def forge_status(self) -> dict:
        return {"enabled": False, "failures": 0}


class _FakeAgent:
    def __init__(self):
        self.stats = {"running": True, "consumed": 4, "emitted": 2}


class _FakeReaper:
    def __init__(self):
        self.paused = False
        self.stats = {
            "paused": False,
            "actions_taken": 1,
            "actions_skipped": 2,
            "ips_shunned": [],
            "cells_locked": [],
            "last_consensus": {},
            "policy": {"min_confidence": 0.7},
        }

    def pause(self) -> None:
        self.paused = True
        self.stats["paused"] = True

    def resume(self) -> None:
        self.paused = False
        self.stats["paused"] = False


class _FakeLogRouter:
    def stats(self) -> dict:
        return {"raw_ingress": 3}


class ControlBusTests(unittest.TestCase):
    def _submit_command(self, base_dir: Path, command: str, args: dict | None = None) -> dict:
        command_id = f"cmd-{time.time_ns()}"
        commands_dir = base_dir / "commands"
        responses_dir = base_dir / "responses"
        commands_dir.mkdir(parents=True, exist_ok=True)
        responses_dir.mkdir(parents=True, exist_ok=True)

        payload = {
            "command_id": command_id,
            "command": command,
            "args": args or {},
        }
        command_path = commands_dir / f"{command_id}.json"
        command_path.write_text(json.dumps(payload), encoding="utf-8")

        response_path = responses_dir / f"{command_id}.json"
        deadline = time.time() + 2.0
        while time.time() < deadline:
            if response_path.exists():
                return json.loads(response_path.read_text(encoding="utf-8"))
            time.sleep(0.05)
        self.fail(f"timed out waiting for response to {command}")

    def test_status_snapshot_returns_live_stats(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            bus = ControlBus(
                base_dir,
                substrates={"ingress": _FakeSubstrate(count=7)},
                agents={"watcher": _FakeAgent()},
                log_router=_FakeLogRouter(),
                reaper=_FakeReaper(),
            )
            bus.start()
            try:
                response = self._submit_command(base_dir, "status_snapshot")
            finally:
                bus.stop()

        self.assertTrue(response["ok"])
        snapshot = response["snapshot"]
        self.assertTrue(snapshot["live"])
        self.assertEqual(snapshot["substrates"]["ingress"]["count"], 7)
        self.assertEqual(snapshot["agents"]["watcher"]["consumed"], 4)
        self.assertEqual(snapshot["log_streams"]["raw_ingress"], 3)

    def test_pause_and_resume_commands_hit_live_reaper(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            reaper = _FakeReaper()
            bus = ControlBus(
                base_dir,
                substrates={"operator": _FakeSubstrate()},
                agents={},
                log_router=_FakeLogRouter(),
                reaper=reaper,
            )
            bus.start()
            try:
                pause_response = self._submit_command(base_dir, "reaper_pause")
                self.assertTrue(pause_response["ok"])
                self.assertTrue(reaper.paused)

                resume_response = self._submit_command(base_dir, "reaper_resume")
                self.assertTrue(resume_response["ok"])
                self.assertFalse(reaper.paused)
            finally:
                bus.stop()
