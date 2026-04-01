"""Local command bus for SecureCore operator controls.

The command bus lets local CLI tools talk to the live organism without
booting a second copy of the app. Commands are exchanged through the
filesystem so the operator surface stays local-only and headless.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from securecore.control.shun import shun_ip, unshun_ip


class ControlBus:
    """File-backed local control channel for the live organism."""

    def __init__(self, base_dir: str | Path, substrates: dict, agents: dict, log_router, reaper,
                 operator_writer=None, registry=None, permission_gate=None):
        self._base_dir = Path(base_dir)
        self._commands_dir = self._base_dir / "commands"
        self._responses_dir = self._base_dir / "responses"
        self._heartbeat_path = self._base_dir / "heartbeat.json"
        self._substrates = substrates
        self._agents = agents
        self._log_router = log_router
        self._reaper = reaper
        self._operator_writer = operator_writer
        self._registry = registry
        self._permission_gate = permission_gate
        self._running = False
        self._thread: threading.Thread | None = None
        self._started_at = datetime.now(UTC).isoformat()

        self._commands_dir.mkdir(parents=True, exist_ok=True)
        self._responses_dir.mkdir(parents=True, exist_ok=True)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True, name="securecore-control-bus")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _serve(self) -> None:
        while self._running:
            self._write_heartbeat()
            for command_path in sorted(self._commands_dir.glob("*.json")):
                self._handle_file(command_path)
            time.sleep(0.25)

    def _write_heartbeat(self) -> None:
        self._heartbeat_path.write_text(
            json.dumps(
                {
                    "live": True,
                    "updated_at": datetime.now(UTC).isoformat(),
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def _handle_file(self, command_path: Path) -> None:
        try:
            payload = json.loads(command_path.read_text(encoding="utf-8"))
        except Exception as exc:
            response = {
                "ok": False,
                "error": f"invalid command payload: {exc}",
            }
            command_id = command_path.stem
        else:
            command_id = str(payload.get("command_id", command_path.stem))
            response = self._dispatch(payload)

        response.setdefault("ok", True)
        response["command_id"] = command_id
        response["handled_at"] = datetime.now(UTC).isoformat()
        response_path = self._responses_dir / f"{command_id}.json"
        temp_path = response_path.with_suffix(".json.tmp")
        temp_path.write_text(json.dumps(response, separators=(",", ":"), sort_keys=True), encoding="utf-8")
        temp_path.replace(response_path)

        try:
            command_path.unlink()
        except FileNotFoundError:
            pass

    def _dispatch(self, payload: dict[str, Any]) -> dict[str, Any]:
        command = payload.get("command", "")
        args = payload.get("args", {}) or {}

        if command == "status_snapshot":
            return {"snapshot": self._status_snapshot()}
        if command == "reaper_pause":
            self._reaper.pause()
            return {"status": "paused"}
        if command == "reaper_resume":
            self._reaper.resume()
            return {"status": "resumed"}
        if command == "reaper_shun":
            ip = str(args.get("ip", "")).strip()
            reason = str(args.get("reason", "manual CLI shun"))
            if not ip:
                return {"ok": False, "error": "ip required"}
            return shun_ip(
                ip=ip,
                reason=reason,
                operator_substrate=self._operator_writer or self._substrates.get("operator"),
            )
        if command == "reaper_unshun":
            ip = str(args.get("ip", "")).strip()
            reason = str(args.get("reason", "manual CLI unshun"))
            if not ip:
                return {"ok": False, "error": "ip required"}
            return unshun_ip(
                ip=ip,
                reason=reason,
                operator_substrate=self._operator_writer or self._substrates.get("operator"),
            )
        if command == "registry_snapshot":
            return {"registry": self._registry.summary() if self._registry else {}}
        if command == "gate_denials":
            return {"denials": self._permission_gate.recent_denials() if self._permission_gate else []}

        return {"ok": False, "error": f"unknown command: {command}"}

    def _status_snapshot(self) -> dict[str, Any]:
        return {
            "live": True,
            "started_at": self._started_at,
            "substrates": {
                name: {
                    "count": sub.count(),
                    "forge": sub.forge_status(),
                }
                for name, sub in self._substrates.items()
            },
            "agents": {
                name: agent.stats
                for name, agent in self._agents.items()
            },
            "reaper": self._reaper.stats,
            "log_streams": self._log_router.stats() if self._log_router else {},
        }
