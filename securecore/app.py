"""SecureCore Application Factory.

This is where the organism comes alive. The app factory:
  1. Loads and validates config
  2. Initializes the database and JWT
  3. Creates all substrates (truth layers)
  4. Creates all agents (interpreters)
  5. Wires agents to substrates
  6. Initializes structured logging
  7. Registers real routes and trap routes
  8. Starts the agent processing pipeline

Every touch creates multiple coordinated records:
  raw -> normalized -> forensic -> agent interpretation -> escalation outcome
"""

import logging
import os
from pathlib import Path
import sys
import threading
import time

if __name__ == "__main__" and (__package__ is None or __package__ == ""):
    repo_root = Path(__file__).resolve().parent.parent
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)

from flask import Flask

from securecore.config import load_settings, validate_settings
from securecore.core.db import db
from securecore.core.auth import jwt

# Substrates
from securecore.substrates.ingress import IngressSubstrate
from securecore.substrates.mirror import MirrorSubstrate
from securecore.substrates.evidence import EvidenceSubstrate
from securecore.substrates.telemetry import TelemetrySubstrate
from securecore.substrates.agent_decisions import AgentDecisionsSubstrate
from securecore.substrates.operator import OperatorSubstrate
from securecore.substrates.hid import HIDSubstrate

# Agents
from securecore.agents.watcher import WatcherAgent
from securecore.agents.profiler import ProfilerAgent
from securecore.agents.escalation import EscalationAgent
from securecore.agents.decoy_orchestrator import DecoyOrchestratorAgent
from securecore.agents.chain_auditor import ChainAuditorAgent
from securecore.agents.containment import ContainmentAdvisorAgent
from securecore.agents.cognitive import CognitiveAgent

# Control
from securecore.control.reaper import Reaper, ReaperPolicy
from securecore.control.command_bus import ControlBus

# Permissions
from securecore.permissions.registry import CallerRegistry
from securecore.permissions.gate import PermissionGate
from securecore.permissions.types import SubstrateWriter, SubstrateReader

# Logging
from securecore.log_streams.streams import LogRouter

# Routes
from securecore.routes.health import health_bp
from securecore.routes.auth import auth_bp
from securecore.routes.events import events_bp
from securecore.control.routes import control_bp, init_control_routes

logger = logging.getLogger("securecore")


def _configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )


def _agent_ticker(agents: list, interval: float = 30.0):
    """Background thread that ticks all agents periodically."""
    while True:
        time.sleep(interval)
        for agent in agents:
            try:
                agent.tick()
            except Exception as exc:
                logger.error("Agent tick failed for %s: %s", agent.name, exc)


def create_app() -> Flask:
    settings = load_settings()
    validate_settings(settings)
    _configure_logging()

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(settings)

    db.init_app(app)
    jwt.init_app(app)

    # ============================================================
    # SUBSTRATES - ground truth layers
    # ============================================================
    data_dir = os.path.join(os.path.dirname(__file__), settings.get("DATA_DIR", "data"))
    log_dir = os.path.join(os.path.dirname(__file__), settings.get("LOG_DIR", "logs"))

    substrates = {
        "ingress": IngressSubstrate(os.path.join(data_dir, "substrates")),
        "mirror": MirrorSubstrate(os.path.join(data_dir, "substrates")),
        "evidence": EvidenceSubstrate(os.path.join(data_dir, "substrates")),
        "telemetry": TelemetrySubstrate(os.path.join(data_dir, "substrates")),
        "agent_decisions": AgentDecisionsSubstrate(os.path.join(data_dir, "substrates")),
        "operator": OperatorSubstrate(os.path.join(data_dir, "substrates")),
        "hid": HIDSubstrate(os.path.join(data_dir, "substrates")),
    }

    # ============================================================
    # LOGGING - one stream per concern
    # ============================================================
    log_router = LogRouter(log_dir)

    # ============================================================
    # PERMISSIONS - register all callers, set gate on all substrates
    # ============================================================
    registry = CallerRegistry()
    gate = PermissionGate(registry)

    # Register every autonomous component with explicit permissions
    # No self-registration. The factory defines who can touch what.

    agent_names = [
        "watcher", "profiler", "escalation",
        "decoy_orchestrator", "chain_auditor", "cognitive", "containment",
    ]
    agent_entries = {}
    for aname in agent_names:
        agent_entries[aname] = registry.register(
            caller_id=f"agent:{aname}",
            caller_type="agent",
            module_path=f"securecore.agents.{aname}",
            allowed_write=["agent_decisions"],
            allowed_read=["ingress", "mirror", "evidence", "telemetry", "hid", "agent_decisions"],
        )

    reaper_entry = registry.register(
        caller_id="control:reaper",
        caller_type="control",
        module_path="securecore.control.reaper",
        allowed_write=["operator"],
        allowed_read=["agent_decisions", "hid"],
    )

    trap_entry = registry.register(
        caller_id="routes:traps",
        caller_type="routes",
        module_path="securecore.decoys.routes",
        allowed_write=["ingress", "mirror", "evidence", "telemetry"],
        allowed_read=[],
    )

    shun_entry = registry.register(
        caller_id="control:shun",
        caller_type="control",
        module_path="securecore.control.shun",
        allowed_write=["operator"],
        allowed_read=[],
    )

    # Set the gate on every substrate
    for sub in substrates.values():
        sub.set_permission_gate(gate)

    # Build writer/reader interfaces
    def _writer(caller_entry, substrate_name):
        return SubstrateWriter(substrates[substrate_name], caller_entry.caller_id, caller_entry.signing_key)

    def _reader(substrate_name):
        return SubstrateReader(substrates[substrate_name])

    # ============================================================
    # AGENTS - interpreters on substrate truth
    # ============================================================
    agents = {}

    # Each agent gets a SubstrateWriter for agent_decisions only
    # and SubstrateReaders for their watched substrates

    watcher_writer = _writer(agent_entries["watcher"], "agent_decisions")
    watcher = WatcherAgent(watcher_writer)
    watcher.watch(substrates["ingress"])
    agents["watcher"] = watcher

    profiler_writer = _writer(agent_entries["profiler"], "agent_decisions")
    profiler = ProfilerAgent(profiler_writer)
    profiler.watch(substrates["ingress"])
    profiler.watch(substrates["mirror"])
    agents["profiler"] = profiler

    escalation_writer = _writer(agent_entries["escalation"], "agent_decisions")
    escalation = EscalationAgent(escalation_writer)
    escalation.watch(substrates["agent_decisions"])
    escalation.watch(substrates["mirror"])
    agents["escalation"] = escalation

    decoy_orch_writer = _writer(agent_entries["decoy_orchestrator"], "agent_decisions")
    decoy_orch = DecoyOrchestratorAgent(decoy_orch_writer)
    decoy_orch.watch(substrates["mirror"])
    decoy_orch.watch(substrates["agent_decisions"])
    agents["decoy_orchestrator"] = decoy_orch

    chain_auditor_writer = _writer(agent_entries["chain_auditor"], "agent_decisions")
    chain_auditor = ChainAuditorAgent(
        chain_auditor_writer,
        watched_substrates=list(substrates.values()),
        evidence_substrate=substrates["evidence"],
    )
    agents["chain_auditor"] = chain_auditor

    cognitive_writer = _writer(agent_entries["cognitive"], "agent_decisions")
    cognitive = CognitiveAgent(cognitive_writer, hid_substrate=substrates["hid"])
    cognitive.watch(substrates["ingress"])
    cognitive.watch(substrates["mirror"])
    cognitive.watch(substrates["hid"])
    agents["cognitive"] = cognitive

    containment_writer = _writer(agent_entries["containment"], "agent_decisions")
    containment = ContainmentAdvisorAgent(containment_writer)
    containment.watch(substrates["agent_decisions"])
    containment.watch(substrates["mirror"])
    agents["containment"] = containment

    # Start all agents
    for agent in agents.values():
        agent.start()

    # Start agent ticker thread
    agent_list = list(agents.values())
    ticker = threading.Thread(target=_agent_ticker, args=(agent_list,), daemon=True)
    ticker.start()

    # ============================================================
    # ROUTES - real and trap
    # ============================================================
    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(events_bp)

    # ============================================================
    # REAPER - autonomous containment executor
    # ============================================================
    reaper_operator_writer = _writer(reaper_entry, "operator")
    reaper = Reaper(
        decisions_substrate=substrates["agent_decisions"],
        operator_writer=reaper_operator_writer,
        hid_substrate=substrates["hid"],
        policy=ReaperPolicy(
            min_confidence=0.7,
            shun_cooldown_seconds=300.0,
            auto_shun_enabled=True,
            dry_run=False,
        ),
    )
    reaper.start()

    shun_operator_writer = _writer(shun_entry, "operator")
    control_bus = ControlBus(
        os.path.join(data_dir, "runtime", "control_bus"),
        substrates=substrates,
        agents=agents,
        log_router=log_router,
        reaper=reaper,
        operator_writer=shun_operator_writer,
        registry=registry,
        permission_gate=gate,
    )
    control_bus.start()

    # Control plane routes
    init_control_routes(substrates, agents, log_router, reaper, operator_writer=shun_operator_writer)
    app.register_blueprint(control_bp)

    # Trap routes (honeypot)
    if app.config.get("HONEYPOT_ENABLED", True):
        from securecore.decoys.routes import trap_bp, init_trap_routes
        init_trap_routes(
            ingress_writer=_writer(trap_entry, "ingress"),
            mirror_writer=_writer(trap_entry, "mirror"),
            evidence_writer=_writer(trap_entry, "evidence"),
            telemetry_writer=_writer(trap_entry, "telemetry"),
            log_router=log_router,
        )
        app.register_blueprint(trap_bp)

    # Store references on app for CLI access
    app.substrates = substrates
    app.agents = agents
    app.log_router = log_router
    app.reaper = reaper
    app.control_bus = control_bus
    app.registry = registry
    app.permission_gate = gate

    with app.app_context():
        from securecore.core import models  # noqa: F401
        db.create_all()

    logger.info(
        "SecureCore organism alive: %d substrates, %d agents, %d log streams",
        len(substrates), len(agents), len(LogRouter.STREAM_NAMES),
    )

    return app


app = create_app()

if __name__ == "__main__":
    host = app.config["BIND_HOST"]
    port = int(app.config["BIND_PORT"])
    app.run(host=host, port=port, debug=False)
