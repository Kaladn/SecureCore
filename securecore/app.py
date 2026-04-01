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
import threading
import time

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

# Agents
from securecore.agents.watcher import WatcherAgent
from securecore.agents.profiler import ProfilerAgent
from securecore.agents.escalation import EscalationAgent
from securecore.agents.decoy_orchestrator import DecoyOrchestratorAgent
from securecore.agents.chain_auditor import ChainAuditorAgent
from securecore.agents.containment import ContainmentAdvisorAgent

# Control
from securecore.control.reaper import Reaper, ReaperPolicy

# Logging
from securecore.logging.streams import LogRouter

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
    }

    # ============================================================
    # LOGGING - one stream per concern
    # ============================================================
    log_router = LogRouter(log_dir)

    # ============================================================
    # AGENTS - interpreters on substrate truth
    # ============================================================
    agent_decisions_sub = substrates["agent_decisions"]

    agents = {}

    # Watcher: watches ingress, emits to agent_decisions
    watcher = WatcherAgent(agent_decisions_sub)
    watcher.watch(substrates["ingress"])
    agents["watcher"] = watcher

    # Profiler: watches ingress + mirror, emits profiles
    profiler = ProfilerAgent(agent_decisions_sub)
    profiler.watch(substrates["ingress"])
    profiler.watch(substrates["mirror"])
    agents["profiler"] = profiler

    # Escalation: watches agent_decisions + mirror, emits escalation recs
    escalation = EscalationAgent(agent_decisions_sub)
    escalation.watch(agent_decisions_sub)
    escalation.watch(substrates["mirror"])
    agents["escalation"] = escalation

    # Decoy Orchestrator: watches mirror + agent_decisions, emits strategy
    decoy_orch = DecoyOrchestratorAgent(agent_decisions_sub)
    decoy_orch.watch(substrates["mirror"])
    decoy_orch.watch(agent_decisions_sub)
    agents["decoy_orchestrator"] = decoy_orch

    # Chain Auditor: periodically verifies all substrate chains
    chain_auditor = ChainAuditorAgent(
        agent_decisions_sub,
        watched_substrates=list(substrates.values()),
        evidence_substrate=substrates["evidence"],
    )
    agents["chain_auditor"] = chain_auditor

    # Containment Advisor: watches escalation decisions, recommends actions
    containment = ContainmentAdvisorAgent(agent_decisions_sub)
    containment.watch(agent_decisions_sub)
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

    # Control plane routes
    init_control_routes(substrates, agents, log_router, reaper)
    app.register_blueprint(control_bp)

    # Trap routes (honeypot)
    if app.config.get("HONEYPOT_ENABLED", True):
        from securecore.decoys.routes import trap_bp, init_trap_routes
        init_trap_routes(
            ingress_sub=substrates["ingress"],
            mirror_sub=substrates["mirror"],
            evidence_sub=substrates["evidence"],
            telemetry_sub=substrates["telemetry"],
            log_router=log_router,
        )
        app.register_blueprint(trap_bp)

    # ============================================================
    # REAPER - autonomous containment executor
    # ============================================================
    reaper = Reaper(
        decisions_substrate=agent_decisions_sub,
        operator_substrate=substrates["operator"],
        policy=ReaperPolicy(
            min_confidence=0.7,
            shun_cooldown_seconds=300.0,
            auto_shun_enabled=True,
            dry_run=False,
        ),
    )
    reaper.start()

    # Store references on app for CLI access
    app.substrates = substrates
    app.agents = agents
    app.log_router = log_router
    app.reaper = reaper

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
