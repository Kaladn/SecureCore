# SecureCore

SecureCore is a localhost-only defensive security organism. The GitHub repo is intentionally locked as pre-Forge: the active runtime is Python, substrates are append-only hash-chained JSONL truth stores, agents infer from truth, and the Reaper executes containment through a weighted consensus gate.

## Current runtime
- 7 substrates: ingress, mirror, evidence, telemetry, agent_decisions, operator, hid
- 7 agents: watcher, profiler, escalation, cognitive, chain_auditor, decoy_orchestrator, containment
- 7 structured log streams
- Flask control plane on `127.0.0.1` only
- 40+ trap routes with deterministic decoy content
- Windows Firewall shun engine
- 6 pinned Python dependencies
- No npm, no runtime package installs, no external services by default

## Pre-Forge lock
- Forge is planned, not active in runtime
- Symbolizer is planned, not active in runtime
- Rust migration is planned, not active in runtime
- JSONL substrates remain the authoritative truth stores
- Agents never mutate evidence
- Loggers log, agents infer

## Repo layout
- `securecore/` runtime organism
- `tests/` runtime and support tests
- `security_local/` legacy prototype retained for lineage only

## Quick start
```powershell
python -m pip install -r securecore\requirements.txt
Copy-Item securecore\.env.example securecore\.env
python securecore\cli\seed_admin.py
python -m unittest discover -s tests -t . -v
python -c "import securecore.app; print('securecore app import ok')"
```

## Runtime entry points
- `python securecore\app.py` starts the localhost control plane
- `python securecore\cli\seed_admin.py` seeds the admin account
- `python -m unittest discover -s tests -t . -v` runs the current support suite

## Notes
This public repository carries runtime and support structures only. Broader design papers, migration notes, and local planning artifacts stay out of GitHub.
