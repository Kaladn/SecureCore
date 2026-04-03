# SecureCore

SecureCore is a localhost-only defensive security organism. This public repo stays locked to runtime and support structures only. The active organism is still Python: substrates append immutable truth, Forge is being introduced under those substrate contracts, agents infer from truth, and the Reaper executes containment through a weighted consensus gate.

## Current runtime
- 7 substrates: ingress, mirror, evidence, telemetry, agent_decisions, operator, hid
- 7 agents: watcher, profiler, escalation, cognitive, chain_auditor, decoy_orchestrator, containment
- 7 structured log streams
- Flask control plane on `127.0.0.1` only
- 40+ trap routes with deterministic decoy content
- Windows Firewall shun engine
- 6 pinned Python dependencies
- No npm, no runtime package installs, no external services by default

## Current cut line
- Forge foundation exists on the `forge` branch as an optional dual-write storage spine
- Rust migration is planned, not active in runtime
- JSONL substrates remain the authoritative truth stores until cutover is explicitly proven
- Agents never mutate evidence
- Loggers log, agents infer

## Operator Surface Direction
SecureCore is moving toward one primary operator surface instead of many competing control planes.

- One Rust front door serving the chat control center
- One local Ollama-backed model path
- Three radio-button modes: `Support`, `Operations`, `Build`
- One trust-gated authority path for all mutations
- Read-only satellites only: popup displays and CLI instruments may observe, but they do not get private mutation lanes

Mode selection changes context, retrieval, contract, and allowed requests. It does not change what the system trusts.

### Current lock
- `Grounded` is a reserved preset slot, not a fourth visible mode
- block cite and block note live beside messages, not as separate messages
- continue chat is a branch operation
- settings come last, after the other systems are proven
- the Rust layer is a front door, not a second brain

### Mode doctrine
- `Support`
  - grounded help, explanation, citations, operator-safe answers
- `Operations`
  - runtime inspection, status, live cells, containment review, trusted operator commands
- `Build`
  - drafting, code assistance, continue flows, tool maker, approval workflows

The current runtime already contains the backbone this will grow around:

- `securecore/help/` for grounded support behavior
- `securecore/control/` for local control transport and runtime command handling
- `securecore/permissions/` for registry and gating
- `securecore/llm/` for local model access and role-specific contexts
- `securecore/substrates/` for append-only truth

## Planned Chat Spine
The future chat system is not a separate toy layered beside the organism. It is intended to become a first-class SecureCore subsystem built around the same truth and authority rules as the rest of the runtime.

### Chat memory
Chat memory is planned as a shared append-only spine carrying:

- conversations
- messages
- blocks
- branches
- citations
- notes
- continue state
- artifact references

The design rule is:

```text
One ledger.
One truth.
Blocks are indexed projections, not competing storage authorities.
```

### Required chat capabilities
- block-level citations
- block-level annotations
- continue from item
- continue from code
- branch-aware history
- response grounding citations
- shared retrieval and memory rollups later

### Tool Maker placement
Tool Maker belongs inside `Build` mode. It is not a separate UI.

Its governed lifecycle is expected to be:

```text
describe
-> draft proposal
-> validate
-> sandbox test
-> approve
-> activate
```

## Roadmap To V1
The current operator-platform wrap is expected to move in this order:

1. Chat surface
   - Rust front door for chat/static
   - Python chat backend
   - block cite, block note, continue chat
2. Chat memory + citations
   - memory spine
   - manual and grounding citations
   - retrieval across conversations
3. 6-1-6 mapping + data lake
   - Rust compute for mapping
   - lake ingestion from chat memory + substrates
4. Grounded chat + lexicon
   - fuller retrieval grounding
   - SecureCore lexicon rebuild
5. Settings menu
   - full system settings surface after the rest is proven

See [docs/architecture/Chat Control Center Architecture.md](docs/architecture/Chat%20Control%20Center%20Architecture.md) for the fuller doctrine document.

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

## Rear-Looking Snapshot
- SecureCore has been pulled out of the earlier Security Local bootstrap and re-formed as a layered organism with explicit truth, inference, control, and deception boundaries.
- The current pre-Forge runtime is live as a Python organism built around 7 substrates, 7 agents, 7 structured log streams, a consensus-gated Reaper, and a localhost-only Flask control plane.
- Truth is still carried by append-only hash-chained JSONL substrates. Agents interpret that truth but do not mutate it. The Reaper executes validated actions rather than inventing policy.
- The repo has already been narrowed on purpose: runtime and support structures are public, while broader planning papers and local design archives stay outside GitHub.
- The current shape is intentionally transitional. It is stable enough to inspect, test, and extend, but it is not yet in Forge cutover mode.

## Next Units
This section is a living execution ledger. Each item starts as a forward-looking task. When a unit is completed, rewrite the line into past tense so the README becomes its own rolling project history instead of accumulating stale plans.

- Pending: prove the public runtime cleanly with a deterministic end-to-end vertical slice, including one trap hit flowing through substrates, agents, consensus, and operator logging.
- Pending: prove Forge dual-write, WAL recovery, and writer behavior under load before treating it as a trustworthy backing layer.
- Pending: replace hot-path synchronous write pressure with a safer writer pattern so truth capture stays deterministic under stress without blocking request handling.
- Pending: wire a real HID collector behind the existing HID substrate so human-attestation signals come from hardware activity rather than synthetic records alone.
- Pending: lock logging and write-path visibility before branching the operator command center into active UI work.
- Pending: converge the operator surface into one trust-gated chat control center with read-only satellites only after runtime write integrity is proven.
