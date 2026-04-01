# ARCHITECTURE.md

## Document

**Name:** Security Local Architecture
**Version:** 1.0
**Status:** Active
**Scope:** Python-only, localhost-only, no-npm local security platform

## Purpose

This document defines the structural design of Security Local.

It explains:

* the system shape
* module boundaries
* runtime flow
* maintenance flow
* storage ownership
* how components communicate
* what is intentionally absent

This is the build map for implementation, not a sales pitch.

---

## Architectural Summary

Security Local is a **small, local-first defensive platform** built with Python and a server-rendered local UI.

The architecture is optimized for:

* local safety
* reduced attack surface
* clear authority boundaries
* simple audit paths
* deterministic startup
* easy inspection and repair

It explicitly avoids:

* npm-based front-end stacks
* browser build pipelines
* hidden background installers
* internet-first assumptions
* giant all-in-one scripts
* mixed maintenance and runtime behavior

---

## High-Level Shape

```text
Operator
  -> Local UI (Jinja + vanilla JS)
  -> Local API (Flask)
  -> Core Authorities
       -> Config
       -> Auth
       -> Events
       -> Collectors
       -> Detection
       -> Intel
  -> Local Storage (SQLite first)
  -> Maintenance CLI
```

This is a **single-host architecture** in phase 1.
There is no remote node mesh, no public API surface, and no browser-side application framework.

---

## Core Design Rules

### 1. Python only

All runtime and maintenance logic is Python.

### 2. Localhost only

Primary runtime binds to `127.0.0.1` only.

### 3. No npm

UI is delivered through templates and static files checked into repo.

### 4. Thin UI, thick server rules

The UI presents data and submits requests. Authority lives in server modules.

### 5. Runtime and maintenance are separate

Routine application flow must not contain schema mutation, package install, training, or hidden remediation.

### 6. Authority ownership is explicit

Each subsystem owns specific data and actions.

---

## Main Components

## 1. App Shell

**Responsibility:** application boot, blueprint registration, settings load, startup validation, DB init.

Primary file:

* `app.py`

Responsibilities:

* call config loader
* enforce startup invariants
* initialize Flask extensions
* register routes
* create app context
* fail closed on invalid startup state

Must not:

* contain collector logic
* contain intel normalization logic
* contain business rules beyond assembly and boot control

---

## 2. Config Authority

**Responsibility:** configuration loading and validation.

Suggested files:

* `core/config.py`

Responsibilities:

* read environment variables
* enforce localhost bind
* validate required keys
* define safe defaults
* reject malformed startup state

Must not:

* log secret values
* mutate non-config data
* silently fall back to unsafe network binds

Key invariants:

* bind host is `127.0.0.1`
* required secrets exist
* database URI is valid
* disabled-by-default connectors stay disabled unless explicitly enabled

---

## 3. DB Layer

**Responsibility:** DB initialization and shared session access.

Suggested files:

* `core/db.py`
* `migrations/`

Responsibilities:

* initialize SQLAlchemy
* provide clean DB access to authority modules
* support migration path

Must not:

* become a dumping ground for business logic
* bypass authority ownership rules

Initial storage choice:

* SQLite

Reason:

* local-first
* low dependency burden
* simple backup/inspection during early phases

Future upgrade path:

* PostgreSQL only if requirements justify it explicitly

---

## 4. Auth Authority

**Responsibility:** identity, password verification, RBAC, token/session issuance.

Suggested files:

* `core/auth.py`
* `core/routes/auth.py`
* auth-related models in `core/models.py`

Responsibilities:

* verify credentials
* issue auth tokens
* attach role claims
* enforce role checks on privileged routes
* emit auth events later

Must not:

* own intel imports
* own collector runs
* trust UI-provided role state

Expected models:

* `User`
* `Role`

Expected route shape:

* `POST /api/login`
* `GET /api/me`

---

## 5. Event Authority

**Responsibility:** append-first security event recording and retrieval.

Suggested files:

* `core/routes/events.py`
* event model in `core/models.py`
* optional future service module `core/events/service.py`

Responsibilities:

* accept valid event writes from authorized paths
* expose recent event history
* preserve timestamps and source tags
* support future export and retention rules

Must not:

* silently rewrite or delete history in runtime mode
* allow broad wildcard mutation

Expected model:

* `SecurityEvent`

Expected route shape:

* `GET /api/events`
* `POST /api/events` (admin-only/manual/internal paths only)

---

## 6. Collector Authority

**Responsibility:** read-only host inspection.

Suggested files:

* `core/collectors/__init__.py`
* `core/collectors/listeners.py`
* `core/collectors/defender.py`
* `core/collectors/firewall.py`
* `core/collectors/services.py`

Responsibilities:

* gather local host state
* return normalized read-only snapshots
* fail safely when unsupported or unavailable

Must not:

* modify firewall rules
* disable services
* remediate host state from ordinary runtime routes

Initial collector targets:

* listening ports
* Defender state
* firewall profile state
* selected Windows service state

Collector output style:

* structured dict/list payloads
* explicit timestamps
* no raw shell dump as public contract unless wrapped in a normalized result object

---

## 7. Detection Authority

**Responsibility:** evaluate collected state or imported intel against rules.

Suggested files:

* `core/detection/__init__.py`
* `core/detection/rules.py`
* `core/detection/engine.py`

Responsibilities:

* run deterministic rules first
* generate findings
* emit events when thresholds/conditions are met
* optionally support later model-assisted scoring

Must not:

* retrain itself in runtime mode
* fetch remote dependencies dynamically
* hide why a finding was produced

Phase 1 preference:

* deterministic rule checks only

Example early rules:

* non-local listener detected
* unexpected public-facing port open
* Defender disabled
* firewall profile mismatch

---

## 8. Intel Authority

**Responsibility:** external threat intel ingestion and normalization.

Suggested files:

* `core/intel/__init__.py`
* `core/intel/models.py`
* `core/intel/adapters/`
* `core/intel/service.py`

Responsibilities:

* ingest external feed data when enabled
* normalize indicators into local schema
* record source provenance
* log import success/failure
* maintain per-feed kill switch behavior

Must not:

* run by default in phase 1
* embed secrets in UI responses
* directly control auth or event ownership

Phase 1 state:

* present as scaffold only
* disabled by default

---

## 9. UI Authority

**Responsibility:** local presentation layer.

Suggested files:

* `templates/`
* `static/`
* optional UI routes under `core/routes/ui.py`

Responsibilities:

* render pages
* present health state, auth state, events, and collector output
* submit forms or fetch JSON from local API

Must not:

* contain core security logic
* rely on build tools
* fetch CDN packages
* implement authority decisions in client code

Technology choice:

* Jinja templates
* plain CSS
* vanilla JS

Why:

* low attack surface
* no npm
* easy diffing and audit

---

## 10. Maintenance CLI

**Responsibility:** explicit operator-driven administrative actions.

Suggested files:

* `cli/seed_admin.py`
* future `cli/migrate.py`
* future `cli/import_intel.py`
* future `cli/verify_integrity.py`

Responsibilities:

* seed admin user
* run migrations
* perform offline imports
* run future integrity checks
* execute training only if such capability exists later

Must not:

* be callable through hidden runtime routes
* perform silent background changes

Maintenance mode is separate by intent, invocation path, and logging.

---

## Storage Architecture

## Initial DB schema groups

### Auth tables

* `roles`
* `users`

### Event tables

* `security_events`

### Future intel tables

* `intel_sources`
* `indicators`
* `indicator_import_runs`

### Future posture tables

* `host_snapshots`
* `detector_findings`

### Future maintenance tables

* `maintenance_runs`
* `config_audit`

---

## Data ownership map

### Auth owns

* users
* roles
* session/token semantics

### Events owns

* security_events

### Intel owns

* indicators
* feed source metadata
* import run records

### Collectors own

* normalized snapshot objects before persistence

### Detection owns

* findings derived from collectors/intel

No module should directly mutate another authority’s core tables as a shortcut.

---

## Runtime Request Flow

## Login flow

```text
User -> /api/login -> Auth Authority -> User lookup -> password verify -> token issue -> response
```

## Event read flow

```text
User -> /api/events -> auth check -> Event Authority -> DB read -> JSON response
```

## Manual admin event flow

```text
Admin user -> /api/events POST -> auth check -> role check -> Event Authority -> DB append -> response
```

## Collector read flow (future)

```text
User -> /api/collectors/listeners -> auth check -> Collector Authority -> local host inspection -> normalized output -> response
```

## Detection flow (future)

```text
collector output or scheduled run -> Detection Authority -> rules -> finding/event creation -> DB append
```

---

## Maintenance Flow

Maintenance is intentionally out-of-band from normal runtime.

Example:

```text
Operator shell -> python cli/seed_admin.py -> app context -> Auth models -> DB write -> console output + event log later
```

Example future import:

```text
Operator shell -> python cli/import_intel.py -> Intel adapter -> normalization -> DB write -> import log
```

This separation prevents runtime APIs from accumulating dangerous “just this once” admin behaviors.

---

## Module Communication Rules

### Allowed communication style

* route -> authority/service -> DB/model
* route -> collector -> normalized result
* detector -> event append service
* maintenance CLI -> authority/service -> DB/model

### Disallowed communication style

* template -> DB direct mutation
* static JS -> authority bypass
* collector -> firewall modification in read-only mode
* intel adapter -> UI template coupling
* auth module -> direct threat intel ownership

---

## File and Package Layout

```text
security_local/
  app.py
  requirements.txt
  .env.example
  core/
    __init__.py
    config.py
    db.py
    logging_setup.py
    auth.py
    models.py
    routes/
      __init__.py
      health.py
      auth.py
      events.py
      ui.py
    collectors/
      __init__.py
      listeners.py
      defender.py
      firewall.py
      services.py
    detection/
      __init__.py
      rules.py
      engine.py
    intel/
      __init__.py
      models.py
      service.py
      adapters/
        __init__.py
  cli/
    seed_admin.py
  templates/
    base.html
    login.html
    dashboard.html
  static/
    app.js
    app.css
  tests/
    test_config.py
    test_auth.py
    test_events.py
```

This layout is intentionally boring.
That is a feature.

---

## Startup Sequence

```text
1. load environment
2. validate required settings
3. enforce localhost bind
4. configure logging
5. initialize Flask app
6. initialize JWT/DB extensions
7. register blueprints
8. create/open DB structures
9. start local runtime
```

Fail-closed points:

* missing required config
* invalid bind host
* invalid port value
* DB unavailable
* extension init failure

---

## Security Control Placement

### Where localhost enforcement lives

* `core/config.py`

### Where role enforcement lives

* `core/auth.py`

### Where event append rules live

* Event Authority route/service layer

### Where collector read-only behavior lives

* collector modules + route boundaries

### Where intel enablement flags live

* config + intel service layer

### Where maintenance separation lives

* CLI boundary, not UI wishes

---

## What Is Intentionally Missing

The following are intentionally absent from this architecture:

* npm
* React/Vite/webpack
* axios
* browser build chains
* WebSocket dependency unless truly justified later
* remote agent mode
* automatic remediation engine
* background auto-training
* one-file mega runtime
* scraping stack inside the core runtime

These are not omissions by accident. They are exclusions by design.

---

## Architecture Decisions

### Decision 1: Flask over heavier stacks

Reason:

* enough for local API + server-rendered UI
* low complexity
* straightforward audit path

### Decision 2: SQLite first

Reason:

* local-first simplicity
* low operational overhead
* easy inspection and backup

### Decision 3: Jinja + vanilla JS

Reason:

* no npm
* low client complexity
* easier to inspect

### Decision 4: deterministic rules before ML

Reason:

* explainability
* faster validation
* less hidden behavior

### Decision 5: maintenance via CLI

Reason:

* prevents runtime sprawl
* keeps dangerous actions explicit

---

## Extension Path

Future expansion is allowed only if it preserves the core posture.

Possible later additions:

* tamper-evident event chaining
* signed export bundles
* optional offline intel import packs
* remediation mode under a separate contract
* stronger integrity verification of source files

Any of these must preserve:

* no npm
* localhost-first default
* authority boundaries
* runtime/maintenance separation

---

## Implementation Priorities

### Phase 1

* app shell
* config validation
* DB init
* login route
* role guard
* event routes
* admin seed CLI
* minimal UI stub
* tests for config/auth failures

### Phase 2

* `/api/me`
* collector modules
* dashboard page
* event viewer
* read-only posture routes

### Phase 3

* detection rules
* finding generation
* event correlation
* retention/migration cleanup

### Phase 4

* intel scaffolding
* feed adapters disabled by default
* provenance model

---

## Summary

Security Local uses a deliberately narrow architecture:

* one local app shell
* clearly separated authority modules
* local DB
* server-rendered UI
* explicit maintenance CLI
* no npm
* no public bind
* no hidden convenience layers

The architecture is meant to stay understandable under stress.
If a new feature makes the structure harder to reason about, it must justify itself or stay out.
