# OPS_CONTRACT.md

## Contract

**Name:** Security Local Ops Contract
**Version:** 1.0
**Status:** Active
**Scope:** Python-only, localhost-only, no-npm local security platform

## Purpose

This contract defines the operating rules, boundaries, responsibilities, and non-negotiable constraints for the Security Local system.

The goal is simple:

* keep the system local-safe
* keep the architecture auditable
* keep the runtime small and deterministic
* prevent convenience features from silently becoming attack surface

---

## Core Operating Principle

Security Local is a **local-first defensive platform**.

It is not:

* a cloud-first service
* a scraping platform
* a browser app build chain
* a generic AI playground
* a multi-purpose monolith

Security Local must remain:

* Python-only
* localhost-only by default
* explicit in trust boundaries
* modular by authority
* hostile to silent expansion of scope

---

## Non-Negotiable Rules

### 1. No npm

The system shall not require Node.js package installation for runtime, development, UI rendering, or packaging.

Forbidden:

* npm
* pnpm
* yarn
* axios
* React
* Vite
* webpack
* browser package manager bootstraps
* CDN-injected runtime libraries unless explicitly frozen and vendored for offline use

Allowed:

* plain HTML
* plain CSS
* vanilla JavaScript
* server-rendered templates
* Python package management through pinned requirements only

### 2. Localhost-only runtime

The primary application runtime shall bind to `127.0.0.1` only unless an explicit future contract version says otherwise.

Default binding:

* host: `127.0.0.1`

Forbidden by default:

* `0.0.0.0`
* public listening sockets
* LAN exposure
* automatic UPnP behavior
* silent remote enablement

### 3. No external connectivity by default

External network access is disabled by default.

Any connector to outside services must be:

* explicitly enabled
* individually named
* individually logged
* individually kill-switchable
* isolated from UI code
* isolated from secret display paths

### 4. No runtime package installs

The system shall never install packages during runtime.

Forbidden:

* runtime `pip install`
* shelling out to package managers during normal operation
* auto-bootstrap dependency installation from UI/API actions

### 5. No training from public runtime routes

Model training, tuning, or mutation operations are maintenance actions only.

Forbidden in normal runtime:

* training endpoints exposed to general API clients
* background self-modifying model behavior
* automatic retraining from user traffic

### 6. No debug-mode production shortcuts

Forbidden in the hardened runtime:

* `debug=True`
* adhoc TLS as a substitute for real transport design
* broad CORS enablement without scoped need
* developer convenience flags left active in release mode

---

## Authority Boundaries

The system is divided by authority. Each authority owns its own data and actions.

### 1. Config Authority

Owns:

* environment loading
* startup validation
* secrets reference locations
* encryption key references
* safe defaults

May:

* validate configuration
* refuse startup
* expose non-sensitive config health state

May not:

* return secrets over API
* mutate unrelated data domains

### 2. Auth Authority

Owns:

* user identity
* password verification
* role lookup
* token/session issuance
* auth policy enforcement

May:

* authenticate users
* authorize protected actions
* emit auth events

May not:

* bypass RBAC
* read raw secrets unrelated to auth
* directly manage threat feed ingestion

### 3. Event Authority

Owns:

* security events
* event creation rules
* event querying
* event retention/export policy

May:

* append events
* expose event history
* tag event severity and source

May not:

* rewrite historical events except through explicit maintenance tooling and audit
* silently delete records

### 4. Intel Authority

Owns:

* threat indicator schemas
* feed normalization
* provenance
* feed health state

May:

* import indicators
* normalize indicators
* cache feed snapshots
* expose read-only intel views

May not:

* own authentication
* expose upstream secrets
* call UI-layer code

### 5. Collector Authority

Owns:

* host inspection collectors
* local environment snapshots
* read-only system state gathering

May:

* inspect listeners
* inspect Defender state
* inspect firewall status
* inspect services, tasks, startup state

May not:

* change host state unless future maintenance contracts explicitly allow it
* execute remediation from read-only runtime paths

### 6. Detection Authority

Owns:

* rules
* scoring
* optional anomaly models
* hit generation

May:

* evaluate collected state
* produce findings
* emit security events

May not:

* retrain itself from runtime traffic
* fetch external dependencies at evaluation time

### 7. UI Authority

Owns:

* presentation
* local dashboards
* form submission surfaces
* read-only rendering of authorized data

May:

* display data
* submit authenticated commands within policy

May not:

* contain business logic that bypasses API rules
* directly read secrets
* dynamically install front-end dependencies

---

## Data Rules

### Data ownership

Each authority owns its own storage objects and may not directly mutate another authority’s records except through a documented service boundary.

### Write discipline

All writes must occur through explicit authority-owned functions or routes.

Forbidden:

* cross-module direct table mutation as a shortcut
* silent schema drift
* convenience writes from templates or static JS

### Event model

Security events are append-first.

Expected properties:

* timestamp
* type
* severity
* source
* details
* provenance if applicable

### Secret handling

Secrets must never be:

* logged in plaintext
* returned by API
* embedded in templates
* hardcoded in source
* shipped in example configs as real values

---

## Startup Contract

On startup, the application must validate:

* required configuration presence
* localhost binding
* database availability
* logging readiness
* disabled-by-default external connectors

Startup must fail closed if required invariants are violated.

Examples of fail-closed conditions:

* missing secret key
* invalid JWT key
* bind host not equal to `127.0.0.1`
* unreadable database path
* malformed configuration

---

## API Contract Rules

### General rules

All API routes must:

* have a clear owner authority
* return structured JSON
* validate input
* reject missing/invalid data cleanly
* log meaningful security-relevant failures

### Auth requirements

Protected routes require authentication.
Privileged routes require explicit role checks.

### Forbidden API behavior

* secret return paths
* wildcard admin mutation routes
* “do everything” endpoints
* hidden maintenance functionality exposed in runtime APIs

---

## Logging Contract

Logging must be structured and intentional.

Logs should record:

* startup state
* auth success/failure
* authorization failure
* collector execution success/failure
* feed import success/failure
* detection hits
* maintenance actions

Logs must not record:

* raw secrets
* plaintext passwords
* full token contents
* sensitive decrypted config material

---

## Maintenance Contract

Maintenance is a separate mode of operation.

Maintenance actions include:

* database migration
* admin seeding
* key rotation support
* offline import/export
* model training
* retention cleanup
* integrity verification

Maintenance actions must be:

* explicit
* operator-initiated
* logged
* separated from routine runtime traffic

---

## Testing Contract

Before a feature is considered valid, it must prove:

* startup validation works
* localhost binding enforcement works
* auth failure behavior works
* RBAC denial behavior works
* event append/read flow works
* collectors fail safely when unsupported

Preferred testing order:

1. config validation
2. auth/login failures
3. role enforcement
4. route responses
5. collector read-only behavior

---

## Security Posture Rules

The system prefers:

* deny by default
* explicit enablement
* small trusted surface
* read-only inspection before mutation
* deterministic behavior over magic automation

The system rejects:

* feature creep disguised as convenience
* network exposure disguised as usability
* monolithic “all in one script” patterns
* automatic internet dependencies

---

## Change Control

Any change that affects one of the following must update this contract version or append a contract note:

* binding model
* package policy
* secret handling policy
* authority boundaries
* maintenance/runtime separation
* storage/write rules
* network access policy

Minor code changes that do not alter these rules do not require a contract version bump.

---

## Initial Implementation Obligations

Phase 1 implementation must provide at minimum:

* config loader with localhost enforcement
* DB bootstrap
* auth route
* role enforcement helper
* security events route
* admin seed CLI
* no-npm UI stub
* tests for config and auth failure behavior

---

## Refusal Conditions

The system must refuse to start or refuse an action when:

* required config is missing
* binding is non-local in local-safe mode
* unauthorized role attempts privileged action
* maintenance-only action is requested from runtime path
* unsupported collector attempts a state-changing operation

---

## Summary

This contract exists to stop the project from turning into a fragile convenience stack.

Security Local is a disciplined local platform with hard boundaries:

* Python only
* localhost only
* no npm
* no silent remote reach
* no mixed-authority shortcuts
* no runtime self-expansion

If a future feature fights those rules, the feature changes or the contract is versioned explicitly.
