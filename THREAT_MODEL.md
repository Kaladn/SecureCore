# THREAT_MODEL.md

## Document

**Name:** Security Local Threat Model
**Version:** 1.0
**Status:** Active
**Scope:** Python-only, localhost-only, no-npm local security platform

## Purpose

This document defines the threats Security Local is designed to reduce, the trust boundaries it must respect, the assumptions it makes, and the attack paths it must explicitly defend against.

This is a practical threat model, not a marketing diagram.

It exists to answer five questions:

1. what are we protecting
2. who or what can hurt it
3. how they can reach it
4. what we are doing about it
5. what we are intentionally not solving yet

---

## System Summary

Security Local is a **local-first defensive platform** that runs on a Windows host, uses Python only, binds to `127.0.0.1` by default, and forbids npm-based runtime or UI supply chains.

Primary goals:

* inspect local host security posture
* store security-relevant events
* support authenticated local administration
* optionally ingest threat intelligence through explicitly enabled connectors
* remain small, auditable, and hard to accidentally expose

Security Local is not intended to be:

* internet-facing by default
* a cloud-managed endpoint product
* a browser-heavy SPA platform
* a remote management suite
* a self-mutating AI service

---

## Assets to Protect

### 1. Secrets

Examples:

* app secret keys
* JWT signing keys
* connector credentials
* encrypted config material
* local admin bootstrap credentials

Why they matter:

* compromise allows impersonation, abuse of privileged routes, or feed abuse

### 2. Auth state

Examples:

* user records
* password hashes
* role assignments
* session or token issuance behavior

Why they matter:

* compromise allows unauthorized access or privilege escalation

### 3. Security events

Examples:

* event logs
* alert records
* collector findings
* maintenance history

Why they matter:

* tampering destroys trust in the platform and blinds detection

### 4. Intel data

Examples:

* imported indicators
* source provenance
* feed health state
* snapshots of prior imports

Why they matter:

* poisoned intel can create false trust or false panic

### 5. Host posture snapshots

Examples:

* listening ports
* Defender state
* firewall state
* service state
* scheduled task summaries

Why they matter:

* these are the system’s view of local safety; corruption or spoofing undermines decision-making

### 6. Application integrity

Examples:

* Python source
* templates/static assets
* DB schema
* migration files
* packaged release artifacts

Why they matter:

* attacker modification could turn a defensive tool into an attack path

---

## Security Objectives

### Confidentiality

Protect secrets, auth state, and any sensitive system inspection results from unauthorized disclosure.

### Integrity

Prevent unauthorized modification of code, configuration, event history, and admin actions.

### Availability

Keep the local defensive tool usable during stress without allowing availability shortcuts to create major exposure.

### Auditability

Make important actions explainable after the fact.

### Scope discipline

Prevent the tool from silently becoming broader, more remote, or more supply-chain dependent than intended.

---

## Threat Actors

### 1. External opportunistic attacker

Capabilities:

* scans for exposed services
* targets weak local web apps accidentally bound to LAN/public interfaces
* abuses stale packages, default creds, or debug mode

Relevant risk:

* accidental exposure of a localhost tool to non-local interfaces

### 2. Targeted remote actor

Capabilities:

* attempts phishing, malware delivery, credential theft, persistence, remote execution
* leverages nation-state or advanced criminal tradecraft
* abuses any exposed admin or connector surface

Relevant risk:

* if the host is compromised elsewhere, Security Local becomes a target for tampering or privilege abuse

### 3. Local malware already present on host

Capabilities:

* reads files
* scrapes tokens/secrets
* tampers with app files or DB
* hijacks sessions
* spawns processes and opens listeners

Relevant risk:

* this is one of the most realistic high-impact scenarios

### 4. Insider / local user misuse

Capabilities:

* valid local access
* accidental misconfiguration
* misuse of admin features
* disabling protections for convenience

Relevant risk:

* safety drift caused by operator shortcuts

### 5. Supply-chain attacker

Capabilities:

* poisons packages
* compromises dependency publisher account
* ships malicious updates
* abuses installer/bootstrap flow

Relevant risk:

* exactly why npm is forbidden and runtime package install is disallowed

### 6. Feed poisoning attacker

Capabilities:

* injects bad intel through upstream compromise or credential abuse
* manipulates imported external data

Relevant risk:

* false indicators, bad decisions, or corrupted trust in imported data

---

## Trust Boundaries

### Boundary 1: Local host OS ↔ Security Local process

The application trusts the host only partially.

Assumption:

* the OS is not already fully hostile at startup

Reality:

* the host may still contain malware, hostile processes, or unsafe listeners

Implication:

* Security Local must record and inspect local state, not blindly trust it

### Boundary 2: Runtime ↔ Secrets

Runtime code may reference secrets but must not expose them through logs, templates, or API responses.

### Boundary 3: Runtime ↔ Maintenance

Maintenance operations are separate from standard runtime routes.

Implication:

* a normal authenticated user route must not mutate system structure or retrain models

### Boundary 4: UI ↔ API

The UI is presentation, not authority.

Implication:

* all privileged logic must be enforced server-side

### Boundary 5: Local platform ↔ External connectors

External feeds are untrusted until normalized, validated, and logged.

Implication:

* no direct pass-through of upstream data into privileged workflows

### Boundary 6: Collector reads ↔ Host mutation

Collectors are read-only by default.

Implication:

* state-changing remediation is not allowed from read-only collector paths

---

## Assumptions

### Assumptions we make

* Python runtime and pinned dependencies are locally installed intentionally
* the application binds only to `127.0.0.1` in local-safe mode
* the operator can control Windows firewall posture outside the app
* local DB storage is acceptable for first-phase use
* users with admin role are trusted more than ordinary users, but still audited

### Assumptions we do not make

* we do not assume internet access is safe
* we do not assume threat intel feeds are trustworthy without normalization
* we do not assume the local host is already clean
* we do not assume UI code is an enforcement layer
* we do not assume convenience features are worth new attack surface

---

## Entry Points

### 1. Local API routes

Examples:

* login
* current user info
* event query
* admin event creation
* future collector read routes

Threats:

* auth bypass
* RBAC bypass
* input abuse
* session/token abuse
* accidental exposure beyond localhost

### 2. CLI maintenance commands

Examples:

* seed admin
* migrate DB
* import intel
* rotate keys
* train optional models

Threats:

* operator misuse
* secrets leakage through shell history or logs
* unintended privilege actions

### 3. Configuration loading

Examples:

* `.env`
* encrypted config files
* secret references

Threats:

* missing values
* weak defaults
* maliciously altered config
* silent remote bind changes

### 4. Database access

Examples:

* auth reads
* event writes
* intel inserts

Threats:

* unauthorized mutation
* schema shortcuts
* event deletion or rewrite

### 5. External feed connectors

Examples:

* future threat intel imports

Threats:

* poisoned feed data
* credential leakage
* retry storms
* parser bugs

### 6. Static/UI assets

Examples:

* templates
* vanilla JS
* local forms

Threats:

* XSS from unsafe rendering
* UI confusion leading to unintended actions
* hidden logic drifting into client-side code

---

## Priority Threats

### T1. Accidental network exposure

Description:
A localhost tool is accidentally bound to `0.0.0.0`, LAN, or public interfaces.

Why this matters:
This turns a local admin surface into a remotely reachable target.

Controls:

* startup enforcement of `127.0.0.1`
* fail closed on non-local bind
* no remote mode in phase 1
* no UPnP behavior

Residual risk:

* reverse proxies or local tunneling tools could still expose it outside intended boundaries

### T2. Supply-chain compromise

Description:
A dependency or frontend build chain pulls malicious code.

Why this matters:
This is a direct route to full compromise.

Controls:

* no npm policy
* no runtime package install
* pinned Python requirements
* optional future wheelhouse/offline package strategy

Residual risk:

* Python dependency chain still exists and must be managed carefully

### T3. Secret disclosure

Description:
Secrets leak through source, logs, templates, API responses, or local config mishandling.

Controls:

* secret values excluded from logs
* config validation
* no secret-returning routes
* encrypted config support where appropriate
* example configs use placeholders only

Residual risk:

* malware with local file access may still exfiltrate secrets

### T4. Privilege escalation

Description:
A non-admin user gains admin capabilities through route bugs, token bugs, or role confusion.

Controls:

* explicit RBAC checks
* server-side role enforcement
* no client-side trust
* auditable privileged actions

Residual risk:

* bugs in auth/session implementation could still exist until tested

### T5. Event tampering

Description:
An attacker alters or removes security events to hide activity.

Controls:

* append-first event model
* maintenance-only deletion or rewrite paths
* audit logging for maintenance actions
* future tamper-evident hash chain option

Residual risk:

* local DB compromise by a strong local attacker can still damage history

### T6. Poisoned threat intel

Description:
Bad external data creates false findings or blinds the operator.

Controls:

* connectors disabled by default
* provenance recording
* normalization layer
* per-feed logging and kill switches
* cached snapshots for rollback comparison

Residual risk:

* trusted upstream source compromise remains possible

### T7. Dangerous monolith behavior

Description:
One giant script mixes runtime API, training, scraping, connector code, and admin behavior.

Why this matters:
Failure domains overlap and auditing collapses.

Controls:

* authority separation
* maintenance/runtime split
* narrow first-phase scope

Residual risk:

* project drift can reintroduce monolith patterns if not enforced

### T8. Read-only collector drift into remediation

Description:
Collectors that should inspect only begin changing host state.

Controls:

* collector authority defined as read-only by default
* remediation requires future explicit contract
* tests for unsupported mutation attempts

Residual risk:

* shell-outs or helper code could violate this if not reviewed carefully

### T9. XSS or unsafe UI rendering

Description:
Local UI renders untrusted strings unsafely.

Controls:

* Jinja autoescaping
* avoid raw HTML rendering of event details
* keep client-side JS small and boring

Residual risk:

* future dashboards can still introduce rendering bugs

### T10. Local malware abuse of Security Local

Description:
Malware already on the machine uses local secrets, tokens, DB access, or routes.

Controls:

* minimize secret exposure
* reduce privileged routes
* bind localhost only
* prefer short-lived tokens
* audit admin actions

Residual risk:

* if host compromise is deep, the app cannot fully defend itself

---

## Abuse Cases

### Abuse case 1

A developer adds a future feature and binds the server to all interfaces for convenience.

Expected response:

* startup refusal in local-safe mode
* contract violation

### Abuse case 2

A UI page tries to perform an admin action without server-side role enforcement.

Expected response:

* route denies action regardless of client state

### Abuse case 3

A connector returns malformed or malicious intel data.

Expected response:

* normalization rejects or quarantines it
* error is logged
* connector can be disabled

### Abuse case 4

An operator wants “just one little auto-install” to fetch missing front-end tooling.

Expected response:

* rejected by package policy

### Abuse case 5

A collector script attempts to disable a firewall rule from a read-only route.

Expected response:

* forbidden by collector contract
* requires future maintenance/remediation path if ever allowed

---

## Security Controls by Layer

### Configuration layer

* required key validation
* safe defaults
* non-local bind refusal
* no secret echo

### Auth layer

* hashed passwords
* explicit role checks
* short-lived tokens later
* audited privileged operations

### Data layer

* explicit writes only
* authority ownership
* append-first event design
* future migrations instead of ad hoc schema changes

### Runtime layer

* localhost bind only
* debug off
* no runtime installs
* no auto-training
* no hidden maintenance endpoints

### Connector layer

* disabled by default
* feed-specific timeouts/retries
* provenance and logging
* normalization before storage

### UI layer

* server-rendered pages
* vanilla JS only
* minimal client logic
* escaped rendering

### Maintenance layer

* explicit CLI actions
* logged actions
* separate from ordinary runtime requests

---

## Out of Scope for Phase 1

The following are intentionally not solved yet:

* remote fleet management
* cross-machine trust mesh
* browser push notifications
* full EDR behavior set
* kernel-level tamper resistance
* strong protection against a fully compromised OS
* hardware-backed secret isolation
* enterprise SSO
* distributed detection clustering

These may exist later only through explicit design and contract updates.

---

## Residual Risk Statement

Even with this model, Security Local cannot fully protect itself if:

* the host OS is already deeply compromised
* an attacker has high-privilege local execution
* secrets are stolen from outside the app boundary
* the operator deliberately weakens the local posture

The platform is designed to **reduce avoidable exposure and improve local visibility**, not to act as magical immunity.

---

## Verification Checklist

A change is safer when it can answer yes to these questions:

* does it preserve localhost-only binding
* does it avoid npm and runtime package install
* does it keep secrets out of logs and responses
* does it preserve server-side RBAC
* does it keep collectors read-only unless explicitly changed by contract
* does it avoid merging maintenance behavior into runtime routes
* does it shrink or at least not expand the trusted surface

If the answer is no, the change needs redesign or a contract update.

---

## Summary

Security Local is defending against the most common ways a local defensive tool turns into its own problem:

* accidental exposure
* supply-chain drag-in
* secret leakage
* privilege confusion
* monolithic sprawl
* poisoned external inputs
* audit loss

The posture is simple on purpose:

* local first
* Python only
* no npm
* no silent remote reach
* read before write
* small trusted surface

That simplicity is not a limitation. It is one of the main defenses.
