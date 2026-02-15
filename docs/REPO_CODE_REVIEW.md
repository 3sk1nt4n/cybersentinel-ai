# Repository Code Review (High-Level)

_Date:_ 2026-02-15  
_Scope:_ backend + frontend source in this repository (static review, no runtime integration test stack)

## Executive Summary

The project is a strong prototype with clear modular separation (routers/services/core, and frontend API encapsulation), but there are several **production-critical security and reliability gaps** that should be addressed before internet exposure.

- **Critical:** no auth/authorization on sensitive control-plane endpoints.
- **High:** scanner command execution model can misreport failed scans as success.
- **High:** secrets/config handling has insecure defaults and plaintext persistence.
- **Medium:** runtime dependency installation in service startup introduces supply-chain and availability risk.

## Key Findings

### 1) Missing authentication/authorization on security-sensitive endpoints (**Critical**)

The API registers operational endpoints (`/api/scan`, `/api/settings`, `/api/intel`, etc.) without any auth dependency or token checks in routers. Anyone with network access to the backend can run scans and mutate provider/API-key settings.

**Evidence:**
- Router registration with no auth guards in app bootstrap: `backend/app/main.py`.
- Settings update endpoint accepts writes directly: `backend/app/routers/settings.py`.
- Scan run endpoint executes scans directly from request data: `backend/app/routers/scan.py`.

**Recommendation:**
- Add API-key or JWT middleware/dependency for all `/api/*` endpoints.
- Introduce role checks for write operations (`/settings/update`, scan execution).
- Restrict CORS and bind backend to private network in compose defaults.

### 2) Scan success semantics can mask real failures (**High**)

`_run_in_sandbox` sets `"success": True` whenever any output exists, even if exit code is non-zero. Many tooling errors can still generate output and be incorrectly reported as successful scans.

**Evidence:** `backend/app/services/scanner.py` (`success=True` unconditional return with exit code captured but not used for success decision).

**Recommendation:**
- Set `success = (proc.returncode == 0)` as primary rule.
- If specific tools require stderr-on-success handling, implement per-tool exception rules.
- Return structured status fields (`status`, `stderr`, `stdout`, `exit_code`) to UI.

### 3) Command construction remains brittle despite sanitization (**High**)

Most scan functions build shell strings and execute via `bash -c`. Current sanitization is blacklist-based and fragile.

**Evidence:**
- `docker exec ... bash -c <command>` execution pattern.
- String interpolation of user-derived values across scan commands.

**Recommendation:**
- Replace shell-string execution with argument-vector execution where possible.
- Add strict allowlist validators for targets/options (domain/IP/URL parsers).
- Disallow raw free-form options from untrusted users in public mode.

### 4) Insecure default secrets in configuration (**High**)

Default values include predictable secret material (e.g., app secret and Neo4j password).

**Evidence:** `backend/app/core/config.py` has `secret_key="change-me"` and hardcoded `neo4j_password` default.

**Recommendation:**
- Fail fast on startup if required secrets are unchanged.
- Remove sensitive defaults from code and require `.env`/secret store injection.
- Add docs warning + sample random generation command in setup docs.

### 5) Plaintext persistence of API keys in writable env file (**High**)

Settings updates are written directly into `settings.env`/`.env` in plaintext.

**Evidence:** `backend/app/routers/settings.py` writes `ENV_KEY=value` lines without encryption or file-permission hardening.

**Recommendation:**
- Store sensitive keys in a dedicated secret backend (or Docker secrets at minimum).
- If file persistence is required, restrict permissions (`0600`) and separate non-secret config from secrets.
- Add audit logging for config mutations (who/when/what key class).

### 6) Runtime `pip install` in service path (**Medium**)

Threat intel puller attempts to install `requests` at runtime if missing.

**Evidence:** `backend/app/services/threat_intel_puller.py` executes `os.system("python -m pip install requests --quiet")`.

**Recommendation:**
- Remove runtime installs; pin dependencies in `requirements.txt` and fail with actionable startup errors.
- Enforce immutable container images for reproducibility.

### 7) Broad exception swallowing reduces observability (**Medium**)

Startup/lifespan initialization catches broad exceptions and often suppresses them (`pass`), which can hide broken dependencies and produce partial startup states.

**Evidence:** multiple `except Exception: pass` blocks in `backend/app/main.py` lifespan setup.

**Recommendation:**
- Log exceptions with structured logger and component tags.
- Mark critical subsystem failures as unhealthy in `/health/full`.

## Positive Notes

- Good modular decomposition of routers/services/core and readable naming.
- Parameterized SQL usage in chat history service avoids basic SQL injection risks.
- Frontend API abstraction is centralized and easy to evolve.

## Suggested Prioritized Remediation Plan

1. **Week 1 (Blockers):** authn/authz for `/api`, secure secrets handling, scanner success semantics fix.
2. **Week 2:** harden scanner input validation and remove shell-string command execution where feasible.
3. **Week 3:** observability cleanup (structured logs, no silent exceptions), dependency immutability hardening.

## Validation Performed

- Syntax sanity check: Python compile pass for `backend/app`.
- Manual static inspection of representative backend and frontend modules.
