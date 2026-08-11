# AGENTS.md — Orca-managed development collaboration contract for cain-agent

> **This file is the single source of truth for how humans and AI agents
> collaborate on this codebase under Orca orchestration.**  Every agent
> dispatched into this repository must follow these rules.  The file is
> maintained by the project Lead (human) and read by all Workers (AI agents).

---

## 1. Project identity

| Field | Value |
|---|---|
| **Product** | Cain — Real-world AI Penetration Testing Engineer |
| **Product runtime** | `cain-agent run --target …` — a CLI that drives an AI-powered penetration-testing pipeline (**recon → test → report**) |
| **Runtime LLM** | Claude Agent SDK (`claude-agent-sdk>=0.2.0`) |
| **License** | Apache-2.0 |
| **Repo** | `https://github.com/cdxiaodong/cain-agent` |
| **Git user** | `cdxiaodong` (noreply GitHub email) |
| **Default branch** | `main` |

---

## 2. External Orca orchestration vs product runtime

This distinction is critical — confusing the two leads to broken builds and
commit-amendment loops:

| | **Orca orchestration layer** | **cain-agent product runtime** |
|---|---|---|
| **What it is** | How humans + AI agents collaborate to *build* cain-agent | What cain-agent *does* when users run it |
| **Who acts** | Orca-dispatched Workers (AI agents), supervised by a human Lead | End users: `pip install cain-agent && cain-agent run --target example.com` |
| **Entry point** | Orca `task_*` dispatch → Worker terminal → `orca orchestration send worker_done` | `src/cain_agent/cli.py:main()` → `Orchestrator.run()` |
| **Tools** | Read/Write/Edit/Bash/Grep/Glob (repository editing) | Bash (sandboxed, ScopeGuard-filtered) |
| **Safety** | CI (ruff + pyright + pytest) | ScopeGuardHook (allow/deny lists), `--i-have-authorization` gate, credential redaction |
| **Files touched** | Source, tests, docs, config, CI, skills | Workspace directory (`./workspace/`) — never the repo |

**Rule:** An agent working on the orchestration layer must **never** invoke
`cain-agent run` against a real target.  Product-runtime execution belongs to
the end user with written authorization.

> **Target architecture vs current wiring.**  The Claude Agent SDK pipeline
> described above (and in §8) is the **target architecture**; the classic
> Route A wiring below is what `cmd_run` actually does today.  As of
> 2026-08-11, `src/cain_agent/cli.py:cmd_run` injects the **classic handlers
> route** via `Orchestrator(executor, workspace, handlers=...)`:
> `make_recon_handler` / `make_test_handler` (`src/cain_agent/handlers.py`)
> drive recon/test and **share the discovery executor**, while
> `make_report_handler` (`src/cain_agent/pipeline.py`) drives
> `FindingsPipeline` through a **separate validation executor** — discovery
> and validation never share a session (dual-session validation, §8.5).  Two
> things remain intentionally out of this route: the BreachWeave multi-agent
> bridge `create_multi_agent_handlers`
> (`src/cain_agent/multi_agent/handler.py`) is **not wired** — classic Route A
> is the default path — and the report stage still writes only a placeholder
> (`report-placeholder.json`); real report markdown is a later concern.  The
> Orchestrator's default `placeholder_handler` (`src/cain_agent/orchestrator.py`)
> remains only as a fallback for callers that pass no handlers; `cmd_run` does
> not use it.

---

## 3. Roles: Lead vs Worker

### Lead (human — @cdxiaodong)

- **Owns:** architecture decisions, roadmap priority, public API surface,
  `AGENTS.md`, `ROADMAP.md`, `CHANGELOG.md`, `README.md`, `pyproject.toml`
  version bumps
- **Owns `main` branch exclusively** — Workers never commit or push to `main`;
  only the Lead merges
- Reviews and approves Worker output before merge
- Runs `cain-agent` product against real authorized targets (never a Worker's
  job)

### Worker (Orca-dispatched AI agent — you)

- **Owns:** implementation of discrete tasks assigned via Orca dispatch
- Works in the **current worktree** the coordinator selected — that worktree
  may be on `main` — and never commits, pushes, merges, or tags (see §4.1)
- Produces a `worker_done` report with evidence (see §7)
- Escalates via `orca orchestration ask` when a decision is genuinely the
  Lead's to make
- Follows the rules in this file without exception

---

## 4. Worker constraints (hard rules)

### 4.1 Git — Workers never commit, push, merge, or tag

- **Never** run `git commit`, `git push`, `git merge`, or `git tag`.
- **Never** modify `.git/config` or change the remote URL.
- The coordinator selects the worktree a Worker edits in; when that is the
  **current worktree** it may be on `main`.  Editing there is allowed — the
  prohibition is on `commit`/`push`/`merge`/`tag`, not on the branch name.
- If a task description implies a commit is needed, escalate to the Lead.
- The only git operations allowed: `git branch`, `git status`,
  `git diff`, `git log` (read-only).

### 4.2 File scopes — disjoint ownership

Each Worker task receives an explicit file-scope list.  Do **not** touch files
outside that list.  When in doubt, check with the Lead.

> An explicit file-scope list in a task file **overrides** the default
> ownership table below.  If a task file authorizes a file this table lists as
> Lead-owned (e.g. `AGENTS.md`), the Worker may edit it within the task's
> scope.

| Owner | Scope |
|---|---|
| **Lead** | `AGENTS.md`, `ROADMAP.md`, `CHANGELOG.md`, `README.md`, `README.zh-CN.md`, `pyproject.toml`, `LICENSE`, `.github/` |
| **Worker (per task)** | Assigned by the Lead; typically a subset of `src/`, `tests/`, `skills/`, `bench/`, `docs/` |
| **Shared (read-only for Workers)** | `src/cain_agent/__init__.py`, `src/cain_agent/cli.py`, `src/cain_agent/scope.py`, `src/cain_agent/orchestrator.py` |

### 4.3 Authorized-security constraints

**cain-agent is a penetration-testing tool. Every Worker MUST respect these
constraints as hard engineering rules, not AI self-discipline:**

1. **Zero real targets in tests.**  All test fixtures use synthetic hosts
   (`example.com`, `public.example.com`, `test.local`, `10.0.0.0/24`,
   `192.168.0.0/16`).  Public (non-local) fixtures use synthetic domains
   (`example.com` / `public.example.com`), never a real resolver IP.  Never
   hard-code a real IP, domain, or URL in any test or source file.

2. **Zero real credentials.**  No API keys, tokens, passwords, or secrets
   anywhere in the repository — not in source, not in tests, not in docs, not
   in comments, not in commit messages.

3. **Zero live network in tests.**  Tests mock the Claude Agent SDK (see
   `tests/test_executor.py` — `_install_fake_query`), mock cloud SDKs
   (`oss2`, `boto3`, etc.), and never open real TCP connections.  If a test
   requires network behavior, use `pytest.monkeypatch` or `unittest.mock`.

4. **No product runtime invocation.**  Workers never run `cain-agent run`
   against any target (local or remote).  The product is for end users only.

5. **Reporting real vulnerabilities.**  If a Worker accidentally discovers a
   real vulnerability in a dependency, it must escalate to the Lead
   immediately via `orca orchestration send --type escalation`.

### 4.4 Worktrees — optional, conflict-driven

- A fresh Worker terminal works in the **current worktree** it was launched
  in.  Separate Orca worktrees are **optional** — created only when a task
  explicitly requests one or concrete conflicts (e.g. parallel Workers
  editing the same files) require isolation.
- A Worker writes files **only inside the worktree the coordinator selected**.
- When a Worker completes, the Lead reviews changes and decides whether to
  merge into `main`.

---

## 5. Test discipline

### 5.1 Required verification commands

Before a Worker reports `worker_done`, it must run **all three** of these
commands from the repository root and confirm they pass:

```bash
# 1. Lint (zero changes expected)
ruff check src/ tests/

# 2. Type-check (zero errors expected)
pyright src/ tests/

# 3. Unit tests (all pass, zero failures)
pytest tests/ -v
```

If any command fails, the Worker must fix the issue before reporting done.
If the failure is pre-existing (not caused by the Worker's changes), the
Worker must note it in the `worker_done` body.

### 5.2 Test patterns (do these, not that)

- ✅ `pytest.monkeypatch` to replace `cain_agent.executor.query` — see `tests/test_executor.py`
- ✅ `asyncio.run()` for async hook tests — no `pytest-asyncio` dependency
- ✅ `capsys` for CLI output capture — see `tests/test_smoke.py`
- ✅ `Scope(in_scope=[…], out_of_scope=[…])` for scope tests — see `tests/test_scope.py`
- ❌ Real network calls, real SDK calls, real cloud API calls
- ❌ Hard-coded credentials or real target hosts

---

## 6. Worker completion protocol

### 6.1 `worker_done` — the single required handshake

Every Worker **must** send exactly one `worker_done` before exiting:

```bash
orca orchestration send \
  --type worker_done \
  --subject "<short status>" \
  --body "<3-sentence executive summary>" \
  --task-id task_<uuid> \
  --dispatch-id ctx_<uuid> \
  --outcome succeeded|failed \
  --files-modified "path/a,path/b" \
  [--report-path <path-to-artifact>] \
  [--json]
```

### 6.2 Evidence required

The `--body` must answer three questions:

1. **What you did** — concrete changes, not intentions
2. **What you found** — any issues, edge cases, or pre-existing breakage
3. **What's left** — any follow-up the Lead should know about

For tasks that produce significant output (reports, design docs, benchmarks),
include `--report-path <path-to-artifact>` so the Lead can read the full
result.

### 6.3 Heartbeats (optional)

Heartbeats are **optional**: send one only when the live dispatch preamble
explicitly asks for a heartbeat, and only while actively working.  Use a JSON
payload carrying the dispatch context (`taskId`, `dispatchId`, `phase`) rather
than the obsolete `--from`/`--dispatch-capability` flags:

```bash
orca orchestration send \
  --type heartbeat --subject "alive" \
  --payload '{"taskId": "task_<uuid>", "dispatchId": "ctx_<uuid>", "phase": "implementing"}'
```

### 6.4 Communication

- **Questions** → `orca orchestration ask --question "…"`
- **Blocker** → `orca orchestration send --type escalation --subject "Blocked: …"`
- **Never** use `AskUserQuestion` — the Orca coordinator cannot see TUI prompts.

---

## 7. Repository structure (what lives where)

```
cain-agent/
├── src/cain_agent/         # Product runtime (Python package)
│   ├── cli.py              # CLI entry point
│   ├── orchestrator.py     # Deterministic state machine (recon→test→report)
│   ├── executor.py         # Claude Agent SDK wrapper
│   ├── scope.py            # ScopeGuard: YAML allow/deny + PreToolUse hook
│   ├── workspace.py        # Workspace manager (external memory)
│   ├── validator.py        # FindingValidator (separate session)
│   ├── findings.py         # Finding dedup + severity
│   ├── redact.py           # Credential redaction
│   ├── pipeline.py         # Pipeline utilities
│   ├── cloud/              # Cloud attack modules (7 providers)
│   ├── multi_agent/        # Multi-agent framework (BreachWeave)
│   └── toolchain/          # T3MP3ST toolchain (46 tools)
├── tests/                  # pytest suite (zero real network/credentials)
├── skills/                 # 65+ cloud attack skill definitions
├── bench/                  # Benchmark framework + config
├── docs/                   # Technical articles + design docs
├── templates/              # Config templates (scope, etc.)
├── tasks/                  # Lead's task dispatch files
├── exploits/               # Reconstructed exploit references
├── tools/                  # Auxiliary tool scripts
├── Dockerfile              # Docker one-click run
├── pyproject.toml          # Build config + tool settings
├── AGENTS.md               # ← This file (Orca collaboration contract)
├── ROADMAP.md              # Phase tracking (Lead-owned)
├── CHANGELOG.md            # Release notes (Lead-owned)
└── README.md               # Public-facing README (Lead-owned)
```

---

## 8. Key design invariants (do not break)

These are the architectural invariants documented in the source and enforced
by CI.  A Worker's changes must preserve every one of them.

1. **Deterministic state machine** — `orchestrator.py:STAGES = ("recon", "test", "report")` is hard-coded; no external stage injection.
2. **Scope is engineering, not AI** — `scope.py:ScopeGuardHook` blocks tool calls before the LLM sees them; scope enforcement is not a prompt-level suggestion.
3. **Workspace is the truth** — all state lives as files in `./workspace/`
   (`state.json` is written durably after each stage, and `Orchestrator.load_state`
   reads it back).  The state files are durable and traceable, but crash-resume
   is **not** implemented: `Orchestrator.run()` always restarts at `recon`, and
   re-running a completed stage raises `StageOrderError`.  Treat `state.json` as
   durable memory, not as a resume checkpoint.
4. **Dual-LLM split** — Planner (strategy) / Executor (Claude Agent SDK, tactics) run in separate sessions.
5. **Validation loop** — Finder and Validator agents run in independent sessions (no self-verification).
6. **Read-only by default** — the tool whitelist starts as `["Bash"]`; all tools must be explicitly allowed.
7. **Zero real data** — no API keys, real targets, or network calls in the repository itself (see §4.3).

---

## 9. Quick reference for Workers

```bash
# Before reporting done — all three must pass:
ruff check src/ tests/        # lint
pyright src/ tests/           # type-check
pytest tests/ -v              # unit tests

# Which branch am I on?
git branch --show-current

# What did I change?
git diff --stat
```

---

*Last updated: 2026-08-11.  This file is maintained by the project Lead.
Workers: if you find an ambiguity or missing rule, escalate — do not guess.*
