# Orca Orchestration for cain-agent Development

> **Audience**: Orca-dispatched Workers (AI agents) and the human Lead
> supervising cain-agent development.
>
> **Prerequisite**: Read `AGENTS.md` first — this guide explains *how* the
> orchestration machinery works; AGENTS.md defines *what* every Worker must
> obey.

---

## 1. The two-layer architecture

cain-agent development runs on **two distinct layers**.  Confusing them is
the single most common mistake a Worker can make.

```
┌──────────────────────────────────────────────────────────┐
│                    Orca orchestration layer               │
│  (how humans + AI agents collaborate to BUILD cain-agent) │
│                                                          │
│  Lead ──▶ Run ──▶ Task DAG ──▶ Worker ──▶ worker_done    │
│                  (dispatch)      (AI agent)   ──▶ review  │
│                                                 ──▶ merge │
├──────────────────────────────────────────────────────────┤
│                cain-agent product runtime                 │
│  (what cain-agent DOES when end users run it)             │
│                                                          │
│  $ cain-agent run --target example.com                   │
│  ──▶ CLI ──▶ Orchestrator (recon→test→report)            │
│       ──▶ Claude Agent SDK (LLM tactics)                 │
│       ──▶ ScopeGuardHook (safety)                        │
│       ──▶ Workspace (external memory)                    │
└──────────────────────────────────────────────────────────┘
```

| | **Orca orchestration layer** | **cain-agent product runtime** |
|---|---|---|
| **Purpose** | Coordinate AI agents that *build* cain-agent | Execute AI-powered penetration tests |
| **Entry point** | Orca dispatch → Worker terminal → `orca orchestration send worker_done` | `src/cain_agent/cli.py:main()` |
| **LLM runtime** | Claude (the Worker itself) — reads/writes repo files | **Claude Agent SDK** (`claude-agent-sdk>=0.2.0`) — the product's embedded AI |
| **Who acts** | Orca-dispatched Workers supervised by the human Lead | End users with written authorization |
| **Tools** | Read, Write, Edit, Bash, Grep, Glob (repo editing) | Bash (sandboxed, ScopeGuard-filtered) |
| **Safety** | CI (ruff+pyright+pytest), Lead review gate | `--i-have-authorization` gate, ScopeGuardHook, credential redaction |
| **Files touched** | `src/`, `tests/`, `skills/`, `bench/`, `docs/` | `./workspace/` — never the repo |

**Hard rule**: The Claude Agent SDK is the **product runtime** — it powers
`cain-agent run` for end users.  Orca coordinates the **development** of
cain-agent.  A Worker never invokes the product runtime against a real
target; a Worker never uses the Claude Agent SDK to edit repository files.

### 1.1 Current runtime vs target architecture

The product-runtime diagram above is the **target architecture**; the classic
Route A wiring below is what `cmd_run` actually does today.  As of 2026-08-11:

- `src/cain_agent/cli.py:cmd_run` injects the **classic handlers route** into
  `Orchestrator(executor, workspace, handlers=...)` via `_build_handlers`:
  `make_recon_handler` / `make_test_handler` (`src/cain_agent/handlers.py`)
  drive recon/test and **share the discovery executor**;
  `make_report_handler` (`src/cain_agent/pipeline.py`) drives
  `FindingsPipeline` through a **separate validation executor**, so discovery
  and validation never share a session (dual-session validation).  The
  `recon → test → report` loop now produces real recon/test artifacts and a
  validated findings summary.
- Two things remain intentionally out of this route: the BreachWeave
  multi-agent bridge `create_multi_agent_handlers`
  (`src/cain_agent/multi_agent/handler.py`) is **not wired** — classic Route A
  is the default path, the multi-agent bridge is a separate later path — and
  the report stage still writes only a placeholder (`report-placeholder.json`);
  real report markdown is a later concern.
- The Orchestrator's default `placeholder_handler`
  (`src/cain_agent/orchestrator.py`) remains only as a fallback for callers
  that pass no handlers; `cmd_run` does not use it.

So a Worker reading the product diagram should treat it as the intended end
state, with the classic handlers route as the current reality.

---

## 2. AionUi vs Orca — who does what

Both tools appear in the cain-agent workflow, but their responsibilities are
completely disjoint.

### AionUi

AionUi is the **local control plane** for the agent environment that hosts
cain-agent development — the desktop surface where the human Lead configures
and monitors local agents.  AionUi handles:

- **Conversations** — managing local agent conversations/sessions
- **Models** — selecting and configuring the LLM models local agents run on
- **MCP servers** — managing which MCP server connections local agents can use
- **Skills** — managing the skill library local agents can load
- **Cron** — scheduling recurring local jobs (e.g. the production-line
  wake-ups described in `CHANGELOG.md`)

AionUi is **not** the cain-agent product UI.  There is no implementation
evidence in this repository of a finding browser, scope editor, workspace
explorer, or end-user penetration-testing interface; those would be product
features of `cain-agent run` and are out of scope here.  AionUi is also not
the coordination layer — it does not dispatch development tasks, track Worker
completion, or manage Worker terminals.

### Orca

Orca is the **development coordination platform** for cain-agent.  It manages:

- **Task dispatch** — the Lead creates tasks; Orca delivers them to Worker
  terminals
- **Terminal management** — a fresh agent terminal runs in the current
  worktree by default; separate Orca worktrees are **optional**, used only
  when a task requests one or concrete conflicts (e.g. parallel Workers
  editing the same files) require isolation
- **Communication** — `orca orchestration ask` for questions,
  `worker_done` for completion, `escalation` for blockers
- **Message loop** — check / wait / release / ack for reliable, idempotent
  delivery (see §3.3)
- **Artifact tracking** — every Worker's output is recorded in the Dispatch
  Run for the Lead to review

Orca is **not** involved in running cain-agent against targets.  It is a
development tool, never a product dependency.

| Responsibility | AionUi | Orca |
|---|---|---|
| Configure local agent models / MCP / Skills / Cron | ✅ | — |
| Dispatch development tasks to AI Workers | — | ✅ |
| Track Worker completion and evidence | — | ✅ |
| Route Worker questions to the Lead | — | ✅ |
| Provide isolated worktrees when Workers collide | — | ✅ (optional) |

---

## 3. The full orchestration flow

### 3.1 Overview

```
Lead creates Run
      │
      ▼
  Task DAG (one or more tasks, sequenced or parallel)
      │
      ├──▶ Task A ──▶ Worker terminal ──▶ worker_done ──▶ Lead review ──▶ merge?
      │
      ├──▶ Task B ──▶ Worker terminal ──▶ worker_done ──▶ Lead review ──▶ merge?
      │
      └──▶ Task C (depends on A + B) ──▶ …
      │
      ▼
  Release (Lead cuts a release from merged main)
```

### 3.2 Step by step

#### Step 1 — Lead creates a Run

The Lead decides what work needs to be done (from `ROADMAP.md` or ad-hoc)
and creates an Orca **Run**.  A Run is a container for one or more Tasks.

#### Step 2 — Lead builds the Task DAG

Each Task is a self-contained unit of work with:

- A **task file** (using the template at `tasks/TEMPLATE.md`) that declares
  the objective, allowed files, forbidden files, dependencies, acceptance
  tests, and security constraints
- A **dispatch** that binds the task to a specific Worker terminal

Tasks can be sequenced (B starts after A completes) or run in parallel (A
and B dispatched simultaneously).  The DAG encodes these relationships.

#### Step 3 — Worker terminal receives dispatch

Orca delivers the task to a Worker terminal with a preamble that includes:

- The Worker's terminal handle (`term_<uuid>`)
- The task ID (`task_<uuid>`)
- The dispatch ID (`ctx_<uuid>`)
- The CLI commands available (`check`, `reply`, `ask`, and `send` with
  `worker_done`, `heartbeat`, `escalation` types)

The Worker reads `AGENTS.md` for the collaboration contract, then starts
work.

#### Step 4 — Worker executes the task

The Worker:

1. Reads the task file to understand the objective and constraints
2. Works in the **current worktree** by default — a fresh terminal does not
   create a branch or switch worktrees unless the task file explicitly
   requests one
3. Implements the changes, **only touching files in the allowed list**
4. Runs the verification commands: `ruff check`, `pyright`, `pytest`
5. Fills the evidence table in the task file
6. Sends `worker_done` with a 3-sentence executive summary

While actively working on a long task, the Worker may send periodic
**heartbeats** so the Lead can distinguish "still thinking" from "hung".
Heartbeats are optional — send them only when the live dispatch preamble asks
for one.  A blocked `orca orchestration ask` needs no heartbeat (the blocked
call itself shows the Worker is alive); `orca orchestration check --wait`
emits JSON keepalive lines to stderr while it waits, which let the caller tell
the process is alive, but those keepalives are **not** heartbeat messages.  If
the Worker hits a decision that belongs to the Lead, it uses
`orca orchestration ask` — never `AskUserQuestion`.

#### Step 5 — Lead reviews the Worker's output

The Lead:

1. Reads the `worker_done` body and any attached report
2. Checks the evidence table (lint, type-check, tests, diff)
3. Reviews the actual code changes
4. Fills the **reviewer gate** in the task file:
   - Allowed-files check
   - Security-constraints check
   - Acceptance-tests check
   - Code review
   - Merge decision (`approved` / `changes-requested` / `rejected`)

#### Step 6 — Lead merges (or re-dispatches)

If approved, the Lead integrates the Worker's changes into `main`.  Only the
Lead touches `main` — Workers never commit, push, or merge.

If changes are requested, the Lead creates a follow-up task or re-dispatches
the same task with feedback.

#### Step 7 — Release

When enough work has accumulated on `main`, the Lead:

1. Updates `CHANGELOG.md` with the new entries
2. Bumps the version in `pyproject.toml`
3. Tags the release: `git tag vX.Y.Z`
4. Pushes the tag: `git push origin vX.Y.Z`
5. Updates `ROADMAP.md` checkboxes

### 3.3 Coordinator ↔ Worker message loop (check / wait / release / ack)

Deliveries between the coordinator and a Worker are FIFO and idempotent: a
Delivery is replayed until the Worker acknowledges it.

1. **check** — `orca orchestration check` returns the **bound Run's oldest
   full Delivery batch** (one or more messages delivered as a unit).  The
   bound Run replays the same Delivery until it is acked.  `--peek` reads
   without marking read; `--all` returns the full message history.
2. **wait** — `orca orchestration check --wait [--timeout-ms <n>]` blocks
   until a matching Delivery arrives or the timeout expires.  While blocked
   it emits a JSON keepalive line every 15s to stderr so the caller can tell
   the process is alive; keepalives are transport-level liveness, not
   heartbeat messages.
3. **release** — for a settled Worker (`worker_done` with `succeeded` or
   `failed`) whose `worker_done` the coordinator accepts, release comes
   **before** the ack: `orca orchestration worker-release --dispatch
   <dispatch_id>` closes that Worker's terminal (the output archive is
   preserved for later reads).  A retained terminal stays live for debugging.
4. **ack** — after the batch has been processed and — for an accepted
   `worker_done` — after release, `--ack <delivery_id>` acknowledges the
   Delivery; it is replayed until acked.  **Process every message before
   acknowledging.**

`orca orchestration ask --question "…"` is a blocking variant of the loop: it
records a **question message** in the Dispatch Run and blocks until the
coordinator replies, then prints the reply.  (A decision gate is a separate
construct, created with `orca orchestration gate-create`.)
`orca orchestration reply --id <msg_id> --body "…"` answers an individual
message.

---

## 4. Worker lifecycle (what you, the AI agent, actually do)

```
Receive dispatch
      │
      ▼
Read AGENTS.md + task file
      │
      ▼
Work in current worktree (separate worktree only if the task requests it)
      │
      ▼
Implement changes (only allowed files)        ◀── heartbeat during long work
      │
      ▼
ruff check + pyright + pytest                 ◀── fix failures, re-run
      │
      ▼
Fill evidence table in task file
      │
      ▼
Send worker_done ──▶ STOP.  Do not start new work.
```

### 4.1 Communication during work

| Situation | Command |
|---|---|
| Long active work — optional liveness (only if preamble asks) | `orca orchestration send --type heartbeat --payload '{"taskId":"…","dispatchId":"…","phase":"…"}'` |
| Poll / block for coordinator messages | `orca orchestration check [--wait] [--timeout-ms <n>]` |
| Acknowledge a processed message batch | `orca orchestration check --ack <delivery_id>` |
| Need Lead decision | `orca orchestration ask --question "…"` |
| Hit a hard blocker | `orca orchestration send --type escalation` |
| Task complete | `orca orchestration send --type worker_done` |

### 4.2 After worker_done

**Stop.**  The Worker's turn ends when `worker_done` is sent.  Do not start
new work, do not poll for messages, do not run cleanup.  If the Lead has
more work, a fresh dispatch arrives with a new preamble — treat it as a new
session.

---

## 5. Task file format

Every task uses the template at `tasks/TEMPLATE.md`.  The template captures:

| Section | Who fills it | When |
|---|---|---|
| Objective (§1) | Lead | Task creation |
| Allowed files (§2) | Lead | Task creation |
| Forbidden files (§3) | Lead | Task creation |
| Dependencies (§4) | Lead | Task creation |
| Acceptance tests (§5) | Lead | Task creation |
| Security constraints (§6) | Lead | Task creation |
| Evidence (§7) | Worker | Before `worker_done` |
| worker_done report (§8) | Worker | Before `worker_done` |
| Reviewer gate (§9) | Lead | During review |

Task files live in `tasks/` with the naming convention
`YYYY-MM-DD-<am|pm|session>.md` for time-boxed sessions, or
`task-<slug>.md` for individual tasks.

---

## 6. Key invariants (do not break)

These are the rules that keep the orchestration layer from corrupting the
product or colliding with other Workers:

1. **Fresh Workers use the current worktree** — a new agent terminal works
   in the worktree it was launched in.  Separate Orca worktrees are optional,
   used only when a task requests one or concrete conflicts (e.g. parallel
   Workers editing the same files) require isolation.
2. **Workers do not commit, push, merge, or tag** — the coordinator selects
   the worktree a Worker edits in (fresh terminals stay in the current
   worktree, which may be on `main`); Workers leave every commit, branch, and
   merge decision to the Lead.
3. **Workers never invoke `cain-agent run`** — product execution is for end
   users with authorization, never for development agents.
4. **Claude Agent SDK is product-only** — it powers `cain-agent run`, not
   Orca task execution.  A Worker uses the Orca harness (Read/Write/Edit/Bash),
   not the SDK.
5. **Every `worker_done` carries evidence** — lint, type-check, and test
   results are non-negotiable.
6. **The Lead is the sole merge gate** — no Worker output reaches `main`
   without human review.

---

## 7. Quick reference

```bash
# What am I working on?
cat tasks/<task-file>.md

# Which worktree am I in? (fresh terminals stay in the current worktree)
git worktree list

# Verification (all three must pass before worker_done)
ruff check src/ tests/
pyright src/ tests/
pytest tests/ -v

# Send completion (Orca 1.4.179: omit --from unless impersonating;
# --dispatch-capability is obsolete)
orca orchestration send \
  --type worker_done \
  --subject "<short status>" \
  --body "<3-sentence summary: what you did, what you found, what's left>" \
  --task-id task_<uuid> \
  --dispatch-id ctx_<uuid> \
  --outcome succeeded \
  --files-modified "path/a,path/b" \
  [--report-path <path-to-artifact>] \
  [--json]

# Poll / block for coordinator messages, then acknowledge the batch
orca orchestration check [--wait] [--timeout-ms <n>]
orca orchestration check --ack <delivery_id>
```

---

*Last updated: 2026-08-11.  Maintained as part of the cain-agent
orchestration documentation.  Workers: if the flow described here differs
from what you observe, escalate — the doc may be stale.*
