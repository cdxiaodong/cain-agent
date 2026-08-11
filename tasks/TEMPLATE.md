# Task: <short-kebab-case-summary>

> **Task ID**: `<task_…>` (assigned by Orca)
> **Dispatch ID**: `<ctx_…>` (assigned by Orca)
> **Worker terminal**: `<term_…>` (assigned by Orca)
> **Created**: `YYYY-MM-DD HH:MM`
> **Lead**: @cdxiaodong
> **Status**: `pending | in_progress | done | failed`

---

## 1. Objective

<!-- One paragraph describing what this task must accomplish.  Be concrete —
     name the deliverable (file, module, doc, benchmark run) and the
     acceptance threshold. -->

---

## 2. Allowed files

<!-- Paths this Worker may read AND write.  Paths outside this list are
     off-limits.  Use repo-relative paths. -->

- [ ] `path/to/file_a.py`
- [ ] `path/to/file_b.md`

---

## 3. Forbidden files

<!-- Hard boundaries.  These are NEVER touched by a Worker.  When in doubt,
     add the file here rather than guessing. -->

- `AGENTS.md` (Lead-owned)
- `ROADMAP.md` (Lead-owned)
- `CHANGELOG.md` (Lead-owned)
- `README.md` / `README.zh-CN.md` (Lead-owned)
- `pyproject.toml` (Lead-owned)
- `LICENSE` (Lead-owned)
- `.github/` (Lead-owned)

**Git rules** (see AGENTS.md §4.1): Workers never run `git commit`, `git push`,
`git merge`, or `git tag` — the Lead is the only merge gate.  The coordinator
selects the worktree a Worker edits in: the **current worktree** by default
(which may be on `main`), or an **optional isolated worktree** when the task
requests one or parallel Workers would conflict.  Editing in the current
worktree on `main` is allowed; committing, merging, and tagging are not.
Workers do not create `feat/…` / `fix/…` branches.

---

## 4. Dependencies

<!-- What must exist before this task can start?  Other tasks, merged PRs,
     data files, infra?  Link to the blocking task/dispatch. -->

- [ ] …

---

## 5. Acceptance tests

<!-- Concrete, automatable checks.  Every item must be a yes/no question. -->

- [ ] `ruff check src/ tests/` passes with zero changes
- [ ] `pyright src/ tests/` passes with zero errors
- [ ] `pytest tests/ -v` passes with zero failures
- [ ] New/changed code has corresponding tests
- [ ] …

---

## 6. Security constraints (hard rules)

<!-- Taken from AGENTS.md §4.3.  Check every one before worker_done. -->

- [ ] **Zero real targets** — all fixtures use synthetic hosts (`example.com`, `test.local`, `10.0.0.0/24`)
- [ ] **Zero real credentials** — no API keys, tokens, passwords, or secrets in any file
- [ ] **Zero live network** — all tests mock the Claude Agent SDK and cloud SDKs
- [ ] **No product-runtime invocation** — `cain-agent run` is never called by a Worker
- [ ] **No pentest-agent-mvp code** — never referenced, imported, or copied
- [ ] **No leaked Claude Code code** — never referenced, imported, or copied

---

## 7. Evidence

<!-- Attach concrete proof that the task was done.  Delete rows that don't
     apply; add rows for task-specific checks. -->

| Check | Command / Source | Expected | Actual |
|---|---|---|---|
| Worktree | `git worktree list` | edits confined to the coordinator-selected worktree | |
| Lint | `ruff check src/ tests/` | zero changes | |
| Type-check | `pyright src/ tests/` | zero errors | |
| Unit tests | `pytest tests/ -v` | all pass | |
| Diff summary | `git diff --stat` | only allowed files touched | |

---

## 8. worker_done report

<!-- Fill this section before sending worker_done.  The body is a 3-sentence
     executive summary.  Orca 1.4.179: `--from` / `--dispatch-capability` are
     obsolete — identify the dispatch with `--task-id` / `--dispatch-id`. -->

```bash
orca orchestration send \
  --type worker_done \
  --subject "<short status>" \
  --body "\
<What you did — concrete changes, not intentions.>
<What you found — issues, edge cases, pre-existing breakage.>
<What's left — follow-up the Lead should know about.>" \
  --task-id task_<uuid> \
  --dispatch-id ctx_<uuid> \
  --outcome succeeded|failed \
  --files-modified "path/a,path/b" \
  [--report-path <path-to-artifact>] \
  [--json]
```

---

## 9. Reviewer gate

<!-- The Lead fills this section after reviewing the Worker's output. -->

- [ ] Allowed-files check — only declared files were touched
- [ ] Security-constraints check — all 6 items confirmed
- [ ] Acceptance-tests check — all boxes checked, evidence table filled
- [ ] Code review — diff reviewed, no surprises
- [ ] Merge decision — `approved` / `changes-requested` / `rejected`

**Reviewer**: @cdxiaodong
**Reviewed**: `YYYY-MM-DD HH:MM`
**Decision**: `…`

---

*Template version: 1.0.  This file is the single task template for all
Orca-dispatched cain-agent Workers.  The Lead fills sections 1–6 when
creating a task; the Worker fills sections 7–8 before sending worker_done;
the Lead fills section 9 during review.*
