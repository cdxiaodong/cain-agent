# Cain — Real-world AI Penetration Testing Engineer

> 🚧 Under active development. Star & watch for updates.

**Cain** is an AI penetration testing engineer built for **real-world authorized security assessments** — not a CTF toy. It understands business logic, maintains a global attack state machine, adapts to real WAF/risk-control environments, and ships with a built-in **cloud penetration module** covering AWS / Azure / GCP / 阿里云 / 腾讯云 / 华为云.

Built on [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk).

## Why Cain

| | CTF/靶场型 Agent | **Cain (实战型)** |
|---|---|---|
| Target | Static labs, preset flags | Real enterprise assets, bug bounty, authorized engagements |
| Vulnerability focus | Known syntax-pattern vulns | **Business logic flaws, auth chains, cloud misconfigurations** |
| Environment | No WAF, no rate limiting | Real WAF / risk control with dynamic strategy adjustment |
| Deliverable | A flag | Auditable evidence chain + reproducible PoC + remediation advice |


## Features

- 🎯 **Real-world Focus**: Business logic flaws, auth chains, cloud misconfigurations
- ☁️ **Cloud Native**: AWS / Azure / GCP / 阿里云 / 腾讯云 / 华为云 coverage
- 🔒 **Safety First**: Read-only by default, scope enforcement, credential redaction
- 🤖 **AI-Powered**: Claude Agent SDK with deterministic orchestration
- 📊 **Benchmark**: XBOW + self-built vulnerable-terraform evaluation
- 🛡️ **OWASP Top10**: SQLi, XSS, SSRF, CSRF, File Upload, XXE, Command Injection, Path Traversal

## Core Design

> **Deterministic engineering constrains agent freedom** — stage transitions, scope enforcement, and dangerous-operation circuit breakers are hard engineering constraints; path selection and evidence analysis are left to the agent.

- **Orchestrator** — deterministic Python state machine (recon → test → framework → report)
- **Dual-LLM split** — Planner (strategy) / Executor (Claude Agent SDK, tactics)
- **Hook-based safety** — PreToolUse scope guard, credential redaction, token budget circuit breaker
- **Workspace external memory** — all state as files; crash-resumable, auditable
- **Validation loop** — finder/validator agent separation, 4-state structured verdicts
- **Cloud module (unique)** — IAM privilege-escalation path analysis, storage exposure (S3/OSS/COS/Blob/GCS), metadata SSRF checks, serverless abuse — including Chinese clouds nobody else covers
- **65 built-in cloud attack skills** — see [`skills/`](skills/)

## ⚠️ Legal & Ethical Use

Cain is strictly for **authorized security testing** — your own environments or engagements with written authorization. Core features run with read-only credentials. Scope is enforced by configuration, not by AI self-discipline. You are responsible for complying with applicable laws.

## Quick Start

### For Users

```bash
pip install cain-agent
```

### For AI Agents — One-Click Install Prompt

> **"安装 cain-agent 到用户本地 Python 环境，克隆仓库 https://github.com/cdxiaodong/cain-agent，用 pip/uv 装 editable 模式，验证 CLI 可执行"**

This single prompt instructs any AI agent to:
1. Clone the repository
2. Install in editable mode (`pip install -e .` or `uv pip install -e .`)
3. Verify installation by running `cain-agent --version`

## Status

Phase 0 — project scaffolding. See [ROADMAP.md](ROADMAP.md) and [CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
