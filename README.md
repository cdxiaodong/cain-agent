# Cain — Real-world AI Penetration Testing Engineer

**Cain** is an AI penetration-testing engineer built for **real-world authorized security assessments** — not a CTF toy. It walks a deterministic attack pipeline, enforces scope with engineering constraints (not AI self-discipline), and ships a **cloud penetration module** covering AWS / Azure / GCP / 阿里云 / 腾讯云 / 华为云 — including the Chinese clouds nobody else covers.

> 🚧 Actively developed. Star & watch for updates.

Built on the [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk).

---

## Why Cain

| | CTF/靶场型 Agent | **Cain (实战型)** |
|---|---|---|
| Target | Static labs, preset flags | Real enterprise assets, bug bounty, authorized engagements |
| Vulnerability focus | Known syntax-pattern vulns | **Business-logic flaws, auth chains, cloud misconfigurations** |
| Environment | No WAF, no rate limiting | Real WAF / risk control with dynamic strategy adjustment |
| Deliverable | A flag | Auditable evidence chain + reproducible PoC + remediation advice |

---

## Features

- 🎯 **Real-world Focus**: Business-logic flaws, auth chains, cloud misconfigurations
- ☁️ **Cloud Native**: AWS / Azure / GCP / 阿里云 / 腾讯云 / 华为云 coverage
- 🔒 **Safety First**: Read-only by default, scope enforcement, credential redaction
- 🤖 **AI-Powered**: Claude Agent SDK with deterministic orchestration
- 📊 **Benchmark**: self-built vulnerable-terraform evaluation, four-metric scoring
- 🛡️ **OWASP Top 10**: SQLi, XSS, SSRF, CSRF, File Upload, XXE, Command Injection, Path Traversal

---

## Quick Start

```bash
git clone https://github.com/cdxiaodong/cain-agent
cd cain-agent
pip install -e .          # or: uv pip install -e .
pip install -e ".[cloud]" # optional AWS S3, Huawei OBS, and Kubernetes checks

cain-agent --version
```

### For AI Agents — One-Click Install Prompt

> **"安装 cain-agent 到用户本地 Python 环境，克隆仓库 https://github.com/cdxiaodong/cain-agent，用 pip/uv 装 editable 模式，验证 CLI 可执行"**

This single prompt instructs any AI agent to:
1. Clone the repository
2. Install in editable mode (`pip install -e .` or `uv pip install -e .`)
3. Verify installation by running `cain-agent --version`

### Run against a target

The target is written into `scope.yaml` and enforced on every tool call:

```bash
cain-agent run \
  --target https://app.example.com \
  --total-budget 1800
```

**Flags:** `--target` (required) · `--workspace` (state dir, default `./workspace`) · `--total-budget` (wall-clock seconds) · `--idle-timeout` (per-step seconds)

### Choose an execution backend

Cain uses the default `claude` backend unless `--backend pi` is specified. The
pi backend requires Node.js 20 or newer and a one-time bridge installation:

```bash
npm ci --prefix toolchain/pi
export ANTHROPIC_API_KEY="your-api-key"
cain-agent run --target https://app.example.com --backend pi
```

Choose another supported provider and model with `--pi-provider` and
`--pi-model`; its standard API-key environment variable must be set (for
example, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`, or
`OPENROUTER_API_KEY`). For an Anthropic Messages-compatible gateway, set
`PI_BASE_URL` and use `ANTHROPIC_AUTH_TOKEN` as its bearer credential:

```bash
export PI_BASE_URL="https://gateway.example.com"
export ANTHROPIC_AUTH_TOKEN="your-gateway-token"
cain-agent run --target https://app.example.com \
  --backend pi --pi-model your-gateway-model-id
```

See [the pi bridge guide](toolchain/pi/README.md) for the complete provider and
gateway configuration.

---

## Architecture

> **Deterministic engineering constrains agent freedom** — stage transitions, scope enforcement and dangerous-operation circuit breakers are hard constraints; path selection and evidence analysis are left to the agent.

```
                    ┌──────────────────────────────────────────────┐
                    │                 Cain CLI                     │
                    │   cain-agent run --target <t> [--dry-run]    │
                    └───────────────────┬──────────────────────────┘
                                        │
                            ┌───────────▼───────────┐
                            │    Scope Bootstrap     │  target → scope.yaml
                            └───────────┬───────────┘
                                        │
                            ┌───────────▼───────────┐
                            │      Orchestrator      │  deterministic state machine
                            │  recon → test → report │  crash-resumable · scoped
                            └──┬────────┬────────┬──┘
                               │        │        │
              ┌────────────────▼┐   ┌───▼────┐  ┌▼──────────────┐
              │  Recon  Handler │   │  Test  │  │    Report      │
              │  (skill-guided) │   │Handler │  │   Handler      │
              └────────┬────────┘   └───┬────┘  └───────┬────────┘
                       │                │                │
                       └────────┬───────┴───────┬────────┘
                                │               │
                    ┌───────────▼──────┐   ┌────▼───────────────┐
                    │   SDK Executor    │   │  Findings Pipeline  │
                    │ (Planner/Executor)│   │ finder → validator  │  distinct sessions
                    │  allowed_tools=[] │   │ (never shared)      │
                    └─────────┬─────────┘   └─────────────────────┘
                              │
        ┌─────────────────────┼──────────────────────┐
        │                     │                      │
┌───────▼────────┐  ┌─────────▼─────────┐  ┌─────────▼────────┐
│  PreToolUse     │  │   Readonly Guard   │  │   Cloud Module    │
│  Scope Guard    │  │  46 read-only      │  │  IAM privesc ·    │
│  + Cred redact  │  │  security tools    │  │  storage · SSRF   │
└─────────────────┘  └────────────────────┘  └──────────────────┘

All state lives as files in the Workspace (external memory) —
crash-resumable and auditable end-to-end.
```

**Safety is structural, not behavioral:**
- **Scope enforcement** — a `PreToolUse` hook blocks any tool call whose target falls outside `scope.yaml`; scope is enforced by configuration, not by the model's good behavior.
- **Read-only toolchain** — 46 built-in security tools (recon / scan / verify / post / report), each with a per-tool `dangerous_flags` blacklist; write/exploit/persist operations (`POST`, `PUT`, `DELETE`, `aws rm/mv/cp`, …) are rejected before execution.
- **Finder ≠ Validator** — discovery and validation run in **separate agent sessions** that never share context, so a finding can't be self-confirmed. Verdicts are 4-state structured output.
- **Credential redaction** — a redaction hook strips secrets before anything is persisted.

---

## Cloud Module — the part nobody else does

```
aws_s3 · azure_blob · gcp_gcs · aliyun_oss · tencent_cos · huawei_obs   →  storage exposure
aws IAM · tencent_cam · aliyun_ram                                        →  privilege-escalation path analysis
k8s_rbac · docker_image                                                 →  cluster & image posture
cloud metadata SSRF (IMDS / 169.254.169.254 across 7 providers)
```

**IAM / RAM privilege-escalation graph** — models entities → escalation actions → high-privilege targets as a directed graph, exports **DOT / JSON** for rendering, and finds escalation paths via BFS. Driven by the existing `aliyun_ram` / `tencent_cam` rule sets.

## Benchmark — prove it, don't claim it

- **Self-built vulnerable-terraform range** (`bench/aliyun-vuln-tf/`) with per-scene expected-detection fixtures.
- **Benchmark executor** (`bench/run_benchmark.py`) scores each scene against four metrics: detection rate, false-positive rate, wall time, token cost — no hallucinated percentages; untested results are marked **untested**.
- **44 test files** covering the cloud modules, skills, pipeline and CLI.

---

## ⚠️ Legal & Ethical Use

Cain is strictly for **authorized security testing** — your own environments or engagements with written authorization. Core features run with read-only credentials; scope is enforced by configuration, not by AI self-discipline. You are responsible for complying with applicable laws.

## Status

Core MVP is functional — deterministic pipeline, safety hooks, cloud module and benchmark are in place. See [ROADMAP.md](ROADMAP.md) for what's next and [CHANGELOG.md](CHANGELOG.md) for recent work.

## License

Apache-2.0. See [LICENSE](LICENSE).
