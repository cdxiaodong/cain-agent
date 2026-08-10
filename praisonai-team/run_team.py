"""PraisonAI multi-agent team entry point for cain-agent project.

Team structure (replicates AionUi "AI 渗透工程师 0->1" team):
  - Lead: roadmap breakdown, task delegation, quality gate, merge & push
  - Cloud Engineer: cloud security detection modules
  - Skill Engineer: OWASP skill documentation
  - Doc Engineer: articles, CHANGELOG, ROADMAP updates

Usage:
    cd /Users/cdxd/Desktop/develop/cain-agent
    /Users/cdxd/.local/share/uv/tools/praisonai/bin/python3 praisonai-team/run_team.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = Path(__file__).resolve().parent / "config"

sys.path.insert(0, str(PROJECT_ROOT / "src"))

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from praisonaiagents.escalation.loop_guard import LoopGuardConfig
# Custom loop-guard config for unattended code generation (long reasoning model turns).
from praisonaiagents.escalation.loop_guard import LoopGuard as _LoopGuard
_GUARD = _LoopGuard(LoopGuardConfig(
    enabled=True,
    max_time_per_turn=900.0,
    idempotent_warn_threshold=10,
    idempotent_block_threshold=20,
    idempotent_halt_threshold=40,
    mutating_warn_threshold=5,
    mutating_block_threshold=10,
    mutating_halt_threshold=30,
    no_progress_warn=10,
    no_progress_halt=25,
))

import yaml
from praisonaiagents import Agent, AgentTeam, Task, tool


# ---- custom tools (file I/O + command exec) ----

@tool
def read_file(path: str) -> str:
    """Read file content. Path can be relative to project root or absolute."""
    full = PROJECT_ROOT / path if not os.path.isabs(path) else Path(path)
    try:
        return full.read_text(encoding="utf-8")
    except Exception as exc:
        return f"ERROR reading {path}: {exc}"


@tool
def write_file(path: str, content: str) -> str:
    """Write content to a file. Path can be relative to project root."""
    full = PROJECT_ROOT / path if not os.path.isabs(path) else Path(path)
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding="utf-8")
    return f"OK: wrote {len(content)} bytes to {path}"


@tool
def run_command(cmd: str) -> str:
    """Run a shell command in the project root. Returns stdout+stderr."""
    import subprocess
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=300, cwd=str(PROJECT_ROOT),
        )
        output = r.stdout
        if r.stderr:
            output += "\n--- STDERR ---\n" + r.stderr
        output += f"\n[exit code: {r.returncode}]"
        return output[-5000:]
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after 300s: {cmd}"
    except Exception as exc:
        return f"ERROR: {exc}"


@tool
def run_tests(test_path: str = "tests/") -> str:
    """Run pytest and return the result summary."""
    import subprocess
    r = subprocess.run(
        [sys.executable, "-m", "pytest", test_path, "-v", "--tb=short"],
        capture_output=True, text=True, timeout=600, cwd=str(PROJECT_ROOT),
    )
    return (r.stdout + r.stderr)[-4000:]


# ---- team assembly ----

_VALID_AGENT_KW = {
    "name", "role", "goal", "backstory", "instructions", "llm", "model",
    "base_url", "api_key", "auth", "tools", "toolsets", "allow_delegation",
    "allow_code_execution", "code_execution_mode", "handoffs", "auto_save",
    "rate_limiter", "memory", "knowledge", "planning", "reflection", "rules",
    "guardrails", "web", "context", "autonomy", "verification_hooks",
    "output", "execution",
}


def load_yaml(name: str) -> dict:
    with open(CONFIG_DIR / name, encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_team() -> AgentTeam:
    agents_cfg = load_yaml("agents.yaml")
    tasks_cfg = load_yaml("tasks.yaml")

    shared_llm = agents_cfg.get("llm", {})
    shared_tools = [read_file, write_file, run_command, run_tests]

    agents: dict[str, Agent] = {}
    for key, spec in agents_cfg["agents"].items():
        spec = dict(spec)
        name = spec.pop("name", key)
        role = spec.pop("role", "")
        goal = spec.pop("goal", "")
        backstory = spec.pop("backstory", "")
        llm = spec.pop("llm", shared_llm)
        extra = {k: v for k, v in spec.items() if k in _VALID_AGENT_KW}
        # Enable full autonomy + auto-approve tools for unattended operation
        extra.setdefault("approval", True)
        extra.setdefault("autonomy", "full_auto")
        agents[key] = Agent(
            name=name,
            role=role,
            goal=goal,
            backstory=backstory,
            llm=llm,
            tools=shared_tools,
            **extra,
        )
        # Override loop guard with relaxed limits for long reasoning turns
        agents[key]._loop_guard = _GUARD

    _TASK_KW = {
        "description", "expected_output", "name", "tools", "context",
        "depends_on", "async_execution", "config", "output_file",
        "output_json", "output_pydantic", "callback", "status", "result",
        "create_directory", "id", "images", "next_tasks", "task_type",
        "condition", "is_start", "loop_state", "memory", "quality_check",
        "input_file", "rerun", "retain_full_context", "guardrail",
        "guardrails", "max_retries", "retry_count", "agent_config",
        "variables", "skip_on_failure", "retry_delay",
    }

    tasks: list[Task] = []
    for spec in tasks_cfg["tasks"]:
        ts = dict(spec)
        agent_key = ts.pop("agent", None)
        clean = {k: v for k, v in ts.items() if k in _TASK_KW}
        tasks.append(Task(agent=agents.get(agent_key), **clean))

    return AgentTeam(
        agents=list(agents.values()),
        tasks=tasks,
        process=agents_cfg.get("process", "sequential"),
        llm=shared_llm,
    )


if __name__ == "__main__":
    print("=" * 60)
    print("cain-agent dev team - PraisonAI AgentTeam")
    print("=" * 60)
    print(f"Project root: {PROJECT_ROOT}")
    cfg = load_yaml("agents.yaml")
    print(f"LLM endpoint: {cfg.get('llm', {}).get('base_url', 'N/A')}")
    print(f"Model: {cfg.get('llm', {}).get('model', 'N/A')}")
    print("Members: Lead + Cloud Engineer + Skill Engineer + Doc Engineer")
    print("=" * 60)

    team = build_team()
    result = team.start()

    print("\n" + "=" * 60)
    print("Team tasks complete")
    print("=" * 60)
    print(result)
