# cain-agent 冒烟测试报告

- 测试任务编号：scheduled smoke 2026-08-06 16:12
- 实际执行时间：2026-08-07 09:37 (Asia/Shanghai)
- 执行者：smoke-tester（Codex 一次性 cron 唤醒）
- 机器：macOS / zsh，venv 在仓库根 `.venv`（Python 3.14.2）
- 结论：**通过（PASS）** —— 工具能跑起来。安装成功、CLI 正常启动、Agent 编排循环（recon → test → report）成功启动并跑完，全程零真实目标、零真实云凭证、零对外网络扫描。

> 文件名/分支名按派活单指令保留 `2026-08-06`；实际跑测发生在次日（调度触发延迟）。

---

## 1. 总览（一句话）

cain-agent 0.1.0 在本地 venv 可装、CLI 可起、`Orchestrator.run()` Agent 循环可启动并完成全部三阶段，产物落盘与 state.json 追溯正常。冒烟目标达成。

| 检查项 | 结果 |
|---|---|
| 安装 `pip install -e ".[dev]"` | ✅ 成功 |
| CLI `--version` | ✅ `cain-agent 0.1.0`，exit 0 |
| CLI `--help` | ✅ 输出 usage，exit 0 |
| Agent 循环启动 | ✅ `Orchestrator.run()` 跑通 recon/test/report，exit 0 |
| 安全约束（无真实目标/凭证/外网） | ✅ 全程未触网、未用凭证、scope 仅 127.0.0.1 |

---

## 2. 安装

```bash
cd /Users/cdxd/Desktop/develop/cain-agent
.venv/bin/python --version          # Python 3.14.2
.venv/bin/pip install -e ".[dev]"
```

结果：依赖全部已满足（`claude-agent-sdk`、`pyyaml`、`oss2`、`requests` + dev 的 `pytest/ruff/pyright`），可编辑安装 cain-agent 0.1.0 构建成功，exit 0。无报错。

---

## 3. CLI 启动

```bash
.venv/bin/cain-agent --version   # -> cain-agent 0.1.0   (exit 0)
.venv/bin/cain-agent --help      # -> usage: cain-agent [-h] [--version] ...  (exit 0)
```

说明：CLI 目前为 Phase 0 stub（见 `src/cain_agent/cli.py`），仅实现 `--version`，**没有 `run`/`scan` 类子命令**。这是设计现状，非缺陷。冒烟要求的「最小运行」改走下一节的编排循环直驱。

---

## 4. 最小运行（Agent 编排循环）

由于 CLI 暂无 run/scan 子命令，采用项目自身的 Agent 循环入口 `Orchestrator.run()`（`src/cain_agent/orchestrator.py`）做最小验证。它组合了 `SDKExecutor` + `ScopeGuardHook` + `Workspace`，是 CLI 后续要暴露的同一套引擎。

- 临时工作区：`mktemp -d`（不复用任何真实目录）
- 授权范围 `scope.yaml`：`in_scope: [127.0.0.1]`，`out_of_scope: []` —— 仅本机回环，无任何真实目标
- executor：`SDKExecutor()` 默认零工具（只读原则），构造不触网（网络只在 `run()` 内调 `query()` 时才发生）
- handler：默认 placeholder handler，纯写占位 JSON，不产生任何真实侦察/测试行为
- 安全兜底：60 秒看门狗（后台进程 + sleep + kill -9）

实测输出（节选）：

```
[smoke] workspace=/tmp/cain-smoke.XXXXXX
[smoke] stages=('recon', 'test', 'report')
[smoke] scope hook mounted: 1 matcher(s)
[smoke] starting agent loop (recon -> test -> report, placeholder handlers)...
[smoke] loop finished.
[smoke] final state.json:
{
  "current_stage": "report",
  "completed_stages": ["recon", "test", "report"],
  "updated_at": "2026-08-07T01:37:52+00:00",
  "history": [ ... 三阶段各有 started_at/finished_at/summary/artifacts ... ]
}
```

工作区落盘（全部命中预期）：

```
assets.json  findings.json  scope.yaml  state.json
recon/recon-placeholder.json
test/test-placeholder.json
report/report-placeholder.json
```

结论：编排循环启动成功，顺序跑完 recon → test → report，状态可追溯，ScopeGuardHook 已挂到 executor（1 matcher）。因 placeholder handler 为同步文件写，瞬时完成，看门狗未触发；进程正常 exit 0 自行结束。

---

## 5. 遇到的报错与处理

| # | 现象 | 原因 | 处理 | 是否影响结论 |
|---|---|---|---|---|
| 1 | `timeout 60 ...` 报 `command not found: timeout` | macOS 默认无 `timeout`（需 coreutils 的 `gtimeout`） | 改用 shell 后台进程 + `sleep 60` + `kill -9` 自建看门狗，等价 60s 兜底 | 否 |

无其它报错。安装、CLI、编排循环均一次跑通。

---

## 6. 复现步骤

```bash
cd /Users/cdxd/Desktop/develop/cain-agent

# (1) 安装
.venv/bin/pip install -e ".[dev]"

# (2) CLI
.venv/bin/cain-agent --version     # 期望: cain-agent 0.1.0
.venv/bin/cain-agent --help        # 期望: usage: cain-agent ...

# (3) 最小运行：建临时工作区（scope 仅 127.0.0.1）
WS=$(mktemp -d /tmp/cain-smoke.XXXXXX)
cat > "$WS/scope.yaml" <<'YAML'
in_scope:
  - 127.0.0.1
out_of_scope: []
YAML

# (4) 直驱 Orchestrator.run()（60s 看门狗兜底）
.venv/bin/python - <<'PY'
import json
from cain_agent.executor import SDKExecutor
from cain_agent.orchestrator import Orchestrator
from cain_agent.workspace import Workspace
import os
ws = Workspace(os.environ["WS"])
orch = Orchestrator(SDKExecutor(), ws)
state = orch.run()
print(json.dumps(state, ensure_ascii=False, indent=2))
PY
#   -> 期望: completed_stages 为 ["recon","test","report"]，exit 0
```

---

## 7. 范围声明（按派活单红线）

本次冒烟**只验证「能不能跑起来」**，不做深度测试、不找 bug、不评效果。全程：

- 仅以 `127.0.0.1` 为授权范围，**未指向任何真实目标**
- **未使用任何真实云凭证**（未触碰 aliyun_oss/aliyun_ram 的真实调用路径）
- **未发起任何对外网络扫描**（executor 未进入 `query()` 网络路径，handler 为占位）
- 进程在确认循环成功启动并跑完后，由看门狗/正常退出终止，**未让其继续运行**
