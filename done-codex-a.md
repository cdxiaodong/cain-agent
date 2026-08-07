# Codex-A 交付汇报 · 2026-08-08（Day 6 · 任务 2）

## 基本信息

- **分支**: `feat/2026-08-08-cli-run`
- **基线**: `f884fbe`（main）
- **Commit**: `781f6ff` — `feat(cli): CLI run 子命令 — 编排循环接进命令行`
- **署名**: `cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>` ✓

## 改动文件清单

| 文件 | 操作 | 行数变化 |
|------|------|----------|
| `src/cain_agent/cli.py` | 修改 | +211 −5 |
| `tests/test_cli_run.py` | 新建 | +410 |
| `README.md` | 修改（Quick Start 用法段） | +25 |
| **合计** | | **+641 −5** |

## 功能实现

### CLI 结构
- argparse 子命令: `run` + 保留 `--version`
- `run` 参数: `--target`(必填) / `--workspace`(默认 ./workspace) / `--idle-timeout`(默认 300s) / `--total-budget` / `--dry-run` / `--i-have-authorization`

### 安全接线（全部复用冻结件，零改动 orchestrator/workspace/scope）
1. Workspace 初始化
2. scope.yaml 写入 target（仅它一个 in_scope）
3. ScopeGuardHook 挂载（executor.add_pre_tool_use_hook）
4. executor 构造（allowed_tools=["Bash"]，注释说明 Phase 1 最小面）
5. Orchestrator 三阶段 recon → test → report

### 授权门
- `is_local_target()` 判定: loopback IP (127.0.0.1/::1) / localhost / .local/.localhost 后缀 / RFC 1918 私网 + link-local
- 公网 target 无 `--i-have-authorization` → exit 2 + stderr 提示书面授权要求
- `--dry-run` 同样执行授权检查

### 退出码
- 0: 正常完成 / 用户中断（打印 partial 摘要）
- 2: 参数非法 / 无授权 / scope 初始化失败

### 其他
- `_build_executor` 为模块级独立函数，测试 monkeypatch 替身，零真实 Agent 启动、零 token
- stdout 摘要打印各阶段产物路径
- 全程不打印凭证环境变量值

## 自测结果（三绿）

| 门禁 | 命令 | 结果 |
|------|------|------|
| ruff | `ruff check src/cain_agent/cli.py tests/test_cli_run.py` | ✅ All checks passed! |
| pyright | `pyright src/cain_agent/cli.py tests/test_cli_run.py` | ✅ 0 errors, 0 warnings |
| pytest | `python -m pytest -q`（全量） | ✅ 318 passed, 1 skipped |
| pytest | `python -m pytest tests/test_cli_run.py -q`（本次） | ✅ 29 passed |

### 测试覆盖（29 用例）
- `--version` 和无参 help 输出
- `is_local_target`: loopback/IPv6 localhost/.local/私网/带端口/公网（11 例）
- dry-run: 初始化 workspace + scope、不启动 Agent、公网需授权、公网+授权通过
- 授权门: 公网无授权被拒(exit 2)、公网+授权通过、loopback/私网/.local 免授权
- 参数错误: 缺 --target、空 target
- 完整 run: 三阶段跑完 + 产物落盘、stdout 无凭证泄露
- build_parser 结构校验

## 验收对照

| 验收项 | 状态 | 说明 |
|--------|------|------|
| argparse 子命令 run + --version | ✅ | |
| --target/--workspace/--idle-timeout/--total-budget/--dry-run | ✅ | |
| Workspace 初始化 → scope.yaml → ScopeGuardHook → executor → Orchestrator | ✅ | 全复用冻结件 |
| 公网 target 无 --i-have-authorization 被拒（有测试钉死） | ✅ | test_public_target_without_auth_rejected |
| 零真实 Agent 启动 | ✅ | _build_executor 被 monkeypatch 替身 |
| 冻结文件零改动 | ✅ | executor/scope/workspace/orchestrator/findings/validator/pipeline/redact/cloud/* 未动 |
| README 用法段补充 | ✅ | Quick Start 段（CLI 命令 + 参数对照表） |
| 三绿 | ✅ | ruff + pyright + pytest 全通过 |
| commit 署名正确 | ✅ | cdxiaodong <84082748+cdxiaodong@users.noreply.github.com> |

## 备注

- 共享工作区中 Lead 的 `src/cain_agent/handlers.py` 和 `tests/test_handlers.py` 为未跟踪文件（Task 1 产物），不在本任务改动范围内，未触碰。这两个文件有 1 个 ruff E501 和 1 个 pyright 类型错误，由 Lead 自行修复。
- Python 3.14 的 `ipaddress.is_private` 将 TEST-NET-3 (203.0.113.0/24) 归类为 private，测试中使用 8.8.8.8 / 1.1.1.1 作为公网 IP 样本以确保判定逻辑正确。
