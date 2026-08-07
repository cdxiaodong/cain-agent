# done-claude-core — 任务 1 · Findings 校验流水线(dedup + validator 串接,StageHandler 注入)

> 执行人:Claude 主力工程师 · 2026-08-07(产线 Day 5)
> 派活单:`tasks/2026-08-07.md` 任务 1
> 注:本文件覆盖仓库根 Day 4 同名汇报(Day 4 内容已合入 main,git 历史可查)。

## 分支

`core/2026-08-07-findings-pipeline`(从最新 main `8578553` 切出)

- `d92ea18` feat(core): Findings 校验流水线 — dedup + validator 串接,StageHandler 注入挂 Orchestrator
- 本文件随 `docs(core)` 提交同分支

commit 署名已验证:`cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`。

> 过程备注:首次提交时共享工作目录被 Codex-A 切到 `feat/2026-08-07-cred-redact-hook`,commit 误落该分支;已通过临时 worktree cherry-pick 回本分支 + `update-ref` 恢复 Codex-A 分支指针(`303dba4`)完成修正。Codex-A 未提交工作(`done-codex-a.md`)未受影响,两边文件范围完全隔离,feat 分支历史不含本任务任何内容。

## 改动文件清单(严格限定在派活单范围内)

| 文件 | 改动 |
|---|---|
| `src/cain_agent/pipeline.py` | 新建:`FindingsPipeline` / `ValidationSummary` / `make_report_handler` |
| `tests/test_pipeline.py` | 新建:12 个用例 |
| `done-claude-core.md` | 更新:本汇报(覆盖 Day 4 同名文件) |

冻结文件零改动:`git diff main --stat` 仅以上三件。

## 实现要点

1. **流程硬编码**:读 findings.json → `dedup` 指纹去重 → 逐条 `FindingValidator.validate` → `Workspace.save_findings` 原子写回 → 汇总落盘 `report/validation-summary.json`。
2. **幂等**:`TERMINAL_RESULTS = {confirmed, false_positive}` 终态跳过不重复校验;非终态(`validation_inconclusive` / `validation_system_error`)重跑时重新校验,给瞬时故障恢复后的翻案机会;去重后数量不膨胀(有重跑用例钉死)。
3. **容错**:单条校验抛 `ValidatorError` 以外的异常 → 该条标 `validation_system_error`(reason="校验执行异常,待复验")+ 记入失败清单(finding_id + 异常类型),流水线继续;`ValidatorError`(配置级硬约束,如防自证)直接上抛不吞。
4. **防自证**:构造时复用 `FindingValidator` 的"同 session 即拒绝"硬约束,发现 executor 必填作对照。
5. **注入组装**:`make_report_handler(pipeline)` 返回符合 `StageHandler` 协议的同步可调用对象(内部 `run_sync()` 桥接异步校验),`Orchestrator(handlers={"report": ...})` 直接注入;handler 先跑校验流水线再落 `report/report-placeholder.json` 占位产物,产物路径记入 state.json。
6. **汇总落盘**:`report/validation-summary.json` 含 total / 四状态计数(补零固定 schema)/ dedup_removed / validated / skipped_terminal / failures 清单。
7. **技术注记**:`Workspace.write_json` 的临时文件落在根目录,不支持子目录路径;汇总文件在 pipeline 内用同款「mkstemp + os.replace」原子写进 `report/`(不改冻结文件 workspace.py)。

## 自测结果(三绿,均在本分支隔离 worktree 内跑)

- `ruff check src tests` → All checks passed!
- `pyright --pythonpath .venv/bin/python` → 0 errors, 0 warnings
- `pytest tests/ -q` → **233 passed, 1 skipped**(main 基线 222 + 本任务新增 12 例,全绿;267 为共享工作树含 Codex-A redact 测试的口径)

测试覆盖(全部 fake executor + tmp_path,零 token 零触网):

- 全链路:两条新 finding → confirmed,规则表压定级(public-read→high / misconfiguration→medium),findings.json 与汇总双落盘一致;
- 终态跳过幂等:confirmed/false_positive 零校验调用,重跑汇总与 findings.json 逐字节一致;
- 非终态重验:inconclusive 重跑再校验可翻案为 confirmed;
- 单条容错:RuntimeError → 该条 system_error + 失败清单,另一条照常 confirmed;
- 配置错误上抛:`ValidatorError` 不被容错吞掉;
- 去重计数:大小写/空白变体判同,dedup_removed=1,保序留首条;
- 真实组装:`Orchestrator(handlers={"report": make_report_handler(p)})` 跑通 recon→test→report,state.json 产物清单含汇总与占位报告;handler 路径同样遵守终态跳过;
- 空 findings 边界:照常落汇总。

## 验收对照

| 验收项 | 状态 |
|---|---|
| 三绿(ruff/pyright/pytest) | ✅ |
| 幂等/容错/与 Orchestrator 真实组装有测试钉死 | ✅ 各至少 2 例 |
| 冻结文件零改动 | ✅ 仅 import,`git diff` 可证 |
| 改动范围只动 pipeline.py + test_pipeline.py | ✅ |
| 汇总落盘 report/validation-summary.json(总数/各状态/去重数/失败清单) | ✅ |
| 不生成真实报告 markdown、不接真实云数据 | ✅ 仅占位产物 |

— Claude 主力工程师,Day 5 任务 1 交付
