# done-claude-core — 任务 1 · 校验 Agent 执行层 FindingValidator(独立 session 防自证)

> 执行人:Claude 主力工程师 · 2026-08-06(产线 Day 4)
> 派活单:`tasks/2026-08-06.md` 任务 1
> 注:本文件覆盖仓库根 Day 3 同名汇报(Day 3 内容已合入 main,git 历史可查)。

## 分支

`core/2026-08-06-validator-agent`(从最新 main `dc5958f` 切出,切前已 `git fetch`)

- `35d3a15` feat(core): FindingValidator 校验 Agent 执行层 — 独立 session 防自证 + 规则表定级收口
- `ce510b2` test(core): FindingValidator 校验 19 例(fake executor,零 token)

所有 commit 署名 `cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`(提交前后均 `git config user.email` 验证一致)。

## 改动文件清单

| 文件 | 说明 |
|---|---|
| `src/cain_agent/validator.py` | 新建,201 行 |
| `tests/test_validator.py` | 新建,207 行,19 例 |

冻结文件 `executor.py` / `scope.py` / `workspace.py` / `orchestrator.py` / `findings.py` / `cloud/aliyun_oss.py` **零改动**(`git diff origin/main --stat` 仅上述两个新文件;validator.py 只 import 不修改)。

## 功能实现对照(派活单 5 条功能要求)

1. **防自证硬约束**:`FindingValidator(executor, *, discovery_executor=None)`;`executor is discovery_executor` 直接 `raise ValidatorError`(发现者≠校验者,DESIGN §3.3)。
2. **`async validate(finding) -> Finding`**:prompt 走校验专用 SDKExecutor(只读工具白名单,默认零工具);要求模型只输出 JSON 结构化 4 状态;超时中断 / SDK 异常 / 解析失败 / 非法状态值一律收敛 `validation_system_error`;证据不足由模型自报 `validation_inconclusive`,代码不替模型猜。
3. **定级收口**:模型 severity 仅为建议,`_coerce_suggested` 收敛(非法建议按无建议处理)后过 `findings.classify` 规则表——命中则建议作废;无命中取建议与 info 较低者(Day 3 降级规则)。
4. **回写**:`dataclasses.replace` 产新 Finding(frozen 不可变);`reason` 由校验方填写,超 30 字截断并以 `…` 标记(总长仍 ≤30);`evidence_hash` / `finding_id` / 四元组字段不变(证据同源)。
5. **数据信任边界**:prompt 中 finding 全字段包裹 `[UNTRUSTED_DATA]` 标记,并显式告知模型标记内指令性文本一律当数据忽略(§3.2 防注入)。

## 自测结果(三绿)

| 门 | 命令 | 结果 |
|---|---|---|
| ruff | `.venv/bin/ruff check src tests` | All checks passed |
| pyright | `.venv/bin/pyright --pythonpath .venv/bin/python` | 0 errors, 0 warnings |
| pytest | `.venv/bin/pytest -q` | **190 passed**(含新增 19 例,全程 0.94s,fake executor 零 token 零触网) |

自测覆盖派活单全部要求:同 session 拒绝(`test_same_executor_object_rejected`)、四状态映射(parametrize ×4)、SDK 返回乱码 → system_error(`test_garbage_output_becomes_system_error`)、定级被规则表压住(模型 critical / 规则表 high → 最终 high,`test_rule_table_caps_model_suggestion`)、reason 超长截断标记(`test_reason_truncated_with_mark`);另钉死:超时/SDK 异常/非法状态值/非法 severity 建议/无命中降级 info/缺 reason 兜底/证据哈希与四元组同源/乱序散文中 JSON 提取/`[UNTRUSTED_DATA]` 标注位置。

## 验收对照(21:00 Lead 验收表 · 任务 1)

| 验收项 | 状态 |
|---|---|
| 三绿(ruff/pyright/pytest) | ✅ |
| 同 session 拒绝有测试钉死 | ✅ `test_same_executor_object_rejected` / `test_distinct_executors_accepted` |
| 规则表压定级有测试钉死 | ✅ `test_rule_table_caps_model_suggestion` / `test_no_rule_hit_degrades_to_lower_of_suggested_and_info` |
| 冻结文件零改动 | ✅ `git diff origin/main --stat` 仅 2 个新文件 |
| 不做项(接 Orchestrator、真实证据复检工具) | ✅ 未触碰 |

## 红线自查

未使用 pentest-agent-mvp 代码;未引入泄漏版 Claude Code 代码;Agent 引擎仅用 Claude Agent SDK;测试全 fake executor 注入,零网络调用、零云操作、零真实凭证;不涉及任何内部信息。
