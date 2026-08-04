# done-claude-core — 任务 1 · Finding 校验数据模型 + 指纹去重 + 定级规则表

> 执行人:Claude 主力工程师 · 2026-08-05
> 派活单:`tasks/2026-08-05.md` 任务 1

## 分支

`core/2026-08-05-finding-validator`(从最新 main `4d74363` 切出,已 `git fetch` 确认)

- `096cdc1` feat(core): Finding 校验数据模型 + 指纹去重 + 定级规则表
- `6e9c892` test(core): Finding 校验 36 例

所有 commit 署名 `cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`(提交前 `git config user.email` 已验证)。

## 改动文件清单

| 文件 | 说明 |
|---|---|
| `src/cain_agent/findings.py` | 新建,283 行 |
| `tests/test_findings.py` | 新建,223 行,36 例 |

冻结文件 `workspace.py` / `orchestrator.py` / `executor.py` / `scope.py` **零改动**(`git diff main --stat` 仅上述两个新文件;测试中只 import Workspace 做 round-trip 兼容验证)。

## 功能实现对照

1. **Finding 数据类**:字段全对齐 DESIGN §3.3——`finding_id` / `result`(confirmed | false_positive | validation_system_error | validation_inconclusive 四状态 StrEnum)/ `severity`(critical|high|medium|low|info StrEnum)/ `evidence_hash`(`sha256:<64位小写hex>` 正则强校验;`hash_evidence(text)` 工具函数从证据文本算哈希,证据只哈希不落明文,§3.2 数据信任边界)/ `reason`(≤30 字按 Unicode 码点计,超长拒绝)/ `cloud` / `service` / `resource` / `issue_type`。构造即校验,非法值一律抛 `FindingError`。
2. **指纹去重**:`fingerprint(finding)` = 四元组归一化(小写 + 去首尾空白)后 `\x1f` 连接的 sha256;`dedup(findings)` 保序去重,同指纹保留首次出现(教训:CyberStrikeAI #178)。
3. **定级规则表**:`SEVERITY_RULES` 为代码常量数据(公开可写存储=critical、公开读+敏感数据=high、公开读=high、元数据端点可达=high、仅配置不规范=misconfiguration=medium),按优先级排列、首命中生效;`classify(finding, suggested=None)` 纯函数查表——规则命中时模型建议作废;无命中时取建议与 info 的较低者(即保守降级 info,教训:CyberStrikeAI #163)。
4. **findings_json 兼容**:`to_dict/from_dict` 纯 str dict,缺键/多键/非 dict 均拒绝;与 `Workspace.save_findings/load_findings` 实测 round-trip 无损。

## 自测结果(三绿)

| 门 | 命令 | 结果 |
|---|---|---|
| ruff | `.venv/bin/ruff check src tests` | All checks passed |
| pyright | `.venv/bin/pyright --pythonpath .venv/bin/python` | 0 errors, 0 warnings |
| pytest | `.venv/bin/pytest -q` | **151 passed**(含新增 36 例,全程 0.59s,纯逻辑零触网) |

> 备注:裸 `pyright` 会因 venv 解析不到 `oss2` 报 1 个 import 错误——该问题在 main 上同样存在(环境配置问题,非本次改动引入),指定 venv 解释器后 0 错误。

自测覆盖派活单全部要求:四状态枚举非法值拒绝、severity 非法值拒绝、reason 超长/空拒绝、evidence_hash 格式四种坏例拒绝、四元组归一化去重(大小写/空白变体判同)、规则表优先级(首命中生效、规则压过模型建议)、无命中降级取低(模型报 critical 也只给 info)、JSON round-trip、Workspace findings.json 读写兼容。

## 验收对照

| 验收项 | 状态 |
|---|---|
| 三绿(ruff/pyright/pytest) | ✅ |
| 去重归一化有测试钉死 | ✅ `test_case_and_whitespace_variants_share_fingerprint` / `test_dedup_order_preserving` |
| 定级降级有测试钉死 | ✅ `test_rule_hit_overrides_model_suggestion` / `test_no_hit_degrades_to_lower_of_suggested_and_info` |
| round-trip 有测试钉死 | ✅ `test_to_dict_from_dict_lossless` / `test_workspace_findings_json_compatible` |
| 冻结文件零改动 | ✅ `git diff main --stat` 仅 2 个新文件 |
| 不做项(校验 Agent 独立 session、OSS/Web 模块) | ✅ 未触碰 |

## 红线自查

未使用 pentest-agent-mvp 代码;未引入泄漏版 Claude Code 代码;无网络调用、无云操作;不涉及任何内部信息。
