# Done 汇报 · 任务 1 真实 StageHandler(Claude 主力)

- **日期**:2026-08-08(产线 Day 6)
- **分支**:`core/2026-08-08-stage-handlers`(从 main `f884fbe` 切出,tip `802136a`)
- **执行人**:Claude 主力工程师
- **署名核验**:`cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`(`git config user.email` 提交前已验证)

## 改动文件清单(严格限定在派活单范围内)

| 文件 | 动作 | 说明 |
|---|---|---|
| `src/cain_agent/handlers.py` | 新建(529 行) | SkillLoader + make_recon_handler + make_test_handler |
| `tests/test_handlers.py` | 新建(336 行) | 14 个单测,零 token 零触网 |

**冻结文件零改动**:`git diff f884fbe..HEAD --stat` 仅上述两个文件。

## 功能对照(派活单五条全落实)

1. **make_recon_handler(executor, skill_loader)**:prompt = 阶段目标(存活验证/技术栈指纹/端点提取,**禁止资产扩张**红线明写)+ scope.yaml 原文复述 + 结构化 scope 摘要 + recon 阶段技能;产物落 `recon/endpoints.json`(端点草稿,非法条目跳过计数)+ `recon/recon-output.txt`(脱敏后原始输出)。
2. **make_test_handler(executor, skill_loader)**:读 `recon/endpoints.json` + `assets.json`(以 `[UNTRUSTED_DATA]` 边界包裹进 prompt,复用 validator 常量),L1 探测边界明写(L2/L3 声明不做),注入 skills/web 三技能(sqli/ssrf/xss,phase=test);疑似漏洞按 `Finding` 模型落 `findings.json`,`result` 恒为 `validation_inconclusive`,severity 过 `classify` 规则表收口(模型建议可被压低),证据原文只进 `hash_evidence` 哈希不落明文,`finding_id` 由指纹确定性派生。
3. **SkillLoader**:扫描 `skills/**/SKILL.md`,frontmatter `phase` 字段匹配才注入当前阶段;技能目录缺失/文件不可读/零命中一律降级为无技能 prompt 并把原因记入 `SkillLoader.issues`,不炸。
4. **脱敏实战接线**:所有 Agent 输出落盘前过 `redact.redact`(原始文本)/ `redact_dict`(结构化产物),CredRedactHook 配套件第一次实战接线;测试用假 AK 串(`LTAI4GfAKEak12345678TEST`)钉死"明文不落盘、`<REDACTED:aliyun_ak:...>` 占位出现"。
5. **幂等友好**:recon 重跑覆盖同名产物(内容字节级一致);findings.json 按指纹合并——同指纹原位替换、不同指纹追加,重跑数量不膨胀;其他来源 Finding(如云模块已确认条目)不被改写。

## 自测结果(三绿)

- `ruff check src tests` → **All checks passed**
- `pyright --pythonpath .venv/bin/python` → **0 errors, 0 warnings**(注:不带 `--pythonpath` 时 main 上即存在 oss2 导入解析报错,属 venv 识别问题,非本次引入)
- `pytest -q` → **318 passed, 1 skipped**(其中本任务新增 14 个,全部通过)

测试覆盖(全部用 FakeExecutor 预制返回 + tmp_path workspace + 真实 skills/web 文件,零 token 零触网):

- recon 产物落盘结构(端点草稿字段、非法条目跳过、原始输出文本)
- recon prompt 含阶段目标/禁止资产扩张/scope 复述;web 测试技能不混入 recon
- recon 输出无 JSON 时 endpoints 置空 + caveats 留痕,不炸
- test handler 生成合法 Finding(过 `Finding.from_dict` 校验、初值 inconclusive、规则表压级:模型 critical → info)
- test prompt 注入真实 skills/web 三技能 + UNTRUSTED 边界 + recon 产物 + assets
- SkillLoader 按阶段过滤 / 真实技能 phase 核对 / 目录缺失降级 / 零命中记录
- 脱敏接线:recon/test 两条链路假 AK 均不落盘
- 幂等:recon 重跑字节一致;test 重跑同指纹不膨胀;其他来源 Finding 保留

## 验收对照(派活单验收表任务 1)

| 合并前提 | 状态 |
|---|---|
| 三绿 | ✅ ruff / pyright / pytest 全过 |
| Finding 合法性有测试钉死 | ✅ `test_test_handler_writes_legal_findings` |
| 技能过滤有测试钉死 | ✅ 4 个 SkillLoader 测试 |
| 脱敏接线有测试钉死 | ✅ 2 个脱敏测试(recon/test 双链路) |
| 幂等有测试钉死 | ✅ 2 个幂等测试 + 合并语义测试 |
| 冻结文件零改动 | ✅ diff 仅 2 个新文件 |

## 过程事故记录(需要 Lead 知悉)

本工作区与 Codex-A **共享同一工作树并行作业**,期间 Codex-A 切换了 HEAD 分支,导致本任务首个 commit(`4c12313`)一度落在 `feat/2026-08-08-cli-run` 上且 parent 为 Codex-A 的 `781f6ff`。已用 git plumbing(read-tree/write-tree/commit-tree/update-ref,全程不碰工作树)把本任务 commit 以 `802136a` 直接重建在 main `f884fbe` 之上,Codex-A 分支指针与其全部改动完好无损。**建议后续并行任务使用 git worktree 隔离,避免共享 HEAD。**

## 不做项确认

未接真实目标端到端(留 benchmark)、未改 CLI(任务 2 范围)、未实现 L2/L3。接口对齐说明:handlers 直接实现 orchestrator 的 `StageHandler` 协议(`StageContext` 进 `StageResult` 出),与 `Orchestrator(handlers={...})` 注入点完全对齐,Lead 接线时 `handlers={"recon": ..., "test": ...}` 即可。
