# done — feat/2026-08-30-report-markdown(Claude 主力)

> 交付:2026-08-30(report-markdown 任务)
> 分支:`feat/2026-08-30-report-markdown`(基线 main=68867b8,独立 worktree)

## 交付内容

**人类可读报告生成器**:report 阶段在 `aggregated-report.json` 之外产出
全结构 `report.md`。

- 新模块 `src/cain_agent/report_markdown.py`(纯 Python 模板,零新依赖):
  - 执行摘要:目标(授权范围 in/out 原文)、生成时间、编排路线、
    阶段耗时表(state.json history:recon/test 起止与秒数)、发现统计
    (四状态中文计数);
  - findings 表:severity emoji 着色标记(🔴🟠🟡🔵⚪)+ 置信度百分比 +
    依据链摘要(solver+verification+memory×N),severity 从高到低、
    同级按置信度降序;
  - 逐条发现详情:资源/云服务/校验结论(池表决)/置信度/证据哈希/
    依据链/记忆旁证;
  - 证据哈希索引:只引用 `sha256:` 哈希并声明原文不落明文;
  - 修复建议:`REMEDIATION_ADVICE` 常量表(定级规则表五类云场景 +
    skills/web 十三类),未知 issue_type 回落按 severity 通用建议;
  - 法律声明尾部(与 README 授权声明对齐)。
- `orchestration.py`:删除原简版 `_markdown`,handler 接
  `collect_execution_meta`(scope.yaml/state.json 容错采集,缺失降级为
  占位说明而非报告失败)+ `render_report_markdown`;
  `aggregated-report.json` / Route A fallback 语义零改动。
- 表格单元格转义(竖线/换行/反斜杠),防不可信资源串破坏表格。

## 测试

- 新增 `tests/test_report_markdown.py` 17 例:空/单条/多 severity 三态、
  同级置信度 tie-break、未知定级中性标记、修复建议覆盖与回落、
  单元格转义、元数据采集(正常/缺失/损坏/时间不可解析)、确定性渲染、
  聚合报告真源 shape 兼容;
- `tests/test_orchestrate.py` 端到端扩展:report.md 实际含执行摘要/
  授权范围/阶段耗时/着色表格/证据哈希/修复建议/法律声明。

## 质量门

- ruff check:绿;新文件 ruff format 已过;
- pytest:1037 passed + 3 skipped(基线 1020 + 17);
- pyright:22 errors 与 main 基线完全一致(全部为既有 cloud-deps/杂项
  基线错误,零新增;新文件零错误)。

## 备注

- report 阶段自身耗时在其完成后才落 state.json,耗时表脚注已说明;
- Route A fallback(中心编排不可用时)仍只落 report-placeholder.json,
  人类可读报告仅中心编排路径产出——如需 fallback 也出 report.md 可后续
  派活;
- 未跑真实 token 冒烟(渲染为纯函数,fixture 端到端已覆盖真实链路)。
