# done-2026-09-09-codex-b(任务3:test/2026-09-09-report-trust-boundary)

> 执行:监工(Lead 09-13 委托,任务1/2 验收通过后续领);09-09 三任务至此收官。

## 基线

main=a6d923a(任务2 已合入),1153 passed / 3 skipped。

## 交付

`tests/test_report_trust_boundary.py`(新):14 例,全部纯渲染路径,
零触网零真实凭据(合成 canary)。

先确认的契约(据此断言):`_escape_cell` 只做 markdown 表格安全转义
(反斜杠/换行/竖线),不做 HTML 转义——HTML 原样进入 markdown 是显示
契约;证据原文只以哈希进报告;未知 severity 回落 `·` 且置底。

覆盖:恶意管道/换行/反斜杠注入不破坏表格;HTML 字符表格结构安全;
未知定级中性回落+排序;大小写归一化;空结论;仅证据哈希;空 meta
占位;损坏 scope.yaml/state.json 降级;证据 canary 与损坏文件内容
不回流报告;同输入渲染确定性。

## 记录的发现(不改实现,按派活单口径)

**证据索引节与表格/详情排序不一致**(显示一致性小问题,非信任边界缺陷):
- 位置:`src/cain_agent/report_markdown.py` `_render_evidence_index`
  (无 sorted,按 conclusions 输入序);表格(`_render_findings_table`
  L338)与详情(L359)均有 `sorted(conclusions, key=_conclusion_sort_key)`
- 最小复现:输入 [severity=ultra, severity=high] 两结论 → 表格节
  HIGH 在 ULTRA 前(定级排序在位),证据索引仍按输入序
- 预期(若修复):索引节与表格节同序;实际:输入序
- 已用 `test_known_inconsistency_evidence_index_follows_input_order`
  钉死现状,修复后该断言应反转

## 三门原始摘要

```
ruff check src tests          All checks passed!
pyright --pythonpath .venv/bin/python src tests
                              0 errors, 0 warnings, 0 informations
pytest -q                     1167 passed, 3 skipped in 2.72s
```

## 阻塞

无。09-09 三任务(1/2/3)全部交付完毕。
