# done-2026-09-14-任务1(fix/2026-09-14-evidence-index-sort)

> 执行:监工(派活单明示监工领取制;09-17 凌晨补位——09-15/16 日更连续中断)。

## 基线

main=b47ab77(09-14 验收日报),1167 passed / 3 skipped。

## 交付

- `_render_evidence_index` 接入 `sorted(conclusions, key=_conclusion_sort_key)`,
  与表格/详情同序(severity 定级序+置信度降序)
- 记录性测试 `test_known_inconsistency_evidence_index_follows_input_order`
  按 09-13 done 汇报预告反转断言并更新文档串
- 范围仅此两处,未动 `_escape_cell` 等其它函数

## 三门原始摘要

```
ruff check src tests          All checks passed!
pyright --pythonpath .venv/bin/python src tests
                              0 errors, 0 warnings, 0 informations
pytest -q                     1167 passed, 3 skipped in 2.90s
```

## 阻塞

无。任务2(bac_replay 构造器)/任务3(bac_chain 组合测试)留池,监工可继续领取。
