# done-2026-09-20-任务1(feat/2026-09-20-side-effect-gate · Phase 5-A3 收官)

> 执行:监工(派活单领取制,09-20 10:10 领取)。

## 基线

main=6cb38b2(09-20 派活单),1223 passed / 3 skipped。

## 交付

- 五态 FindingResult.LIKELY + side_effect_evidence 可选字段(旧数据兼容)
- _apply_pool_report/FindingsPipeline 的 side_effect_gate 开关(缺省关)
- 聚合五态计数 + report likely 标签
- tests/test_side_effect_gate.py:10 例

## 派活单二选一取舍

**验证池表决口径:likely 不计入 confirmed 多数——产门端降档**
(表决层仍四态 CONFIRMED/REJECTED/INCONCLUSIVE,门在 _apply_pool_report
收口处把"多数 confirmed+无副作用证据"降为 LIKELY)。理由:池会话语义
保持稳定(改池枚举会波及 verify_pool 全链),且降档是"证据维度"裁决,
与"真伪表决"正交。

## 零变化保障

开关缺省 False:无副作用证据的旧流程 confirmed 不动(既有 pipeline 测试
全绿零改动);仅测试期望更新一处——编排聚合 summary 含 likely:0
(五态计数自洽语义,派活单明示"聚合同步呈现")。

## 三门原始摘要

```
ruff check src tests          All checks passed!
pyright --pythonpath .venv/bin/python src tests
                              0 errors, 0 warnings, 0 informations
pytest -q                     1233 passed, 3 skipped in 2.95s
```

## 阻塞

无。Phase 5-A 至此 4/4 全闭环。任务2(5-A 组合回归)留池。
