# done-2026-09-18-任务2(feat/2026-09-18-evidence-replay · Phase 5-A2)

> 执行:监工(派活单领取制,09-18 21:46 领取)。

## 基线

main=8b87216(09-18 验收日报),1199 passed / 3 skipped。

## 交付

- `findings.py`:`EvidenceReplay`(名称白名单+值形态构造拒绝)、
  `Finding.replay` 可选字段(旧数据双向兼容)、from_dict 白名单校验
- `report_markdown.py`:「重放清单」节(仅 method/url/名称)
- `tests/test_evidence_replay.py`:15 例

## 三门原始摘要

```
ruff check src tests          All checks passed!
pyright --pythonpath .venv/bin/python src tests
                              0 errors, 0 warnings, 0 informations
pytest -q                     1214 passed, 3 skipped in 2.11s
```

## 阻塞

无。任务3(分歧呈现)留池。
