# done-2026-10-09-C2(feat/2026-10-09-predicate-distill · Phase 5-C2)

> 执行:监工(10-04 单任务2,经 10-07/08 断流顺延,10-09 00:35 领取)。

## 基线

main=0c3369f(10-08 状态记录),1312 passed / 3 skipped。

## 交付

- `src/cain_agent/patchdiff/distill.py` + `__init__` 导出
- `tests/test_predicate_distill.py`:22 例

## 设计要点

- prompt 模板纯字符串(本任务不调 LLM,接线留 C3/C4);
- 防幻觉=词边界符号白名单:两关键字段一个都不引用实际符号即拒,
  错误消息含白名单样例(帮 LLM 自我纠正重试);
- 空 changeset.symbols() 场景跳过符号检查(只结构校验),防误杀。

## 三门原始摘要

```
ruff check src tests          All checks passed!
pyright --pythonpath .venv/bin/python src tests
                              0 errors, 0 warnings, 0 informations
pytest -q                     1334 passed, 3 skipped in 3.51s
```

## 阻塞

无。Phase 5-C 进度 2/4(C3 变体接线/C4 蒸馏反哺待出单)。
