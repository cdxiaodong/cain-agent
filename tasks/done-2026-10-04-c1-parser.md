# done-2026-10-04-任务1(feat/2026-10-05-patchdiff-parser · Phase 5-C1)

> 执行:监工(10-04 深夜单领取,10-04 23:56 执行)。

## 基线

main=d996a2f(10-04 派活单),1292 passed / 3 skipped。

## 交付

- `src/cain_agent/patchdiff/{__init__,parser}.py`(新子包)
- `tests/test_patchdiff_parser.py`:15 例

## 先复现后修记录(两处解析器真 bug,测试抓出)

1. `--- ` 配对分支 `i += 2` 连 `+++` 一起消费——current_file 永不设置,
   任何 hunk 都报"文件头之前"。修:只前进一行,+++ 下一轮自处理。
2. hunk 内层循环无界吞行——多文件 diff 的第二组 `diff/+++` 头被当作
   hunk 内容,文件路径不切换(第二文件 hunk 归错第一文件)。修:内层
   遇文件头三前缀即 break 交回主循环。

## 三门原始摘要

```
ruff check src tests          All checks passed!
pyright --pythonpath .venv/bin/python src tests
                              0 errors, 0 warnings, 0 informations
pytest -q                     1307 passed, 3 skipped in 2.93s
```

## 阻塞

无。任务2(C2 谓词蒸馏)留池。
