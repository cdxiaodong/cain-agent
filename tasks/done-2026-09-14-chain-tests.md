# done-2026-09-14-任务3(test/2026-09-14-bac-chain-tests)

> 执行:监工(派活单监工领取制,09-17 13:50 补位领取)。

## 基线

main=0c42d28(09-17 状态记录),1167 passed / 3 skipped。

## 交付

`tests/test_bac_chain.py`(新,13 例,不改 src):组合链
`load_evidence → judge_bac` 的贯通与边界——

- 贯通 4 例:跨账号读越权 horizontal≥0.8 / 灰区 0.6 降置信 / 403 防护
  在位 / 垂直越权(特权+低权角色)
- 组合场景 2 例:403+依赖页 INSERT → MBAC 优先置信≤0.55+冲突证据
  rationale(09-09 任务1 修复③组合验证);2xx+update → mbac 0.75
- 输入层拒绝异常传播 4 例:敏感键/bool 冒充 int/越界相似度/非法枚举
  ——judge_bac 不被调用,无半判定对象
- 两层语义差异 2 例:同账号、归属=重放者输入层合法判定层 none
- 1 例钉死异常先于判定抛出的传播顺序

未发现需记录的实现缺陷(按 09-09 任务 3 先例行声明)。

## 三门原始摘要

```
ruff check src tests          All checks passed!
pyright --pythonpath .venv/bin/python tests/test_bac_chain.py
                              0 errors, 0 warnings, 0 informations
pytest -q                     1180 passed, 3 skipped in 2.44s
```

## 阻塞

无。任务2(bac_replay 构造器)留池。
