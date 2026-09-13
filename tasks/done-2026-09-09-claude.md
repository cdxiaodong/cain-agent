# done-2026-09-09-claude(任务1:core/2026-09-09-bac-evidence-guards)

> 执行:监工(Lead 跨会话委托,09-13);交付:48e5a04,已推送分支。

## 基线

main=0679327(09-12),1115 passed / 3 skipped。

## 复现(修复前,实际输出)

```
缺陷1 同账号误判: horizontal 0.85      # object_owner==replay_as=="alice"
缺陷2 NaN相似度仍出结论: horizontal 0.5
缺陷3 403短路吞掉依赖页变化: none False  # POST+INSERT 变化被「防护在位」吞
```

## 修复(先复现钉死后修)

1. **身份前置检查**:`replay_as` 为空最先拒绝;`object_owner` 缺失或
   `==replay_as` 在 MBAC 与读越权分支均排除——跨账号重放是越权结论前提。
2. **数值显式校验**:similarity 须 [0,1] 有限数、threshold 须 (0,1]
   有限数,非法 raise ValueError,不产出任何置信结论。
3. **判定序调整**:MBAC(依赖页变化)先于拒绝状态码短路——写效果是比
   状态码更硬的证据;403+变化并存=冲突证据,置信≤0.55 且 rationale 注明
   「不能仅凭状态码称防护在位,须人工复核」。

## API 兼容

`judge_bac`/`RequestPair`/`ResponseDiff`/`BACConfig` 签名零变化;合法输入
行为不变(23/23 全过,含 09-07 全部 14 例原用例);非法输入从「产生结论」
收紧为「显式拒绝」。

## 文件清单

- `src/cain_agent/web/bac_core.py`(+math;判定序 0-7 重构;docstring 同步)
- `tests/test_bac_core.py`(+9 例钉死用例)

## 三门原始摘要

```
ruff check src tests          All checks passed!
pyright --pythonpath .venv/bin/python src tests
                              0 errors, 0 warnings, 0 informations
pytest -q                     1124 passed, 3 skipped in 2.62s
```

## 阻塞

无。任务2(bac_evidence)/任务3(report-trust)留池待领。
