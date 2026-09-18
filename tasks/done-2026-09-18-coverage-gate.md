# done-2026-09-18-任务1(feat/2026-09-18-coverage-gate · Phase 5-A1)

> 执行:监工(派活单领取制,09-18 16:35 领取)。

## 基线

main=c65dfd1(09-17 验收日报),1180 passed / 3 skipped。

## 交付

- `src/cain_agent/gates.py`(新):`CoverageConfig`/`CoverageVerdict`/
  `check_coverage` 纯函数,三维度阈值(端点数/每端点探测数/探测覆盖率)
- recon 接线:gate 判定落盘 `recon/gate.json`(幂等产物),blocked 进
  caveats;test 接线:blocked 降级 dry-run(Agent 不启动+留痕文件),
  gate 缺失/损坏=pass 兼容旧工作区
- CLI `--coverage-gate`(store_true)

## 设计取舍(需验收知悉)

派活单同时写了「缺省开」与「缺省行为零变化」。实测缺省开会拦截既有
集成测试的空端点链路(model_routing 2 例红),违反零变化原则——**取
零变化优先**:CoverageConfig 全阈值缺省 0、handler 缺省 off、CLI 缺省
关。显式开启即获完整门控语义。与 Phase 2.7「缺省行为零变化」先例对齐。

## 三门原始摘要

```
ruff check src tests          All checks passed!
pyright --pythonpath .venv/bin/python src tests
                              0 errors, 0 warnings, 0 informations
pytest -q                     1199 passed, 3 skipped in 3.23s
```

## 阻塞

无。probe 计数数据源未接入(纯函数已支持,接线留 B 阶段 Scout)。
任务2(可重放证据包)/任务3(分歧呈现)留池。
