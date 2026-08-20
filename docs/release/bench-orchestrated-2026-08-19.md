# 编排模式 Benchmark 对比记录（2026-08-19）

## 结论

benchmark 框架现可将同一组场景依次交给经典模式和编排模式执行，统一采集
finding 确认率、墙钟耗时与 token 消耗，并输出汇总表和逐场景明细。

本轮使用 3 个离线确定性场景验证采集和报告链路。两种模式的 finding 确认率
均为 66.7%；编排模式因包含多会话表决，记录的耗时和 token 消耗高于经典模式。

## 运行方式

```bash
python bench/run_benchmark.py \
  --compare-input bench/comparison-2026-08-19.json \
  --output /tmp/bench-orchestrated-2026-08-19.md
```

输入文件固定场景集合，并为每个场景提供经典与编排两种模式的结构化执行结果。
框架会物化场景列表，保证两种 runner 接收相同的场景 ID 与顺序；单个 runner
失败会被记录为错误，不会中断其余场景。

## 汇总对比

| 模式 | finding 确认率 | 已确认/总 finding | 总耗时 | token 消耗 | 错误数 |
|---|---:|---:|---:|---:|---:|
| classic | 66.7% | 4/6 | 0.012s | 538 | 0 |
| orchestrated | 66.7% | 4/6 | 0.020s | 1260 | 0 |

相对经典模式，本轮编排模式确认率持平，总耗时增加约 66.7%，token 消耗增加
约 134.2%。该增量符合多会话独立表决需要额外执行的预期。

## 逐场景明细

| 场景 | 模式 | finding 确认率 | 耗时 | token 消耗 | 状态 |
|---|---|---:|---:|---:|---|
| confirmed-majority | classic | 100.0% (2/2) | 0.004s | 180 | ok |
| rejected-majority | classic | 50.0% (1/2) | 0.004s | 176 | ok |
| inconclusive-split | classic | 50.0% (1/2) | 0.004s | 182 | ok |
| confirmed-majority | orchestrated | 100.0% (2/2) | 0.007s | 420 | ok |
| rejected-majority | orchestrated | 50.0% (1/2) | 0.006s | 414 | ok |
| inconclusive-split | orchestrated | 50.0% (1/2) | 0.007s | 426 | ok |

## 口径与限制

- finding 确认率按 `confirmed_findings / findings` 汇总；没有 finding 时记为 0%。
- token 优先读取 `total_tokens`，否则汇总输入、输出和缓存创建 token；也可由
  runner 直接提供 `token_cost`。
- 耗时可由 runner 提供，也可由框架使用单调时钟测量。
- 本轮是离线框架回归，不包含网络、模型或真实目标波动，数值不能作为生产性能
  基线；它验证的是双模式同场景执行、计量与报告路径。

## 验证

```text
pytest -q tests/test_benchmark_framework.py tests/test_benchmark_comparison.py
11 passed
```
