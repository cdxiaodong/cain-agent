# 本地 Finding Fixture 编排闭环记录 · 2026-08-21

## 结论

| 验收点 | 结果 | 说明 |
|---|---|---|
| 本地可复现漏洞场景 | 通过 | `bench/fixtures/local-ssti.json` 离线记录 SSTI 探测请求与证明响应 |
| 产出 finding | 通过 | 1 条 `ssti` 候选进入 `findings.json`，原始响应只进入证据哈希 |
| 验证池多数表决 | 通过 | `confirmed=3 / rejected=0 / inconclusive=0`，流水线收口为 confirmed |
| confidence + 依据链 | 通过 | Manager 聚合输出 confidence `0.894`，basis 覆盖 solver、verification、memory |
| 本地依赖 | 通过 | 不启动网络服务、不依赖 Flask 或外部模型，使用确定性校验 executor |

## 场景与执行路径

Fixture 使用本地回环地址与预记录响应：请求模板为算术表达式，响应包含
唯一证明标记。runner 会校验证明标记存在，把 request/response 规范化后计算
SHA-256 证据哈希，再物化一条 `validation_inconclusive` 的候选 Finding。

执行路径不是回放最终报告：

1. 候选 Finding 写入临时 Workspace；
2. `FindingsPipeline` 执行去重与三 session 验证池表决；
3. 多数确认后写回 `confirmed` 并生成 validation summary；
4. `MultiAgentOrchestration` 装载 Blackboard、Manager 与 report solver；
5. Manager 聚合表决事实和语义记忆，输出聚合报告。

最终报告关键值：

```json
{
  "route": "multi_agent",
  "summary": {
    "total": 1,
    "results": {
      "confirmed": 1,
      "false_positive": 0,
      "validation_system_error": 0,
      "validation_inconclusive": 0
    }
  },
  "conclusion": {
    "finding_id": "local-ssti-offline",
    "issue_type": "ssti",
    "consensus": "confirmed",
    "confidence": 0.894,
    "evidence_hash": "sha256:c8e1e69c21ab7ce39eb9b1c4effc30096a078bff5394f36624b8d7d953df017b"
  }
}
```

依据链：

| 来源 | 证据 | 分数 |
|---|---|---:|
| solver | `finding-ingest` 上报候选 | 1.0 |
| verification | 复用三路表决：confirmed=3, rejected=0, inconclusive=0 | 1.0 |
| memory | 命中 `validation:local-ssti-offline` 相似记录 | 0.442 |

## 复现

```bash
uv run python bench/run_benchmark.py \
  --suite local-finding-fixture \
  --output /tmp/local-finding-fixture.json
```

回归测试：

```bash
uv run pytest -q \
  tests/test_finding_fixture.py \
  tests/test_benchmark_framework.py \
  tests/test_benchmark_comparison.py \
  tests/test_orchestrate.py \
  tests/test_manager.py
```

结果：`31 passed`。

按 08-19 smoke 的既有口径排除 11 个预存云依赖收集错误文件后：
`681 passed, 3 skipped`。裸环境全量收集仍会因这些预存错误中断，
对应依赖治理由同日并行任务负责，本分支不混入该修复。

## 限制

该 fixture 解决的是编排链路缺少真实 finding 数据闭环的问题，用于确定性回归。
离线校验 session 只比对预期证据哈希，不代表目标可达性、模型能力或生产性能；
网络靶场评测仍需在授权环境中单独执行。`ssti` 未命中现有定级规则表，流水线按
保守策略收口为 `info`，这是预期行为。
