# Benchmark 评测体系

> 对标 XBOW 靶场评测方法论，建立 cain-agent 能力评估体系

## 评测目标

| 指标 | 说明 | 目标值 |
|---|---|---|
| **检出率** | 真阳性 / 总漏洞数 | ≥ 80% |
| **误报率** | 假阳性 / 总报告数 | ≤ 15% |
| **平均耗时** | 单目标端到端时间 | ≤ 10 分钟 |
| **平均 token 成本** | 单目标消耗 token 数 | ≤ 50k |

## 评测方法

### 1. XBOW 靶场（公开基准）

XBOW 是业界公认的 Web 渗透 benchmark，包含 40+ 真实漏洞场景。

**评测流程**：
1. 部署 XBOW 靶场（Docker）
2. 运行 cain-agent 对每个场景进行测试
3. 对比 cain-agent 输出与 XBOW ground truth
4. 计算检出率/误报率/耗时/token 成本

**参考**: https://github.com/xbow-engineering/xbow-benchmark

### 2. 自建靶场（国产云差异化）

基于 `bench/aliyun-vuln-tf/` 的 vulnerable-terraform 场景，评测国产云渗透能力。

**已有场景**：
- 场景一：OSS 公开桶 + 敏感文件
- 场景二：RAM 过度授权用户

**评测流程**：
1. terraform apply 部署靶场
2. 运行 cain-agent 云模块检测
3. 对比 cain-agent findings 与场景预设漏洞
4. terraform destroy 清理资源

## 评测指标（9 项）

对齐 3000+ 评测经验的方法论：

| 类别 | 指标 | 计算方式 |
|---|---|---|
| **准确性** | 检出率（Recall） | TP / (TP + FN) |
| **准确性** | 精确率（Precision） | TP / (TP + FP) |
| **准确性** | F1 分数 | 2 × (P × R) / (P + R) |
| **效率** | 平均耗时 | Σ(单场景耗时) / 场景数 |
| **效率** | 平均 token 成本 | Σ(单场景 token) / 场景数 |
| **鲁棒性** | 错误率 | 系统错误 / 总运行数 |
| **鲁棒性** | 超时率 | 超时场景 / 总场景数 |
| **覆盖率** | 漏洞类型覆盖 | 已测漏洞类型 / OWASP Top10 |
| **覆盖率** | 云平台覆盖 | 已支持云数 / 6（AWS/Azure/GCP/阿里/腾讯/华为） |

## 结果展示

README badge 趋势图（示例）：

```
检出率: ▓▓▓▓▓▓▓▓░░ 80% (↑ 5%)
误报率: ▓▓▓░░░░░░░ 12% (↓ 3%)
耗时:   ▓▓▓▓▓▓░░░░ 6min (↓ 2min)
```

## 运行方式

```bash
# XBOW 靶场评测（待实现）
python bench/run_benchmark.py --suite xbow --output results/xbow-2026-08.md

# 自建靶场评测（待实现）
python bench/run_benchmark.py --suite vuln-tf --output results/vuln-tf-2026-08.md

# 同一组场景的经典/编排对比
python bench/run_benchmark.py \
  --compare-input bench/comparison-2026-08-19.json \
  --output results/comparison.md

# 本地离线 SSTI 场景：真实进入 finding、验证池与聚合报告
python bench/run_benchmark.py \
  --suite local-finding-fixture \
  --output results/local-finding-fixture.json
```

对比输入的 `scenarios` 数组中，每项包含唯一 `id`，以及 `classic`、
`orchestrated` 两组结果。结果字段为 `findings`、`confirmed_findings`、
`duration_sec`，并可通过 `token_cost` 或 SDK `usage` 提供 token 消耗。
框架固定场景集合与顺序，汇总 finding 确认率、总耗时和 token 消耗，
同时保留逐场景明细与错误状态。

## 注意事项

- **零真实凭证**：评测用 mock 凭证或只读子账号
- **只读原则**：不执行破坏性操作（删除/改写资源）
- **授权声明**：XBOW 靶场为公开评测集，自建靶场为自有环境
