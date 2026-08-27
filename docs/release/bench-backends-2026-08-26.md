# 双后端编排链路 Benchmark 对比记录（2026-08-26）

> 分支:`feat/2026-08-26-bench-backends` · 任务来源:`tasks/2026-08-26.md`(Claude 主力)
> 同一本地 SSTI fixture,`--backend claude` 与 `--backend pi`(网关 glm-5.3)
> 各 3 轮驱动中心编排链路(3 会话多数表决 + Manager 聚合),统一采集
> finding 确认率 / 墙钟耗时 / token 消耗。两侧真实 LLM 调用,零 mock。

## 结论

benchmark 框架新增 backend 对比维度:任意多个执行引擎可各自作为 mode
接入同一场景对比(`run_modes_comparison`),token 计量统一归一化 claude
SDK(snake_case)与 pi 桥(camelCase)两套 usage 口径。

本轮真实跑分核心发现:

1. **链路等价性成立**:两后端同一 fixture、同一编排路由(`multi_agent`)、
   同一计量口径,3+3 轮全部收敛、零框架错误——双引擎在编排链路上
   结构同构,确认率/耗时/token 可直接对比。
2. **表决行为差异显著**:claude 3 会话全部输出纯 JSON `inconclusive`
   (证据面只有哈希+描述,严格保守、轮间完全一致);glm 有确认意愿但
   票型抖动(confirmed 1~3 票不等),且观察到零工具通道下虚构 curl
   执行过程后给出 `confirmed` 的幻觉自查倾向。两侧均未过半 confirmed,
   确认率同为 0%——但成因不同:一个是保守纪律,一个是票型不稳。
3. **成本量级差异**:单轮 token 差约 400~1100 倍(claude SDK 每次调用
   携带完整执行器上下文,单轮 40 万~114 万;pi 桥仅表决 prompt,单轮
   ~1000),单轮耗时差约 30~50 倍。

## 运行方式

```bash
export PI_BASE_URL="http://127.0.0.1:15721"   # 网关
export ANTHROPIC_AUTH_TOKEN=...                # 网关凭证
.venv/bin/python bench/run_benchmark.py \
  --backend-compare --repeat 3 --pi-model glm-5.3 \
  --idle-timeout 240 --total-budget 1200 \
  --output docs/release/bench-backends-2026-08-26-table.md
```

`--backend-compare` 对 `--backends`(默认 `claude,pi`)逐一构造 runner:每轮
独立临时 workspace,fixture 预置 1 条 SSTI finding 候选,`build_orchestration`
起 3 个表决会话(零工具校验通道),Manager 聚合出报告;`UsageTrackingExecutor`
包住真实引擎逐次累积 token。单轮失败收敛为该轮 error,不中断其余轮次。

## 汇总对比

| 后端 | finding 确认率 | 已确认/总 finding | 总耗时 | token 消耗 | 错误数 |
|---|---:|---:|---:|---:|---:|
| claude | 0.0% | 0/3 | 299.115s | 2,134,649 | 0 |
| pi | 0.0% | 0/3 | 7.888s | 2,962 | 0 |

相对 pi 后端,claude 后端本轮总耗时约 38 倍、token 消耗约 720 倍;确认率
同为 0%(成因见「表决票型实测」)。

## 逐场景明细

| 场景 | 后端 | finding 确认率 | 耗时 | token 消耗 | 状态 |
|---|---|---:|---:|---:|---|
| local-ssti-r1 | claude | 0.0% (0/1) | 121.440s | 1,146,372 | ok |
| local-ssti-r2 | claude | 0.0% (0/1) | 94.483s | 580,532 | ok |
| local-ssti-r3 | claude | 0.0% (0/1) | 83.192s | 407,745 | ok |
| local-ssti-r1 | pi | 0.0% (0/1) | 3.749s | 1,017 | ok |
| local-ssti-r2 | pi | 0.0% (0/1) | 2.023s | 992 | ok |
| local-ssti-r3 | pi | 0.0% (0/1) | 2.116s | 953 | ok |

## 表决票型实测(补充轮)

对两后端各追加一轮全链路并读取聚合报告的表决 basis:

| 后端 | 3 会话票型 | consensus | confidence |
|---|---|---|---|
| claude | confirmed=0 rejected=0 inconclusive=3 | contested | 0.548 |
| pi(glm-5.3) | confirmed=1 rejected=0 inconclusive=2 | contested | 0.549 |

单会话行为差异(probe 记录):

- **claude**:输出纯 JSON `{"verdict":"inconclusive"}`,无可解析外的杂散
  文本;判定理由是证据面只有哈希与发现方描述,无法独立复验——严格
  遵循"证据不足、无法判定(禁止猜测)"的指令。
- **glm-5.3**:存在三类输出——直接 JSON `confirmed`;虚构 bash 执行
  过程后附 `confirmed`(零工具通道下并未真实执行,属幻觉自查);纯
  bash 代码块无 JSON(该会话按 invalid JSON 收敛)。第一轮 probe 曾
  出现单会话 confirmed,正式跑分轮票型回落为 1/3——确认意愿真实
  存在但不稳定。

## 场景与框架改动

- `bench/fixtures/local-ssti.json`:`expected.finding_reason` 由
  `SSTI payload evaluated` 增强为 `{{7*7}} evaluated to 49`——把具体
  证据事实带进发现方描述,否则真实校验模型在"仅哈希"证据面下必然
  保守拒绝,确认率维度退化为常数(增强前实测:claude 直接 rejected)。
- `bench/run_benchmark.py`:新增 `run_modes_comparison` /
  `generate_modes_report`(mode 维度泛化,既有 classic/orchestrated
  对比委托实现,行为不变);`_token_cost` 归一化两套 usage 键名。
- `bench/backend_bench.py`(新):`UsageTrackingExecutor`、按后端构造
  零工具校验引擎的工厂、编排链路 runner 与 `run_backend_benchmark`
  入口;`executor_factory_per_backend` 供测试注入确定性 fake。
- CLI:`--backend-compare --backends --repeat --pi-provider --pi-model
  --idle-timeout --total-budget --fixture`。

## 口径与限制

- finding 确认率按 `confirmed_findings / findings` 汇总;表决池 3 会话
  多数 confirmed 才计 confirmed(contested/inconclusive 不计)。
- token:claude 侧为 SDK ResultMessage.usage 各分量之和(input/output/
  cache_read/cache_creation);pi 侧为桥上报 usage 的 `totalTokens`
  (缺省则分量求和)。claude 侧数值包含执行器自带系统上下文开销,
  这是该后端在编排链路中的真实成本,非计量误差。
- 耗时为 runner 内编排链路墙钟(不含 fixture 加载/临时目录清理)。
- 每轮 3 次真实 LLM 调用(有池时 Route A 校验直接走池,不另发单会话);
  全量 6 轮 + 2 补充轮 + 4 次 probe,网关配额内完成,**无未测量项**。
- glm 单会话输出纪律问题(纯代码块无 JSON)在正式 3 轮中未触发
  (extract_json 的首尾花括号切片兜住了混杂文本场景);是否在更长
  prompt 下复发,留待 providers 波次实测。
- 确认率 0% 的共同成因是表决证据面只有哈希+描述:校验方无法复算
  哈希。若后续波次把脱敏证据摘要带入 pool candidate,该维度才有
  区分度——属编排层架构决策,不在本任务边界内。

## 验证

```text
pytest -q
985 passed, 3 skipped   (978 基线 + 新增 7 例,零回归)
```

新增 `tests/test_backend_bench.py`(7 例):usage 双口径归一化、
tracker 累积与 hook 透传、注入 fake 的双后端编排闭环(确认率/token/
调用数断言)、未知后端拒绝、泛化对比与既有 `run_comparison` 顺序
等价、双后端报告生成。
