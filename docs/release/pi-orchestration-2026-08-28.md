# pi 后端编排模式全链路实测 · 2026-08-28

> 分支:`feat/2026-08-28-pi-orchestration` · 任务来源:`tasks/2026-08-28-am.md`(Claude 主力)
> 目标:中心编排 + FindingsPipeline 双会话(发现≠校验)在 pi 后端的全链路真实
> 实测——Manager 聚合 / 验证池 / 语义记忆行为等价验证,校验会话零工具双防线
> 实测,发现与校验 provider 可不同配置的组合冒烟。
> 真实通道:本地 Anthropic Messages 兼容网关(`PI_BASE_URL`,模型 glm-5.3 系),
> 凭证经环境变量注入,零入库。

## 结论速览

| 验收点 | 结果 | 说明 |
|---|---|---|
| 全链路真实运行(recon→test→report) | ✅ | exit 0,三阶段 51s,编排路由 multi_agent |
| Manager 聚合(pi 后端) | ✅ | dispatched 2,聚合 1 条,结论含置信度+依据链 |
| 验证池真实表决(pi 后端) | ✅ | 3 会话真实 LLM 表决,多数决/安全降级两路径均实测 |
| 语义记忆命中(pi 后端) | ✅ | memory_hits 非空(score 0.46~0.48),basis 三源齐备 |
| 零工具第一防线(桥不注册) | ✅ | 强诱惑 prompt 下零 tool_request;对照组同 prompt 真实调用 2 次 |
| 零工具第二防线(Python 白名单) | ✅ | allowed_tools=[] 下任何 tool_request 一律 deny(新增单测钉死) |
| 发现≠校验 provider 组合冒烟 | ✅ | 发现 glm-5.3+工具面 / 校验 glm-5.3-air+零工具,同链路真实跑通 |
| 双后端结构等价 | ✅ | 同 fixture 两后端 route/consensus 映射/basis 三源/记忆命中同构 |
| 测试套件 | ✅ | 997 passed + 3 skipped(基线 991 + 新增 6,零回归) |

## 一、全链路真实运行(`--backend pi` 编排模式)

- 目标(自建,已授权):`http://103.236.66.228:3333/`
- 参数:`--backend pi --pi-model glm-5.3 --idle-timeout 240 --total-budget 900`
- 种子:`bench/fixtures/local-ssti.json` 离线 SSTI 候选预置进 workspace
  `findings.json`(靶场当前真实状态为 0 可发现项,与 08-19/08-25 基线一致;
  预置候选让 report 阶段的验证池/Manager/语义记忆在**同一次真实运行**里被
  真实驱动,而非空转聚合 0 条)。
- test 阶段 `_merge_findings` 按指纹合并:真实探测 0 新增,种子候选原样保留
  (`findings.json 共 1 条`),发现通道与校验通道在结构上互不污染。

| 阶段 | 耗时 | 产物与结果 |
|---|---:|---|
| recon | 21s | `endpoints.json` 1 端点(GET /),nginx/1.24.0 + Next.js,RSC payload 内嵌数据 |
| test | 20s | 真实 L1 探测 0 findings(靶场真实状态),种子候选保留 |
| report | 9s | `route=multi_agent`,Manager dispatched 2,聚合 1 条,3 会话真实表决 confirmed=0/rejected=0/inconclusive=3 → contested,confidence 0.546,basis=solver+verification+memory,memory_hit 0.46 |

与 08-25 冒烟对比:本轮 recon 收敛为 1 个合并端点条目(上轮 3 条,
`/_next` 静态资源被并入 notes)——recon 粒度是模型行为波动,产物 schema
与链路语义一致;report 阶段从「聚合 0 条」推进到「真实表决+聚合 1 条」,
编排三件套首次在 pi 后端全链路中被真实数据驱动。

聚合报告结论(节选):

```json
{
  "finding_id": "local-ssti-offline",
  "consensus": "contested",
  "confidence": 0.546,
  "basis": [
    {"source": "solver", "detail": "solver finding-ingest 上报", "score": 0.5},
    {"source": "verification", "detail": "复用已存表决: confirmed=0 rejected=0 inconclusive=3", "score": 0.5},
    {"source": "memory", "detail": "相似记录 context::validation:local-ssti-offline", "score": 0.46}
  ]
}
```

「复用已存表决」是设计行为:Route A 流水线先驱动验证池完成 3 会话真实表决
并写黑板 fact,Manager 聚合时复用该 fact 而非二次烧 token 重复表决。

## 二、校验会话零工具语义双防线实测

**第一防线(桥不注册工具)** — 真实桥 + 真实模型(glm-5.3),同一强诱惑
prompt(要求用 Bash 执行 `echo` 并用 Read 读 `/etc/hostname`):

| 实验 | tools | 结果 |
|---|---|---|
| A(校验通道同款配置) | `[]` | `tool_calls=[]`,turns=1,模型纯文本回复——零 tool_request 过协议 |
| B(对照组) | `["Bash"]` | 真实 tool_request×2:`echo ZEROTOOL_PROBE_0828` + `cat /etc/hostname`;模型自述"没有可用的 Read 工具(当前仅有 Bash 工具)" |

B 证明该 prompt 确实会诱发工具调用(甚至自发用 Bash 替代缺失的 Read),
A 的零调用只能归因于桥侧未注册任何工具——第一防线实测成立,且注册面与
白名单严格一致(模型感知的工具面 = Python 下发的 tools 列表)。

**第二防线(Python 侧二次白名单)** — 即使桥侧异常注册了工具并发回
tool_request,`PiExecutor._judge` 对 `name not in allowed_tools` 一律拒绝。
新增单测 `test_pi_validation_session_contract_denies_any_tool_request`
钉死该校验通道契约:`allowed_tools=[]` 下 Bash/Read 两笔请求全部
`verdict allow=False`,审计记录(`tool_calls`)照常保留不丢轨迹;
`test_pi_bridge_registers_only_whitelisted_tool_names` 从桥源码断言注册面
严格来自 `tools` 列表与工具工厂的交集。

## 三、发现≠校验 provider 可不同配置的组合冒烟

**配置面**:CLI 新增 `--pi-validation-provider` / `--pi-validation-model`
(缺省沿用发现通道配置),校验通道零工具语义不变;`_build_validation_executor`
独立构造,与发现 executor 是不同对象(防自证约束在结构上成立)。

```text
$ cain-agent run --target http://x/ --backend pi \
    --pi-model glm-5.3 --pi-validation-model glm-5.3-air --dry-run
  pi provider/model: anthropic/glm-5.3
  pi 校验通道:      anthropic/glm-5.3-air(零工具)
```

**组合冒烟**(全真实调用):

| 通道 | 配置 | 实测 |
|---|---|---|
| 发现 | glm-5.3 + Bash/Read/Grep/Glob | 真实工具回路:`tool_calls=[('Bash', {'command': 'echo COMBO_PROBE_0828'})]`,输出原样回报 |
| 校验 | glm-5.3-air + 零工具 | 真实表决 JSON(verdict=inconclusive),无任何 tool_request |
| 组合编排 | 发现 glm-5.3 / 校验 glm-5.3-air | fixture → 3 会话真实表决:`verify-0 confirmed / verify-1 输出不合规→inconclusive / verify-2 confirmed` → **多数 confirmed(2/3)** → consensus=confirmed,confidence=0.896,basis 三源齐备,memory_hit 0.462 |

多数决路径(confirmed)与安全降级路径(输出不合规→inconclusive)在本次
组合冒烟里都被真实走到。本轮也再次观察到 GLM 系校验输出纪律波动
(表决 prompt 偶发无 JSON 输出),池语义将其收敛为 inconclusive 票
(保守方向),与 08-26 bench 记录一致。

**诚实声明**:本机网关的 `glm-5.3-air` / `deepseek-v4` 等 id 实测自述均为
GLM(Z.ai)——网关将其别名到同一上游。本冒烟证明的是**会话级配置分离**
(发现/校验各自 provider+model 独立生效、互不串扰),多厂商模型差异属
providers 波次(凭证缺失未跑通,见 pi-providers-2026-08-26)。

## 四、双后端行为等价对照

同一 fixture、同一编排代码、同一脚本结构,仅校验会话执行引擎不同:

| 对照字段 | pi(PiExecutor, glm-5.3) | claude(SDKExecutor) |
|---|---|---|
| route | multi_agent | multi_agent |
| summary.results | validation_inconclusive=1 | validation_inconclusive=1 |
| consensus | contested | contested |
| confidence | **0.548** | **0.548**(逐位一致) |
| basis 三源 | solver+verification+memory | solver+verification+memory |
| memory_hits 键 | `validation:local-ssti-offline`(0.48) | `validation:local-ssti-offline`(0.477) |
| 3 会话票型 | 3×inconclusive(2×invalid JSON+1×invalid verdict) | 3×inconclusive(2×invalid JSON+1×invalid verdict) |
| Manager dispatched | 2 | 2 |
| 墙钟 | ~1min | ~11min |

本轮两侧表决会话均未输出合规 JSON——两后端此刻经网关路由到同一 GLM 系
上游,表决 prompt 的输出纪律波动同源;要点在于**错误路径的收敛完全同构**:
两侧都把不合规会话收敛为 inconclusive 票(绝不伪造),最终 contested
分支、confidence 数值、basis 结构、记忆命中逐字段一致。干净表决路径的
等价证据:pi 侧组合冒烟(§三)走到 confirmed 多数分支(2/3 confirmed,
confidence 0.896);claude 侧 08-26 bench 三轮均输出纯 JSON 表决票。
consensus 映射的两条分支(confirmed/contested)在两后端都有真实运行覆盖。

等价判据全部成立:

1. **路由同构**:两后端均收敛 `route=multi_agent`,Manager dispatched=2
   (ingest + report),无 Route A 回退。
2. **表决语义同构**:票 → consensus → 四态映射同一套代码路径
   (多数 confirmed→confirmed;无多数/输出不合规→contested→
   validation_inconclusive)。pi 侧两轮分别走到 contested 与 confirmed
   两条收口路径,claude 侧见上表及 08-26 bench。
3. **依据链同构**:basis 三源(solver/verification/memory)两后端齐备,
   memory_hits 键同为 `validation:<finding_id>`(语义记忆检索与表决事实
   写回黑板的行为与后端无关)。
4. **安全降级同构**:模型输出不合规时,两后端都收敛为 inconclusive 票
   (绝不伪造 confirmed/rejected)——错误路径同样等价。

## 五、代码改动清单

- `src/cain_agent/cli.py`:新增 `--pi-validation-provider` /
  `--pi-validation-model`(缺省沿用发现通道);`_build_validation_executor`
  支持校验通道独立 provider/model;dry-run 输出校验通道配置行。
- `tests/test_pi_executor.py`:新增 6 例——校验通道独立配置解析/构造/
  缺省镜像、dry-run 校验通道输出、零工具第二防线契约(allowed_tools=[]
  下任何 tool_request 全拒)、桥源码注册面白名单断言。
- 本报告。桥(`toolchain/pi/bridge.mjs`)与编排层
  (`src/cain_agent/multi_agent/`)零改动——双会话/验证池/语义记忆在 pi
  后端的行为等价不依赖任何桥侧或编排层适配。

## 六、测试与交付

```text
pytest -q
997 passed, 3 skipped   (991 基线 + 新增 6 例,零回归)
```

全链路运行日志与聚合产物见 `tmp_run_fullpi/`(临时,不入库;关键证据已
摘录进本报告)。

## 七、遗留与建议(后续波次)

- GLM 系校验输出纪律波动(表决 prompt 偶发纯文本/代码块无 JSON)在零工具
  通道下持续可观察;池的安全降级掩盖了其危害,但 confirmed 票型会偏低。
  若后续波次把脱敏证据摘要带入 pool candidate(08-26 已提出),建议同步
  考虑表决 prompt 的输出约束强化(桥不动,prompt 拼装在 Python 侧)。
- 网关模型目录为空 + 非 glm id 别名到同一上游:会话级配置分离已可配置,
  但"发现用高能力/校验用低成本模型"的实际收益测算需等 providers 波次
  拿到真实多厂商凭证后补。
- recon 端点数在两轮真实运行间波动(3 vs 1):模型行为差异,非链路语义
  差异;若需稳定可复现的 recon 口径,可考虑 recon 阶段技能 prompt 中加
  端点枚举下限约定(属 Codex-B pi-skills 波次的技能适配范畴)。
