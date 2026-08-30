# Cain — 实战型 AI 渗透测试工程师

> ⚠️ **法律与合规声明(请先读)**
>
> Cain 仅用于**已获授权**的安全测试——你自己的环境，或持有书面授权的测试项目。
> 核心功能默认以**只读**凭证运行；授权范围(scope)由配置文件**工程强制校验**，而非依赖 AI 自律。
> 未获书面授权，禁止对任何第三方系统发起测试；使用者须自行遵守所在地区与目标系统适用的全部法律法规。
> **仅限授权测试，作者不承担任何因滥用产生的法律责任。**

> 🚧 正在积极开发中。欢迎 Star / Watch 关注进展。

[English](README.md) · **简体中文**

**Cain** 是一个面向**真实授权安全评估**的 AI 渗透测试工程师——不是解靶场题的 CTF 玩具。
它走确定性的攻击流水线，用**工程约束**（而非 AI 自律）强制 scope，并内置覆盖
AWS / Azure / GCP / 阿里云 / 腾讯云 / 华为云 的**云渗透模块**——含其他项目都不覆盖的国产云。

基于 [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk) 构建。

---

## 为什么是 Cain

| 维度 | CTF / 靶场型 Agent | **Cain(实战型)** |
|---|---|---|
| 目标 | 静态靶场、预设 flag | 真实企业资产、Bug Bounty、授权项目 |
| 漏洞面 | 已知语法模式漏洞 | **业务逻辑漏洞、鉴权链、云配置错误** |
| 对抗环境 | 无 WAF、无限流 | 真实 WAF / 风控下的动态策略调整 |
| 交付物 | 一个 flag | 可审计的证据链 + 可复现 PoC + 修复建议 |

---

## 快速上手

```bash
git clone https://github.com/cdxiaodong/cain-agent
cd cain-agent
pip install -e .          # 或: uv pip install -e .
pip install -e ".[cloud]" # 可选启用 AWS S3、华为 OBS 与 Kubernetes 检查

cain-agent --version
```

### 给 AI Agent 的一键安装指令

> **"安装 cain-agent 到用户本地 Python 环境，克隆仓库 https://github.com/cdxiaodong/cain-agent，用 pip/uv 装 editable 模式，验证 CLI 可执行"**

这一条指令即可让任意 AI agent 完成：
1. 克隆仓库
2. 以 editable 模式安装（`pip install -e .` 或 `uv pip install -e .`）
3. 运行 `cain-agent --version` 验证安装

### 对目标执行

目标会写入 `scope.yaml`，并在每次工具调用时强制校验：

```bash
cain-agent run \
  --target https://app.example.com \
  --total-budget 1800
```

**参数：** `--target`（必填）· `--workspace`（状态目录，默认 `./workspace`）· `--total-budget`（墙钟秒数）· `--idle-timeout`（单步秒数）

### 选择执行后端

Cain 默认使用 `claude` 后端；传入 `--backend pi` 即可切换到 pi 后端。pi 后端
需要 Node.js 20 或更高版本，并需一次性安装桥依赖：

```bash
npm ci --prefix toolchain/pi
export ANTHROPIC_API_KEY="your-api-key"
cain-agent run --target https://app.example.com --backend pi
```

通过 `--pi-provider` 和 `--pi-model` 可指定其他受支持的 provider 与模型；同时
需要设置对应的标准 API key 环境变量，例如 `OPENAI_API_KEY`、`GEMINI_API_KEY`、
`DEEPSEEK_API_KEY` 或 `OPENROUTER_API_KEY`。使用兼容 Anthropic Messages 协议的
网关时，设置 `PI_BASE_URL`，并通过 `ANTHROPIC_AUTH_TOKEN` 提供 Bearer 凭证：

```bash
export PI_BASE_URL="https://gateway.example.com"
export ANTHROPIC_AUTH_TOKEN="your-gateway-token"
cain-agent run --target https://app.example.com \
  --backend pi --pi-model your-gateway-model-id
```

完整的 provider 与网关配置见 [pi 桥说明](toolchain/pi/README.md)。

### 按阶段混搭模型路由

侦察阶段跑的是大量重复性枚举，测试阶段才需要高能力模型做漏洞判断——
可以让两个执行阶段各走各的引擎与模型：

```bash
# recon 走 pi + 网关低成本模型，test 保持高能力 claude 后端
cain-agent run --target https://app.example.com \
  --recon-backend pi --recon-provider anthropic --recon-model your-gateway-model-id \
  --test-backend claude
```

参数与回退规则：

- `--recon-backend` / `--test-backend`：单阶段引擎覆盖（`claude` / `pi`），
  缺省回落 `--backend`；
- `--recon-provider` / `--recon-model`、`--test-provider` / `--test-model`：
  单阶段 pi 通道的 provider 与模型，缺省分别回落 `--pi-provider` /
  `--pi-model`（claude 后端忽略这两个参数）；
- report 阶段经既有 `--pi-validation-provider` / `--pi-validation-model`
  独立配置（缺省同样回落 `--pi-provider` / `--pi-model`），recon / test /
  report 三阶段皆可分治路由。

行为约束：

- **缺省零变化**：不传任何 `--recon-*` / `--test-*` 参数时，两阶段共享
  同一个执行会话，与只配 `--backend` 的历史行为完全一致；
- **scope 拦截不降级**：无论怎么混搭，每个执行通道都挂同一个
  ScopeGuardHook，授权范围硬拦截、发现≠校验双会话语义全部保持。

## 输出产物

一次 `run` 结束后,工作区 `report/` 目录落三件产物:

- **`report.md`** —— 人类可读报告:执行摘要(目标/授权范围/阶段耗时/发现统计)、
  findings 表(severity 着色标记 + 置信度 + 依据链摘要)、逐条发现详情、
  证据哈希索引(证据原文只哈希不落明文)、按问题类型的修复建议、法律声明;
- **`aggregated-report.json`** —— 机器可读版聚合报告(schema_version 1),
  与 `report.md` 同源,供下游系统消费;
- **`validation-summary.json`** —— 校验流水线汇总(四状态计数与失败明细)。

`report.md` 由纯 Python 模板渲染(零新依赖),同一聚合数据恒定输出,
渲染逻辑见 `src/cain_agent/report_markdown.py`。

---



> **用确定性工程约束 Agent 的自由度**——阶段流转、scope 校验、危险操作熔断是硬工程约束；
> 路径选择与证据分析交给 Agent。

```
                    ┌──────────────────────────────────────────────┐
                    │                 Cain CLI                     │
                    │   cain-agent run --target <t> [--dry-run]    │
                    └───────────────────┬──────────────────────────┘
                                        │
                            ┌───────────▼───────────┐
                            │      Scope 初始化      │  目标 → scope.yaml
                            └───────────┬───────────┘
                                        │
                            ┌───────────▼───────────┐
                            │      Orchestrator      │  确定性状态机
                            │  recon → test → report │  可崩溃恢复 · 受 scope 约束
                            └──┬────────┬────────┬──┘
                               │        │        │
              ┌────────────────▼┐   ┌───▼────┐  ┌▼──────────────┐
              │  Recon  Handler │   │  Test  │  │    Report      │
              │  (技能引导)      │   │Handler │  │   Handler      │
              └────────┬────────┘   └───┬────┘  └───────┬────────┘
                       │                │                │
                       └────────┬───────┴───────┬────────┘
                                │               │
                    ┌───────────▼──────┐   ┌────▼───────────────┐
                    │   SDK Executor    │   │  Findings Pipeline  │
                    │ (Planner/Executor)│   │ finder → validator  │  独立会话
                    │  allowed_tools=[] │   │ (永不共享上下文)     │
                    └─────────┬─────────┘   └─────────────────────┘
                              │
        ┌─────────────────────┼──────────────────────┐
        │                     │                      │
┌───────▼────────┐  ┌─────────▼─────────┐  ┌─────────▼────────┐
│  PreToolUse     │  │   Readonly Guard   │  │     云模块        │
│  Scope 守卫     │  │  46 个只读         │  │  IAM 提权 ·       │
│  + 凭证脱敏     │  │  安全工具          │  │  存储 · SSRF      │
└─────────────────┘  └────────────────────┘  └──────────────────┘

全部状态以文件形式落在工作区（外置记忆）——端到端可崩溃恢复、可审计。
```

**安全是结构性的，而非行为性的：**
- **Scope 强制** —— `PreToolUse` 钩子拦截任何目标落在 `scope.yaml` 之外的工具调用；由配置强制，而非靠模型自觉。
- **只读工具链** —— 内置 46 个只读安全工具（侦察 / 扫描 / 验证 / 后渗透 / 报告），每个工具带独立的 `dangerous_flags` 黑名单；写入 / 利用 / 持久化操作（`POST`、`PUT`、`DELETE`、`aws rm/mv/cp` 等）在执行前即被拒绝。
- **发现者 ≠ 校验者** —— 发现与校验跑在**互不共享上下文的独立 Agent 会话**，结论无法自我确认；判定为 4 状态结构化输出。
- **凭证脱敏** —— 脱敏钩子在落盘前剥离机密信息。

---

## 云模块 —— 别人没做的那部分

```
aws_s3 · azure_blob · gcp_gcs · aliyun_oss · tencent_cos · huawei_obs   →  存储暴露
aws IAM · tencent_cam · aliyun_ram                                        →  提权路径分析
k8s_rbac · docker_image                                                 →  集群与镜像态势
云元数据 SSRF（覆盖 7 家厂商的 IMDS / 169.254.169.254）
```

**IAM / RAM 提权路径图** —— 将 实体 → 提权动作 → 高权限目标 建模为有向图，导出 **DOT / JSON** 供前端渲染，并用 BFS 查找提权路径。由现有 `aliyun_ram` / `tencent_cam` 规则集驱动。

## 基准评测 —— 拿证据，不靠口号

- **自建 vulnerable-terraform 靶场**（`bench/aliyun-vuln-tf/`），每个场景带预期检出对照。
- **Benchmark 执行器**（`bench/run_benchmark.py`）按四指标跑分：检出率、误报率、墙钟耗时、token 成本——不编造百分比，未测结果明确标注「未测量」。
- **44 个测试文件**，覆盖云模块、技能、流水线与 CLI。

---

## ⚠️ 合规与伦理使用

Cain 严格用于**已授权的安全测试**——你自己的环境，或持有书面授权的测试项目。核心功能默认以
只读凭证运行；授权范围由配置强制约束，不依赖 AI 自律。使用者须遵守适用的法律法规。

## 现状

核心 MVP 已可用——确定性流水线、安全钩子、云模块与基准评测均已就位。后续规划见 [ROADMAP.md](ROADMAP.md)，近期进展见 [CHANGELOG.md](CHANGELOG.md)。

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。
