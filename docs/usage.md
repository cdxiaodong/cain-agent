# Cain 用户指南

> 面向第一次接触 Cain 的使用者:从安装到跑完第一次授权测试,以及双后端/模型
> 路由的选型建议。CLI 参数全量说明见 `cain-agent run --help`。
> **前置阅读**:README 的法律与合规声明——Cain 仅用于已获授权的测试。

## 1. 安装

### 基础安装(Python ≥ 3.11)

```bash
git clone https://github.com/cdxiaodong/cain-agent
cd cain-agent
pip install -e .          # 或: uv pip install -e .
cain-agent --version      # 验证安装
```

### 可选组件

```bash
pip install -e ".[cloud]"   # AWS S3 / 华为 OBS / Kubernetes 检测(可选)
pip install -e ".[dev]"     # 开发:ruff / pyright / pytest
```

pi 执行后端需要 Node.js ≥ 20(见 §4):

```bash
npm ci --prefix toolchain/pi
```

## 2. 第一次运行

### 授权范围先行

目标是**已获授权**的测试对象(自建靶场、自有环境或书面授权项目)。
首次运行会自动把目标写入工作区 `scope.yaml`:

```bash
cain-agent run \
  --target https://app.example.com \
  --workspace ./workspace \
  --total-budget 1800
```

- `--target`(必填):目标 host/URL,归一化后作为唯一 in_scope 条目;
- `--workspace`:状态目录(默认 `./workspace`),全部产物落在这里;
- `--total-budget`:墙钟总预算秒数(推荐先用 1800 起步);
- `--idle-timeout`:单步空闲超时秒数(默认 300)。

**scope 是工程强制的**:每次工具调用前由 PreToolUse 钩子校验,目标落在
`scope.yaml` 之外一律拒绝——不依赖模型自觉。要调整范围,直接编辑
`workspace/scope.yaml`:

```yaml
in_scope:
  - app.example.com
  - "*.internal.example.com"   # 通配子域
  - 203.0.113.0/24             # CIDR
out_of_scope:
  - mail.internal.example.com  # deny 优先
```

### 先跑 dry-run 看执行计划

```bash
cain-agent run --target https://app.example.com --dry-run
```

打印目标/工作区/阶段计划/后端配置,不启动任何 Agent。

## 3. 读懂输出产物

一次 run 结束后,`workspace/report/` 落三件产物:

| 文件 | 用途 |
|---|---|
| `report.md` | 人类可读报告:执行摘要、findings 表(severity/置信度/依据链)、证据哈希索引、修复建议、法律声明 |
| `aggregated-report.json` | 机器可读聚合报告(schema_version 1),供下游系统消费 |
| `validation-summary.json` | 校验流水线汇总:四状态计数与失败明细 |

`workspace/` 其余文件是各阶段中间产物(assets/findings/state),支持崩溃恢复
——中断后重跑同命令会从断点续走。

## 4. 选择执行后端

默认 `claude` 后端(Claude Agent SDK)。`--backend pi` 切换到 pi 后端
(经 Node 桥,支持多 provider):

```bash
# 默认 provider(anthropic)
export ANTHROPIC_API_KEY="sk-..."
cain-agent run --target https://app.example.com --backend pi

# deepseek(低成本)
export DEEPSEEK_API_KEY="sk-..."
cain-agent run --target https://app.example.com \
  --backend pi --pi-provider deepseek --pi-model deepseek-chat

# Anthropic Messages 协议兼容网关
export PI_BASE_URL="https://gateway.example.com"
export ANTHROPIC_AUTH_TOKEN="your-gateway-token"
cain-agent run --target https://app.example.com \
  --backend pi --pi-model your-gateway-model-id
```

**两个后端的安全语义完全一致**:scope 白名单、发现≠校验双会话、默认拒绝、
idle/total 双防线——切换后端不改变任何安全约束。

## 5. 按阶段混搭模型(成本优化)

侦察是重复性枚举,测试才需要高能力判断——可以让两个阶段各走各的引擎:

```bash
cain-agent run --target https://app.example.com \
  --recon-backend pi --recon-provider anthropic --recon-model cheap-model-id \
  --test-backend claude
```

- 阶段参数(`--recon-*` / `--test-*`)缺省回落全局 `--backend` /
  `--pi-provider` / `--pi-model`;
- 不传任何阶段参数时行为与只配 `--backend` 完全一致;
- report 校验通道另有 `--pi-validation-provider` / `--pi-validation-model`
  独立配置。

## 6. 常见问题

**Q: 提示 `pi bridge not found`?**
pi 后端需要 `npm ci --prefix toolchain/pi`(Node ≥ 20),详见
`toolchain/pi/README.md`。

**Q: 测试阶段 0 findings?**
先看 `validation-summary.json` 与 recon 的 endpoints.json——可能是攻击面
确实被前置防护(如 nginx 405)拦住,详见各 smoke 报告对同类场景的归因示例。

**Q: 想中断?** Ctrl-C 会优雅收敛:已完成的阶段产物保留,重跑同命令断点续走。

**Q: 如何贡献/报告问题?** 见 `docs/community.md`(Issue 模板与安全报告通道)。
