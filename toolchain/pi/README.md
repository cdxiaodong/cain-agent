# pi 桥 — cain-agent 第二执行引擎的 Node 侧

`cain-agent run --backend pi` 时,Python 侧 `PiExecutor` 会 spawn 本目录的
`bridge.mjs`(Node 子进程),经 stdio JSON 行协议驱动 agent 运行时,LLM provider
可切换(anthropic / openai / google / deepseek …)。

## 安装(一次性)

```bash
cd toolchain/pi
npm install
```

需要 Node ≥ 20。未安装时 `--backend pi` 会给出明确错误并退出,默认后端
`claude`(Claude Agent SDK)不受影响。

## 协议

| 方向 | 消息 | 说明 |
|---|---|---|
| → 桥 | `{"type":"run","prompt","tools","provider","model","maxTurns"}` | 启动一次执行 |
| ← 桥 | `{"type":"tool_request","id","name","input"}` | 工具调用回 Python 判定 |
| → 桥 | `{"type":"verdict","id","allow"}` | scope 判决(allow=false 即拒绝) |
| ← 桥 | `{"type":"tool_result","id","ok","output"}` | 审计记录 |
| ← 桥 | `{"type":"text","delta"}` | 助手文本增量 |
| ← 桥 | `{"type":"done","text","usage","numTurns","error"}` | 最终收敛 |

## 安全语义

桥自身不判断放行 —— 每笔工具调用必须等到 Python 侧 verdict 才执行;
scope 判定逻辑单点在 `src/cain_agent/scope.py` 的 ScopeGuardHook,
双会话(发现≠校验)、默认拒绝、idle/total 双防线全部在 Python 侧,
与 claude 后端语义一致。

## 用法示例

```bash
# 默认 provider(anthropic)
cain-agent run --target http://your-range.example/ --backend pi

# 指定 provider 与模型
cain-agent run --target http://your-range.example/ \
  --backend pi --pi-provider deepseek --pi-model deepseek-chat
```

环境变量:provider 的 API key 走各自约定(`ANTHROPIC_API_KEY` /
`OPENAI_API_KEY` / `GOOGLE_API_KEY` / `DEEPSEEK_API_KEY`),桥进程继承
当前 shell 环境。
