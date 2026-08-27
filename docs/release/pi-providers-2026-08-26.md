# pi 多 provider 实测记录（2026-08-26 夜班）

## 结论

本轮**未达到“真实跑通至少两家非 Anthropic provider”验收线**。本机发现的
DeepSeek、Gemini、OpenRouter 三枚历史凭证均无法完成推理鉴权；GitHub Models
端点处于退役 brownout，GitHub Copilot 也未能换取可用 token。

本轮没有把零文本、零 token 的返回误记为成功。实测同时发现并修复了桥接层
吞掉 provider 错误的问题：assistant 消息的 `stopReason=error` 与
`errorMessage` 现在会进入 `done.error`，Python 侧可稳定得到
`ExecutorResult.is_error=True`。

## 方法

统一使用 `@earendil-works/pi-ai` 0.84.x 与仓库内 Node 桥，密钥仅在单次测试
进程中通过 provider 约定的环境变量传入，没有写入仓库、命令输出或本文档。

计划对每个可用 provider 执行同一组三项提示：

| 维度 | 判定方法 |
|---|---|
| 中文指令遵循 | 要求只用简体中文输出一句话，检查是否混入英文 |
| JSON 输出纪律 | 要求仅输出单行固定 schema，使用 JSON parser 校验 |
| 工具调用稳定性 | 强制调用 `Bash` 执行 `printf PI_TOOL_OK`，检查工具记录与最终文本 |

## 鉴权与连通性结果

| pi provider / 通道 | 目标模型或端点 | 环境变量 | 实测结果 | 是否计入跑通 |
|---|---|---|---|---:|
| `deepseek` | `deepseek-v4-flash` | `DEEPSEEK_API_KEY` | `/models` 返回 HTTP 401，凭证无效 | 否 |
| `google` | `gemini-2.5-flash` | `GEMINI_API_KEY` | Generative Language `/models` 返回 HTTP 400，凭证无效 | 否 |
| `openrouter` | DeepSeek / Google 上游模型 | `OPENROUTER_API_KEY` | 模型目录可匿名读取；推理返回 HTTP 401 `Missing Authentication header` | 否 |
| GitHub Models | OpenAI-compatible 推理端点 | 临时环境变量 | HTTP 410，服务提示 scheduled retirement brownout | 否 |
| `github-copilot` | Copilot 模型目录 | `COPILOT_GITHUB_TOKEN` | 已登录 GitHub 凭证无法换取 Copilot token | 否 |

首轮 DeepSeek 与 Google 桥调用均在约 0.4-0.7 秒内返回空文本、零 token、零轮次。
修复错误传播后，相同无效鉴权会明确收敛为 `is_error=True`，不再形成假阳性。

## 模型行为对比

| 上游模型 | 工具调用稳定性 | JSON 输出纪律 | 中文指令遵循 | 说明 |
|---|---|---|---|---|
| DeepSeek | 未测量 | 未测量 | 未测量 | 鉴权在模型执行前失败 |
| Google Gemini | 未测量 | 未测量 | 未测量 | 鉴权在模型执行前失败 |

没有真实模型输出时，不能从传输层错误推断模型行为差异。

## 本轮代码改动

- 桥注册表新增 pi 原生 `openrouter` 与 `github-copilot` provider。
- README 更正 Google 环境变量为 `GEMINI_API_KEY`，补充 OpenRouter 与 Copilot
  环境变量约定。
- 桥把 provider 错误传播到 `done.error`，避免失败被报告为成功。

## 补跑条件

提供至少两家有效凭证后，按上表三项同题提示重新运行。DeepSeek 应优先使用
`DEEPSEEK_API_KEY` 原生通道；第二家可用 `GEMINI_API_KEY`、`OPENAI_API_KEY`
或 `OPENROUTER_API_KEY`。验收数据必须同时包含非空响应、非零 token 用量与
无错误的最终状态，工具项还必须包含实际 `Bash` 调用记录。
