#!/usr/bin/env node
// pi bridge — cain-agent 第二执行引擎的 Node 侧。
//
// 协议(stdio,每行一个 JSON;与 src/cain_agent/pi_executor.py 对应):
//   stdin : {"type":"run","prompt","tools","provider","model","maxTurns"}
//           {"type":"verdict","id","allow"}          ← Python 侧 scope 判决
//   stdout: {"type":"tool_request","id","name","input"} 工具调用回判
//           {"type":"tool_result","id","ok","output"}   审计(无论放行与否)
//           {"type":"text","delta"}                    助手文本增量
//           {"type":"done","text","usage","numTurns","error"}
//
// 安全:桥自身不判断放行 —— 每笔工具调用必须等到 Python 侧 verdict
// 才执行;tools 为空时不给模型注册任何工具(零工具只读通道)。

import { createInterface } from "node:readline";
import { execFile } from "node:child_process";
import { Agent } from "@earendil-works/pi-agent-core";
import { createModels } from "@earendil-works/pi-ai";

const enc = new TextEncoder();
let nextId = 1;

function emit(obj) {
  process.stdout.write(enc.encode(JSON.stringify(obj) + "\n"));
}

// ---- Python → 桥:verdict 应答 -------------------------------------------------

const pendingVerdicts = new Map(); // id -> {resolve}
function awaitVerdict(id) {
  return new Promise((resolve) => pendingVerdicts.set(id, resolve));
}

// ---- Bash 工具(scope 判定在 Python 侧,工具名保持 "Bash" 与 hook matcher 对齐) ----
//
// AgentTool 契约(实测 0.84.x):execute(toolCallId, params, ...) 两参起;
// 返回值 content + details 均必填;label 为 UI 必填字段。

function makeBashTool() {
  return {
    name: "Bash",
    label: "Bash",
    description: "Run a shell command and return combined stdout/stderr.",
    parameters: {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    },
    async execute(_toolCallId, params) {
      const command = String(params?.command ?? "");
      const id = String(nextId++);
      emit({ type: "tool_request", id, name: "Bash", input: { command } });
      const allow = await awaitVerdict(id);
      if (!allow) {
        const output = "blocked by scope guard: target outside authorized scope";
        emit({ type: "tool_result", id, ok: false, output });
        return { content: [{ type: "text", text: output }], details: { blocked: true } };
      }
      const output = await new Promise((resolve) => {
        execFile("bash", ["-c", command], { timeout: 120_000, maxBuffer: 8 * 1024 * 1024 },
          (err, stdout, stderr) => {
            const text = `exit=${err ? (err.code ?? 1) : 0}\n${stdout ?? ""}${stderr ?? ""}`;
            resolve(text.slice(0, 200_000));
          });
      });
      emit({ type: "tool_result", id, ok: true, output });
      return { content: [{ type: "text", text: output }], details: { blocked: false } };
    },
  };
}

// ---- provider 注册(动态加载;缺包只影响该 provider,不影响其他) ------------------

const PROVIDER_MODULES = {
  anthropic: "anthropic",
  openai: "openai",
  google: "google",
  deepseek: "deepseek",
  "github-copilot": "github-copilot",
  openrouter: "openrouter",
};

async function loadProvider(name) {
  const mod = PROVIDER_MODULES[name];
  if (!mod) return null;
  const pkg = await import(`@earendil-works/pi-ai/providers/${mod}`);
  const factory =
    pkg.default ??
    pkg[`${name}Provider`] ??
    pkg[`${mod}Provider`] ??
    null;
  return typeof factory === "function" ? factory : null;
}

// ---- 自定义网关(可选) -----------------------------------------------------------
//
// PI_BASE_URL 指向 Anthropic Messages 协议兼容网关时:目录内模型覆盖 baseUrl,
// 目录外模型名透传构造(ad-hoc Model,最小必填字段)。auth 仍走 provider 的
// 环境变量约定(ANTHROPIC_AUTH_TOKEN / ANTHROPIC_API_KEY / ...)。

function makeAdHocModel(provider, id, baseUrl) {
  return {
    id,
    name: id,
    api: "anthropic-messages",
    provider,
    baseUrl,
    reasoning: true,
    input: ["text", "image"],
    cost: {},
    contextWindow: 200_000,
    maxTokens: 32_000,
  };
}

// ---- 主流程 -------------------------------------------------------------------

async function main(task) {
  const models = createModels();
  const providerName = String(task.provider || "anthropic");
  const providerFactory = await loadProvider(providerName);
  if (!providerFactory) {
    emit({ type: "done", text: "", usage: null, numTurns: 0, error: `unknown or unloaded provider: ${providerName}` });
    return;
  }
  models.setProvider(providerFactory());

  const baseUrlOverride = process.env.PI_BASE_URL || null;

  let model = null;
  if (task.model) {
    model = models.getModel(providerName, String(task.model)) ?? null;
    if (!model && !baseUrlOverride) {
      emit({ type: "done", text: "", usage: null, numTurns: 0, error: `unknown model: ${providerName}/${task.model}` });
      return;
    }
    if (!model) {
      model = makeAdHocModel(providerName, String(task.model), baseUrlOverride);
    } else if (baseUrlOverride) {
      model = { ...model, baseUrl: baseUrlOverride };
    }
  }

  const tools = Array.isArray(task.tools) ? task.tools : [];
  const agentTools = tools.includes("Bash") ? [makeBashTool()] : [];

  // 轮次上限:Agent 无 setMaxTurns(实测 0.84.x),用 shouldStopAfterTurn 计数拦截;
  // 计数恒启用(done.numTurns 有意义),maxTurns>0 时才触发停轮。
  const maxTurns = task.maxTurns ? Number(task.maxTurns) : 0;
  let turnsDone = 0;

  const agent = new Agent({
    initialState: {
      systemPrompt:
        "You are the execution engine of an authorized security-testing pipeline. " +
        "Answer with precise, structured output; every shell command you need must go " +
        "through the Bash tool.",
      model: model ?? undefined,
      tools: agentTools,
    },
    streamFn: models.streamSimple.bind(models),
    shouldStopAfterTurn: () => {
      turnsDone += 1;
      return maxTurns > 0 && turnsDone >= maxTurns;
    },
  });

  // agent_end(实测 0.84.x)只带 messages: AgentMessage[] —— 最终文本/usage 从
  // 最后一条 assistant 消息提取;numTurns 以 shouldStopAfterTurn 计数为准。
  let finalText = "";
  let usage = null;
  let error = null;
  const unsub = agent.subscribe((event) => {
    if (event.type === "message_update" && event.assistantMessageEvent?.type === "text_delta") {
      emit({ type: "text", delta: event.assistantMessageEvent.delta });
    } else if (event.type === "agent_end") {
      for (let i = event.messages.length - 1; i >= 0; i--) {
        const msg = event.messages[i];
        if (msg?.role !== "assistant") continue;
        if (Array.isArray(msg.content)) {
          finalText = msg.content
            .filter((c) => c?.type === "text")
            .map((c) => c.text)
            .join("");
        } else if (typeof msg.content === "string") {
          finalText = msg.content;
        }
        usage = msg.usage ?? null;
        if (msg.stopReason === "error") {
          error = String(msg.errorMessage || "provider request failed");
        }
        break;
      }
    }
  });

  try {
    await agent.prompt(String(task.prompt ?? ""));
    await agent.waitForIdle();
  } catch (err) {
    error = String(err?.message ?? err);
  } finally {
    unsub();
  }
  emit({ type: "done", text: finalText, usage, numTurns: turnsDone, error });
}

// ---- stdio 驱动 ----------------------------------------------------------------

// stdin EOF 不立即退出:等运行中的 run 收敛(管道模式下 echo 完就 EOF,
// 立即 exit 会杀掉进行中的执行;Python 侧持续持有 stdin,行为不变)。
let running = null;

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return; // 非 JSON 行忽略
  }
  if (msg.type === "verdict") {
    const waiter = pendingVerdicts.get(String(msg.id));
    if (waiter) {
      pendingVerdicts.delete(String(msg.id));
      waiter(Boolean(msg.allow));
    }
    return;
  }
  if (msg.type === "run" && !running) {
    running = main(msg)
      .catch((err) => {
        emit({ type: "done", text: "", usage: null, numTurns: 0, error: String(err?.message ?? err) });
      })
      .finally(() => {
        running = null;
      });
  }
});
rl.on("close", () => {
  if (running) {
    running.then(() => process.exit(0));
  } else {
    process.exit(0);
  }
});
