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

function makeBashTool() {
  return {
    name: "Bash",
    description: "Run a shell command and return combined stdout/stderr.",
    parameters: {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    },
    async execute({ args }) {
      const id = String(nextId++);
      emit({ type: "tool_request", id, name: "Bash", input: { command: args.command } });
      const allow = await awaitVerdict(id);
      if (!allow) {
        const output = "blocked by scope guard: target outside authorized scope";
        emit({ type: "tool_result", id, ok: false, output });
        return { content: [{ type: "text", text: output }] };
      }
      const output = await new Promise((resolve) => {
        execFile("bash", ["-c", args.command], { timeout: 120_000, maxBuffer: 8 * 1024 * 1024 },
          (err, stdout, stderr) => {
            const text = `exit=${err ? (err.code ?? 1) : 0}\n${stdout ?? ""}${stderr ?? ""}`;
            resolve(text.slice(0, 200_000));
          });
      });
      emit({ type: "tool_result", id, ok: true, output });
      return { content: [{ type: "text", text: output }] };
    },
  };
}

// ---- provider 注册(动态加载;缺包只影响该 provider,不影响其他) ------------------

const PROVIDER_MODULES = {
  anthropic: "anthropic",
  openai: "openai",
  google: "google",
  deepseek: "deepseek",
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

  let model = null;
  if (task.model) {
    model = models.getModel(providerName, String(task.model));
    if (!model) {
      emit({ type: "done", text: "", usage: null, numTurns: 0, error: `unknown model: ${providerName}/${task.model}` });
      return;
    }
  }

  const tools = Array.isArray(task.tools) ? task.tools : [];
  const agentTools = tools.includes("Bash") ? [makeBashTool()] : [];

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
  });

  let finalText = "";
  let usage = null;
  const unsub = agent.subscribe((event) => {
    if (event.type === "message_update" && event.assistantMessageEvent?.type === "text_delta") {
      emit({ type: "text", delta: event.assistantMessageEvent.delta });
    } else if (event.type === "agent_end") {
      const msg = event.assistantMessage ?? {};
      finalText = typeof msg.content === "string" ? msg.content : finalText;
      usage = event.usage ?? msg.usage ?? null;
    }
  });

  let error = null;
  try {
    if (task.maxTurns) agent.setMaxTurns?.(Number(task.maxTurns));
    await agent.prompt(String(task.prompt ?? ""));
    await agent.waitForIdle();
  } catch (err) {
    error = String(err?.message ?? err);
  } finally {
    unsub();
  }
  emit({ type: "done", text: finalText, usage, numTurns: 0, error });
}

// ---- stdio 驱动 ----------------------------------------------------------------

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
  if (msg.type === "run") {
    main(msg).catch((err) => {
      emit({ type: "done", text: "", usage: null, numTurns: 0, error: String(err?.message ?? err) });
    });
  }
});
rl.on("close", () => process.exit(0));
