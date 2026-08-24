# done-claude-main · 2026-08-25 · pi 后端真实冒烟 + 桥 API 对齐实测

> 对应派活单 `tasks/2026-08-25-am.md`(监工补位)· Claude 主力名下任务
> `feat/2026-08-25-pi-smoke`

## 分支与提交

- 分支:`feat/2026-08-25-pi-smoke`(已推送 origin)
- 提交:`4bc7b84` — `fix(pi): 桥 API 对齐实测(0.84.x) + 真实冒烟全链路绿`
- 署名:`cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`
- 改动:`toolchain/pi/bridge.mjs`(6 处 API 修正+网关支持)、
  `toolchain/pi/README.md`、`src/cain_agent/pi_executor.py`(1 处 limit)、
  `.gitignore`、`package-lock.json`、报告 `docs/release/pi-smoke-2026-08-25.md`

## 派活四项全部完成

1. **npm install** ✅ Node 24,6 包 0 漏洞(package-lock 已入库)
2. **最小真实调用打通 + API 修正** ✅ 桥原按文档臆写,实测 0.84.x 有 6 处
   出入:工具 `execute` 签名/`details`+`label` 必填、`agent_end` 只带
   `messages`(文本/usage 从末条 assistant 提取)、无 `setMaxTurns`(改
   `shouldStopAfterTurn` 恒计数)、stdin EOF 截杀。另加 `PI_BASE_URL`
   网关支持(Anthropic Messages 兼容网关,目录外模型 ad-hoc 透传)。
   Python 侧协议不动;唯一 Python 改动是 `_spawn_bridge` limit 32MB
   (recon 级长 done 行触发 StreamReader 64KB 上限,首轮冒烟 recon 产物
   因此整体丢失,修复后重跑恢复)。
3. **靶场非 dry-run 全链路** ✅ `http://103.236.66.228:3333/` + 网关
   glm-5.3:recon 24s 出 3 端点(与 08-19 claude 基线一致)、test 16s
   0 findings(nginx 405,靶场真实状态)、report multi_agent 编排,
   exit 0 三阶段完成。
4. **scope 越权实测** ✅ out-of-scope(example.com)判拒不执行、模型如实
   转述;in-scope 放行真实执行观测 HTTP 200。桥回 Python 单点判决、
   默认拒绝,与 claude 后端语义逐点对齐。

## 测试

- `tests/test_pi_executor.py` 19 例全绿;全量 **975 passed + 3 skipped**
  (worktree 独立 venv,boto3/kubernetes 已装收集零错误)

## 遗留给后续波次

- numTurns 现恒计数(未设 maxTurns 也有值),编排层注意口径
- 多 provider 冒烟归 `feat/2026-08-25-pi-providers`(Codex-A)
- openai 兼容网关 ad-hoc 构造留 providers 波次
