# done-claude-core · 2026-08-19 晚 · 编排模式全链路 smoke

## 分支与提交

- 分支：`feat/2026-08-19-orchestrated-smoke`（已推送 origin）
- 报告提交：`d64be9e` — `test(smoke): 编排模式全链路 smoke — 三阶段走通+真实聚合报告+scope强制`
- 署名：`cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`
- 交付物：`docs/release/smoke-2026-08-19.md`

## 验收结论

对自建靶场 `http://103.236.66.228:3333/` 跑**非 dry-run** `cain-agent run`，exit 0：

| 验收点 | 结果 |
|---|---|
| recon→test→report 三阶段编排走通 | ✅ `completed_stages=[recon,test,report]` |
| report 真实聚合报告（非占位） | ✅ `route=multi_agent`，无 `report-placeholder.json` 回退，Manager 实派 2 任务 |
| report 含 confidence 与依据链 | ⚠️ 机制真实+单测覆盖；本轮 0 findings 未在真实数据演练 |
| scope 白名单强制生效 | ✅ 实际请求仅触达 `103.236.66.228`，零越权出网 |

## 关键事实

- recon 提取 3 端点（含 `POST /api/wishes`），正确识别 nginx/1.24.0 + Next.js。
- test 合法地产出 **0 findings**：唯一写入端点 `POST /api/wishes` 被 nginx 层 405
  拦截（独立 curl 复核一致，未达后端），无可达攻击面。**非"链路没跑"，也非"无漏洞"**。
- scope：test 19 条 + recon 41 条实际命令全部只打授权 IP；文本中的
  `evil.com`/`169.254.169.254` 等系注入技能示例 payload，非执行命令。

## 发现问题（只记录，不修；详见 smoke 报告）

1. 云端测试套件缺 boto3 等未声明依赖，`pytest -q` 收集即 11 个 ModuleNotFoundError
   （排除后 678 passed + 3 skipped）——pre-existing（main `db2fb45`），CI 同样会挂。
2. ScopeGuardHook 命令语义误拦仍在：grep 正则/本地路径/chunk 文件名/`2>` 被误判为
   target 并拒整条命令（本轮 48 次 deny 全属此类，recon agent 自述被迫绕行）。
3. `POST /api/wishes` nginx 405 与前端 JS 声称可用矛盾——靶场侧配置观察。
4. confidence/依据链需一个能稳定产出 ≥1 finding 的靶场场景才能在真实数据闭环。

## 自测

- 全量（排除 11 个云端收集错误文件）：`678 passed, 3 skipped`
- 基线核对：recon/test/report 产物、state.json、会话 JSONL 逐条核验通过
