# done-claude-main · 2026-08-29 · 阶段模型路由收官(Phase 2.7 最后一项)

> 对应派活单 `tasks/2026-08-29.md` · Claude 主力名下任务
> `feat/2026-08-29-model-routing`(已推送 origin)

## 分支与提交

- 分支:`feat/2026-08-29-model-routing`(已推送 origin,禁直提 main 已遵守)
- 提交:`cac5fed` — feat(cli): 阶段模型路由 — recon/test 混搭引擎与
  provider/model
- 署名:`cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`
- 改动:`src/cain_agent/cli.py`、`tests/test_model_routing.py`(新增 18 例)、
  `README.zh-CN.md`(「按阶段混搭模型路由」一节)、本 mailbox

## 任务完成情况

1. **pipeline 级模型混搭路由** ✅ 新增
   `--recon-backend/--test-backend`(choices claude/pi,缺省回落
   `--backend`)+ 配套 `--recon-provider/--recon-model`、
   `--test-provider/--test-model`(缺省回落 `--pi-provider/--pi-model`;
   claude 后端忽略)。典型组合 `--recon-backend pi + 网关低成本模型
   --test-backend claude` 即派活单要求的"recon 低成本/test 高能力"。
2. **缺省行为零变化** ✅ 解析层:全部缺省时 recon/test 配置相等;构造层:
   配置相同即共享**同一个** executor 对象(identity 断言钉死),既有
   `_build_executor` 测试注入点原样保留;dry-run 展示面缺省零新增输出
   (真实 dry-run 冒烟逐行比对确认)。
3. **路由分发测试** ✅ 18 例四层覆盖:配置解析回退链(7)/构造层共享 vs
   各走各的(4,含混搭类型与参数、显式同配置仍共享)/全流程分发(3:
   侦察 prompt 只进 recon 通道、测试 prompt 只进 test 通道、guard 双挂载)/
   parser 与 dry-run 面(4)。全程零 token 零触网替身。
4. **README 说明** ✅ 「按阶段混搭模型路由」小节:示例 + 参数回退规则 +
   缺省零变化与 scope 拦截不降级两条行为约束。

## 安全语义(混搭不降级)

- **scope 硬拦截双挂载**:Orchestrator 只给它收到的 executor 挂
  ScopeGuardHook;混搭下 recon 通道由 CLI 补挂同一套(pi 桥无 hook 时
  工具调用默认放行,漏挂即失守)。集成测试断言两通道各至少 1 个 hook。
- **防自证对照随发现通道**:findings 由 test 阶段产出,FindingsPipeline
  的 discovery_executor 改取 test executor(发现者≠校验者不变)。

## 测试

- 全量 `pytest -q`:**1019 passed + 3 skipped**(1001 基线 + 新增 18,零回归)
- ruff check + format:全绿
- 真实 CLI 冒烟:缺省 dry-run 与旧版输出一致;混搭 dry-run 正确展示
  两阶段后端与"共享发现会话: 否"

## 遗留移交

- 「recon=pi+网关 glm / test=claude」组合的真实 token 跑分未做(派活单
  未要求;低成本通道收益测算依赖 providers 凭证波次,同 08-28 报告遗留)
- ROADMAP Phase 2.7 模型路由条目待 Lead 验收时勾选

## 通道备注

本会话无 team MCP 工具(与 08-21 dispatch-status 记录一致),按惯例以
本文件作 mailbox 汇报;分支已推送,待 Lead 验收合并。
