# done-claude-main · 2026-08-28 · pi 编排模式全链路实测 + 双会话语义验证

> 对应派活单 `tasks/2026-08-28-am.md` · Claude 主力名下任务
> `feat/2026-08-28-pi-orchestration`(已推送 origin)

## 分支与提交

- 分支:`feat/2026-08-28-pi-orchestration`(已推送 origin,禁直提 main 已遵守)
- 提交:`721311d` — feat(pi): 校验通道独立 provider/model 配置 + pi 编排
  全链路实测报告
- 署名:`cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`
- 改动:`src/cain_agent/cli.py`、`tests/test_pi_executor.py`(+6 例)、
  报告 `docs/release/pi-orchestration-2026-08-28.md`

## 派活四项全部完成

1. **`--backend pi` 编排模式全链路实测** ✅ 自建靶场
   `http://103.236.66.228:3333/` + 网关 glm-5.3,exit 0,三阶段 51s
   (recon 21s/test 20s/report 9s)。fixture 候选预置使 report 阶段编排
   三件套在同一次真实运行里被真实驱动:Manager dispatched 2 聚合 1 条、
   验证池 3 会话真实表决、语义记忆命中 0.46、route=multi_agent。
2. **Manager 聚合/验证池/语义记忆行为等价** ✅ 同 fixture 同脚本双后端
   A/B:route/consensus 映射/basis 三源/记忆命中键逐字段同构,confidence
   同为 0.548(逐位一致);错误路径收敛同构(输出不合规→inconclusive 票,
   绝不伪造)。consensus 两分支均有真实运行覆盖(pi 侧另走通 confirmed
   多数分支 2/3,confidence 0.896)。
3. **校验会话零工具语义双保险实测** ✅ 第一防线(桥不注册):真实桥+真实
   模型,强诱惑 prompt 下零 tool_request,对照组同 prompt 注册 Bash 后
   真实调用 2 次(归因成立,且模型感知工具面=白名单);第二防线(Python
   二次白名单):allowed_tools=[] 下任何 tool_request 一律 deny,新增单测
   钉死契约。
4. **发现≠校验 provider 可不同配置组合冒烟** ✅ CLI 新增
   `--pi-validation-provider/--pi-validation-model`(缺省沿用发现通道);
   组合冒烟全真实:发现 glm-5.3+工具面真实回路 / 校验 glm-5.3-air+零工具
   真实表决 / 组合编排 confirmed 多数收口。诚实声明:本机网关非 glm id
   实为同上游别名,本冒烟证明会话级配置分离,多厂商差异属 providers 波次。

## 测试

- 全量 `pytest -q`:**997 passed + 3 skipped**(991 基线 + 新增 6,零回归)

## 遗留移交(详见报告 §七)

- GLM 表决输出纪律波动致 confirmed 票型偏低(池安全降级兜住),建议
  后续波次强化表决 prompt 输出约束(Python 侧拼装,桥不动)
- recon 端点粒度轮间波动(3 vs 1),如需稳定口径归 Codex-B 技能适配范畴
- 网关模型目录为空+别名同上游,"高低搭配"收益测算待 providers 凭证

## 通道备注

本会话无 team MCP 工具(与 08-21 dispatch-status 记录一致),按惯例以
本文件作 mailbox 汇报;分支已推送,待 Lead 21:00 验收合并。
