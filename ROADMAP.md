# ROADMAP — cain-agent

> 总目标与排期详见 `DESIGN.md(内部设计文档,未随仓库发布)`(设计真源)。
> 本文件是产线每日执行的任务看板,Lead 每天 21:00 验收后更新勾选状态。

## Phase 0 · 地基(2026.08)

- [x] GitHub rename → cain-agent,保留 star/fork
- [x] Apache-2.0 LICENSE
- [x] 新 README(实战定位 + 法律声明)
- [x] Python 骨架:pyproject + src/cain_agent + tests + CI(ruff/pyright/pytest)
- [x] git 署名配置(cdxiaodong + noreply 邮箱)
- [x] GitHub 仓库 topics/description/homepage 补全(2026-08-03 晚 gh 应用 12 topics + description,homepage 按建议留空)
- [x] 旧仓库内容归档整理(66 个云技能保留,盘点见 docs/legacy-inventory.md;exploits/install-tools 待重构项已排入后续 Phase)

## Phase 1 · MVP(2026.09-10)

- [x] SDKExecutor 最小封装(Claude Agent SDK + allowed_tools + Hook 注册)(2026-08-03,core 分支合入)
- [x] scope.yaml + ScopeGuardHook(第一个 Hook,安全先行)(2026-08-03,feat 分支合入)
- [x] Orchestrator 状态机:recon → test → report 最小闭环(2026-08-04,core 分支合入,含 Workspace 外置记忆)
- [x] 3 个核心 Web skill:SQLi / XSS / SSRF(2026-08-04,test 分支合入,含格式校验)
- [x] 云模块起步:阿里云 OSS 暴露检测(2026-08-04,feat 分支合入)
- [x] Workspace 外置记忆(assets.json / findings.json)(2026-08-04,随 Orchestrator 落地)
- [x] Docker 一键运行 + 3 分钟演示视频(Docker 镜像 2026-08-05 合入;演示视频待人工录屏)

## Phase 2 · 校验闭环(2026.11-12)

- [x] 校验 Agent 分离 + 4 状态结构化输出(2026-08-06,FindingValidator 执行层合入,独立 session 防自证)
- [x] 指纹去重 + 定级规则表(2026-08-05,findings.py 合入)
- [x] 云模块:RAM 提权路径分析(2026-08-06,aliyun_ram.py 合入)
- [x] 自建阿里云 vulnerable-terraform 靶场 + 首轮 benchmark(三场景:OSS 公开桶/RAM 过度授权/RAM 管理员;2026-08-31 首轮离线跑分 检出8/误报0/漏报0,1049 绿,报告 docs/release/bench-vulntf-2026-08-31.md;**Phase 2 全部收官**)
- [x] 第一篇传播文章("首个懂国产云的实战 AI 渗透 Agent")(2026-08-10,初稿定稿 + 七厂商/OWASP Top10 更新)

## Phase 2.5 · 中心编排器(2026-08-15 至 08-19,多 Agent 团队提前交付)

- [x] 并行验证池:finding 校验多数表决,交叉确认防单点误判(2026-08-15 起步,08-16 接入 FindingsPipeline)
- [x] 失败自愈:auto_prompt 重派策略 retry/decompose/skip(2026-08-15)
- [x] scope 端口匹配闭环:裸 host 白名单正确命中带端口请求(2026-08-15,含回归测试)
- [x] 语义记忆底座:finding/上下文向量化存储 + 相似度检索,solver 间共享可检索上下文(2026-08-16)
- [x] scope 修复后 smoke 复测:自建靶场非 dry-run 全链路(2026-08-16)
- [x] 中心 Manager 判断聚合:finding 表决 + 记忆旁证 → confidence 结论列表(2026-08-17 交付,08-19 合入)
- [x] 编排全链路接线:Manager/Solver/验证池/语义记忆接入 `cain-agent run`,report 阶段真实聚合报告,经典 Route A 可回退(2026-08-17 交付,08-19 合入)
- [x] 第四篇架构文章:从单 Agent 到多 Agent 编排(2026-08-17 交付,08-19 合入)
- [x] 编排模式 smoke 验证 + auto_prompt 接入编排层 + 编排 vs 经典 benchmark 对比(2026-08-20~22 完成:smoke 零越权走通三阶段、自愈接线 936 绿、benchmark 对比表;后续 scope 误拦修复与 finding fixture 于 08-22 验收合入)

## Phase 2.7 · pi 后端生态(双执行引擎兼容,2026-08-24 起)

> 执行引擎已双轨(claude / pi),本阶段把 pi 后端从「协议打通」推进到
> 「生产可用 + 成本优势可证」。

- [x] pi 真实冒烟:npm install + 真实 LLM 调用,桥 API 字段实测修正,自建靶场
  `--backend pi` 非 dry-run 全链路 + scope 越权实测(2026-08-25,桥 API 6 处修正+网关支持)
- [x] 多 provider 实测:deepseek / openai / google 至少两家跑通,记录行为差异
  (2026-08-27,provider 路由扩展+错误传播,含 openrouter/github-copilot)
- [x] 工具面扩展:Read / Grep / Glob 注册 + 对应 scope / readonly 拦截
  (2026-08-27,判决回 Python,白名单对齐 claude 后端)
- [x] 技能加载适配:SkillLoader 三阶段技能在 pi 后端的 prompt 验证
  (2026-08-28,阶段化技能注入验证,提示词经桥生效)
- [x] 中心编排 + FindingsPipeline 双会话(发现≠校验)在 pi 后端实测
  (2026-08-28,多 Agent 编排经 pi 后端跑通,链路等价性验证;校验通道支持
  独立 provider/model 配置)
- [x] benchmark:claude vs pi 同场景对比(确认率 / 耗时 / token 成本)——
  双后端的价值证明(2026-08-27,bench-backends-2026-08-26.md)
- [x] README(中英)双后端文档 + 桥安装说明(2026-08-28,后端配置文档与 CI 收口)
- [x] CI:pi 协议测试稳定化;桥依赖版本锁定(package-lock)
  (2026-08-28,桥依赖缓存入 CI)
- [x] 模型路由(深化):pipeline 级混搭 —— recon 用低成本模型、test 用
  高能力模型,按阶段选 provider/model(2026-08-29 合入 6336d66:CLI 分阶段
  backend/provider/model 路由,缺省行为零变化,18 项路由测试;Phase 2.7 9/9 全闭环)

## Phase 3 · 扩能+传播(原计划 2027.01-04,核心条目已提前至 2026-08-10 完成)

> 注:本阶段原排期 2027.01-04;以下标 [x] 的技能/云模块/文章条目已由多 Agent 团队于 2026-08-10 提前交付,剩余 [ ] 项仍按 2027.01-04 窗口推进。

- [x] OWASP Top10 技能补全 + framework 专项(2026-08-10,多 Agent 团队完成 13/13:SQLi/XSS/SSRF/命令注入/文件上传/路径遍历/反序列化/信息泄露/CSRF/XXE/SSTI/Open Redirect/文件包含)
- [x] 云模块扩 AWS / 腾讯云 / Azure / 华为云 / GCP(2026-08-10,七大云厂商全覆盖;含腾讯云 CAM 提权检测)
- [x] IAM/RAM 提权路径图可视化(2026-08-12 iam-graph 分支交付:有向图建模+BFS 提权路径+DOT 导出,已合入 main;ROADMAP 08-22 补记勾选)
- [x] 2-3 篇技术文章(2026-08-10,多 Agent 团队完成「首个懂国产云」「校验闭环设计」「Benchmark 体系」三篇)
- [x] Gitee 同步(2026-08-30 合入 bf13143:scripts/gitee_sync.sh 镜像推送,GITEE_TOKEN 环境变量零硬编码+dry-run,README「国内镜像」节,真推留用户首推)
- [x] 社区贡献审查(2026-09-03 合入 4096e00:外部 issue #4-#8 安全审查
  确认并修复——验证池独立性/scope 对称拒绝/bearer 脱敏/blackboard 健壮性;
  PR#2 思路吸收 31cd94b;issue/PR 关闭时机留用户拍板)
- [ ] v0.2.1 发版(2026-09-04 预案终备就绪:docs/release/v0.2.1-release-plan.md,
  六步命令+回滚,含 #4-#8 安全修复的 67 commit 积累;**待用户拍板执行**)
- [ ] 社区运营

## Phase 4 · 达标冲刺(2027.05-07)

- [ ] 按数据补短板;2027.07 前确认 fork ≥ 200 → 提交人才认定申请
- [ ] Plan B 触发线:2027.04 fork < 80 时切换策略

## Phase 5 · 攻防经验吸收(2026.09 起,分 A-E 子阶段逐期开发)

> 来源:2026-09 对业界顶级攻防研究方法论的系统研读与提炼(九条经验,
> 内部参考档案留存);全部条目匿名化表述,落地延续「监工领取制+最小
> 切片+先钉死后修+三门全绿」产线模式,每子阶段 1-2 个派活单。

### 5-A · 验证纪律强化(先行,纯代码零依赖)

- [ ] A1 覆盖率退出门:recon 退出由代码校验(endpoints 数/探测计数阈值),
  不达标 caveats 标记 + state 门控,test 读 blocked 门降级 dry-run;
  新增 `src/cain_agent/gates.py` 纯函数 `check_coverage`
- [ ] A2 可重放证据包:findings 增可选 `replay` 字段(泛化
  web/bac_evidence 结构,method/url/参数白名单键不含值);
  report.md 增「重放清单」节(证据原文照旧只哈希)
- [ ] A3 confirm 副作用门:validator 增 `side_effect_evidence`,
  无副作用证据的 confirmed 降级新状态 `likely`(第五状态),
  验证池表决取保守,聚合与 report 同步
- [ ] A4 分歧呈现:findings 增 `model_dissent`(验证池反对票理由,
  只含依据不含凭证),report.md 详情节呈现分歧子块

### 5-B · 上下文工程

- [ ] B1 patterns 蒸馏格式 + 首批:`skills/patterns.jsonl` 五字段假设
  (target_kind/invariant/violation/verify_method/confidence_prior)+
  校验器 `src/cain_agent/patternlib.py`;从既有 web 技能蒸馏 ≥20 条
- [ ] B2 Scout 假设生成:recon→test 间纯规则匹配(零 token)产定点
  假设清单替代全量技能注入;`--scout off` 回落旧行为(缺省零变化)
- [ ] B3 技能 validation_seed 质量门:技能 frontmatter 增已知漏洞
  样例集,加载时校验 seed 自洽,缺失/空章节进 issues;bench 增
  seed 复现跑分入口

### 5-C · patchdiff 变体挖掘(依赖 5-B 格式)

- [ ] C1 补丁 diff 解析层:`src/cain_agent/patchdiff/parser.py`,
  unified diff → 结构化变更集(签名变化/新增校验/删除路径),纯函数
- [ ] C2 根因谓词蒸馏:变更集 → invariant 谓词(复用 B1 五字段格式),
  LLM 辅助 prompt 模板 + 确定性校验(谓词须引用 diff 实际符号)
- [ ] C3 变体搜索接线:test 阶段按谓词定点打击(复用 B2 Scout 通道)
- [ ] C4 蒸馏反哺:谓词 → 技能文档骨架生成器(人审后入库)

### 5-D · BAC 主线 + 组合链(D1 已在任务池)

- [ ] D1 bac_replay 构造器(09-14 派活单任务2,顺延有效)
- [ ] D2 弱原语组合链框架:`src/cain_agent/web/chain_graph.py`,
  三段式建模(原语+放大器+落地)图搜索组链,复用 BAC 置信语义
- [ ] D3 组链评分与报告:report.md 增「组合链」节

### 5-E · 输入信任边界与防御输出(依赖 A2)

- [ ] E1 recon 产物注入隔离:外部内容进 prompt 前显式边界标记 +
  指令区隔离,canary 测试钉死
- [ ] E2 pre-prompt 检测技能:`skills/agent-env/` 确定性规则检测器
  (git 配置 RCE 原语/自动加载路径/.mcp.json/hooks,零误报)
- [ ] E3 补丁重测输出(PatchOps):confirmed finding 生成重放包,
  `cain-agent retest --workspace` 一键复测,产出补丁有效性报告
