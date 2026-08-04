# ROADMAP — cain-agent

> 总目标与排期详见 `/Users/cdxd/Desktop/develop/cloudpentest-agent/DESIGN.md`(设计真源)。
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
- [ ] Docker 一键运行 + 3 分钟演示视频

## Phase 2 · 校验闭环(2026.11-12)

- [ ] 校验 Agent 分离 + 4 状态结构化输出
- [ ] 指纹去重 + 定级规则表
- [ ] 云模块:RAM 提权路径分析
- [ ] 自建阿里云 vulnerable-terraform 靶场 + 首轮 benchmark
- [ ] 第一篇传播文章("首个懂国产云的实战 AI 渗透 Agent")

## Phase 3 · 扩能+传播(2027.01-04)

- [ ] OWASP Top10 技能补全 + framework 专项
- [ ] 云模块扩 AWS / 腾讯云
- [ ] IAM/RAM 提权路径图可视化
- [ ] 2-3 篇技术文章 + Gitee 同步 + 社区运营

## Phase 4 · 达标冲刺(2027.05-07)

- [ ] 按数据补短板;2027.07 前确认 fork ≥ 200 → 提交人才认定申请
- [ ] Plan B 触发线:2027.04 fork < 80 时切换策略
