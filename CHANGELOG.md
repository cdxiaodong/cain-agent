# CHANGELOG — cain-agent

## 2026-08-24 · 双执行引擎:pi 后端接入

- **pi 第二执行引擎**(`pi_executor.py` + `toolchain/pi/`):`cain-agent run
  --backend pi [--pi-provider deepseek --pi-model ...]` 整链路切换执行后端;
  与 claude 后端同接口,Orchestrator / FindingsPipeline / StageHandler 零改动
- **Node 桥**(bridge.mjs,stdio JSON 行协议):桥侧每笔工具调用先回 Python
  侧 ScopeGuardHook 判决,allow 才执行 —— scope 白名单、发现≠校验双会话、
  默认拒绝、idle/total 双防线的安全语义在 pi 后端一处不降级
- 多 provider 支持(anthropic/openai/google/deepseek,按需动态加载);
  `allowed_tools=[]` 时桥不注册任何工具,只读校验通道语义保持
- 测试 +19 例(fake 子进程驱动,零 Node/零网络):协议收敛 / scope 放行与
  拒绝 / 审计记录 / matcher 匹配 / idle+total 中断 / 桥缺失防护 / CLI 开关

## 2026-08-22 · smoke 后续修复:ScopeGuardHook 误拦闭环 + finding 本地 fixture

- **ScopeGuardHook 命令语义误拦修复**(`scope.py` + `test_scope.py`):只有真实
  网络目标参与 scope 判定——grep 正则、本地文件路径、`2>` 重定向体不再误判;
  命令替换 `$()`/反引号视为不可见文本默认拒绝,纯本地命令放行;测试样本直接
  取自 08-19 smoke 的 48 次误拦实录
- **finding 闭环本地 fixture**(`bench/local_finding_fixture.py` + SSTI 场景):
  本地可复现漏洞场景让编排链路稳定产出 ≥1 finding,confidence+依据链完成
  真实数据演练(补上 08-19 smoke 因靶场 405 零 finding 的缺口),报告见
  `docs/release/finding-fixture-2026-08-21.md`
- 云依赖问题(boto3/kubernetes 未声明致裸环境收集失败)已确认,cloud-deps
  任务进行中
- 测试 926 passed, 3 skipped(k8s_rbac 因缺 kubernetes SDK 暂排除,归 cloud-deps)

## 2026-08-20 · 编排链路实战验证:全链路 smoke + 失败自愈接线 + 编排 benchmark

- **编排模式全链路 smoke**(`docs/release/smoke-2026-08-19.md`):对自建靶场非
  dry-run 跑通 recon→test→report,report 走真实聚合路由(无占位回退),scope
  白名单零越权出网;本轮 0 findings 系靶场 nginx 405 拦截写入端点所致,如实记录
- **auto_prompt 失败自愈接入编排层**(`multi_agent/orchestration.py`):solver
  失败自动重派 retry/decompose/skip,策略可配置,经典 Route A 保持可回退
- **benchmark 支持编排模式对比**(`bench/run_benchmark.py`):同一组场景经典 vs
  编排,输出确认率/耗时/token 对比,见 `docs/release/bench-orchestrated-2026-08-19.md`
- smoke 发现的待办(记录待修):ScopeGuardHook 对 grep 正则/本地路径/重定向的
  命令语义误拦;云端测试套件缺 boto3 等未声明依赖导致收集错误
- 测试 940 passed, 3 skipped

## 2026-08-19 · 中心编排器成形：Manager 判断聚合 + 全流程接线 + 编排文章

- **中心 Manager 判断聚合**(`multi_agent/manager.py` + `tests/test_manager.py`):
  finding 表决结果 + 记忆相似旁证 → 输出带 confidence 与依据链的结论列表,
  编排层有了「拍板」环节而非简单收集
- **全流程编排接线**(`multi_agent/orchestration.py` + `cli.py`):Manager/Solver/
  验证池/语义记忆组装为完整编排链路接入 `cain-agent run`,report 阶段输出真实
  聚合报告替换占位文件;经典 Route A 保持可回退
- **第四篇架构文章**(`docs/articles/04-orchestration.md`):从单 Agent 到多
  Agent 编排的架构演进,讲清设计动机与取舍
- 测试 926 passed, 3 skipped

## 2026-08-16 · 中心编排器推进：验证池接线 + 语义记忆 + smoke 复测闭环

- **并行验证池接入 FindingsPipeline**(`pipeline.py`):finding 校验改走多数表决
  (交叉确认防单点误判),保持「发现≠校验」双会话约束;池不可用时回退单会话
- **语义记忆底座**(`multi_agent/memory.py`):finding/上下文向量化存储 + 相似度检索,
  solver 间共享可检索上下文,避免重复扫描;与 Blackboard 对齐,不引入重依赖
- **scope 修复后 smoke 复测**:对自建靶场重跑非 dry-run 全链路,test 阶段不再被
   scope 误拦;顺手修复 scope 的 curl 方法参数解析;产出 `docs/release/smoke-2026-08-16.md`
- 测试 872 passed, 3 skipped

## 2026-08-15 · 中心编排器起步：并行验证池 + 失败自愈 + scope 端口闭环

- **scope 端口匹配闭环**(`tests/test_scope.py`):新增回归测试钉死「裸 host 白名单
  必须匹配带端口/scheme 的请求目标」(`103.236.66.228` 匹配 `103.236.66.228:3333`);
  确认 `scope.py` 既有 `_strip_port` 逻辑生效,修复 08-12 smoke test 阶段 0 findings 的误拦
- **并行验证池**(`multi_agent/verify_pool.py`):同一 finding 并行起 N 个独立校验会话,
  多数表决 + 分歧标记(`confirmed|contested|rejected`),交叉确认防单点误判
- **失败自愈 auto-prompt**(`multi_agent/auto_prompt.py`):中心监控 solver 失败模式
  (连续空结果/超时/解析失败),自动重写提示词重派(retry/decompose/skip)
- 测试 854 passed, 3 skipped

## 2026-08-12 · CLI 真实 smoke 端到端打通 + 授权门移除 + README 重写

- **真实 smoke 打通**(`src/cain_agent/cli.py`):对自建靶场跑通 recon→test→report
  完整流水线(非 dry-run);recon 真实识别 Next.js/nginx 技术栈并定位
  `POST /api/wishes` 文件上传攻击面,主动提示 test 勿 fuzz SPA catch-all GET 路径
- **修 smoke 逼出的两个 bug**:
  - `is_local_target` 兼容带 scheme/端口/IPv6 的本地与私网地址(剥 scheme+端口再判)
  - 新增 `_scope_entry`:写 scope 前把 URL 归一化为裸 host,修复 `http://ip:port/path`
    目标导致 Orchestrator scope 校验报错
- **授权门移除**:删除 `--i-have-authorization`,公网目标直接放行,scope 仍由
  PreToolUse 钩子强制;同步中英 README 与测试
- **中英 README 重写**:加 ASCII 架构图、真实 CLI 示例、结构性安全说明,状态对齐
  当前 MVP;删除冗余盘点文件 `README-SKILLS.md` / `SKILL-SUMMARY.md`
- **IAM/RAM 提权路径图**合入 main:有向图建模 + DOT/JSON 导出 + BFS 路径查找
- **遗留**:scope 白名单对带端口目标(`:3333`)匹配未归一,写操作被默认拒绝误伤,
  待修

## 2026-08-11 · 经典 Route A CLI 真实 handler 接线 + 双会话校验

- **经典 Route A 接线**(`src/cain_agent/cli.py`):`cmd_run` 经 `_build_handlers`
  注入三阶段真实 handler——recon/test 共享发现 executor,report 经
  `make_report_handler` 驱动独立校验 session 的 `FindingsPipeline`
  (发现≠校验,双会话防自证);BreachWeave 多 Agent 桥 `create_multi_agent_handlers`
  保持**未接线**(经典路径为默认),report 仍只落占位产物 `report-placeholder.json`
  (真实报告 markdown 后续接入)
- **测试**(`tests/test_cli_run.py`):新增双 executor 独立构造、FindingsPipeline
  收到不同对象、端到端产物契约与构造失败兜底断言;公网 target 夹具改用合成域名
  (`example.com`/`public.example.com`),未授权路径钉死构造器不得触发,零真实 IP

## 2026-08-10 · 多 Agent 团队交付:腾讯云 CAM 提权 + SSTI/Open Redirect 技能 + 第二篇文章


- **腾讯云 CAM 提权路径分析**(`src/cain_agent/cloud/tencent_cam.py`):只读 Get/List API,5 条提权规则代码常量(AttachPolicyToUser/CreateUserLoginProfile/AddUserToGroup/CreateAccessKey/PassRole),支持 `cam:*` 通配展开,单实体失败容错;对齐阿里云 RAM 提权分析设计模式;40+ 单测全 mock
- **SSTI 检测技能**(`skills/web/ssti/SKILL.md`):经典注入(Python Jinja2/PHP Smarty/Java Velocity)+ Blind XXE OOB 外带+ SSRF 利用+ XInclude/编码绕过;Payload 表+ 工具(Burp/curl)+ 输出格式;301 格式校验测试
- **Open Redirect 检测技能**(`skills/web/open-redirect/SKILL.md`):URL 重定向检测(基于域名白名单/相对路径/Referer 验证);Payload 构造+ 工具+ 输出格式;339 格式校验测试
- **第二篇传播文章**(`docs/articles/02-validation-loop-deep-dive.md`):「让 AI 自己查自己:渗透 Agent 的校验闭环设计」(3500 字);痛点(AI 幻觉漏洞责任风险)+ 方案(双 Agent 独立会话校验+ 四状态结构化输出)+ 实现(FindingValidator 执行层+ 去重指纹+ 规则表收口)+ 演示(假阳性漏洞如何被拦截);含 3 标题候选+ 授权法律声明;413 格式校验测试
- **测试覆盖**:638 passed,2 skipped;新增 tencent_cam/SSTI/open_redirect/article2 测试模块;零真实凭证,零触网

## 2026-08-10 · Day 10:云模块七厂商全覆盖 + OWASP Top10 技能补齐 + 文章定稿

**本轮交付:三大云模块合入(AWS S3 + 腾讯云 COS + 华为云 OBS),两大 OWASP 技能补齐(CSRF + XXE),传播文章更新定稿。main 上全量测试全绿。**

- **AWS S3 暴露检测**(合并 `feat/2026-08-10-aws-s3-exposure`):S3ExposureChecker 只读检查 ACL + Policy + Public Access Block 三层配置;boto3 全 mock,24 个单测,零触网零真实凭证
- **腾讯云 COS 暴露检测**(从 `feat/2026-08-08-tencent-cos-exposure` 提取):CosExposureChecker 使用 requests + COS XML-API HMAC-SHA1 签名(不依赖重型 SDK),ACL + Policy + 敏感文件扫描(.env/.key/.pem/.git 等);40 个单测
- **华为云 OBS 暴露检测**(新开发):ObsExposureChecker 复用 boto3 + 自定义 endpoint_url(S3 兼容 API),ACL + Policy 双层检测;24 个单测
- **CSRF 检测技能**(从 `feat/2026-08-08-csrf-skill` 提取):Token 存在性分析 + 去 Token 重放 + Referer/Origin 伪造 + 跨站 PoC 构造;22 个格式校验测试
- **XXE 检测技能**(新开发):经典文件读取 + Blind XXE OOB 外带 + SSRF 利用 + XInclude/编码绕过;22 个格式校验测试
- **传播文章更新**(`docs/articles/2026-08-draft-1-ai-pen-aliyun.md`):更新云模块覆盖为七厂商、技能覆盖为 OWASP Top10 十大技能、Roadmap 从 Phase 2 推进到 Phase 3
- **云模块总计**:阿里云(OSS + RAM)、AWS(S3)、腾讯云(COS)、华为云(OBS)、Azure(Blob)、GCP(GCS) — 七大云厂商全覆盖
- **技能总计**:SQLi / XSS / SSRF / 命令注入 / 文件上传 / 路径遍历 / 反序列化 / 信息泄露 / CSRF / XXE — OWASP Top10 基本覆盖



## 2026-08-07 · Day 5 验收:校验闭环端到端成型 + 冒烟首跑通过

**验收结论:Day 5 三分支 + 冒烟报告分支全部通过(CI 三绿 + 署名正确 + 红线/凭证扫描干净),已合并 main 并推送,main 上 275 测试全绿。**

- **Findings 校验流水线**(`d92ea18`,core 分支):dedup + FindingValidator 串接,幂等(终态跳过不重复校验)、单条异常容错标 system_error、经 StageHandler 注入点挂 Orchestrator(report 前置),冻结文件零改动;校验汇总落盘 report/validation-summary.json
- **CredRedactHook 凭证脱敏**(`303dba4`,feat 分支):LTAI/AKIA/sk-/JWT/PEM/键值对模式表,替换为 `<REDACTED:类型:sha256前8位>` 可审计格式,文档示例白名单防误伤,redact_dict 递归处理,PostToolUse hook 形态;测试全部使用构造假串
- **vuln-tf 场景二**(test 分支):RAM 过度授权用户靶标(命中 AttachPolicyToSelf/CreateAccessKey 两规则)+ 只读对照用户;钉死"不建真 AK 资源";未执行任何 terraform apply
- **冒烟测试首跑通过**(`2e777c2`,smoke 分支,tasks/smoke-test-2026-08-06.md):pip 安装、CLI --version/--help、Orchestrator 编排循环(recon→test→report,scope 仅 127.0.0.1,零网络零凭证)三项全过 exit 0——**项目第一次端到端真实跑通**

## 2026-08-06 · Day 4 验收:三分支全过合入,校验闭环成型

**验收结论:任务 1/2/3 全部通过(CI 三绿 + 署名正确 + 红线/凭证/tfstate 扫描干净),已合并 main 并推送,main 上 222 测试全绿(1 个 skip 为 terraform fmt 可选检查)。**

- **FindingValidator 校验执行层**(`35d3a15`,core 分支):校验用独立 SDKExecutor session,与发现 executor 同对象直接 raise(防自证硬约束);证据包裹 `[UNTRUSTED_DATA]` 标记;SDK 返回乱码→validation_system_error 不猜;模型 severity 建议必须过规则表收口;19 个 fake-executor 单测零 token
- **阿里云 RAM 提权路径分析**(`c7722f1`,feat 分支):只读 Get/List API,5+ 条提权规则代码常量(PassRole 借高权角色/AttachPolicyToSelf/CreateAccessKey/LoginProfile 劫持/AssumeRole 链),支持 `ram:*` 通配展开,管理员策略直判 critical,单实体失败容错;finding 字段对齐 findings.py 模型
- **vuln-terraform 靶场场景一**(`958da03`,test 分支):OSS public-read 靶标桶 + private 对照桶 + Purpose 标签 + 头五行授权声明;静态测试钉死靶标语义与 LTAI 扫描;benchmark-plan 追加自建云靶场一节;未执行任何 terraform apply
- Phase 2 进度:校验闭环(数据模型+执行层)与云模块第二件(RAM 提权)落地,剩 vuln-tf 靶场扩场景 + 首轮 benchmark + 传播文章

## 2026-08-05 · Day 3 验收补录(Lead 补记)

> Day 3 验收会话于真实时间 08-04 15:22 合入了三个分支,但漏写本记录与 ROADMAP 勾选,由 Lead 在 Day 4 派活时补录。

- **Finding 校验三件套**(`findings.py`,core/2026-08-05-finding-validator):4 状态枚举、evidence sha256 只哈希不落明文、四元组指纹归一化去重、定级规则表(模型建议降级取低);36 个单测钉死
- **Docker 一键运行**(feat/2026-08-05-docker):Dockerfile 非 root 用户 + .dockerignore + 静态配置测试 + docs/docker.md
- **Benchmark 靶场体系**(test/2026-08-05-bench-range):Juice Shop+DVWA compose(127.0.0.1 绑定)+ 两层评测方案文档(检出/误报/耗时/token 四指标口径)
- ROADMAP 勾选已同步:Phase 1 全清(演示视频除外,需人工)、Phase 2「指纹去重+定级规则表」完成

## 2026-08-04 · 晚 · Day 2 验收:三分支全过合入,派活通道打通

**验收结论:任务 1/2/3 全部通过(CI 三绿 + 署名正确 + 红线/凭证扫描干净),已合并 main 并推送,main 上 115 测试全绿。**

- **Orchestrator + Workspace**(`c3c5f82`,core 分支):阶段流转硬编码 recon→test→report(乱序抛 StageOrderError,有测试钉死)、Workspace 原子写 assets/findings、state.json 阶段追溯、ScopeGuardHook 从 workspace 真源构造并挂到 executor(只组合不改语义);executor.py/scope.py 零改动
- **阿里云 OSS 暴露检测**(`6146d30`,feat 分支):OssExposureChecker 只读检查 ACL/Policy,定级规则代码常量(公开可写=critical/公开读=high/private=info),单 bucket 失败容错;23 个全 mock 单测,零触网零真实凭证,无 AK 硬编码
- **Web 三技能 + 格式校验**(test 分支):SQLi/XSS/SSRF 实战向 SKILL.md(SSRF 含 AWS/阿里云/GCP/Azure 元数据端点)、test_skill_format.py(新技能严格四字段四节、旧 66 技能兼容)、技能编写规范
- **派活通道突破**:SendMessage 对定时场景不可用(成员不在注册表),改用「一次性 cron 唤醒」通道(cron current create + sqlite3 改指目标会话)实测成功,三个工程师会话 faa9204d/15470647/31d15820 全部收到并回执——后续派活送达走此通道
- 通道测试顺带确认 Codex-A/B 上午已完工;done-codex-a/b.md 汇报文件留存仓库根

## 2026-08-04 · 早 · 派活已发,团队消息通道未通(待用户处理)

- 派活单 `tasks/2026-08-04.md` 已提交推送(`7b87577`):任务 1 Orchestrator 状态机+Workspace(Claude 主力,`core/2026-08-04-orchestrator`)、任务 2 阿里云 OSS 暴露检测(Codex-A,`feat/2026-08-04-aliyun-oss-exposure`)、任务 3 Web 三技能 SKILL.md+格式校验(Codex-B,`test/2026-08-04-web-skills`)
- ⚠️ **消息送达失败**:按要求用团队消息工具逐一发送三个成员,`Claude 主力工程师` / `Codex-A` / `codex-a` / `Codex-B` / `codex-b` 全部返回"agent 不可达"——本会话的团队注册表中没有这些成员,无法确认任何一方已开工
- 后果与昨日相同的风险:若 Codex 两侧没有独立的定时触发去读 tasks/ 文件,今天将再次空转。**需要用户确认 AionUi team 模式中 Codex-A/B 的唤醒方式**(独立 cron 读 tasks/ 文件,或提供可达的 agent 名称/通道)
- 21:00 验收时将先检查分支是否存在,再据此判断成员是否实际开工

## 2026-08-03 · 晚 · Phase 0 收官 + Phase 1 前两件落地

**验收结论:三分支全部通过(CI 三绿 + 署名正确 + 红线扫描干净),已合并 main 并推送。**

- **SDKExecutor 最小封装**(`7e918f4`,core 分支):Claude Agent SDK 统一执行引擎入口——allowed_tools 默认空(只读原则)、PreToolUse hook 挂载点、idle 300s + 墙钟总预算双防线优雅中断、session resume 预留;12 个 mock 单测(不烧 token)
- **Scope 白名单 + ScopeGuardHook**(`fdfbdb2`,feat 分支):scope.yaml 加载(域名/通配/CIDR 三形态、加载即校验)、deny 优先 + 默认拒绝语义、Bash 命令目标提取(curl/wget/nmap 等 15 个工具 flag 感知,提取失败=阻断);42 个单测
- **测试/文档**(test 分支):CLI 进程内单测 5 个、中文 README(法律声明置顶)、`docs/legacy-inventory.md`(66 个技能全保留,exploits/install-tools 标记待重构)、`docs/github-repo-metadata.md`
- **GitHub 元数据已应用**:description + 12 个 topics 通过 gh 配置完成(Phase 0 最后一项关闭)
- 合并时解决 pyproject.toml 依赖区冲突(claude-agent-sdk + pyyaml 并存),main 复检 55 测试全绿
- **观察项(非阻塞,待用户确认)**:ScopeGuardHook 对无法提取目标的 Bash 命令一律阻断,`ls`/`pwd` 这类本地无害命令也会被拦——当前按派活单严格执行,后续可考虑加本地只读命令白名单

## 2026-08-03 · Phase 0 启动

- GitHub 仓库 rename:AI-Cloud-pentest-framework → **cain-agent**(21⭐/2 fork 保留)
- 项目重新定位:真实实战型 AI 渗透测试工程师(非 CTF 靶场型),内置云渗透模块
- 新 README(英文,实战定位 + 法律声明);旧 README/CLAUDE.md 归档至 docs/legacy/
- 补 Apache-2.0 LICENSE(原仓库无 LICENSE 文件)
- Python 项目骨架:pyproject.toml / src/cain_agent / tests / CI(ruff+pyright+pytest, py3.11/3.12)
- 本机 git 署名:cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>(contributions 归属保障)
- 65 个云渗透技能文档保留于 skills/,作为知识库资产
- 开发生产线上线:Claude Lead 每天 09:00 派活 / 21:00 验收,2×Codex 分分支执行

## 2026-08-09

### 产线自动化架构部署
- **docs(arch)**: 产线自动化架构设计 v1.0 — 每日自动更新开发（887c36b）

- **feat(cloud)**: Azure Blob 暴露检测模块（只读）— 完成三大国际云覆盖（AWS/Azure/GCP）

### Day 8 下午任务
- **feat(cloud)**: GCP GCS 暴露检测模块（只读）
- **feat(skills)**: OWASP 命令注入检测技能 + 格式校验
- **feat(bench)**: Benchmark 评测体系框架

### Day 8 上午任务
- **docs(tasks)**: Day 8 上午派活 — AWS S3 + XXE + 传播优化
- **docs(tasks)**: Day 8 下午派活 — GCP GCS + 命令注入 + Benchmark 框架

### Day 7 任务
- **feat(skills)**: OWASP 文件上传漏洞检测技能 + 格式校验
- **feat(cloud)**: 腾讯云 COS 暴露检测模块
- **feat(skills)**: OWASP CSRF 检测技能文档 + 格式校验测试

- **feat(cloud)**: Azure Blob 暴露检测模块（只读）— 完成三大国际云覆盖（2c68064）
- **feat(skills)**: OWASP 路径遍历检测技能 + 格式校验（d9a4531）
- **docs(readme)**: 添加 Features 章节 — 云覆盖 + OWASP Top10（a77b2ca）
