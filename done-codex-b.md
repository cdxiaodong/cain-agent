# Codex-B 交付汇报 · 2026-08-08(Day 6 · 任务 3)

> 任务:第一篇传播文章初稿 + 演示视频分镜脚本(文档)
> 状态:**完成,ruff / pyright / pytest 三绿(全量 286 passed, 1 skipped);无敏感信息;待 21:00 验收**

## 分支

`test/2026-08-08-article-demo`(从 `main@f884fbe` 切出,**未碰 main**),独立 worktree 隔离开发。

## 改动文件清单(3 个新文件,2 提交,均署名 `cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`,每次提交前 `git config user.email` 验证通过)

| 提交 | 文件 | 说明 |
|---|---|---|
| `aa79bed` docs(article) | `docs/articles/2026-08-draft-1-ai-pen-aliyun.md` | 文章初稿(约 2470 字):3 个标题候选、痛点→差异化→架构→真实能力演示(合成数据)→工程哲学→roadmap→授权法律声明;留 `[图:架构]` 图位标记;GitHub 链接用占位不写死 |
| `aa79bed` docs(article) | `docs/demo-script.md` | 3 分钟演示分镜:5 镜(痛点引入/安装启动/编排循环+校验闭环/云模块/roadmap+star),每镜配旁白文案 + 画面说明 + 录制注意事项 |
| `d18f110` test(article) | `tests/test_article_format.py` | 11 项静态校验:文章存在/字数区间/3 标题候选/授权关键词/敏感字样(平安/pingan)/公网 IP(除 127.0.0.1)/外露域名(除 example.com)/分镜存在 |

未改:src/、README、pyproject、其他 docs 文件、任何冻结文件。

## 自测结果(三绿)

| 门 | 命令 | 结果 |
|---|---|---|
| ruff | `ruff check src tests` | **All checks passed** |
| pyright | `pyright -p pyproject.toml --pythonpath .venv/bin/python` | **0 errors, 0 warnings, 0 informations** |
| pytest(本任务) | `pytest tests/test_article_format.py -v` | **11 passed** |
| pytest(全量回归) | `pytest -q` | **286 passed, 1 skipped**(skip = terraform fmt 可选检查) |

> pyright 备注:默认调用误报 `import oss2` 为无法解析,是 main 既有的 venv 发现怪癖(与本次改动无关),按产线 recipe 用 `--pythonpath .venv/bin/python` 指向 venv 解释器即 0 error。

## 验收对照(对照 tasks/2026-08-08.md 任务 3)

| 验收项 | 要求 | 实际 |
|---|---|---|
| 三绿 | ruff / pyright / pytest | ✅ 全绿 |
| 事实声明与已合入功能一一对应 | 文内能力声明对应仓库真实功能 | ✅ 仅声明已合入件:Orchestrator/Workspace、SDKExecutor、ScopeGuardHook、CredRedactHook、OSS 暴露检测、RAM 提权分析、校验闭环(findings/validator/pipeline)、Docker、vuln-tf 靶场两场景、Web 三技能、冒烟首跑通过;未声明未合入的 CLI run(以"编排循环已验证"口径表述) |
| 无敏感信息 | 无平安内部信息、无真实厂商漏洞细节、无真实目标 | ✅ 测试钉死(无"平安/pingan"、无外露 IP/域名);演示数据全部合成(桶名 example-bucket-*、用户名 demo 后缀);star/fork 数字用占位不写死 |
| 文章字数 | 1800-3500 字 | ✅ 约 2470 字(测试钉死) |
| 3 标题候选 | — | ✅ 测试钉死 |
| 含授权法律声明 | — | ✅ 文末独立段 + 测试钉死"授权"关键词 |
| 分镜 3 分钟 5 段 | 0:00-0:20 / 0:20-1:00 / 1:00-2:00 / 2:00-2:40 / 2:40-3:00 | ✅ 5 镜齐全,每镜旁白 + 画面说明 |
| 不发布/不改 README/不配图 | — | ✅ 仅留 `[图:架构]` 图位标记 |

## 事实声明映射表(文章声明 → 仓库功能)

| 文章声明 | 对应仓库功能(已合入) |
|---|---|
| 编排循环(确定性状态机 recon→test→report) | `orchestrator.py`(2026-08-04) |
| Workspace 外置记忆(原子写、崩溃可恢复) | `workspace.py`(2026-08-04) |
| SDKExecutor(只读原则、预算熔断) | `executor.py`(2026-08-03) |
| ScopeGuardHook(scope 白名单、deny 优先、默认拒绝) | `scope.py`(2026-08-03) |
| CredRedactHook(凭证脱敏、可审计哈希) | `redact.py`(2026-08-07/Day5) |
| OSS 暴露检测(ACL/Policy 只读、定级代码常量) | `cloud/aliyun_oss.py`(2026-08-04) |
| RAM 提权路径分析(5 类规则、只读 Get/List) | `cloud/aliyun_ram.py`(2026-08-06) |
| 校验闭环(发现/校验分离、去重、四状态) | `findings.py`/`validator.py`/`pipeline.py` |
| vuln-tf 靶场两场景(OSS 公开桶 + RAM 过度授权) | `bench/aliyun-vuln-tf/`(Day4 场景一 + Day5 场景二) |
| Docker 一键运行(非 root) | `Dockerfile`/`docs/docker.md`(2026-08-05) |
| Web 三技能(SQLi/XSS/SSRF) | `skills/web/`(2026-08-04) |
