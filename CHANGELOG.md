# CHANGELOG — cain-agent

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
