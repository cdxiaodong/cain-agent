# cain-agent PraisonAI 团队

复刻 AionUi "AI渗透工程师0->1" 团队模式，用 PraisonAI 多 Agent 框架驱动 cain-agent 产线开发。

## 团队结构

| 角色 | 职责 | 对应 AionUi 角色 |
|------|------|-----------------|
| Lead 监工 | 拆解 ROADMAP、派活、验收、合并推送 | Claude Code (Lead) |
| 云模块工程师 | 云安全检测模块开发 | Claude 主力工程师 |
| 安全技能工程师 | OWASP 技能文档开发 | Codex-A |
| 文档传播工程师 | 传播文章 + 项目文档 | Codex-B |

## 运行

```bash
cd /Users/cdxd/Desktop/develop/cain-agent
/Users/cdxd/.local/share/uv/tools/praisonai/bin/python3 praisonai-team/run_team.py
```

## 配置

- `config/agents.yaml` — 团队成员定义（角色、规则、LLM 配置）
- `config/tasks.yaml` — 任务分配（当前 sprint 的具体开发任务）
- `run_team.py` — 团队入口（自定义工具：read_file / write_file / run_command / run_tests）

## LLM 后端

通过 TencentDB Memory 代理（localhost:8096），模型 glm-4.6。

## 自定义任务

编辑 `config/tasks.yaml`，按 ROADMAP 下一批未完成项编写任务描述。
