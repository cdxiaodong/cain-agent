# cain-agent 产线自动化架构设计

> 目标：每天 09:30 和 14:00 自动派活，11:15 和 17:00 自动验收，GitHub 日更不中断，无需人工干预。

---

## 1. 核心架构

```
┌─────────────────────────────────────────────────────────────┐
│                     监工（claude-temp-0e058a6d）              │
│  · 检测产线故障（Lead 未激活/工程师无响应/验收缺失）           │
│  · 自动补位（重建会话/直接完成任务/推送 GitHub）               │
│  · 确保日更（每天至少 2 次 commit 推送）                       │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                  Lead（Claude Code · 272f7a4f）               │
│  · 09:30/14:00 派活：读 DESIGN.md → 拆任务 → 写派活单         │
│  · 亲自唤醒三个工程师（一次性 cron 通道）                      │
│  · 11:15/17:00 验收：CI 检查 → 合并 → 推送 → 日报             │
└─────────────────────────────────────────────────────────────┘
            │                    │                    │
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ Claude 主力       │  │ Codex-A          │  │ Codex-B          │
│ (faa9204d)       │  │ (15470647)       │  │ (c9a2f3d4)       │
│ · 核心攻坚        │  │ · 功能开发        │  │ · 测试/文档       │
│ · 云模块          │  │ · CLI/工具        │  │ · Benchmark      │
└──────────────────┘  └──────────────────┘  └──────────────────┘
```

---

## 2. 自动化流程

### 2.1 派活流程（09:30 / 14:00）

**触发**: cron `产线派活:cain-agent`（cron_019fc7f7-49b1-7631-a5b8-78c96982cdd0）

**Lead 执行步骤**:
1. 读取 `/Users/cdxd/Desktop/develop/cloudpentest-agent/DESIGN.md` 和 `ROADMAP.md`
2. 确认当前 Phase 和昨日完成状态
3. 拆出 3 个任务（最小颗粒度，可独立完成/测试）
4. 写入 `tasks/YYYY-MM-DD-am.md` 或 `tasks/YYYY-MM-DD-pm.md`
5. 提交推送派活单
6. **亲自唤醒三个工程师**（关键步骤）:
   - 用 `aionui-config` 技能的 `cron current create` 创建一次性任务（当前+3~5分钟，错开）
   - 用 `sqlite3` 修改 `cron_jobs.conversation_id` 指向目标会话
   - 触发后 6 分钟检查 `messages` 表确认全员开工
   - 删除一次性任务

**监工检查点**（09:45 / 14:45）:
- ✅ 派活单文件存在（`tasks/YYYY-MM-DD-*.md`）
- ✅ Lead 已推送派活单（git log 检查）
- ✅ 三个工程师 mailbox 有未读消息
- ✅ 三个工程师已创建分支（git branch 检查）
- ❌ 若任一失败 → 监工补位（直接完成任务或重建会话）

---

### 2.2 开发流程（09:30-11:15 / 14:00-17:00）

**工程师执行步骤**:
1. 读取 mailbox 消息，获取任务指令
2. 读取 `tasks/YYYY-MM-DD-*.md` 派活单
3. 创建分支：
   - Claude 主力：`core/YYYY-MM-DD-<主题>`
   - Codex-A：`feat/YYYY-MM-DD-<主题>`
   - Codex-B：`test/YYYY-MM-DD-<主题>`
4. 开发任务（遵循红线：署名正确/零触网/只读原则）
5. 自测三绿：ruff check / pyright / pytest
6. 提交 commit（署名 `cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`）
7. 写完工汇报：`done-<工程师>.md`
8. 推送分支到远程

**监工检查点**（10:15 / 15:15）:
- ✅ 三个分支已创建（git branch 检查）
- ✅ 三个分支有新 commit（git log 检查）
- ✅ 三个 done 汇报文件存在
- ❌ 若任一无响应 → 监工补位（重建会话或直接完成任务）

---

### 2.3 验收流程（11:15 / 17:00）

**触发**: cron `产线验收:cain-agent`（cron_019fc7f8-c3bb-7af1-b938-b4999fde469e）

**Lead 执行步骤**:
1. 检查三个分支的 done 汇报
2. 拉取三个分支到本地
3. 运行 CI 检查：
   - `ruff check src tests` → All checks passed
   - `pyright -p pyproject.toml --pythonpath .venv/bin/python` → 0 errors
   - `pytest -q` → 全绿
4. 检查 commit 署名（`git log --format='%an <%ae>'` 必须全是 `cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`）
5. 红线扫描（无 pentest-agent-mvp / 泄漏 Claude Code / 平安信息）
6. 合并三个分支到 main（`git merge --no-ff`）
7. 推送 main 到 GitHub
8. 更新 `CHANGELOG.md`（记录今日交付）
9. 更新 `ROADMAP.md`（勾选已完成项）
10. 写验收日报：`docs/release/YYYY-MM-DD.md`

**监工检查点**（11:45 / 17:45）:
- ✅ main 有新 merge commit（git log 检查）
- ✅ main 已推送到 GitHub（git status 检查）
- ✅ CHANGELOG.md 已更新
- ✅ ROADMAP.md 已更新
- ✅ 验收日报已生成
- ❌ 若任一失败 → 监工补位（直接合并推送并写日报）

---

### 2.4 监工巡查流程（09:45 / 10:15 / 13:45 / 15:15 / 16:45 / 21:45）

**触发**: cron `产线监工:cain-agent团队巡查`（cron_019fc880-9236-7d10-a03f-2017d8710dd2）

**监工执行步骤**:
1. **送达核查**（09:45 / 14:45）:
   - 检查派活单是否存在
   - 检查 Lead 是否推送派活单
   - 检查三个工程师 mailbox 是否有未读消息
   - 检查三个工程师是否已创建分支
   - 若 Lead 未送达 → 记录失职一次，监工补位唤醒

2. **进度巡查**（10:15 / 15:15）:
   - 检查各分支 commit 进度
   - 检查共享目录冲突/串分支
   - 检查 Codex 死循环迹象
   - 若工程师无响应 → 重建会话或直接完成任务

3. **验收巡查**（11:45 / 17:45）:
   - 检查 main 是否有 merge commit
   - 检查是否已推送 GitHub
   - 检查 CI 是否绿
   - 检查 Lead 日报是否产出
   - 若验收缺失 → 监工直接合并推送并写日报

4. **晚间巡查**（16:45 / 21:45）:
   - 检查全天 commit 数（目标 ≥ 6 个/天）
   - 检查 GitHub 日更（fetch origin 对比）
   - 若日更中断 → 监工立即补位完成一波任务

---

## 3. 故障自愈机制

### 3.1 Lead 未激活

**检测**: cron 派活任务 `last_status = missed` 或 `last_run_at` 超过 24 小时

**处理**:
1. 监工直接读取 DESIGN.md / ROADMAP.md
2. 监工拆分任务并写入派活单
3. 监工推送派活单
4. 监工通过 mailbox 发送唤醒消息给三个工程师
5. 监工记录 Lead 失职一次

---

### 3.2 工程师无响应

**检测**: mailbox 消息 `read=0` 超过 10 分钟，或无新分支/commit

**处理**:
1. 监工检查工程师会话状态（`conversations.status`）
2. 若 `finished` 或 `pending` → 删除旧会话，创建新会话
3. 更新团队配置（`teams.agents` 中的 `conversation_id`）
4. 发送唤醒消息到新会话
5. 若仍无响应 → 监工直接完成任务并推送

---

### 3.3 验收缺失

**检测**: 11:15/17:00 后 30 分钟，main 无 merge commit 或未推送

**处理**:
1. 监工检查三个分支的 done 汇报
2. 监工运行 CI 检查（ruff/pyright/pytest）
3. 监工合并三个分支到 main
4. 监工推送 main 到 GitHub
5. 监工更新 CHANGELOG.md / ROADMAP.md
6. 监工写验收日报
7. 监工记录 Lead 失职一次

---

### 3.4 GitHub 日更中断

**检测**: `git fetch origin && git log origin/main --since="today"` 无 commit

**处理**:
1. 监工立即创建一波任务（简单技能文档/测试）
2. 监工完成任务并提交
3. 监工推送到 GitHub
4. 确保每天至少 2 个 commit

---

## 4. 关键配置

### 4.1 cron 任务

| 任务 | cron ID | 时间表 | 会话 |
|---|---|---|---|
| 派活 | cron_019fc7f7-49b1-7631-a5b8-78c96982cdd0 | `30 9,14 * * *` | Lead (272f7a4f) |
| 验收 | cron_019fc7f8-c3bb-7af1-b938-b4999fde469e | `15 11,17 * * *` | Lead (272f7a4f) |
| 监工 | cron_019fc880-9236-7d10-a03f-2017d8710dd2 | `45 9,13,16,21 * * *` | 监工 (0e058a6d) |

### 4.2 团队成员

| 角色 | 会话 ID | 后端 | 模型 | 职责 |
|---|---|---|---|---|
| Lead | 272f7a4f | claude | default | 派活/验收/唤醒工程师 |
| Claude 主力 | faa9204d | claude | default | 核心攻坚（云模块/引擎） |
| Codex-A | 15470647 | codex | glm-5.2 | 功能开发（CLI/工具/技能） |
| Codex-B | c9a2f3d4 | codex | glm-5.2 | 测试/文档/Benchmark |

### 4.3 红线

1. **禁用**: pentest-agent-mvp 代码（行业机密）
2. **禁用**: 泄漏版 Claude Code 二开（法律风险）
3. **禁用**: 平安内部信息
4. **署名**: 必须 `cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`
5. **安全**: 只读原则，不自动利用/验证性攻击

---

## 5. 监控指标

| 指标 | 目标值 | 检查频率 |
|---|---|---|
| GitHub 日更 | ≥ 2 commit/天 | 每次巡查 |
| 派活送达率 | 100% | 09:45 / 14:45 |
| 工程师响应率 | 100% | 10:15 / 15:15 |
| 验收完成率 | 100% | 11:45 / 17:45 |
| CI 通过率 | 100% | 验收时 |
| 署名正确率 | 100% | 验收时 |
| Lead 失职次数 | 0 | 每日统计 |

---

## 6. 监工自主运维规则

**我（监工）的职责**:
- ✅ 检测产线故障（Lead 未激活/工程师无响应/验收缺失）
- ✅ 自动补位（重建会话/直接完成任务/推送 GitHub）
- ✅ 确保日更（每天至少 2 次 commit 推送）
- ✅ 记录 Lead 失职（每日统计）
- ❌ 不替 Lead 做架构决策
- ❌ 不改业务代码（除非修复产线故障）
- ❌ 不打扰用户报告琐事（只有红线问题才上报）

**自动化检测清单**（每次巡查必做）:
1. 检查 GitHub 是否有当天 commit（无则立即验收合并推送）
2. 检查三个工程师是否有当天分支（无则重建会话）
3. 检查 mailbox 是否有未读消息超过 10 分钟（无响应则重建）
4. 检查 cron 任务是否触发（未触发则直接发 mailbox）

**故障自愈流程**:
1. 工程师无响应 → 总结历史工作 → 删除旧会话 → 创建新会话 → 更新团队配置 → 发送唤醒消息
2. Lead 未派活 → 检查派活单 → 无则创建 → 推送 → 唤醒工程师
3. 验收缺失 → 合并分支 → 推送 GitHub → 更新 ROADMAP

**不再询问用户**:
- 不报告"等待确认"
- 不说"建议你在 AionUi 界面手动触发"
- 不请示"是否需要"
- 直接解决问题并简报结果

**上报红线**（立即通知用户）:
- pentest-agent-mvp 代码泄露
- 泄漏版 Claude Code 使用
- 平安内部信息泄露
- commit 署名错误（非 cdxiaodong + noreply 邮箱）

---

**架构版本**: v1.0（2026-08-09）
**下一步**: 将此架构写入 `docs/automation-architecture.md` 并配置 cron 任务
