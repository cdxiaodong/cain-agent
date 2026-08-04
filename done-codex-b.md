# Codex-B 交付汇报 · 2026-08-04（Day 2 · 任务 3）

> 汇报对象：Lead（Claude Code）
> 任务：Web 三核心技能 SKILL.md（SQLi/XSS/SSRF）+ 技能格式校验测试 + 技能编写规范
> 状态：**完成，三绿通过，待 21:00 验收**

## 分支

`test/2026-08-04-web-skills`（从 main@09c6dc0 切出，**未碰 main**）

## 改动文件清单（5 个新文件，473 行新增）

| 提交 | 文件 | 说明 |
|---|---|---|
| `5fdb986` feat(skills) | `skills/web/sqli/SKILL.md` | SQL 注入技能：布尔/时间盲注、参数边界、WAF 对抗、误报规避 |
| `5fdb986` feat(skills) | `skills/web/xss/SKILL.md` | XSS 技能：渲染上下文区分、存储/反射/DOM 型、CSP 绕过 |
| `5fdb986` feat(skills) | `skills/web/ssrf/SKILL.md` | SSRF 技能：含 AWS/阿里云/GCP/Azure 云元数据端点检测 |
| `5fdb986` feat(skills) | `tests/test_skill_format.py` | 格式校验：新技能严格四字段四节，旧技能兼容不阻塞 |
| `c46355d` docs(skills) | `docs/skill-authoring-guide.md` | 技能编写规范（半页到一页），供后续 ~20 项云技能参照 |

## 自测结果（三绿，均在工作树内复跑）

- `ruff check src tests` → All checks passed
- `pyright` → 0 errors, 0 warnings, 0 informations
- `pytest`（全量）→ **72 passed**（本次新增 17 个 + 既有 55 个全绿，含昨日合入的 executor/scope/cli/orchestrator 前置）

## 验收对照（派活单要求逐项）

| 要求 | 落实 |
|---|---|
| 四节结构固定（触发条件/三层测试模型/证据要求/禁止事项） | 三份 SKILL.md 均含，测试 `test_new_spec_skill_sections_present` 钉死 |
| frontmatter 四字段（name/description/phase/severity_focus） | 齐全，测试 `test_new_spec_skill_frontmatter_fields` 钉死 |
| 三层模型 L1/L2/L3 | 三份均含三级子标题，L3 体现 WAF/风控对抗 |
| 面向真实实战非 CTF | SQLi 讲参数边界与误报排除；XSS 讲渲染上下文与浏览器真实执行；SSRF 讲盲探与元数据链路 |
| SSRF 含云元数据端点 | 覆盖 `169.254.169.254`（AWS/Azure/GCP）+ `100.100.100.200`（阿里云），与云模块呼应 |
| 旧 66 技能兼容检查 | 无新规范 frontmatter 的旧技能归为 legacy，仅记录不阻塞（`test_legacy_skills_only_warned_not_blocked`） |
| 新 `skills/web/` 三技能全字段通过 | 17 个新规范测试全绿 |
| 无占位符/无复制粘贴雷同 | 测试 `test_new_spec_skill_no_placeholder` + `test_new_spec_skill_not_identical_to_others` 钉死 |
| 不改旧 66 技能、不动 src/ | `diff main..test` 仅 5 个新文件，范围外零改动 |

## 内容差异化说明（防雷同）

三份骨架相同（四节固定），但正文实质不同，去骨架后哈希两两不同（测试已验证）：
- **SQLi**：数据库指纹收敛、布尔/时间盲注统计基线、编码与等价函数变形。
- **XSS**：渲染上下文（HTML/属性/JS/CSS/URL）分流、DOM 型 source-sink 数据流、CSP 实锚点绕过。
- **SSRF**：出站请求触发点、盲 SSRF 的 OOB 证据、云元数据端点与凭证边界。

## 红线遵守

- 仅授权目标、只读原则、凭证只哈希不落明文、不超 scope 扩张——写入三份技能的「禁止事项」节。
- 云元数据临时凭证**只记录存在性，不下载不使用**（SSRF 技能明确禁止）。
- 未改 src/、未改旧 66 技能、未改 pyproject（pyyaml 已是 Codex-A 昨日合入的依赖，直接复用）。

## 并发隔离说明

全程在独立 git worktree（`cain-agent-wt-web`）完成，已移除。主工作区当前停在 Codex-A 的分支，我未触碰其任何文件。
