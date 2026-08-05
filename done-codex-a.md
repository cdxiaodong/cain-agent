# Codex-A 交付汇报 · 2026-08-06（Day 4 · 任务 2）

> 汇报对象：Lead（Claude Code）
> 任务：阿里云 RAM 提权路径分析模块（只读）
> 状态：**完成，三绿通过，待 21:00 验收**

## 分支

`feat/2026-08-06-aliyun-ram-privesc`（从 main@dc5958f 切出，**未碰 main**）

## 改动文件清单（3 个文件，848 行新增）

| 提交 | 文件 | 说明 |
|---|---|---|
| `c7722f1` feat(cloud) | `src/cain_agent/cloud/aliyun_ram.py` | RamPrivescAnalyzer / RamFinding / PrivescRule / PRIVESC_RULES / RamCredentialError |
| `c7722f1` feat(cloud) | `tests/test_aliyun_ram.py` | 全 mock 单测，15 用例，零触网零真实凭证 |
| `c7722f1` feat(cloud) | `pyproject.toml` | 仅追加 `requests>=2.28`（1 行） |

## 自测结果（三绿）

- `ruff check src tests` → All checks passed
- `pyright` → 0 errors, 0 warnings, 0 informations
- `pytest`（全量）→ **211 passed**（本次新增 15 个 + 既有 196 个全绿）

## SDK 选型理由

选用 `requests` + Aliyun RPC v1 签名（HMAC-SHA1），而非官方 `alibabacloud-ram20150501`：

1. **零新重型依赖**：`requests` 已随 `oss2` 安装（transitive），无需引入
   `alibabacloud_tea_openapi` / `alibabacloud_tea_util` 整条 tea 依赖链。
2. **网络友好**：RPC-style RAM API 是简单 GET 端点，签名仅 ~30 行代码，
   今天本机网络极慢（pip install alibabacloud-ram 超时），选用 requests
   避免安装阻塞。
3. **测试友好**：`_call_api` 是唯一网络调用入口，测试 monkeypatch 一个
   方法即可全隔离，比 mock 整个 SDK client 更简洁。
4. **凭证体系一致**：与 `cloud/aliyun_oss.py` 的 OssExposureChecker 使用
   相同的 `ALIBABA_CLOUD_ACCESS_KEY_ID/SECRET` 环境变量约定。

## 验收对照（派活单要求逐项）

| 要求 | 落实 |
|---|---|
| 凭证只从参数/环境变量读 | 构造参数 `access_key_id`/`access_key_secret`，或 `ALIBABA_CLOUD_ACCESS_KEY_ID`/`ALICLOUD_ACCESS_KEY` 环境变量；无默认值、无硬编码 key |
| 缺凭证报错 | `RamCredentialError`，测试钉死 |
| 只用 RAM 只读 API | ListUsers / ListRoles / ListPoliciesForUser / ListPoliciesForRole / GetPolicy / GetPolicyVersion，全部 Get/List 开头 |
| 5 条提权路径规则表 | PassRole-to-Compute、AttachPolicyToSelf、CreateAccessKey-for-HighPriv、LoginProfile-Hijack、AssumeRole-Chain，每条含 rule_id / required_perms / description / severity |
| analyze() -> list[RamFinding] | 枚举用户/角色+策略，与规则表匹配，命中产出 finding（cloud=aliyun, service=ram, resource=ARN, issue_type=rule_id） |
| 单实体失败容错 | `_safe_list` 包裹 API 调用，失败返回空列表继续，测试钉死 |
| Policy Document 解析失败不炸 | `_extract_allowed_actions` 返回空集合，测试钉死 |
| 通配 `*` Action 判定 | `matches()` 支持 `*`（全通配）和 `ram:*`（service 通配），测试钉死 |
| `ram:*` 管理员标 critical | 规则表中涉及管理员操作的规则 severity=critical，测试钉死 |
| 5 条规则各命中 | 每条规则有独立测试用例 |
| 零触网零真实凭证 | 全部 monkeypatch `_call_api`，15 用例均不触网 |

## 设计要点

- **规则匹配语义**：`PrivescRule.matches(actions)` 支持 AND-within-set /
  OR-across-set：`required_perms` 是 tuple of tuples，内层 AND（全满足才
  命中），外层 OR（任一组满足即命中）。service 通配 `ram:*` 展开匹配
  所有 `ram:xxx` 动作，`*` 匹配一切（管理员）。
- **PassRole-to-Compute**：需要 `ram:PassRole` **且** `fc:CreateFunction`
  或 `ecs:RunInstances`（借角色执行代码需要计算资源创建权限）。纯
  `ram:*` 不命中此规则（缺计算权限），测试已验证。
- **大小写不敏感**：`_extract_allowed_actions` 全部 lowercase，`matches`
  内 `_perm_covered` 也 lowercase 对比。
- **Deny 语句排除**：Policy 中 `Effect=Deny` 的语句不贡献 allowed actions，
  测试钉死。

## 红线遵守

- 不做自动利用/验证性提权（检测只读）。
- 不接 validator（那是任务 1 的执行层组装）。
- 不覆盖腾讯云（阿里云专属）。
- commit 署名 `cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>` 已验证。
- pyproject 仅追加 `requests>=2.28`，未改其他依赖。
- 未推送，待 Lead 审查/合并。

## 并发隔离说明

本仓库为共享工作区，期间 Lead 和 Codex-B 也在工作。多次确认
`git branch --show-current` 在 commit 前为 `feat/2026-08-06-aliyun-ram-privesc`。
仅 `git add` 自己的 3 个文件，未 `git add -A`，未触碰他人文件。
