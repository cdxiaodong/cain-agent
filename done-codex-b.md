# Codex-B 交付汇报 · 2026-08-07(Day 5 · 任务 3)

> 任务:阿里云 vulnerable-terraform 自建靶场 · **场景二(RAM 过度授权用户)**——为 Day 4 合入的 RAM 提权路径分析模块(`cloud/aliyun_ram.py`)提供端到端回归靶标
> 状态:**完成,ruff / pyright / pytest 三绿;全程未执行任何 terraform init / apply;待 21:00 验收**

## 分支

`test/2026-08-07-vuln-tf-ram`(从 `main@8578553` 切出,**未碰 main**),独立 worktree 隔离开发避免并发碰撞。

## 改动文件清单(3 追加 + 1 重写,均署名 `cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`,每次提交前 `git config user.email` 验证通过)

| 提交 | 文件 | 说明 |
|---|---|---|
| `ca4a132` test(bench) | `bench/aliyun-vuln-tf/main.tf` | 追加场景二(不动场景一):自定义过度授权策略 `vuln_overpriv`(Action `ram:AttachPolicyToUser`+`ram:CreateAccessKey`,Resource `*`)+ 靶标用户 `vuln-ram-user-*` + 对照用户 `safe-ram-user-*`(挂 `AliyunOSSReadOnlyAccess`)+ 两个挂载;全部带 `Purpose=vuln-benchmark` 标签 |
| `ca4a132` test(bench) | `bench/aliyun-vuln-tf/outputs.tf` | 追加场景二:`vuln_ram_user`/`safe_ram_user` 用户名输出 + `expected_detection_scene2`(vuln 命中 `AttachPolicyToSelf`+`CreateAccessKey-for-HighPriv` 两条 critical,safe 零命中) |
| `ca4a132` test(bench) | `tests/test_vuln_tf.py` | 追加 8 项场景二用例(共 20 项,**场景一 12 项零改动**):资源存在/两条提权 Action 绑定/对照只读系统策略/靶标用户 Purpose 标签/钉死不建真 AK/钉死不建 LoginProfile/outputs 对照/README 场景二章节 |
| `1647f07` docs(bench) | `bench/aliyun-vuln-tf/README.md` | 重写(保留场景一全文):加场景二说明、两场景对照表、为什么不建真实 AccessKey(安全设计)、apply/destroy 警告复述、用户名后缀复用 bucket_suffix 说明 |

未改:场景一 `main.tf`/`variables.tf` 旧块、`src/`、`docs/benchmark-plan.md`、`bench/docker-compose.yml`。

## 自测结果(三绿)

| 门 | 命令(worktree 内) | 结果 |
|---|---|---|
| ruff | `ruff check src tests` | **All checks passed** |
| pyright | `pyright -p pyproject.toml --pythonpath .venv/bin/python` | **0 errors, 0 warnings, 0 informations** |
| pytest | `pytest -q` | **230 passed, 1 skipped**(skip = 本机无 `terraform` 二进制,`terraform fmt -check` 跳过,CI 不红) |

> pyright 备注:默认调用会误报 `src/cain_agent/cloud/aliyun_oss.py` 的 `import oss2` 为无法解析——这是 main 既有的 venv 发现怪癖(主仓库默认 pyright 同样报错),与本次改动无关;按产线 recipe 用 `--pythonpath .venv/bin/python` 指向 venv 解释器即 0 error。本次仅 `tests/test_vuln_tf.py` 为 pyright 受影响文件,类型干净。

## 验收对照(对照 tasks/2026-08-07.md 任务 3 验收标准)

| 验收项 | 要求 | 实际 |
|---|---|---|
| 三绿 | ruff / pyright / pytest | ✅ 全绿(见上表) |
| 「不建真 AK」有测试钉死 | 不得创建 `alicloud_ram_access_key` 资源 | ✅ `test_no_ram_access_key_resource` 钉死(main.tf 全文无该资源类型) |
| 未执行任何 terraform apply | 严禁 init/apply | ✅ 全程仅静态校验,未运行 `terraform` 任何子命令(本机甚至未安装二进制,fmt 用例 skip) |

## 任务强制项对照

| 强制项 | 要求 | 实际 |
|---|---|---|
| 改动范围 | 仅 `bench/aliyun-vuln-tf/`(main/variables/outputs/README)+ `tests/test_vuln_tf.py` | ✅ 未越界(variables.tf 未需改动,复用 bucket_suffix) |
| 靶标命中两条规则 | vuln 策略含 `ram:AttachPolicyToUser` + `ram:CreateAccessKey`,Resource `*` | ✅ 对应 `AttachPolicyToSelf` + `CreateAccessKey-for-HighPriv`(均 critical) |
| 对照用户 | 只挂 `AliyunOSSReadOnlyAccess` 系统策略 | ✅ `policy_type = "System"`,零 RAM 写权限,零命中 |
| 不建真 AK | 不创建 AccessKey 资源 | ✅ 测试钉死 |
| 不设登录密码 | vuln 用户纯 API 实体 | ✅ 无 `alicloud_ram_login_profile`(测试钉死) |
| Purpose 标签 | 所有新资源打 `Purpose = vuln-benchmark` | ✅ 两用户 + 自定义策略均带三标签(Purpose/Scenario/ManagedBy) |
| 头部授权声明 | 红字声明保持 | ✅ 场景一头部 8 行声明未动;场景二追加块自带用途说明 |
| 严禁 terraform init/apply | — | ✅ 未执行 |
| commit 署名 | `cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>` | ✅ 每次提交前 `git config user.email` 验证 |
| 写文件用 shell heredoc | 不用 apply_patch | ✅ 全程 heredoc + perl/sed 微调 |

## 设计说明(规则命中映射)

`RamPrivescAnalyzer.PRIVESC_RULES` 中,`ram:AttachPolicyToSelf` 规则的 `required_perms` 为 `(ram:AttachPolicyToUser,) | (ram:AttachPolicyToGroup,) | (ram:AttachPolicyToRole,)`(OR 跨集),`ram:CreateAccessKey-for-HighPriv` 为 `(ram:CreateAccessKey,)`。靶标策略同时授予这两个 Action(且 Resource `*`),因此 apply 后该用户会被分析器精确命中 **2 条 critical 规则**;对照用户仅 `AliyunOSSReadOnlyAccess`(oss:Get*/List*)无任何 RAM 写 Action,零命中。靶场与检测模块的规则表形成闭环。

## 安全说明

- 靶场**故意不创建任何 RAM AccessKey 资源**:靶标只验证「权限配置能否被检出」,不需要真实可用凭证;一旦 apply 出真 AK 写进 state 即构成可用凭证泄露面,违背「只读/当天 destroy」红线。该约束由 `test_no_ram_access_key_resource` 静态钉死。
- vuln 用户为纯 API 实体,不设控制台登录密码(无 LoginProfile),由 `test_no_ram_login_profile` 钉死。
- 两用户均设 `force = true`,destroy 时自动移除挂载的策略,便于当天清理。
