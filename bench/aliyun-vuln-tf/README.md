# 阿里云 vulnerable-terraform 靶场 · 场景一(OSS 公开桶)+ 场景二/三(RAM 过度授权用户 / 管理员权限用户)

> 红线:本靶场仅供**自有阿里云账号**内做 cain-agent 检测模块的端到端回归,属授权测试。
> apply 后**必须当天 destroy**,严禁长期留存误配置资源造成泄露。

本目录提供两个场景,各自为 cain-agent 一个检测模块提供端到端回归靶标:

| 场景 | 靶标 | 验证对象 | 预期 |
|---|---|---|---|
| 一 | `public-read` OSS 桶(对照:`private` 桶) | `cloud/aliyun_oss.py` OSS 暴露检测 | 靶标 `high`,对照 `info` |
| 二 | 过度授权 RAM 用户(对照:只读 RAM 用户) | `cloud/aliyun_ram.py` RAM 提权路径分析 | 靶标命中 ≥2 条 `critical`,对照零命中 |
| 三 | 管理员权限 RAM 用户(对照:只读 RAM 用户) | `cloud/aliyun_ram.py` RAM 提权路径分析 | 靶标命中全部 5 条规则 + `is_admin`,对照零命中 |

---

## 场景一:OSS 公开桶

### 资源

- 1 个 `public-read` OSS 桶(靶标)+ 1 个 `private` OSS 桶(对照)。
- 期望:`public-read` 桶被检出为 `high`(public-read = 任何人可读 = 暴露);`private` 桶判为 `info`(正确配置,不应误报)。
- 价值:国产云漏洞靶场全网空白,是独立传播点(见 `docs/benchmark-plan.md` 自建云靶场一节)。

---

## 场景二:RAM 过度授权用户(给 Day4 RAM 提权分析模块做端到端回归)

### 资源

- **靶标用户** `vuln-ram-user-<suffix>`:挂**自定义过度授权策略**(Action 含 `ram:AttachPolicyToUser` + `ram:CreateAccessKey`,Resource `*`)——正好命中 `RamPrivescAnalyzer` 的两条 critical 规则:`ram:AttachPolicyToSelf`、`ram:CreateAccessKey-for-HighPriv`。
- **对照用户** `safe-ram-user-<suffix>`:仅挂 `AliyunOSSReadOnlyAccess` 系统策略(正确最小权限)——零 RAM 写权限,提权分析应零命中。

### 为什么不创建真实 AccessKey(安全设计)

本靶场**刻意不创建任何 RAM AccessKey 资源**:

- 靶标只验证「权限配置」能否被检测模块检出,**不需要真实可用的 AccessKey**;
- 一旦 apply 出真实 AK 并写进 state,就构成可用凭证泄露面,违背「只读/当天 destroy」的安全红线;
- 检测模块 `RamPrivescAnalyzer` 分析的是「挂载的策略权限」,与是否存在 AK 无关。

> 该约束由 `tests/test_vuln_tf.py::test_no_ram_access_key_resource` 静态钉死:main.tf 不得出现该资源类型。

### RAM 用户名后缀

两用户名复用场景一的 `bucket_suffix` 变量(随机后缀,避免命名冲突,apply 时用 `-var bucket_suffix=$(date +%s)` 注入)。建议 apply 与 destroy 保持同一后缀。

---

## 场景三:管理员权限用户(给 RAM 提权分析模块做「管理员全命中」回归)

> 独立文件:`scene3-main.tf` / `scene3-outputs.tf` / `scene3-variables.tf`,与场景一/二同目录共存(terraform 以整目录为一个 root module)。

### 资源

- **靶标用户** `vuln-admin-user-<suffix>`:挂**内置 `AdministratorAccess` 系统策略**(Action `*`,管理员全权限)——直接命中 `RamPrivescAnalyzer` **全部 5 条规则**(`ram:AttachPolicyToSelf`、`ram:CreateAccessKey-for-HighPriv`、`ram:PassRole-to-Compute`、`ram:LoginProfile-Hijack`、`ram:AssumeRole-Chain`;3 critical + 2 high)且 `is_admin=true`。
- **对照用户** `safe-readonly-user-<suffix>`:仅挂 `AliyunReadOnlyAccess` 系统策略(全局只读,正确最小权限)——零提权权限,提权分析应零命中。

### 与场景二的区别

| 场景 | 靶标策略 | 验证点 |
|---|---|---|
| 二 | 自定义策略(2 条 RAM 写 Action) | 规则**精确匹配**(精准命中 2 条 critical) |
| 三 | 内置 `AdministratorAccess`(Action `*`) | 管理员账户**完整识别**(命中全部 5 条 + `is_admin`) |

### 为什么不创建真实 AccessKey(安全设计)

与场景二相同:本靶场**刻意不创建任何 RAM AccessKey 资源**——靶标只验证「权限配置」能否被检测模块检出,不需要真实可用凭证;一旦 apply 出真实 AK 即构成凭证泄露面。该约束由 `tests/test_vuln_tf_scene3.py::test_scene3_no_ram_access_key_resource` 静态钉死。

### 场景三用法(与场景一/二同目录,apply 时整目录一起加载)

```bash
cd bench/aliyun-vuln-tf
export ALICLOUD_ACCESS_KEY="<your-access-key-id>"   # 自有测试账号的 AK,不写真实值
export ALICLOUD_SECRET_KEY="..."
terraform init
terraform apply -var="bucket_suffix=$(date +%s)" -var="scene3_user_suffix=$(date +%s)" -auto-approve
# 验证:RAM 模块对准 vuln_admin_user(预期命中 5 条规则 + is_admin)
terraform output
terraform destroy -var="bucket_suffix=$(date +%s)" -var="scene3_user_suffix=$(date +%s)" -auto-approve
```

> 场景三 `scene3-variables.tf` 只定义 `scene3_*` 专属变量(用户名后缀 + 可调策略名),`region` 复用主 `variables.tf`,避免 terraform root module 变量同名冲突。

---

## 前置

- 自有阿里云账号(场景一需可建/删 OSS 桶的授权;场景二需 RAM 管理/策略授权);
- 本机装好 `terraform`(`terraform --version` ≥ 1.0);
- 阿里云 provider(`aliyun/alicloud`):首次 `terraform init` 自动拉取。

## 凭证(严禁写 tfvars 提交进仓库)

阿里云 provider 读环境变量,**不要**把 AccessKey/Secret 写进任何 tfvars 文件提交:

```bash
export ALICLOUD_ACCESS_KEY="<your-access-key-id>"   # 自有测试账号的 AK(阿里云 AK 前缀为 LTAI,此处不写真实值)
export ALICLOUD_SECRET_KEY="..."          # 对应 SK
```

> 建议用 RAM 子账号,最小权限,不用主账号 AK。AK/SK 绝不出现在 git 仓库。

## 三步用法:apply → verify → destroy

```bash
cd bench/aliyun-vuln-tf

# 1) 初始化并拉起靶标(当天必做,用完立刻 destroy)
terraform init
terraform apply -var="bucket_suffix=$(date +%s)" -auto-approve

# 2) verify:用 cain-agent 检测模块跑一遍(在仓库根执行)
#    场景一桶名 / 场景二用户名见 terraform output:
terraform output
#    OSS 模块对准 vuln_public_read_bucket(预期 high);RAM 模块对准 vuln_ram_user(预期命中 ≥2 条 critical)。

# 3) destroy:用完即清,严禁留存(当天必做)
terraform destroy -var="bucket_suffix=$(date +%s)" -auto-approve
```

> bucket 名与 RAM 用户名都带随机后缀(`-var bucket_suffix=...`)避免命名冲突。apply 与 destroy 的后缀可不一致(资源名在 state 里固定),但建议保持一致便于管理。

## 费用与清理警告

- OSS 桶在空存储下费用极低,但 `public-read` 桶被外部流量拉取会产生**流出费用**,这就是必须当天 destroy 的原因。
- RAM 用户/策略/挂载本身不产生费用,但过度授权策略一旦留存即风险敞口,同样必须当天 destroy。
- **不**往桶里放任何真实/敏感数据;靶标只验证 ACL/权限配置检测能力,不需要数据。
- 用完务必 `terraform destroy`,确认 `terraform show` 无残留资源。场景二用户设了 `force = true`,destroy 时会自动移除挂载的策略。
- 如 apply 失败(配额/权限),先 `terraform destroy` 清理半成品,再排查。

## 预期检出对照

### 场景一(OSS)

| 桶 | acl | 预期 severity | 说明 |
|---|---|---|---|
| `${prefix}-vuln-public-read-*` | `public-read` | `high` | 靶标:public-read = 暴露 |
| `${prefix}-control-private-*` | `private` | `info` | 对照:private = 正确,不应误报 |

### 场景二(RAM)

| 用户 | 挂载策略 | 预期 | 说明 |
|---|---|---|---|
| `vuln-ram-user-*` | 自定义(`AttachPolicyToUser` + `CreateAccessKey`,Resource `*`) | 命中 2 条 `critical` | 靶标:可自我提权 + 可为他人造 AK |
| `safe-ram-user-*` | `AliyunOSSReadOnlyAccess`(系统) | 零命中 | 对照:最小权限,不应误报 |

检测模块若把对照实体判为暴露(误报)或把靶标漏掉(漏报),均视为回归失败。

## 后续场景(不在本任务范围)

- FC 环境变量密钥、元数据端点 SSRF 等——逐步补齐国产云靶场覆盖面。
