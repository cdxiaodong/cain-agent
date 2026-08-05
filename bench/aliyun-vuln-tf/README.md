# 阿里云 vulnerable-terraform 靶场 · 场景一(OSS 公开桶)

> 红线:本靶场仅供**自有阿里云账号**内做 cain-agent OSS 暴露检测模块的端到端回归,属授权测试。
> apply 后**必须当天 destroy**,严禁长期留存 public-read 桶造成数据泄露。

## 用途

为 ROADMAP Phase 2「自建阿里云 vulnerable-terraform 靶场」提供第一个场景:

- 资源:1 个 `public-read` OSS 桶(靶标)+ 1 个 `private` OSS 桶(对照)。
- 验证对象:`cain-agent` 的 `cloud/aliyun_oss.py` OSS 暴露检测模块(Day 3 合入)。
- 期望:`public-read` 桶被检出为 `high`(public-read = 任何人可读 = 暴露);`private` 桶判为 `info`(正确配置,不应误报)。
- 价值:国产云漏洞靶场全网空白,是独立传播点(见 `docs/benchmark-plan.md` 自建云靶场一节)。

## 前置

- 自有阿里云账号(建议 RAM 只读子账号 + 一个可建 OSS 的授权);
- 本机装好 `terraform`(`terraform --version` ≥ 1.0);
- 阿里云 OSS provider(`aliyun/alicloud`):首次 `terraform init` 自动拉取。

## 凭证(严禁写 tfvars 提交进仓库)

阿里云 provider 读环境变量,**不要**把 AccessKey/Secret 写进任何 tfvars 文件提交:

```bash
export ALICLOUD_ACCESS_KEY="<your-access-key-id>"   # 自有测试账号的 AK(阿里云 AK 前缀为 LTAI,此处不写真实值)
export ALICLOUD_SECRET_KEY="..."          # 对应 SK
```

> 建议用 RAM 子账号,最小权限(建/删 OSS 桶),不用主账号 AK。AK/SK 绝不出现在 git 仓库。

## 三步用法:apply → verify → destroy

```bash
cd bench/aliyun-vuln-tf

# 1) 初始化并拉起靶标(当天必做,用完立刻 destroy)
terraform init
terraform apply -var="bucket_suffix=$(date +%s)" -auto-approve

# 2) verify:用 cain-agent OSS 暴露检测模块跑一遍(在仓库根执行)
#    bucket 名见 terraform output,或:
terraform output vuln_public_read_bucket
#    把检测模块对准上述 bucket,预期定级 high;对照桶预期 info。

# 3) destroy:用完即清,严禁留存(当天必做)
terraform destroy -var="bucket_suffix=$(date +%s)" -auto-approve
```

> bucket 名带随机后缀(`-var bucket_suffix=...`)避免全局命名冲突。apply 与 destroy 的后缀可不一致,因为资源名在 state 里固定;但建议保持一致便于管理。

## 费用与清理警告

- OSS 桶本身在空存储下费用极低(分位数/请求计费),但 `public-read` 桶被外部流量拉取会产生**流出费用**,这就是必须当天 destroy 的原因。
- **不**往桶里放任何真实/敏感数据;靶标只验证 ACL 配置检测能力,不需要数据。
- 用完务必 `terraform destroy`,确认 `terraform show` 无残留资源。
- 如 apply 失败(配额/权限),先 `terraform destroy` 清理半成品,再排查。

## 预期检出对照

| 桶 | acl | 预期 severity | 说明 |
|---|---|---|---|
| `${prefix}-vuln-public-read-*` | `public-read` | `high` | 靶标:public-read = 暴露 |
| `${prefix}-control-private-*` | `private` | `info` | 对照:private = 正确,不应误报 |

检测模块若把 private 桶判为暴露(误报)或把 public-read 桶漏掉(漏报),均视为回归失败。

## 后续场景(不在本任务范围)

- RAM 误配置(提权路径)靶标——与 Codex-A 的 RAM 检测模块呼应。
- FC 环境变量密钥、元数据端点 SSRF 等——逐步补齐国产云靶场覆盖面。
