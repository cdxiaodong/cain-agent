# =====================================================================
# ⚠️  红线声明(必读)⚠️
# =====================================================================
# 本靶场仅供「自有阿里云账号」内做 cain-agent OSS 暴露检测模块的端到端回归,
# 属授权测试。apply 后必须「当天 destroy」(见 README.md 三步用法),
# 不得作为真实目标、不得接入生产网络、不得长期留存公开桶造成数据泄露。
# 严禁将真实 AccessKey 写入 tfvars 提交进仓库——凭证一律用环境变量传入。
# =====================================================================

# 阿里云 OSS provider(region 经变量传入,默认 cn-hangzhou)
terraform {
  required_providers {
    alicloud = {
      source  = "aliyun/alicloud"
      version = "~> 1.220"
    }
  }
}

provider "alicloud" {
  region = var.region
}

# ---------------------------------------------------------------------------
# 场景一靶标:public-read 公开桶(故意误配置,就是 OSS 暴露检测应命中的对象)
# 预期:OSS 暴露检测模块应将其定级为 high(public-read)。
# ---------------------------------------------------------------------------
resource "alicloud_oss_bucket" "vuln_public_read" {
  bucket = "${var.bucket_prefix}-vuln-public-read-${var.bucket_suffix}"

  # ⚠️ 靶标语义:public-read 即任何人都可读取桶内对象——这是靶场故意制造的暴露
  acl = "public-read"

  tags = {
    Purpose   = "vuln-benchmark"
    Scenario  = "oss-public-read"
    ManagedBy = "cain-agent-bench"
  }
}

# ---------------------------------------------------------------------------
# 对照桶:private 私有桶(正确配置,检测模块应判为 info/private)
# 用于验证检测模块不会把私有桶误报为暴露。
# ---------------------------------------------------------------------------
resource "alicloud_oss_bucket" "control_private" {
  bucket = "${var.bucket_prefix}-control-private-${var.bucket_suffix}"

  acl = "private"

  tags = {
    Purpose   = "vuln-benchmark"
    Scenario  = "control-private"
    ManagedBy = "cain-agent-bench"
  }
}


# ===========================================================================
# 场景二:RAM 过度授权用户(给 Day4 RAM 提权分析模块做端到端回归靶标)
# ===========================================================================
# 一个「会被 RamPrivescAnalyzer 检出」的误配置 RAM 用户,与场景一同构:
#   - vuln_ram_user 挂「自定义过度授权策略」(Action 含 ram:AttachPolicyToUser
#     + ram:CreateAccessKey,Resource *)——正好命中 RAM 模块的两条 critical 规则
#     (AttachPolicyToSelf / CreateAccessKey-for-HighPriv)。
#   - safe_ram_user 只挂 AliyunOSSReadOnlyAccess 系统策略——零提权权限,应零命中。
# 安全设计(刻意约束):
#   - 本靶场不创建任何真实 RAM AccessKey 资源(见 tests 钉死),避免 apply 后
#     泄出可用 AK;靶标只验证「权限配置」能否被检出,不需要真实可用凭证。
#   - vuln 用户不设登录密码(纯 API 实体),不创建 LoginProfile。
# ===========================================================================

# ---------------------------------------------------------------------------
# 自定义策略:故意过度授权(靶标语义)
# 命中 RamPrivescAnalyzer:AttachPolicyToSelf(对应 action ram:AttachPolicyToUser)
#                       + CreateAccessKey-for-HighPriv(对应 action ram:CreateAccessKey)
# ---------------------------------------------------------------------------
resource "alicloud_ram_policy" "vuln_overpriv" {
  policy_name = "vuln-overpriv-${var.bucket_suffix}"
  policy_document = jsonencode({
    Version = "1"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ram:AttachPolicyToUser",
          "ram:CreateAccessKey",
        ]
        Resource = "*"
      }
    ]
  })
  description = "靶标:故意过度授权(AttachPolicyToUser + CreateAccessKey),仅供 cain-agent vuln-benchmark 回归"

  tags = {
    Purpose   = "vuln-benchmark"
    Scenario  = "ram-overpriv-policy"
    ManagedBy = "cain-agent-bench"
  }
}

# ---------------------------------------------------------------------------
# 靶标 RAM 用户:挂上述过度授权策略(应命中 >=2 条提权规则)
# ---------------------------------------------------------------------------
resource "alicloud_ram_user" "vuln_ram_user" {
  name         = "vuln-ram-user-${var.bucket_suffix}"
  display_name = "vuln-ram-user-${var.bucket_suffix}"
  comments     = "cain-agent vuln-benchmark 靶标用户(过度授权)"
  force        = true

  tags = {
    Purpose   = "vuln-benchmark"
    Scenario  = "ram-overpriv-user"
    ManagedBy = "cain-agent-bench"
  }
}

resource "alicloud_ram_user_policy_attachment" "vuln_attach" {
  policy_name = alicloud_ram_policy.vuln_overpriv.policy_name
  policy_type = "Custom"
  user_name   = alicloud_ram_user.vuln_ram_user.name
}

# ---------------------------------------------------------------------------
# 对照 RAM 用户:仅挂 AliyunOSSReadOnlyAccess 系统策略(正确最小权限,应零命中)
# ---------------------------------------------------------------------------
resource "alicloud_ram_user" "safe_ram_user" {
  name         = "safe-ram-user-${var.bucket_suffix}"
  display_name = "safe-ram-user-${var.bucket_suffix}"
  comments     = "cain-agent vuln-benchmark 对照用户(只读)"
  force        = true

  tags = {
    Purpose   = "vuln-benchmark"
    Scenario  = "ram-readonly-control"
    ManagedBy = "cain-agent-bench"
  }
}

resource "alicloud_ram_user_policy_attachment" "safe_attach" {
  policy_name = "AliyunOSSReadOnlyAccess"
  policy_type = "System"
  user_name   = alicloud_ram_user.safe_ram_user.name
}
