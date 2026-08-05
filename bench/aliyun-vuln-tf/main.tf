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
