# ---------------------------------------------------------------------------
# 输出:便于 verify 阶段核对桶名与预期检出结果
# ---------------------------------------------------------------------------

output "vuln_public_read_bucket" {
  description = "靶标桶(公开读),应被 OSS 暴露检测模块检出为 high(public-read)"
  value       = alicloud_oss_bucket.vuln_public_read.bucket
}

output "control_private_bucket" {
  description = "对照桶(私有),检测模块应判为 info(private),不应误报为暴露"
  value       = alicloud_oss_bucket.control_private.bucket
}

output "expected_detection" {
  description = "预期检出对照表:给出每个桶应被 OSS 暴露检测模块判定的 severity"
  value = {
    vuln_public_read = {
      bucket  = alicloud_oss_bucket.vuln_public_read.bucket
      acl     = "public-read"
      expect  = "high"
      comment = "public-read = 任何人可读 = 暴露;规则表命中 high"
    }
    control_private = {
      bucket  = alicloud_oss_bucket.control_private.bucket
      acl     = "private"
      expect  = "info"
      comment = "private = 正确配置,非暴露,仅 info"
    }
  }
}


# ---------------------------------------------------------------------------
# 场景二:RAM 过度授权用户(给 RAM 提权分析模块做端到端回归)
# ---------------------------------------------------------------------------

output "vuln_ram_user" {
  description = "靶标 RAM 用户(过度授权),应被 RAM 提权分析模块检出 >=2 条 critical 规则"
  value       = alicloud_ram_user.vuln_ram_user.name
}

output "safe_ram_user" {
  description = "对照 RAM 用户(只挂 OSS 只读系统策略),提权分析应零命中"
  value       = alicloud_ram_user.safe_ram_user.name
}

output "expected_detection_scene2" {
  description = "场景二预期检出对照:vuln 用户命中 AttachPolicyToSelf + CreateAccessKey 两条 critical,对照用户零命中"
  value = {
    vuln_ram_user = {
      user       = alicloud_ram_user.vuln_ram_user.name
      expect     = "critical"
      hit_rules  = ["ram:AttachPolicyToSelf", "ram:CreateAccessKey-for-HighPriv"]
      granted    = ["ram:AttachPolicyToUser", "ram:CreateAccessKey"]
      resource   = "*"
      comment    = "自定义策略含 AttachPolicyToUser + CreateAccessKey,Resource *,命中两条提权规则"
    }
    safe_ram_user = {
      user       = alicloud_ram_user.safe_ram_user.name
      expect     = "info"
      hit_rules  = []
      granted    = ["oss:Get*", "oss:List*"]
      comment    = "仅挂 AliyunOSSReadOnlyAccess 系统策略,无 RAM 写权限,零命中"
    }
  }
}
