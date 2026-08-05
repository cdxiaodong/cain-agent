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
