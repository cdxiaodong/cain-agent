# ---------------------------------------------------------------------------
# 场景三:管理员权限用户(给 Day4 RAM 提权分析模块做端到端回归)
# ---------------------------------------------------------------------------

output "vuln_admin_user" {
  description = "靶标 RAM 用户(挂 AdministratorAccess 管理员策略),应检出 is_admin=true 并命中全部 5 条提权规则"
  value       = alicloud_ram_user.vuln_admin_user.name
}

output "safe_readonly_user" {
  description = "对照 RAM 用户(挂 AliyunReadOnlyAccess 只读策略),提权分析应零命中"
  value       = alicloud_ram_user.safe_readonly_user.name
}

output "expected_detection_scene3" {
  description = "场景三预期检出对照:管理员用户命中全部 5 条规则(3 critical + 2 high)且 is_admin,对照用户零命中"
  value = {
    vuln_admin_user = {
      user       = alicloud_ram_user.vuln_admin_user.name
      expect     = "critical"
      is_admin   = true
      hit_rules  = [
        "ram:AttachPolicyToSelf",
        "ram:CreateAccessKey-for-HighPriv",
        "ram:PassRole-to-Compute",
        "ram:LoginProfile-Hijack",
        "ram:AssumeRole-Chain",
      ]
      granted    = ["*"]
      resource   = "*"
      comment    = "挂 AdministratorAccess 系统策略,Action *,命中全部提权规则且 is_admin=true"
    }
    safe_readonly_user = {
      user       = alicloud_ram_user.safe_readonly_user.name
      expect     = "info"
      is_admin   = false
      hit_rules  = []
      granted    = ["*:Get*", "*:List*"]
      comment    = "仅挂 AliyunReadOnlyAccess 系统策略,零提权权限,零命中"
    }
  }
}
