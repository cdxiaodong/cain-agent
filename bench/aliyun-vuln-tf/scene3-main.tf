# =====================================================================
# ⚠️  红线声明(必读)⚠️
# =====================================================================
# 本靶场仅供「自有阿里云账号」内做 cain-agent RAM 提权检测模块的端到端回归,
# 属授权测试。apply 后必须「当天 destroy」(见 README.md 三步用法),
# 不得作为真实目标、不得接入生产网络、不得长期留存过度授权用户造成凭证泄露。
# 严禁将真实 AccessKey 写入 tfvars 提交进仓库——凭证一律用环境变量传入。
# =====================================================================

# ---------------------------------------------------------------------------
# 场景三:管理员权限用户(给 Day4 RAM 提权分析模块做端到端回归,与场景二互补)
# ---------------------------------------------------------------------------
# 场景二用「自定义过度授权策略」精准命中 2 条规则,验证检测模块的精确规则匹配;
# 场景三用「内置 AdministratorAccess 管理员策略」直接给满权限,验证检测模块
# 对管理员账户的完整识别:
#   - vuln_admin_user 挂 AdministratorAccess(Action "*"),应命中全部 5 条
#     提权规则(3 critical + 2 high)且 is_admin=true。
#   - safe_readonly_user 只挂 AliyunReadOnlyAccess 系统策略(全局只读),应零命中。
# 安全设计(刻意约束,与场景二一致):
#   - 本靶场不创建任何真实 RAM AccessKey 资源(见 tests 钉死),避免 apply 后
#     泄出可用 AK;靶标只验证「权限配置」能否被检出,不需要真实可用凭证。
#   - 用户不设登录密码(纯 API 实体),不创建 LoginProfile。
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 靶标 RAM 用户:挂 AdministratorAccess 系统策略(管理员全权限)
# 命中 RamPrivescAnalyzer 全部规则:
#   ram:AttachPolicyToSelf / ram:CreateAccessKey-for-HighPriv
#   / ram:PassRole-to-Compute / ram:LoginProfile-Hijack / ram:AssumeRole-Chain
# ---------------------------------------------------------------------------
resource "alicloud_ram_user" "vuln_admin_user" {
  name         = "vuln-admin-user-${var.scene3_user_suffix}"
  display_name = "vuln-admin-user-${var.scene3_user_suffix}"
  comments     = "cain-agent vuln-benchmark 靶标用户(管理员全权限)"
  force        = true

  tags = {
    Purpose   = "vuln-benchmark"
    Scenario  = "ram-admin-user"
    ManagedBy = "cain-agent-bench"
  }
}

resource "alicloud_ram_user_policy_attachment" "vuln_admin_attach" {
  policy_name = "AdministratorAccess"
  policy_type = "System"
  user_name   = alicloud_ram_user.vuln_admin_user.name
}

# ---------------------------------------------------------------------------
# 对照 RAM 用户:仅挂 AliyunReadOnlyAccess 系统策略(全局只读,正确最小权限,应零命中)
# ---------------------------------------------------------------------------
resource "alicloud_ram_user" "safe_readonly_user" {
  name         = "safe-readonly-user-${var.scene3_user_suffix}"
  display_name = "safe-readonly-user-${var.scene3_user_suffix}"
  comments     = "cain-agent vuln-benchmark 对照用户(全局只读)"
  force        = true

  tags = {
    Purpose   = "vuln-benchmark"
    Scenario  = "ram-readonly-control"
    ManagedBy = "cain-agent-bench"
  }
}

resource "alicloud_ram_user_policy_attachment" "safe_readonly_attach" {
  policy_name = "AliyunReadOnlyAccess"
  policy_type = "System"
  user_name   = alicloud_ram_user.safe_readonly_user.name
}
