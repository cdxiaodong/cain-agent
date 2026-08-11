# ---------------------------------------------------------------------------
# 场景三变量定义(凭证不在此处——用环境变量 ALICLOUD_ACCESS_KEY / ALICLOUD_SECRET_KEY 传入)
# 注意:region 复用主 variables.tf 的 var.region(terraform 以整目录为一个 root module,
#       变量名全局唯一,场景三只定义专属变量避免与场景一/二同名冲突)。
# ---------------------------------------------------------------------------

variable "scene3_user_suffix" {
  description = "场景三 RAM 用户名后缀(复用主 bucket_suffix 或独立随机串,避免命名冲突)"
  type        = string
  # 调用方用 -var scene3_user_suffix=$(date +%s) 之类注入,默认留空由 apply 时指定
  default     = ""
}

variable "scene3_admin_policy" {
  description = "靶标用户挂载的管理员系统策略名(默认 AdministratorAccess,仅供演示,不填即用默认)"
  type        = string
  default     = "AdministratorAccess"
}

variable "scene3_readonly_policy" {
  description = "对照用户挂载的只读系统策略名(默认 AliyunReadOnlyAccess,仅供演示,不填即用默认)"
  type        = string
  default     = "AliyunReadOnlyAccess"
}
