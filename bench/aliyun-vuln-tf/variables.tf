# ---------------------------------------------------------------------------
# 变量定义(凭证不在此处——用环境变量 ALICLOUD_ACCESS_KEY / ALICLOUD_SECRET_KEY 传入)
# ---------------------------------------------------------------------------

variable "region" {
  description = "阿里云 region,默认杭州(自有测试账号内任选最便宜区域)"
  type        = string
  default     = "cn-hangzhou"
}

variable "bucket_prefix" {
  description = "OSS bucket 名称前缀(全局唯一约束,建议用你自己的标识,如 cain-bench-<github-id>)"
  type        = string
  default     = "cain-bench"
}

variable "bucket_suffix" {
  description = "随机后缀,避免 bucket 全局命名冲突;用随机串而非敏感信息"
  type        = string
  # 调用方用 -var bucket_suffix=$(date +%s) 之类注入,默认留空由 apply 时指定
  default     = ""
}
