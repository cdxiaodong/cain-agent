# done-vuln-tf-bench · vuln-tf 三场景离线静态跑分

## 交付状态

- 分支：`test/2026-08-29-vuln-tf-bench`
- 原始实现：`5903cc4`（已合入 `main`）
- 场景：OSS 公开桶、RAM 过度授权、RAM 管理员
- 结果：3 场景，检出 8，误报 0，漏报 0，平均 token 0
- 报告：`docs/release/bench-vulntf-2026-08-31.md`
- ROADMAP：Phase 2 靶场与首轮 benchmark 已勾选

## 重派复核

- 分支已快进至最新 `origin/main`。
- 修复 `bench/run_benchmark.py` 直接作为脚本执行时的模块导入错误。
- 增加 CLI subprocess 回归测试，覆盖文档中的实际调用方式。
- 专项测试：`45 passed, 2 skipped`
- 全量测试：`1080 passed, 3 skipped`
- 静态检查：`ruff` 通过
- CLI 实跑：3 场景，Recall 100%，Precision 100%，F1 1.000，token 0

## 安全边界

本轮仅解析仓库内 Terraform 文本；未执行 `terraform apply`，未访问网络，
未使用或写入任何真实凭证。
