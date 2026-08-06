# Codex-B 交付汇报 · 2026-08-06(Day 4 · 任务 3)

> 任务:阿里云 vulnerable-terraform 自建靶场 · 场景一(OSS 公开桶)
> 状态:**完成,三绿通过,未执行任何 terraform init/apply,待 21:00 验收**

## 分支

`test/2026-08-06-vuln-terraform`(从 main@dc5958f 切出,**未碰 main**)

## 改动文件清单(4 个新文件 + 1 追加,3 提交,均署名 cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>)

| 提交 | 文件 | 说明 |
|---|---|---|
| `958da03` test(bench) | `bench/aliyun-vuln-tf/main.tf` | 阿里云 provider + public-read 靶标桶 + private 对照桶,头部 8 行红字声明,Purpose 标签 |
| `958da03` test(bench) | `bench/aliyun-vuln-tf/variables.tf` | region(默认 cn-hangzhou)/ bucket_prefix / bucket_suffix |
| `958da03` test(bench) | `bench/aliyun-vuln-tf/outputs.tf` | 两桶名输出 + expected_detection 预期对照(public-read→high / private→info) |
| `958da03` test(bench) | `bench/aliyun-vuln-tf/README.md` | apply/verify/destroy 三步用法、费用与清理警告、凭证走环境变量 |
| `958da03` test(bench) | `tests/test_vuln_tf.py` | 12 项静态校验:HCL 块/靶标语义/Purpose 标签/红字头/LTAI 扫描/三步用法;terraform 不可用则 skip fmt |
| `25d5c0a` docs(bench) | `docs/benchmark-plan.md` | 追加「自建云靶场(国产云差异化)」一节(仅追加,不改已有内容) |

## 自测结果(三绿)

- `ruff check src tests` → All checks passed
- `pyright`(指定 venv 解释器跑全仓库)→ **0 errors, 0 warnings, 0 informations**
- `pytest`(全量)→ **182 passed, 1 skipped**(本次新增 11 passed + 1 skipped,skipped 是 terraform fmt 因本机无 terraform 跳过,符合预期)
- **未执行任何 terraform init/apply**(派活单红线严格遵守)

## 验收对照(派活单逐项)

| 要求 | 落实 |
|---|---|
| 阿里云 provider + OSS 桶,acl=public-read(靶标)+ private(对照) | main.tf 两个 alicloud_oss_bucket resource,测试 `test_vuln_bucket_acl_is_public_read` / `test_control_bucket_acl_is_private` 钉死 |
| bucket 名带随机后缀变量 | variables.tf `bucket_suffix`,main.tf 用 `${var.bucket_prefix}-...-${var.bucket_suffix}` |
| 所有资源打 Purpose = "vuln-benchmark" 标签 | 两桶各带标签块,测试 `test_buckets_have_purpose_tag` 校验标签数 ≥ resource 数 |
| 文件头部红字声明:仅授权测试、apply 后当天 destroy | main.tf 前 8 行声明,测试 `test_main_tf_has_redline_header` 钉死 |
| region(默认 cn-hangzhou)/ bucket 前缀 | variables.tf 含,默认值正确,测试 `test_variables_tf_has_region_and_bucket_prefix` |
| outputs.tf 含两桶名 + 预期检出结果(public→high, private→info) | outputs.tf `expected_detection` 块,测试 `test_outputs_tf_has_expected_detection_outputs` |
| README:apply/verify/destroy 三步、费用与清理警告、凭证环境变量 | README 完整覆盖,测试 `test_readme_has_three_step_usage` 钉死 |
| 静态校验:HCL 块/public-read/Purpose/LTAI 扫描 | 11 项 passed;LTAI 用 `LTAI[A-Za-z0-9]{12,}` 正则识别疑似真实 AK(教学注释提及"LTAI 前缀"不算泄漏,符合工程实际) |
| terraform fmt -check 可用则跑,否则 skip | `@pytest.mark.skipif` 本机无 terraform → skipped,CI 不红 |
| 严禁 terraform init/apply | 全程未执行;只写配置 + 静态检查 |
| benchmark-plan.md 仅追加一节,不改已有内容 | diff 显示 docs/benchmark-plan.md 仅 +30 行追加,原有四节(设计原则/第一层/第二层/评测节奏)完整 |
| 不加更多场景、不动 docker-compose.yml、不动 src/ | 改动仅 bench/aliyun-vuln-tf/ + tests/test_vuln_tf.py + docs/benchmark-plan.md;src/ 与 bench/docker-compose.yml 零改动 |

## 测试设计说明

- **LTAI 扫描口径**:用正则 `LTAI[A-Za-z0-9]{12,}`(真实 AK 通常 24-30 位)识别疑似真实泄漏,而非裸 "LTAI" 字符串——这样教学注释提及"AK 前缀为 LTAI"是允许的(便于读者理解),只有"像真 AK 的长串"才触发。这是实际工程的做法,避免误伤教学文本又仍能抓真实泄漏。
- **靶标语义钉死**:测试以 resource 块切片,确保 `public-read` 绑在靶标桶、`private` 绑在对照桶,防止文件结构改坏后语义错位。
- **terraform fmt 跳过**:本机 terraform 不可用,用 `pytest.skip` 处理,Lead 在有 terraform 的机器上验收时会自动实跑。

## 并发隔离

全程独立 git worktree(`cain-agent-wt-tf`)完成,提交后即移除。主工作区当前在 Lead/Codex-A 分支,我未触碰其任何文件。
