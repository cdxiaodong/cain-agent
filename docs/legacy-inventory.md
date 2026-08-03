# 旧资产归档清单 · cain-agent

> 盘点对象:`skills/`、`exploits/`、`tools/`、`templates/`、`docs/legacy/`。
> 目的:为 ROADMAP「旧仓库内容归档整理」提供落地依据，**不删除任何文件**。
> 判定口径:【保留为知识库】= 有长期参考价值，原样留用；【待重构】= 需在新架构下改造后复用；【建议归档】= 已被取代，仅作历史保留。
> 盘点时间:2026-08-03。

## 1. 总览统计

| 目录 | 文件数 | 说明 |
|---|---:|---|
| `skills/` | 66 | 旧框架遗留的云/基础设施攻击技能文档(全为 `.md`) |
| `exploits/` | 1 | 单篇 AWS IAM 提权利用文档 |
| `tools/` | 1 | 旧框架交互式工具安装脚本 |
| `templates/` | 1 | 渗透测试报告模板 |
| `docs/legacy/` | 2 | 旧框架 README 与 Claude 指令，已被新文档取代 |

> 注:`docs/cloud-services-mapping.md` 位于 `docs/` 根目录，属现行文档而非旧资产，不在本次盘点范围内。

## 2. 逐目录判定

| 目录 | 判定 | 一句理由 |
|---|---|---|
| `skills/`(66 个) | 【保留为知识库】 | ROADMAP 已明确「云技能保留为知识库资产」；是项目云渗透差异化的内容护城河，原样保留供 Skill 加载器引用 |
| `exploits/aws-iam-privilege-escalation.md` | 【待重构】 | 与 `skills/aws-iam-privesc.md`、`skills/aws-iam-attack.md` 内容重叠；Phase 2 校验闭环时统一为「可复现 PoC + 证据链」标准格式 |
| `tools/install-tools.sh` | 【待重构】 | 旧框架依赖手动安装；Phase 1 「Docker 一键运行」落地后，重构为容器构建脚本，宿主不再裸跑安装 |
| `templates/pentest-report-template.md` | 【保留为知识库】 | 报告阶段(Phase 1)直接复用，结构化证据 + 修复建议与交付物设计一致 |
| `docs/legacy/CLAUDE-legacy.md` | 【建议归档】 | 旧框架 Claude 指令，已被 `.claude`/`.codex` 配置取代；已位于 `docs/legacy/`，保留作历史 |
| `docs/legacy/README-cloud-framework-legacy.md` | 【建议归档】 | 旧框架 README，已被新 `README.md` 取代；保留作历史，避免改动以保留 rename 前的叙事 |

## 3. `skills/` 分组清单(66 项，全部【保留为知识库】)

### 3.1 国产云(3)

`aliyun-attack.md` · `huawei-attack.md` · `tencent-attack.md`

> 国产云覆盖是全网独家的差异化卖点，优先级最高。

### 3.2 AWS(25)

`aws-api-gateway-attack` · `aws-apprunner-attack` · `aws-cloudformation-attack` · `aws-cloudwatch-attack` · `aws-cognito-attack` · `aws-ec2-attack` · `aws-ecs-attack` · `aws-eks-attack` · `aws-enum` · `aws-fargate-attack` · `aws-iam-attack` · `aws-iam-privesc` · `aws-lambda-attack` · `aws-lambda-persistence` · `aws-lambda-privesc` · `aws-metadata-attack` · `aws-metadata-ssrf` · `aws-persistence` · `aws-rds-attack` · `aws-s3-attack` · `aws-s3-pentesting` · `aws-secrets-attack` · `aws-sns-attack` · `aws-sqs-attack` · `aws-waf-attack`

(以上文件名均省略 `.md` 后缀)

### 3.3 Azure(4)

`azure-attack` · `azure-devops-attack` · `azure-functions-attack` · `azure-keyvault-attack`

### 3.4 GCP(7)

`gcp-attack` · `gcp-bigquery-attack` · `gcp-cloudfunctions-attack` · `gcp-compute-engine-attack` · `gcp-iam-privesc` · `gcp-pubsub-attack` · `gcp-storage-attack`

### 3.5 DevOps / CI / SCM / 制品库(10)

`bitbucket-attack` · `circleci-attack` · `concourse-attack` · `github-actions-attack` · `github-attack` · `gitlab-attack` · `harbor-attack` · `jenkins-attack` · `jira-attack` · `sonarqube-attack`

### 3.6 数据库 / 消息队列(8)

`cassandra-attack` · `elasticsearch-attack` · `kafka-attack` · `mongodb-attack` · `postgresql-attack` · `rabbitmq-attack` · `redis-attack` · `sqlserver-attack`

### 3.7 基础设施 / 容器 / 服务网格 / 密钥 / IaC(8)

`cdn-attack` · `cloudflare-attack` · `consul-attack` · `docker-attack` · `kubernetes-attack` · `servicemesh-attack` · `terraform-attack` · `vault-attack`

### 3.8 综合方法(1)

`cloud-pentest-comprehensive.md`

## 4. 发现与建议

1. **技能计数出入**:`CHANGELOG.md` / `ROADMAP.md` / 任务派活均记为「65 个云技能」，但 `skills/` 实际为 **66 个** `.md`(已逐组复核:国产云 3 + AWS 25 + Azure 4 + GCP 7 + DevOps/CI 10 + 数据库/MQ 8 + 基础设施 8 + 综合 1 = 66)。建议统一文档口径为 66，或在 README 引用时改为「60+ 云攻击技能」避免硬编码数字。
2. **`docs/legacy/CLAUDE-legacy.md` 存在 9 处失效引用**:其能力映射表引用的 `skills/cloud-recon.md`、`iam-enum.md`、`storage-pentest.md`、`metadata-ssrf.md`、`serverless-exploit.md`、`privilege-escalation.md`、`persistence.md`、`data-exfiltration.md`、`cover-tracks.md` **在仓库中均不存在**。因该文件已归档、不对外暴露，判定为「已知历史问题」，建议在 `docs/legacy/` 增加 `README.md` 标注「仅供历史参考，链接已失效」以免误导。
3. **`exploits/` 与 `skills/` 内容重叠**:`exploits/aws-iam-privilege-escalation.md` 与 `skills/aws-iam-privesc.md` 同主题。Phase 2 引入校验 Agent 后，统一收敛为单一 PoC 来源，删除冗余副本或改为互相引用。
4. **`tools/install-tools.sh` 安全提示**:该脚本安装大量外部安全工具，属旧框架裸机安装路径；Docker 化后应移入容器构建，宿主不应直接执行，README 中需明确「请在授权环境的容器内运行」。

## 5. 处置结论

- **保留**:全部 `skills/`(66)、`templates/pentest-report-template.md`、`docs/legacy/`(原样)。
- **待重构**:`exploits/aws-iam-privilege-escalation.md`(去重 + 标准化)、`tools/install-tools.sh`(容器化)。
- **本次不删除任何文件**;`docs/legacy/` 增补说明性 README 由后续 docs 任务跟进，不在本分支范围。
