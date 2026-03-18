# 云平台服务映射表

本文档提供各云平台服务的对应关系，帮助在不同云平台间迁移渗透测试方法。

## 📊 服务分类映射

### 计算服务

| AWS | Azure | GCP | 阿里云 | 腾讯云 | 华为云 |
|-----|-------|-----|--------|--------|--------|
| EC2 | Virtual Machines | Compute Engine | ECS | CVM | ECS |
| Lambda | Function Apps | Cloud Functions | 函数计算 | SCF | FunctionGraph |
| ECS (容器) | AKS | GKE | ACK/ACK Serverless | TKE/Serverless | CCE |
| Fargate | Container Instances | Cloud Run | ECI | Serverless | Serverless容器 |
| Batch | Batch | Batch | 批计算 | 批量计算 | Batch |

### 存储服务

| AWS | Azure | GCP | 阿里云 | 腾讯云 | 华为云 |
|-----|-------|-----|--------|--------|--------|
| S3 | Blob Storage | Cloud Storage | OSS | COS | OBS |
| EBS | Disk | Persistent Disk | 云盘 | 云硬盘 | 云硬盘 |
| EFS | Files | Filestore | NAS | 文件存储 | SFS |
| Glacier | Archive | Cold Storage | 归档存储 | 归档存储 | 归档存储 |

### 数据库服务

| AWS | Azure | GCP | 阿里云 | 腾讯云 | 华为云 |
|-----|-------|-----|--------|--------|--------|
| RDS | SQL Database | Cloud SQL | RDS | TencentDB | RDS |
| DynamoDB | Cosmos DB | Firestore | TableStore | 表格存储 | GaussDB |
| Neptune | Cosmos DB (Graph) | Bigtable | Lindorm | TcaplusDB | GeminiDB |
| ElastiCache | Redis Cache | Memorystore | Redis | Redis | DCS |

### IAM/认证服务

| AWS | Azure | GCP | 阿里云 | 腾讯云 | 华为云 |
|-----|-------|-----|--------|--------|--------|
| IAM | Azure AD | IAM | RAM | CAM | IAM |
| STS | MS Graph | Service Accounts | STS | STS | STS |
| Cognito | AD B2C | Identity Platform | 无 | 无 | 无 |
| Secrets Manager | Key Vault | Secret Manager | KMS | KMS | KMS |

### 网络服务

| AWS | Azure | GCP | 阿里云 | 腾讯云 | 华为云 |
|-----|-------|-----|--------|--------|--------|
| VPC | VNet | VPC | VPC | VPC | VPC |
| Route 53 | DNS | Cloud DNS | DNS | DNS | DNS |
| CloudFront | CDN | Cloud CDN | CDN | CDN | CDN |
| ELB/ALB/NLB | Load Balancer | Cloud Load Balancing | SLB | CLB/NLB | ELB |

### 无服务器/事件驱动

| AWS | Azure | GCP | 阿里云 | 腾讯云 | 华为云 |
|-----|-------|-----|--------|--------|--------|
| Lambda | Function Apps | Cloud Functions | 函数计算 | SCF | FunctionGraph |
| API Gateway | API Management | API Gateway | API 网关 | API 网关 | APIG |
| EventBridge | Event Grid | Eventarc | 事件总线 | EB | EG |
| SQS | Service Bus | Pub/Sub | 消息队列 | 消息队列 | DMS |

### 安全服务

| AWS | Azure | GCP | 阿里云 | 腾讯云 | 华为云 |
|-----|-------|-----|--------|--------|--------|
| GuardDuty | Defender | Security Command Center | 云安全中心 | 大禹安全 | 安全云脑 |
| Security Hub | Azure Security Center | Event Threat Detection | 态势感知 | 态势感知 | 态势感知 |
| WAF | WAF | Cloud Armor | WAF | WAF | WAF |
| Shield | DDoS Protection | Cloud Armor | DDoS防护 | 大禹 | AAD |

### 监控和日志

| AWS | Azure | GCP | 阿里云 | 腾讯云 | 华为云 |
|-----|-------|-----|--------|--------|--------|
| CloudTrail | Activity Logs | Cloud Audit Logs | ActionTrail | 云审计 | CTS |
| CloudWatch | Monitor | Cloud Monitoring | CloudMonitor | 云监控 | CloudEye |
| S3 Access Logs | Storage Analytics | GCS Access Logs | 访问日志 | 访问日志 | 日志 |

## 🔑 元数据服务端点

| 云平台 | 元数据服务 IP | 端点路径 |
|--------|--------------|---------|
| AWS (IMDSv1) | 169.254.169.254 | `http://169.254.169.254/latest/meta-data/` |
| AWS (IMDSv2) | 169.254.169.254 | `http://169.254.169.254/latest/api/token` (先获取 Token) |
| Azure | 169.254.169.254 | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| GCP | metadata.google.internal | `http://metadata.google.internal/computeMetadata/v1/` |
| 阿里云 | 100.100.100.200 | `http://100.100.100.200/latest/meta-data/` |
| 腾讯云 | metadata.tencentyun.com | `http://metadata.tencentyun.com/latest/meta-data/` |
| 华为云 | 169.254.169.254 | `http://169.254.169.254/openstack/latest/meta_data.json` |

## 📁 存储服务 URL 格式

| 云平台 | 公共访问 URL 格式 |
|--------|------------------|
| AWS S3 | `https://{bucket}.s3.amazonaws.com/` 或 `https://s3.amazonaws.com/{bucket}/` |
| Azure Blob | `https://{account}.blob.core.windows.net/{container}/{blob}` |
| GCP GCS | `https://storage.googleapis.com/{bucket}/{object}` |
| 阿里云 OSS | `https://{bucket}.oss-{region}.aliyuncs.com/{object}` |
| 腾讯云 COS | `https://{bucket}.cos.{region}.myqcloud.com/{object}` |
| 华为云 OBS | `https://{bucket}.obs.{region}.myhuaweicloud.com/{object}` |

## 🔐 IAM 权限提升路径对照

### 创建访问密钥

| 云平台 | 权限 | 命令 |
|--------|------|------|
| AWS | `iam:CreateAccessKey` | `aws iam create-access-key --user-name target` |
| Azure | `microsoft.graph/directory/Write` | `az ad app create --id {id}` |
| GCP | `iam.serviceAccounts.keys.create` | `gcloud iam service-accounts keys create` |
| 阿里云 | `ram:CreateAccessKey` | `aliyun ram CreateAccessKey` |
| 腾讯云 | `cam:CreateAccessKey` | `tccli cam CreateAccessKey` |

### 附加策略

| 云平台 | 权限 | 命令 |
|--------|------|------|
| AWS | `iam:AttachUserPolicy` | `aws iam attach-user-policy` |
| Azure | `roleAssignments/write` | `az role assignment create` |
| GCP | `resourcemanager.projects.setIamPolicy` | `gcloud projects set-iam-policy` |
| 阿里云 | `ram:AttachPolicyToUser` | `aliyun ram AttachPolicyToUser` |
| 腾讯云 | `cam:AttachUserPolicy` | `tccli cam AttachUserPolicy` |

## 🌐 区域代码对照

### AWS 区域

| 代码 | 位置 |
|------|------|
| us-east-1 | 美国东部 (弗吉尼亚北部) |
| us-west-2 | 美国西部 (俄勒冈) |
| eu-west-1 | 欧洲 (爱尔兰) |
| ap-southeast-1 | 亚太地区 (新加坡) |
| ap-northeast-1 | 亚太地区 (东京) |

### 阿里云区域

| 代码 | 位置 |
|------|------|
| cn-hangzhou | 华东1 (杭州) |
| cn-shanghai | 华东2 (上海) |
| cn-qingdao | 华北1 (青岛) |
| cn-beijing | 华北2 (北京) |
| cn-shenzhen | 华南1 (深圳) |

### 腾讯云区域

| 代码 | 位置 |
|------|------|
| ap-guangzhou | 华南地区 (广州) |
| ap-shanghai | 华东地区 (上海) |
| ap-beijing | 华北地区 (北京) |
| ap-chengdu | 西南地区 (成都) |
| ap-hongkong | 中国香港 |

## 📊 渗透测试方法迁移

### S3 存储桶 → 其他云存储

| 方法 | AWS S3 | Azure Blob | GCP GCS | 阿里云 OSS | 腾讯云 COS |
|------|--------|-----------|---------|-----------|-----------|
| 列出存储 | `aws s3 ls` | `az storage account list` | `gsutil ls` | `aliyun oss ls` | `tccli cos GetService` |
| 枚举内容 | `aws s3 ls s3://bucket/` | `az storage blob list` | `gsutil ls gs://bucket/` | `aliyun oss ls oss://bucket/` | `tccli cos GetObject` |
| 检查权限 | `aws s3api get-bucket-acl` | `az storage container show` | `gsutil iam get` | `aliyun oss get-bucket-acl` | `tccli cos GetBucketAcl` |
| 下载数据 | `aws s3 sync` | `az storage blob download` | `gsutil cp` | `aliyun oss cp` | `tccli cos GetObject` |

### Lambda → 其他无服务器

| 方法 | AWS Lambda | Azure Function | GCP Cloud Functions | 阿里云函数计算 | 腾讯云 SCF |
|------|-----------|---------------|-------------------|---------------|-----------|
| 列出函数 | `aws lambda list-functions` | `az functionapp list` | `gcloud functions list` | `aliyun fc ListFunctions` | `tccli scf ListFunctions` |
| 获取代码 | `aws lambda get-function` | `az functionapp show` | `gcloud functions describe` | `aliyun fc GetFunctionCode` | `tccli scf GetFunction` |
| 更新代码 | `aws lambda update-function-code` | `az functionapp deploy` | `gcloud functions deploy` | `aliyun fc UpdateFunctionCode` | `tccli scf UpdateFunctionCode` |
| 注入代码 | Zip + update-function-code | Git + deploy | Source deploy | Code + zip | Code + zip |

## 🎯 快速参考命令对照表

### 身份验证

| 操作 | AWS | Azure | GCP | 阿里云 | 腾讯云 |
|------|-----|-------|-----|--------|--------|
| 配置 | `aws configure` | `az login` | `gcloud auth login` | `aliyun configure` | `tccli configure` |
| 验证 | `aws sts get-caller-identity` | `az account show` | `gcloud config list` | `aliyun sts GetCallerIdentity` | `tccli cam GetUserInfo` |
| 列出用户 | `aws iam list-users` | `az ad user list` | `gcloud iam service-accounts list` | `aliyun ram ListUsers` | `tccli cam ListUsers` |

### 存储操作

| 操作 | AWS | Azure | GCP | 阿里云 | 腾讯云 |
|------|-----|-------|-----|--------|--------|
| 列出 | `aws s3 ls` | `az storage account list` | `gsutil ls` | `aliyun oss ls` | `tccli cos GetService` |
| 同步 | `aws s3 sync` | `az storage blob sync` | `gsutil -m cp` | `aliyun oss cp -r` | `tccli cos GetObject` (循环) |
| 权限 | `aws s3api get-bucket-acl` | `az storage container show` | `gsutil iam get` | `aliyun oss get-bucket-acl` | `tccli cos GetBucketAcl` |

---

## 💡 使用建议

1. **服务迁移**: 当你知道 AWS 某服务的渗透方法时，参考此表找到其他云平台的对应服务
2. **API 端点**: 元数据服务端点不同，但利用方法类似
3. **权限模型**: 虽然 API 不同，但权限提升的思路是相通的
4. **工具适配**: 很多工具只支持 AWS，但可以参考其思路开发其他云平台的工具
