# 云安全渗透测试框架

> 综合云平台渗透测试能力框架 - 支持国际主流云厂商和国内云平台

## 📋 项目概述

本项目整合了多个云渗透测试技能的优点，提供统一的云安全测试方法论，覆盖 AWS、Azure、GCP 以及阿里云、腾讯云、华为云等平台。

---

## 🎯 核心能力映射表

### 按场景选择能力

| 场景 | 使用技能/工具 | 文件位置 |
|------|--------------|---------|
| **云平台侦察** | `skills/cloud-recon.md` | 技能文件 |
| **IAM/RBAC 权限枚举** | `skills/iam-enum.md` | 技能文件 |
| **对象存储渗透** | `skills/storage-pentest.md` | 技能文件 |
| **元数据服务 SSRF** | `skills/metadata-ssrf.md` | 技能文件 |
| **无服务器函数利用** | `skills/serverless-exploit.md` | 技能文件 |
| **权限提升** | `skills/privilege-escalation.md` | 技能文件 |
| **持久化后门** | `skills/persistence.md` | 技能文件 |
| **数据窃取** | `skills/data-exfiltration.md` | 技能文件 |
| **痕迹清除** | `skills/cover-tracks.md` | 技能文件 |

---

## 🔧 能力决策树

```
开始云渗透测试
│
├─ 有凭证吗？
│  ├─ 有 → 进行 [身份识别和权限枚举]
│  └─ 无 → 进行 [云平台侦察]
│
├─ 目标云平台？
│  ├─ AWS → 使用 AWS 专项命令
│  ├─ Azure → 使用 Azure 专项命令
│  ├─ GCP → 使用 GCP 专项命令
│  ├─ 阿里云 → 使用阿里云命令（参考 AWS）
│  ├─ 腾讯云 → 使用腾讯云命令（参考 AWS）
│  └─ 华为云 → 使用华为云命令（参考 Azure）
│
├─ 测试目标？
│  ├─ IAM 权限 → iam:Enum + iam:PrivEsc
│  ├─ 存储桶 → storage:Enum + storage:Exploit
│  ├─ 计算实例 → compute:Enum + metadata:SSRF
│  ├─ 无服务器 → serverless:Enum + serverless:Exploit
│  ├─ 数据库 → database:Enum + database:Exploit
│  └─ 密钥管理 → secrets:Enum + secrets:Exploit
│
└─ 渗透阶段？
   ├─ 侦察 → recon:Passive + recon:Active
   ├─ 枚举 → enum:Assets + enum:Permissions
   ├─ 利用 → exploit:Service + exploit:Chain
   ├─ 横向 → lateral:Cloud + lateral:Hybrid
   ├─ 持久化 → persist:Account + persist:Resource
   └─ 清理 → clean:Logs + clean:Artifacts
```

---

## 📚 快速参考

### 场景 1：获取到云平台凭证

```
用户输入：我拿到了一个 AWS Access Key
↓
能力调用：iam:Enum + aws:GetCallerIdentity
↓
执行流程：
  1. 验证凭证有效性（aws sts get-caller-identity）
  2. 枚举用户权限（enumerate-iam.py）
  3. 列出可访问资源
  4. 查找权限提升路径
```

### 场景 2：发现云存储桶

```
用户输入：发现一个可能的 S3 存储桶
↓
能力调用：storage:Enum + storage:CheckPublic
↓
执行流程：
  1. 检查存储桶是否存在
  2. 测试未授权访问
  3. 枚举存储桶内容
  4. 下载敏感文件
```

### 场景 3：SSRF 漏洞在云环境

```
用户输入：EC2 实例上有 SSRF 漏洞
↓
能力调用：metadata:SSRF + imds:Exploit
↓
执行流程：
  1. 测试 IMDSv1 访问（curl http://169.254.169.254/latest/meta-data/）
  2. 如果失败，尝试 IMDSv2（先获取 Token）
  3. 获取 IAM 安全凭证
  4. 使用获取的凭证进行横向移动
```

### 场景 4：国内云厂商（腾讯云/阿里云）

```
用户输入：需要测试腾讯云
↓
能力调用：tencent:Enum + tencent:Exploit
↓
执行流程：
  1. 使用腾讯云 CLI（tccli）配置凭证
  2. 枚举 CAM 权限（参考 AWS IAM 方法）
  3. 检查 COS 存储桶权限（参考 S3 方法）
  4. 测试 SCF 云函数（参考 Lambda 方法）
  5. 元数据服务 SSRF（参考 AWS IMDS）
```

---

## 🛠️ 工具清单

### 通用工具

| 工具 | 用途 | 安装 |
|------|------|------|
| Scout Suite | 多云安全审计 | `pip install scoutsuite` |
| Pacu | AWS 渗透框架 | `git clone https://github.com/RhinoSecurityLabs/pacu` |
| MicroBurst | Azure 渗透工具包 | `git clone https://github.com/NetSPI/MicroBurst` |

### AWS 专用

| 工具 | 用途 | 安装 |
|------|------|------|
| enumerate-iam | IAM 权限枚举 | `git clone https://github.com/andresriancho/enumerate-iam` |
| Principal Mapper | IAM 关系分析 | `pip install principalmapper` |
| SkyArk | Shadow Admin 发现 | `Import-Module .\SkyArk.ps1` |
| Prowler | AWS 安全审计 | `pip install prowler` |
| aws_consoler | API 转 Console | `git clone https://github.com/NetSPI/aws_consoler` |

### Azure 专用

| 工具 | 用途 | 安装 |
|------|------|------|
| AzureHound | Azure AD 血缘分析 | `git clone https://github.com/BloodHoundAD/AzureHound` |
| ROADtools | Azure AD 操作 | `pip install roadtools` |
| PowerZure | Azure 后渗透 | `git clone https://github.com/hausec/PowerZure` |

### GCP 专用

| 工具 | 用途 | 安装 |
|------|------|------|
| GCP Bucket Brute | GCS 枚举 | `git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute` |
| GCP-IAM-Privilege-Escalation | IAM 权限提升 | `git clone https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation` |

### 国内云厂商

| 云厂商 | CLI 工具 | 配置方式 |
|--------|---------|---------|
| 阿里云 | aliyun-cli | `aliyun configure` |
| 腾讯云 | tccli | `tccli configure` |
| 华为云 | hcloud CLI | `hcloud configure` |

---

## 🌐 云平台服务映射

### 计算服务

| AWS | Azure | GCP | 阿里云 | 腾讯云 |
|-----|-------|-----|--------|--------|
| EC2 | Virtual Machines | Compute Engine | ECS | CVM |
| Lambda | Function Apps | Cloud Functions | 函数计算 | SCF |
| ECS (容器) | AKS | GKE | ACK/ACK Serverless | TKE/Serverless |
| Fargate | Container Instances | Cloud Run | ECI | Serverless |

### 存储服务

| AWS | Azure | GCP | 阿里云 | 腾讯云 |
|-----|-------|-----|--------|--------|
| S3 | Blob Storage | Cloud Storage | OSS | COS |
| EBS | Disk | Persistent Disk | 云盘 | 云硬盘 |
| EFS | Files | Filestore | NAS | 文件存储 |

### IAM 服务

| AWS | Azure | GCP | 阿里云 | 腾讯云 |
|-----|-------|-----|--------|--------|
| IAM | Azure AD | IAM/RBAC | RAM | CAM |
| STS | MS Graph | Service Accounts | STS | STS |
| Cognito | AD B2C | Identity Platform | 无 | 无 |

---

## 🎓 学习路径

1. **初级**：掌握基础 CLI 工具使用
   - AWS CLI / Azure CLI / gcloud
   - 基础资源枚举命令

2. **中级**：理解 IAM/RBAC 模型
   - 权限枚举
   - 权限提升路径
   - 元数据服务利用

3. **高级**：掌握攻击链组合
   - 跨服务权限提升
   - 横向移动
   - 持久化技术

4. **专家**：自定义攻击脚本
   - 自动化渗透流程
   - 特定场景利用
   - 红队演练集成

---

## 📖 技能文件使用说明

每个技能文件包含以下部分：

```markdown
## 触发条件
描述触发此技能的用户输入或场景

## 前置条件
需要的工具、凭证、权限等

## 执行步骤
详细的操作步骤和命令

## 验证方法
如何验证利用是否成功

## 清理步骤
如何清理测试痕迹

## 参考链接
相关文档和资源
```

---


