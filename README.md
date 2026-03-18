# 云安全渗透测试框架

> 综合云平台渗透测试能力框架 - 支持国际主流云厂商和国内云平台

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-AWS%20%7C%20Azure%20%7C%20GCP%20%7C%20Aliyun%20%7C%20Tencent-blue)](https://github.com/your-repo)

## 📖 项目简介

本项目整合了多个云渗透测试技能的优点，提供统一的云安全测试方法论。覆盖以下云平台：

- ✅ AWS (Amazon Web Services)
- ✅ Azure (Microsoft)
- ✅ GCP (Google Cloud Platform)
- ✅ 阿里云 (Aliyun)
- ✅ 腾讯云 (Tencent Cloud)
- ✅ 华为云 (Huawei Cloud)

## 🚀 快速开始

### 安装工具

```bash
# 克隆项目
git clone https://github.com/your-repo/cloud-pentest-framework.git
cd cloud-pentest-framework

# 运行安装脚本 (交互式)
bash tools/install-tools.sh

# 或安装所有工具
bash tools/install-tools.sh --all
```

### 配置凭证

```bash
# AWS
aws configure --profile target

# Azure
az login

# GCP
gcloud auth login

# 阿里云
aliyun configure

# 腾讯云
tccli configure
```

## 📚 文档结构

```
cloud-pentest-framework/
├── CLAUDE.md                          # 主指导文档
├── README.md                          # 项目说明
├── skills/                            # 渗透测试技能
│   └── cloud-pentest-comprehensive.md # 综合渗透测试技能
├── docs/                              # 详细文档
│   └── cloud-services-mapping.md      # 云服务映射表
├── templates/                         # 模板文件
│   └── pentest-report-template.md     # 报告模板
└── tools/                             # 工具和脚本
    └── install-tools.sh               # 工具安装脚本
```

## 🎯 核心功能

### 1. 云平台侦察
- 被动信息收集
- 主动资源枚举
- 公开存储桶发现

### 2. IAM/RBAC 权限测试
- 权限枚举
- 权限提升路径分析
- Shadow Admin 发现

### 3. 存储安全测试
- S3/OSS/Blob/GCS 枚举
- 公共访问检查
- 敏感数据发现

### 4. 元数据服务利用
- SSRF 到元数据端点
- 临时凭证提取
- 角色权限提升

### 5. 无服务器函数测试
- Lambda/Function/Cloud Functions 枚举
- 代码注入
- 环境变量密钥提取

### 6. 数据窃取
- 存储数据下载
- 数据库快照利用
- 密钥管理服务利用

## 📊 云平台服务映射

项目提供了详细的云服务映射表，帮助在不同云平台间迁移渗透测试方法：

| AWS | Azure | GCP | 阿里云 | 腾讯云 |
|-----|-------|-----|--------|--------|
| EC2 | VM | Compute Engine | ECS | CVM |
| S3 | Blob | Cloud Storage | OSS | COS |
| Lambda | Function | Cloud Functions | 函数计算 | SCF |

详细映射请查看: [docs/cloud-services-mapping.md](docs/cloud-services-mapping.md)

## 🛠️ 支持的工具

### 通用工具
- **Scout Suite** - 多云安全审计
- **Pacu** - AWS 渗透框架
- **Prowler** - AWS 安全审计

### AWS 专用
- **enumerate-iam** - IAM 权限枚举
- **SkyArk** - Shadow Admin 发现
- **Principal Mapper** - IAM 分析

### Azure 专用
- **MicroBurst** - PowerShell 工具包
- **AzureHound** - Azure AD 血缘分析
- **ROADtools** - Azure AD 操作

### GCP 专用
- **GCPBucketBrute** - GCS 枚举
- **GCP-IAM-Privilege-Escalation** - IAM 权限提升

## 📖 使用指南

### 场景 1: AWS S3 存储桶测试

```bash
# 列出所有存储桶
aws s3 ls

# 检查存储桶权限
aws s3api get-bucket-acl --bucket bucket-name

# 下载存储桶内容
aws s3 sync s3://bucket-name ./local-folder
```

### 场景 2: Azure 元数据 SSRF

```bash
# 获取实例元数据
curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# 获取访问令牌
curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### 场景 3: 阿里云 OSS 测试

```bash
# 列出存储桶
aliyun oss ls

# 检查权限
aliyun oss get-bucket-acl bucket-name

# 下载文件
aliyun oss cp oss://bucket-name/object ./local
```

### 场景 4: 腾讯云 COS 测试

```bash
# 列出存储桶
tccli cos GetService

# 获取对象
tccli cos GetObject --Bucket bucket-name --Key object-name

# 检查权限
tccli cos GetBucketAcl --Bucket bucket-name
```

## ⚠️ 使用限制

### 法律要求
- ✅ 必须获得书面授权
- ✅ 必须定义测试范围
- ✅ 必须遵守法律法规

### 技术限制
- ⚠️ MFA 可能阻止凭证攻击
- ⚠️ 条件访问可能限制登录
- ⚠️ 所有 API 调用都会被记录
- ⚠️ 异常访问模式会触发告警

## 📚 学习路径

### 初级
1. 学习基础 CLI 工具使用
2. 理解云服务基本概念
3. 掌握资源枚举方法

### 中级
1. 理解 IAM/RBAC 权限模型
2. 掌握权限提升技术
3. 学习元数据服务利用

### 高级
1. 掌握攻击链组合
2. 学习横向移动技术
3. 掌握持久化方法

### 专家
1. 开发自动化攻击脚本
2. 红队演练集成
3. 自定义攻击工具

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License

## 🙏 致谢

- Rhino Security Labs - Pacu 框架
- NCC Group - Scout Suite
- NetSPI - MicroBurst
- 以及所有开源工具的贡献者

## 📞 联系方式

- 项目主页: https://github.com/your-repo/cloud-pentest-framework
- 问题反馈: https://github.com/your-repo/cloud-pentest-framework/issues

---

**免责声明**: 本项目仅供教育和授权安全测试使用。使用本项目工具和技术进行未经授权的测试是非法的。使用者应遵守所有适用法律法规。
