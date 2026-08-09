# 敏感信息泄露漏洞检测技能

## 原理

敏感信息泄露发生在 Web 应用在响应、错误页面、注释、配置文件中暴露了不应公开的信息，攻击者可利用这些信息进行进一步攻击。

**常见泄露点**：
- 错误堆栈（stack trace 暴露路径/框架版本/SQL 语句）
- 备份文件（`.bak` `.swp` `.old` `~`）
- 版本控制目录（`.git/` `.svn/`）
- 配置文件（`.env` `config.php` `web.config`）
- 注释中的硬编码凭证 / 内网 IP / 测试账号
- HTTP 响应头（`Server` `X-Powered-By` 暴露版本）

## 检测方法

### 1. 错误页面触发
```bash
# 触发 500 错误，观察是否泄露堆栈
curl "http://target/api/user?id=abc'"        # 非预期输入
curl "http://target/api/user?id[]=1"          # 类型混淆
```

### 2. 备份/敏感文件探测
```bash
curl "http://target/.git/config"              # Git 泄露
curl "http://target/.env"                     # 环境变量
curl "http://target/config.php.bak"           # 备份文件
curl "http://target/index.php~"               # 编辑器临时文件
```

### 3. 响应头分析
```bash
curl -I "http://target/" | grep -iE "server|x-powered-by|x-aspnet"
```

**判断依据**：
- 响应含 `root:` / `DB_PASSWORD` / `BEGIN RSA` → 严重泄露
- `.git/config` 返回 200 且含 `[core]` → 源码可下载
- 错误页含绝对路径 `/var/www/...` → 信息泄露

## 工具

| 工具 | 用途 |
|---|---|
| curl | 手工探测敏感路径 |
| dirsearch / ffuf | 批量目录扫描 |
| git-dumper | .git 泄露利用（仅授权） |

## 输出格式

```json
{
  "finding_id": "info-disclosure-001",
  "issue_type": "info-disclosure",
  "severity": "medium",
  "endpoint": "/.env",
  "evidence": "返回 200，含 DB_PASSWORD=***",
  "remediation": "禁止 Web 访问敏感文件，关闭详细错误，移除响应头版本信息"
}
```

## 注意事项

- **只读原则**：仅探测是否可访问，不下载/利用泄露内容
- **零触网**：测试用 mock 或本地环境
