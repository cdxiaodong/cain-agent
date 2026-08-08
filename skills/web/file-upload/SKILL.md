# 文件上传漏洞检测技能

## 原理

文件上传漏洞发生在 Web 应用未对上传文件进行充分校验时，攻击者可上传恶意文件（如 Webshell）并执行。

**常见成因**：
- 未校验文件类型（Content-Type 伪造）
- 未校验文件扩展名（双写绕过：shell.phtml）
- 未校验文件内容（图片马：GIF89a<?php phpinfo();?>）
- 上传路径可预测（/uploads/shell.php）

## 检测方法

### 1. 定位上传点
- 头像上传
- 附件上传
- 文件导入功能
- 富文本编辑器

### 2. 测试文件类型校验

**Payload 1 — 双写后缀**:
```bash
curl -X POST http://target/upload -F "file=@shell.phtml"
```

**Payload 2 — MIME 伪造**:
```bash
curl -X POST http://target/upload -F "file=@shell.php;type=image/jpeg"
```

**Payload 3 — 图片马**:
```bash
# 创建 GIF89a 图片马
echo 'GIF89a<?php phpinfo();?>' > test.gif
curl -X POST http://target/upload -F "file=@test.gif"
```

### 3. 验证执行

上传成功后，访问文件 URL 验证是否执行：
```bash
curl http://target/uploads/shell.phtml
curl http://target/uploads/test.gif
```

**判断依据**：
- 返回 PHP 信息 → 文件被执行 → **存在漏洞**
- 返回文件内容 → 未执行 → 安全
- 404 → 文件未上传成功

## 工具

| 工具 | 用途 |
|---|---|
| curl | 命令行测试上传 |
| Burp Suite | 抓包修改 Content-Type/文件名 |
| ExifTool | 制作图片马 |

## 输出格式

```json
{
  "finding_id": "file-upload-001",
  "issue_type": "file-upload",
  "severity": "high",
  "endpoint": "/api/upload",
  "payload": "shell.phtml (双写后缀)",
  "evidence": "访问 /uploads/shell.phtml 返回 phpinfo()",
  "remediation": "白名单校验扩展名+MIME+文件内容，上传目录禁止执行权限"
}
```

## 注意事项

- **只读原则**：仅检测，不利用（不上传真实 Webshell）
- **无害 Payload**：使用 `phpinfo()` 验证，不执行危险操作
- **零触网**：测试用 mock 或本地环境
