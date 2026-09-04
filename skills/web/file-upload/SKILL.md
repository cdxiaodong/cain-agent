---
name: file-upload
description: 文件上传检测技能 —— 面向真实授权系统，验证类型、内容与存储边界并产出无害可复现证据
phase: test
severity_focus: high
---

# 文件上传漏洞检测技能

## 触发条件

仅在授权应用提供上传、导入、头像或附件功能时启用本技能。

## 原理

文件上传漏洞发生在 Web 应用未对上传文件进行充分校验时，攻击者可上传恶意文件（如 Webshell）并执行。

**常见成因**：
- 未校验文件类型（Content-Type 伪造）
- 未校验文件扩展名（双写绕过：shell.phtml）
- 未校验文件内容（图片马：GIF89a<?php phpinfo();?>）
- 上传路径可预测（/uploads/shell.php）

## 三层测试模型

> 对齐 DESIGN §3.1：L1 探测 → L2 验证 → L3 绕过，每层只做上一层成立后才推进的事。

### L1 探测

目标：判定「上传功能对文件类型/内容的校验边界」，不上传任何具备执行能力的文件。

- 类型信号采集：上传一个合法格式文件，记录服务端接受依据（Content-Type 头？扩展名？文件头 magic bytes？三者是否一致校验）。
- 无害异常扩展名：上传扩展名被伪装为合法类型但内容为纯文本的文件（如 `.jpg` 内容实为文本），观察是否仅检查扩展名/Content-Type 而不校验实际内容。

> L1 产出「校验维度假设(扩展名/Content-Type/内容)」，写入 `hypothesis`，不直接下结论。

### L2 验证

目标：用无害图片马把 L1 假设变成可复现证据，禁止真实上传 Webshell。

- 图片马构造：制作合法图片文件并在元数据/尾部追加无害标记（如 `GIF89a<?php echo "CAIN_PROBE";?>`），上传后仅验证「服务端是否原样保存该内容」，不请求执行。
- 存储路径确认：确认上传后文件的可达 URL 与存储目录，判断是否位于 Web 可执行路径下（如 `/uploads/` 是否被 Web 容器解析为可执行）。
- 覆盖/路径可控性：测试文件名是否可控（是否可用 `../` 或绝对路径改变存储位置），仅验证响应中路径回显，不实际触发路径穿越写入。

### L3 绕过

目标：当类型校验被加强时，验证是否仍可绕过。

- 双扩展名：`shell.php.jpg`、`shell.jpg.php`（依赖服务端对末尾/首个扩展名解析差异）。
- 大小写/空字节：`shell.PHP`、`shell.php%00.jpg`（旧版本语言常见截断问题）。
- Content-Type 伪造：修改 multipart 部分的 `Content-Type` 为 `image/jpeg` 而文件名/内容不变。
- 仍仅使用无害标记验证「文件是否被接受与如何解析」，不上传或触发任何具备代码执行能力的内容。

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

## 证据要求

什么才算确认文件上传漏洞（缺一不可）：

1. **可复现**：同一无害探针文件重复上传（≥3 次）稳定被接受并可通过返回的 URL 访问。
2. **对照基线**：提供「合法文件」与「伪装/异常扩展名文件」的成对上传请求/响应，证明差异源于校验缺失而非业务限制。
3. **校验维度确证**：明确记录被绕过的具体维度（扩展名/Content-Type/内容 magic bytes 三者中哪个未被校验）。
4. **可执行性说明**：仅基于「文件是否落在可被 Web 容器解析执行的路径」说明风险，不实际验证代码执行（那属于命令注入范畴，不在本技能内完成）。
5. **证据脱敏**：只记录探针文件名、存储路径与访问 URL，不保存实际可执行内容的字节流。

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

## 禁止事项

- **只读原则**：仅检测，不利用（不上传真实 Webshell）
- **无害 Payload**：使用 `phpinfo()` 验证，不执行危险操作
- **零触网**：测试用 mock 或本地环境
