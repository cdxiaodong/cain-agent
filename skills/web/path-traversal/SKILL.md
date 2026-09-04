---
name: path-traversal
description: 路径遍历检测技能 —— 面向真实授权系统，以允许的无害文件验证路径约束并产出可复现证据
phase: test
severity_focus: high
---

# 路径遍历漏洞检测技能

## 触发条件

仅在授权端点接收文件名、路径、模板或下载资源标识时启用本技能。

## 原理

路径遍历（Path Traversal）发生在 Web 应用未对文件路径进行充分校验时，攻击者可通过 `../` 跳出预期目录，读取任意文件。

**常见成因**：
- 用户输入直接拼接文件路径（`readfile("/uploads/" + user_input)`）
- 未过滤 `../` 序列
- 未限制访问范围（chroot jail 缺失）

## 三层测试模型

> 对齐 DESIGN §3.1：L1 探测 → L2 验证 → L3 绕过，每层只做上一层成立后才推进的事。

### L1 探测

目标：判定「该参数是否被拼接进文件系统路径」，只用允许清单内的无害文件。

- 基准建立：先请求参数的正常值（如合法文件名），记录响应结构（Content-Type、长度、是否为文件流）。
- 单层探测：追加一层 `../` 或替换为已知安全的相对路径标记，观察响应是否发生结构性变化（从「文件不存在」变为「不同内容」），而非直接尝试深层穿越。

> L1 产出「候选参数 + 路径拼接假设」，写入 `hypothesis`，不直接下结论。

### L2 验证

目标：用允许清单内的无害文件（`/etc/passwd`、Windows `win.ini`）把假设变成可复现证据。

- 层数收口：从少到多递增 `../` 数量，确定命中所需的准确层数，证明是「路径拼接生效」而非「服务端恰好也有同名文件」。
- 重复验证：同一 payload 重复请求（≥3 次），确认返回内容稳定为目标文件的已知特征片段（如 `win.ini` 的 `[fonts]` 段、`/etc/passwd` 的 `root:` 行）。
- 编码变体确认：分别验证 `../`、`..\\`、URL 编码 `%2e%2e%2f` 三种写法中哪些生效，为定级与绕过分析提供依据。

### L3 绕过

目标：当 `../` 被过滤或路径被规范化时，验证穿越是否仍可达。

- 编码/双重编码：`%2e%2e%2f`、`%252e%252e%252f`、`..%c0%af`（宽字节/UTF-8 溢出变体，历史 IIS/Apache 已知问题）。
- 过滤旁路：`....//`（依赖简单替换 `../`→`` 后残留出新的 `../`）、混合分隔符 `..\/`。
- Null 截断：`file.txt%00../../etc/passwd`（针对老旧语言的字符串截断行为，需先判断目标语言/框架年代是否可能存在此问题再测）。
- 仍仅使用允许清单文件验证「是否仍能穿越」，不因绕过成功而读取超出清单范围的路径。

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

## 证据要求

什么才算确认路径遍历（缺一不可）：

1. **可复现**：同一 payload 重复请求（≥3 次）稳定返回目标文件的已知内容特征。
2. **对照基线**：提供「合法参数值」与「穿越 payload」的成对请求/响应，证明差异源于路径拼接而非文件本身存在。
3. **层数/编码确证**：记录命中所需的准确 `../` 层数与生效的编码变体，避免「疑似穿越」的模糊定级。
4. **影响说明**：仅基于允许清单内文件（`/etc/passwd`、`win.ini`）已验证的读取能力说明风险边界，不实际读取或推断敏感文件内容。
5. **证据脱敏**：只保存命中判定所需的特征片段（如 `root:` 那一行），不保存 `/etc/passwd` 全文或其他实际敏感文件内容。

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

## 禁止事项

- **只读原则**：仅检测，不读取敏感文件（如私钥/密码）
- **无害 Payload**：使用 `/etc/passwd` / `win.ini` 验证
- **零触网**：测试用 mock 或本地环境
