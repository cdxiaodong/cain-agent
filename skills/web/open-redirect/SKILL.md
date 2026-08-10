---
name: open-redirect
description: 开放重定向检测技能 —— 面向重定向端点，定位未验证目标 URL 参数的端点，通过构造恶意 URL（redirect=//evil.com）诱导用户跳转到钓鱼站点，产生可复现 PoC
phase: test
severity_focus: medium
---

# 开放重定向检测技能（Open Redirect）

> 定位：面向**重定向功能**的开放重定向漏洞，不是简单的外链检测。核心在于「识别哪些参数控制重定向目标」并「证明攻击者可构造 URL 诱导用户跳转到恶意站点」—— 重点检测 URL 参数验证缺失（redirect/url/next/login），而非正常的站内跳转。

## 漏洞原理

开放重定向（Open Redirect）的本质是：Web 应用在执行重定向操作时，**直接使用用户输入的 URL 参数作为跳转目标，未验证其是否为合法的站内地址，导致攻击者可构造恶意 URL 诱导用户跳转到钓鱼网站**。

- **URL 参数直接重定向**：重定向端点接受 `redirect`、`url`、`next`、`target`、`return`、`return_to`、`returnUrl`、`goto`、`link`、`destination` 等参数，直接使用其值作为 `Location` 头的值。
  - 示例：`/login?redirect=https://evil.com/phishing` → `Location: https://evil.com/phishing`
- **域名验证缺失**：服务端未验证重定向目标是否属于白名单域名，或仅检查 URL 是否以 `/` 开头（可被 `//evil.com` 绕过）。
- **相对路径绕过**：部分应用只检查重定向目标是否以 `/` 开头，攻击者使用 `//evil.com`（协议相对 URL）绕过检查。
- **子域名绕过**：部分应用只检查域名是否包含目标域名（如检查是否包含 `target.com`），攻击者使用 `evil.com?target.com` 或 `target.com.evil.com` 绕过。
- **URL 编码绕过**：通过对重定向目标进行 URL 编码、Unicode 编码绕过简单的字符串检查。

**关键判断依据**：提交外部 URL 作为重定向参数后，响应头 `Location` 指向攻击者控制的域名，且用户访问该 URL 后会被自动跳转到恶意站点。

## 触发条件

满足以下任一信号即应进入本技能（侦查阶段 `endpoints.json` 标注了候选开放重定向端点）：

- 端点包含重定向功能：登录后跳转、登出后跳转、第三方授权回调、分享链接跳转等。
- URL 参数名称暗示重定向：`redirect`、`url`、`next`、`return`、`return_to`、`returnUrl`、`goto`、`link`、`target`、`destination`、`callback`、`forward`、`continue`、`ref`。
- 响应状态码为 301/302/307/308：重定向端点通常返回这些状态码，并附带 `Location` 头。
- 响应包含 JavaScript 跳转：页面中包含 `window.location=`、`location.href=`、`location.replace()` 等跳转代码，且跳转目标可由用户输入控制。
- OAuth/OpenID Connect 回调：第三方登录回调 URL 未验证白名单。

## 检测方法

> 流程：重定向端点识别 → 参数提取 → 注入测试 URL → 验证 Location 头 → 构造钓鱼 PoC

### 步骤一：重定向端点筛选

1. **抓包分析**：使用 Burp Suite 或浏览器开发者工具，遍历应用的所有请求，筛选返回 301/302/307/308 状态码的端点。
2. **筛选标准**：
   - 响应状态码为 301/302/307/308 且包含 `Location` 头。
   - URL 参数包含重定向相关名称（`redirect`、`url`、`next`、`return` 等）。
   - 页面包含 JavaScript 跳转代码且跳转目标由参数控制。
3. **记录候选清单**：端点、参数、请求方法、当前重定向目标。

### 步骤二：参数测试

核心验证动作——证明「参数控制重定向目标」。

1. **测试外部域名**：在重定向参数中提交外部域名，观察 `Location` 头：
   ```
   ?redirect=https://evil.com
   ?url=http://attacker.com
   ?next=//evil.com
   ?return_to=//malicious.site
   ```

2. **成功判断**：
   - 响应头 `Location` 的值为注入的外部域名。
   - 浏览器访问该 URL 后被自动跳转到外部域名。
   - JavaScript 跳转代码中的目标被替换为外部域名。

3. **若被拒绝**：尝试不同的 Payload 格式（相对路径、协议相对 URL、编码绕过）。

### 步骤三：绕过测试

当基础测试被拦截时，尝试绕过方法。

1. **相对路径绕过**：
   ```
   ?next=//evil.com
   ?redirect=/\\/evil.com
   ?url=/%2Fevil.com
   ```

2. **子域名绕过**：
   ```
   ?redirect=https://evil.com?target.com
   ?url=https://target.com.evil.com
   ?next=https://evil.com#target.com
   ```

3. **URL 编码绕过**：
   ```
   ?redirect=https://%65%76%69%6c%2e%63%6f%6d
   ?url=https%3A%2F%2Fevil.com
   ```

4. **CRLF 注入**（可结合 XSS）：
   ```
   ?redirect=https://target.com%0d%0aLocation:%20https://evil.com
   ```

5. **@ 符号绕过**：
   ```
   ?redirect=https://target.com@evil.com
   ?url=//evil.com%40target.com
   ```

### 步骤四：钓鱼 PoC 构造

确认漏洞后，构造钓鱼 URL 证明攻击者可诱导用户跳转到恶意站点。

- **基础钓鱼 URL**：
  ```
  https://target.com/login?redirect=https://evil.com/phishing
  ```

- **隐藏真实目标**（使用 URL 缩短服务或域名相似）：
  ```
  https://target.com/login?redirect=https://evil.com/verify-account
  https://target.com/logout?next=//evil.com/login
  ```

- **结合 OAuth 诈骗**：
  ```
  https://target.com/oauth/authorize?client_id=attacker&redirect_uri=https://evil.com/steal-token
  ```

## 三层测试模型

> 对齐 DESIGN §3.1：L1 快速筛选候选 → L2 确认可利用 → L3 测试绕过方法

### L1 探测

目标：快速识别哪些端点和参数存在开放重定向，不做完整绕过测试。

- **状态码筛选**：扫描所有端点，筛选返回 301/302/307/308 的请求。
- **参数名匹配**：对筛选出的端点，检测 URL 参数名是否包含重定向关键词（`redirect`、`url`、`next` 等）。
- **基础外部域名测试**：对候选参数提交 `https://evil.com`，观察 `Location` 头是否直接跳转。

### L2 验证

目标：对 L1 筛选出的候选点，通过多格式 Payload 确认开放重定向存在。

- **多格式验证**：测试 `https://evil.com`、`//evil.com`、`http://evil.com` 等多种格式。
- **浏览器验证**：使用浏览器实际访问构造的 URL，确认是否被跳转到外部域名。
- **影响评估**：根据重定向参数的位置和触发场景定级——登录/支付流程为 high，一般页面为 medium。

### L3 绕过

目标：当基础检测被拦截时，测试绕过方法。

- **编码绕过**：对重定向目标进行 URL 编码、Unicode 编码、双重编码。
- **子域名绕过**：测试 `evil.com?target.com`、`target.com.evil.com` 等格式。
- **CRLF 注入**：尝试在参数中注入 CRLF 字符篡改响应头。
- **JavaScript 跳转测试**：检测页面中的 JavaScript 跳转代码是否可被参数控制。

## 工具

### curl（命令行重定向测试）

```bash
# 基础开放重定向检测（跟随重定向）
curl -L 'https://target.com/login?redirect=https://evil.com'

# 查看响应头（不跟随重定向）
curl -I 'https://target.com/login?redirect=https://evil.com'

# 测试多种参数名
curl -I 'https://target.com/logout?next=https://evil.com'
curl -I 'https://target.com/auth?return_to=https://evil.com'
curl -I 'https://target.com/share?url=https://evil.com'

# 测试相对路径绕过
curl -I 'https://target.com/login?next=//evil.com'
curl -I 'https://target.com/continue?redirect=/\\/evil.com'

# 测试 URL 编码绕过
curl -I 'https://target.com/login?redirect=https://%65%76%69%6c%2e%63%6f%6d'

# 测试 @ 符号绕过
curl -I 'https://target.com/login?redirect=https://target.com@evil.com'

# 查看 JavaScript 跳转
curl 'https://target.com/page?link=evil.com' | grep -i 'location'
```

### Burp Suite（抓包与重放）

1. Proxy → Intercept 捕获重定向请求。
2. Send to Repeater，修改重定向参数值为外部域名。
3. 观察响应头 `Location` 的值是否为外部域名。
4. 使用 Intruder 批量测试多个参数名和多个 Payload。
5. 使用 Match & Replace 规则批量替换重定向参数。

### 浏览器开发者工具

1. Network 面板观察重定向链，查看每个请求的 `Location` 头。
2. Console 面板执行 JavaScript 测试跳转逻辑。
3. 在 URL 栏手动构造测试 URL，观察浏览器行为。

## 输出格式

每个确认的开放重定向漏洞按以下 Finding 结构输出（result 初值 `validation_inconclusive`，留待校验流水线）：

```json
{
  "id": "OPEN-REDIRECT-001",
  "type": "open-redirect",
  "severity": "medium",
  "status": "confirmed",
  "result": "validation_inconclusive",
  "title": "登录接口存在开放重定向漏洞，可诱导用户跳转到钓鱼站点",
  "endpoint": "GET /login",
  "description": "该端点的 redirect 参数未验证目标 URL 是否为站内地址，攻击者可构造 https://target.com/login?redirect=https://evil.com/phishing 诱导用户跳转到钓鱼网站，窃取用户凭证",
  "payload": {
    "method": "GET",
    "url": "/login",
    "parameter": "redirect",
    "payload": "https://evil.com/phishing",
    "location_header": "https://evil.com/phishing"
  },
  "verification_steps": [
    "1. 访问 /login?redirect=https://evil.com，观察响应头 Location 是否为 https://evil.com",
    "2. 使用浏览器实际访问该 URL，确认是否被跳转到 evil.com",
    "3. 测试 //evil.com 绕过以 / 开头的检查",
    "4. 测试 URL 编码绕过可能的过滤",
    "5. 构造钓鱼 URL 证明可诱导用户跳转到恶意站点"
  ],
  "evidence": {
    "response_status": 302,
    "location_header": "https://evil.com/phishing",
    "redirect_parameter": "redirect",
    "bypass_method": "none"
  },
  "remediation": "验证重定向目标 URL 是否属于白名单域名，或使用相对路径重定向；禁止使用用户输入直接作为 Location 头的值，使用映射表或 token 替代"
}
```

## 证据要求

什么才算确认开放重定向（禁止仅凭「参数名可疑」下结论，要证明重定向实际发生）：

1. **重定向实际发生**：提交外部 URL 作为参数后，响应头 `Location` 指向外部域名，这是核心判据。
2. **浏览器验证**：使用浏览器实际访问构造的 URL，确认是否被自动跳转到外部域名（而非仅响应头显示）。
3. **参数控制确认**：证明重定向目标确实由用户输入的参数控制，而非固定逻辑。
4. **绕过方法记录**：若使用了绕过方法（如 `//evil.com`、子域名绕过），需记录具体的绕过 Payload。
5. **影响说明**：注明该开放重定向的触发场景（登录/登出/OAuth 回调/分享链接）和是否需要用户交互，据此定级。

## 禁止事项

- **仅授权目标**：开放重定向测试涉及构造恶意 URL，必须在书面授权范围内操作；检测前与委托方确认哪些端点允许测试重定向。
- **不诱导真实用户**：构造的钓鱼 URL 只在自有测试环境或测试账户间验证，绝不发送给真实用户或发布到公网。
- **不利用漏洞窃取凭证**：禁止利用开放重定向漏洞窃取真实用户的凭证或会话令牌。
- **不结合其他攻击**：禁止将开放重定向与其他攻击（如 XSS、CSRF）组合对真实用户发起攻击。
- **凭证不落明文**：测试中使用的测试账户凭证、会话 Token 在证据中脱敏；只记录「重定向成功」，不存完整 URL 中的敏感参数。
- **不破坏业务逻辑**：测试重定向时避免触发业务逻辑错误或无限重定向循环。
