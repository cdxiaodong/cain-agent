---
name: csrf
description: CSRF 检测技能 —— 面向真实业务系统，定位登录后状态改变操作（改资料/转账/删资源）缺失 CSRF Token 或 Referer 校验的端点，通过去 Token / 伪造 Referer 重放确认漏洞，产出可复现 PoC
phase: test
severity_focus: high
---

# 跨站请求伪造检测技能（CSRF）

> 定位：面向**真实授权业务系统**的 CSRF 验证，不是跑扫描器出报告。核心在于「识别哪些请求是真正的状态改变操作」并「证明攻击者可以跨站伪造该请求」——重点检测登录后敏感操作（修改用户信息、资金转账、删除资源、权限变更），而非 GET 请求的书签链接。

## 漏洞原理

CSRF（Cross-Site Request Forgery）的本质是：Web 应用在执行状态改变操作时，**仅依赖会话 Cookie 鉴别用户身份，而不验证该请求确实由用户主动发起**。

- **GET 型 CSRF**：状态改变操作通过 GET 请求完成（如 `GET /account/delete?id=123`），攻击者只需诱导受害者访问含 `<img src="...">` 的页面即可触发——危害最大但现代框架已少见。
- **POST 型 CSRF**：状态改变通过 POST 请求提交，但服务端不校验 CSRF Token 或 Referer/Origin 头，攻击者构造隐藏表单自动提交（`<form>` + `submit()` + `target=hidden_iframe`）。
- **JSON/AJAX 型 CSRF**：请求体为 JSON 且带 `Content-Type: application/json`，传统表单无法直接构造——但如果服务端容忍 `text/plain` 或 `application/x-www-form-urlencoded` 伪装的 JSON 体，或 CORS 策略允许简单请求跨域，仍可被利用。
- **同源校验缺失**：应用未校验 `Origin` 或 `Referer` 头，或校验逻辑有缺陷（如只检查域名包含而非精确匹配、允许空 Referer），导致跨站请求被接受。

**关键判断依据**：去除 CSRF Token 后重放请求，服务端仍然成功执行操作（返回 200 + 成功特征关键字，或数据库状态实际改变），即确认漏洞存在。

## 触发条件

满足以下任一信号即应进入本技能（侦察阶段 `endpoints.json` 标注了候选 CSRF 端点）：

- 端点执行状态改变操作：修改用户信息（昵称/邮箱/密码）、资金操作（转账/提现/充值）、资源管理（删除文件/清空数据）、权限变更（添加管理员/授权设备）。
- 请求依赖会话 Cookie 鉴权：`Cookie: session=...` 或 `Authorization: Bearer` 头存在，但请求体中没有额外的 CSRF Token 字段。
- GET 请求执行写操作：URL 参数直接导致数据变更（`?action=delete&id=...`、`?do=transfer&amount=...`），违反 RESTful 原则。
- POST 表单缺少 Token：提交表单中没有 `csrf_token` / `_token` / `authenticity_token` / `__RequestVerificationToken` 等隐藏字段。
- 同源校验可绕：Referer/Origin 头被忽略或只做了宽松匹配（如 `Referer: https://evil.com/?target.com` 通过了 `contains("target.com")` 校验）。

## 检测方法

> 流程：抓包分析 → 提取状态改变请求 → 去除 CSRF Token / 伪造 Referer → 重放 → 判断是否成功

### 步骤一：抓包与端点筛选

1. **代理抓包**：使用 Burp Suite 或浏览器开发者工具（Network 面板），登录后遍历应用的核心功能（个人设置、资金操作、资源管理），捕获所有状态改变请求。
2. **筛选标准**：
   - 请求方法为 GET（写操作）或 POST/PUT/DELETE/PATCH。
   - 请求携带会话凭证（Cookie 或 Authorization 头）。
   - 响应表明操作执行（200 + 成功提示、301/302 跳转到操作结果页、数据库状态变化）。
3. **记录候选清单**：端点、方法、参数、是否携带 CSRF Token、Referer/Origin 校验情况。

### 步骤二：Token 存在性分析

1. 检查请求体中是否存在 CSRF Token 字段（常见名称：`csrf_token`、`_token`、`authenticity_token`、`__RequestVerificationToken`、`csrfmiddlewaretoken`、`_csrf`）。
2. 检查 Cookie 中是否存在双重提交 Cookie 模式（`Set-Cookie: csrf_token=xxx` 且请求体或头中带同值）。
3. 检查自定义请求头（`X-CSRF-Token`、`X-XSRF-TOKEN`、`X-Requested-With`）是否被服务端强制校验。
4. **无 Token**：直接进入步骤三重放验证。
5. **有 Token**：尝试去除 Token 或篡改 Token 值后重放，看是否仍被接受。

### 步骤三：去 Token 重放

核心验证动作——证明「没有 CSRF 防护时操作仍可执行」。

1. **去除 Token**：从请求中删除 CSRF Token 字段、Cookie、自定义头，保持其余参数和会话凭证不变。
2. **重放请求**：用 `curl` 重放去 Token 后的请求，观察响应。
3. **成功判断**：
   - 响应状态码为 200（或操作成功的预期状态码）。
   - 响应体包含成功特征关键字（如 `"success": true`、`"code": 0`、`"message": "操作成功"`、`"result": "ok"`）。
   - 数据库状态实际改变（如个人信息已更新、资源已删除——通过后续查询确认）。
4. **若被拒绝**（返回 403 / Token 校验失败）：说明 CSRF Token 防护有效，进入步骤四测试 Referer 校验。

### 步骤四：Referer / Origin 伪造

当 CSRF Token 存在且有效时，测试同源校验是否有缺陷。

1. **伪造 Referer**：用 `curl -H "Referer: https://evil.com/"` 重放请求，观察是否被接受。
2. **去除 Referer**：用 `curl` 不带 Referer 头（模拟 `<meta name="referrer" content="no-referrer">` 场景），观察是否被接受。
3. **子域名绕过**：用 `Referer: https://target.com.evil.com/`（利用 `contains()` 校验缺陷）。
4. **Origin 头测试**：同上策略测试 `Origin` 头伪造与缺失。

### 步骤五：跨站 PoC 构造

确认漏洞后，构造最小可复现 PoC 证明攻击者可在第三方站点触发该操作。

- **GET 型**：`<img src="https://target.com/account/delete?id=123" style="display:none">`
- **POST 型**：隐藏表单 + JS 自动提交：

```html
<form id="csrf-form" action="https://target.com/api/transfer" method="POST">
  <input type="hidden" name="to_account" value="attacker_account">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('csrf-form').submit();</script>
```

- **JSON 型**（若服务端容忍 `text/plain`）：

```html
<form id="csrf-form" action="https://target.com/api/settings" method="POST"
      enctype="text/plain">
  <input type="hidden"
         name='{"email":"attacker@evil.com","padding":"'
         value='"}'>
</form>
<script>document.getElementById('csrf-form').submit();</script>
```

## 三层测试模型

> 对齐 DESIGN §3.1：L1 快速筛选候选 → L2 确认可利用 → L3 对抗防护绕过。

### L1 探测

目标：快速识别哪些端点是状态改变操作且缺少 CSRF Token，不做完整重放。

- **GET 写操作扫描**：从 `endpoints.json` 筛选 GET 方法且路径含 `delete` / `update` / `transfer` / `set` / `change` / `remove` / `admin` 等动词的端点——这些是最明显的 CSRF 候选。
- **POST Token 缺失检查**：对 POST/PUT/DELETE 端点检查请求体是否含 CSRF Token 字段，无 Token 的端点标记为高风险候选。
- **会话依赖确认**：确认端点依赖 Cookie 而非每次请求重新输入密码——如果操作需要二次密码验证（如支付宝的支付密码），CSRF 难以利用，降级风险。

### L2 验证

目标：对 L1 筛选出的候选端点，通过去 Token 重放证明漏洞存在。

- **去 Token 重放**：按步骤三执行，去除所有 CSRF Token 相关字段/头/Cookie 后用 `curl` 重放。
- **成功确认**：响应状态码 200 + 成功特征关键字，或通过后续请求确认数据库状态已改变（如个人信息页显示篡改后的值）。
- **影响评估**：根据操作类型定级——资金操作（转账/提现）为 critical，个人信息修改为 high，偏好设置为 medium。

### L3 绕过

目标：当 CSRF Token 防护存在时，测试是否有绕过路径。

- **Token 可预测**：分析 Token 生成算法（如基于时间戳、用户 ID hash、递增序列），若可预测则可构造有效 Token。
- **Token 不绑定会话**：用 A 用户的 Token 替换 B 用户请求中的 Token，若被接受说明 Token 未绑定会话。
- **方法覆盖**：用 `_method=PUT` / `X-HTTP-Method-Override: PUT` 绕过只对 POST 做 CSRF 校验但实际路由到 PUT/PATCH/DELETE 的框架。
- **空 Token 绕过**：将 Token 值设为空字符串或 `null`，部分实现只检查字段存在而非值有效性。
- **Referer 缺省绕过**：步骤四的 Referer/Origin 校验缺陷测试。

## 工具

### curl（命令行重放）

```bash
# 原始请求（含 Token，从 Burp Copy as curl 获取）
curl -X POST 'https://target.com/api/profile/update' \
  -H 'Cookie: session=USER_SESSION_VALUE' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'name=newname&email=new@example.com&csrf_token=TOKEN_VALUE'

# 去 Token 重放（删除 csrf_token 字段）
curl -X POST 'https://target.com/api/profile/update' \
  -H 'Cookie: session=USER_SESSION_VALUE' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'name=csrf_test&email=csrf@example.com'

# 伪造 Referer 重放
curl -X POST 'https://target.com/api/profile/update' \
  -H 'Cookie: session=USER_SESSION_VALUE' \
  -H 'Referer: https://evil.com/' \
  -d 'name=csrf_test&email=csrf@example.com'

# GET 型 CSRF 验证
curl 'https://target.com/account/delete?id=999' \
  -H 'Cookie: session=USER_SESSION_VALUE'
```

### Burp Suite（抓包与重放）

1. Proxy → Intercept 捕获状态改变请求。
2. Send to Repeater，在 Repeater 中删除 CSRF Token 参数后 Send，观察响应。
3. 使用 Match & Replace 规则批量去除 Token 头测试多个请求。
4. Generate CSRF PoC：Repeater 右键 → Engagement tools → Generate CSRF PoC。

## 输出格式

每个确认的 CSRF 漏洞按以下 Finding 结构输出（result 初值 `validation_inconclusive`，留给校验流水线）：

```json
{
  "id": "CSRF-001",
  "type": "csrf",
  "severity": "high",
  "status": "confirmed",
  "result": "validation_inconclusive",
  "title": "个人资料更新接口存在 CSRF 漏洞",
  "endpoint": "POST /api/profile/update",
  "description": "该端点修改用户个人信息时未校验 CSRF Token 或 Referer，攻击者可构造跨站请求在用户不知情下修改其邮箱、密码等敏感信息",
  "payload": {
    "method": "POST",
    "url": "/api/profile/update",
    "headers": {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    "body": "name=csrf_test&email=attacker@evil.com",
    "note": "无 CSRF Token，无 Referer 校验，仅依赖会话 Cookie"
  },
  "verification_steps": [
    "1. 登录目标系统获取有效会话 Cookie",
    "2. 用 curl 去除所有 Token 字段后重放 POST 请求",
    "3. 观察响应状态码是否为 200 且包含成功特征关键字",
    "4. 访问个人资料页确认信息已被篡改",
    "5. 构造 HTML 隐藏表单 PoC，在第三方域名页面中自动提交验证跨站触发"
  ],
  "evidence": {
    "response_status": 200,
    "response_indicator": "\"success\": true",
    "token_present": false,
    "referer_check": false
  },
  "remediation": "为所有状态改变操作添加 CSRF Token 校验（同步令牌模式或双重提交 Cookie），并校验 Origin/Referer 头精确匹配可信域名"
}
```

## 证据要求

什么才算确认 CSRF（禁止仅凭「请求没有 Token」下结论，要证明去 Token 后操作仍成功执行）：

1. **去 Token 重放成功**：去除所有 CSRF Token 相关字段后重放请求，服务端返回操作成功（200 + 成功关键字），这是核心判据。
2. **状态改变确认**：通过后续请求或页面确认目标状态实际改变（个人信息页显示篡改值、资源确实被删除），不依赖单一响应状态码。
3. **跨站可触发性**：PoC 在模拟第三方站点（不同 Origin）提交时，浏览器自动携带受害者的 Cookie 完成请求——证明攻击者无需获取凭证即可触发操作。
4. **影响说明**：注明该 CSRF 能执行的操作类型（改资料/转账/删数据）与是否需要受害者交互（自动提交 vs 需要点击），据此定级。
5. **证据脱敏**：请求中的会话 Cookie / Token 值在证据中脱敏；只记录「凭证存在 + 类型」，不落明文。

## 禁止事项

- **仅授权目标**：CSRF 测试需向授权目标发送状态改变请求（可能修改/删除数据），必须在书面授权范围内操作；测试前与委托方确认哪些端点允许实际执行写操作、哪些只能做只读分析。
- **不破坏真实数据**：优先使用测试账号、使用可逆操作（修改而非删除）；若必须测试删除类操作，选择测试专用资源或使用标记值（如用户名改为 `csrf_test_<timestamp>`）便于回溯清理。
- **不对真实用户发起 CSRF**：CSRF PoC 只在自有测试环境或测试账号间验证，绝不诱导真实用户访问含 CSRF Payload 的页面。
- **凭证不落明文**：测试中使用的会话 Cookie / Token / Session ID，证据只记录类型与是否存在，不存原文。
- **不测试资金真实转移**：涉及转账/支付类操作的 CSRF，只验证「请求是否被接受」（到达业务逻辑层），不实际完成资金转移——到业务层校验通过即足够定级。
