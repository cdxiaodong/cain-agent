---
name: xss
description: XSS 测试技能 —— 面向真实业务系统，区分渲染上下文（HTML/属性/JS/CSS/URL），覆盖存储型/反射型/DOM 型，对抗 CSP 与输入过滤，产出可复现 PoC
phase: test
severity_focus: high
---

# 跨站脚本测试技能（XSS）

> 定位：面向**真实业务系统**的注入验证。核心难点不是找一个能弹 `alert` 的点，而是判断「用户输入最终落在哪个渲染上下文、该上下文的转义是否真实生效、能否在浏览器实际执行」——多数 XSS 误报源于没区分上下文就下结论。

## 触发条件

满足以下任一信号即应进入本技能：

- 参数值在响应中被**原样或部分回显**（侦察阶段 `endpoints.json` 已标注回显点）：搜索结果页回显关键词、个人资料页回显昵称/签名、错误页回显输入、列表页回显排序字段。
- 回显点位于不同上下文需分别评估：HTML 正文（`<div>{name}</div>`）、属性（`<input value="{q}">`）、JavaScript 字符串（`var q = "{q}";`）、CSS（`background:url({x})`）、URL（`<a href="{u}">`）——同一参数可能多上下文回显，每处单独评估。
- 用户输入持久化并在后续页面渲染：评论、笔记、工单、个人资料、消息——存储型 XSS 的影响半径远大于反射型，优先级更高。
- 客户端存在基于不可信输入的 DOM 操作：URL hash / `location.search` 被 `innerHTML` / `document.write` / `eval` / 模板引擎（Vue `v-html`、React `dangerouslySetInnerHTML`）消费。
- 富文本/Markdown 渲染器存在：WYSIWYG 编辑器（CKEditor/TinyMCE）、Markdown 转 HTML（marked/markdown-it）——这些组件的 sanitizer 配置错误是高发点。
- CSP 头存在但策略宽松：`script-src` 含 `unsafe-inline` / `unsafe-eval` / 大量 CDN 域名 / 通配符 `*`，或存在可被滥用上传 JS 的可信域（JSONP endpoint、CDN 资源）。

## 三层测试模型

> 对齐 DESIGN §3.1。XSS 的 L1/L2/L3 划分核心是「上下文判定」与「是否真执行」，而非 payload 多寡。

### L1 探测

目标：确认用户输入在响应中存在、并定位其渲染上下文，不急于弹窗。

- 回显确认：传一个唯一标记（如 `cainxss7f3a`），在响应源码中 grep 该标记，定位所有回显位置及其所在上下文（HTML body / 属性值 / script 块 / style / href）。
- 转义检测：传入 `<>"'=()/ \` 这些「上下文元字符」，检查响应中它们是被转义（`&lt;` / `&quot;` / `\\`）、编码（`\u003c`）、过滤（直接消失）、还是原样保留——每个回显点单独记录「过滤面」。
- 上下文细分：属性内回显要看是否在引号内、引号类型（单/双/无引号）、属性类型（事件属性 `onload` / 普通 `value` / URL `href` / `src`）；JS 上下文要看字符串定界符、是否在模板字符串 `` ` `` 内。

### L2 验证

目标：证明在该上下文下输入能**突破当前上下文进入可执行上下文**，并在浏览器真实执行。

- HTML 正文上下文：若 `<` 未转义，用 `<img src=x onerror=...>` / `<svg onload=...>`；关键不是 payload 长度，而是确认能注入新的合法 HTML 标签并触发事件处理器。
- 属性上下文：若属性用双引号且 `"` 未转义，用 `"><script>...` 闭合标签；若在事件属性内（如 `value="{x}"` 后跟 `onfocus`），尝试 `autofocus onfocus=...`；URL 属性（`href`）优先用 `javascript:` 协议而非注入标签。
- JS 字符串上下文：定界符（`"` / `'` / `` ` ``）若未转义，用 `";alert(1)//` 闭合字符串；若在模板字符串内需考虑 `${...}` 插值逃逸。
- DOM 型：用 `#hash` / `?param=` 携带 payload，确认它被 `innerHTML` 等危险 sink 消费——DOM 型的证据要包含「source → sink 的数据流」，不能只给一个能弹窗的 URL。
- 存储型验证：提交 payload 后，访问所有可能渲染该输入的页面（作者页、列表页、搜索页、RSS、邮件预览），确认它在哪个页面、哪个上下文执行——存储型的价值证明在于「跨用户、跨会话触发」。

### L3 绕过

目标：在存在 WAF / 输入过滤 / CSP 时证明 XSS 仍可达。

- 过滤面规避：若 `<script>` 被过滤，换 `<svg>` / `<img>` / `<body>` / `<iframe>` 等可触发事件的标签；若 `onerror=` 被过滤，换 `onpointerover` / `ontoggle` / `onanimationstart` 等冷门事件；若 `alert` 被过滤，换 `confirm` / `prompt` / `eval` / `top.name`。
- 编码绕过：HTML 实体编码（`&#106;`）、JS Unicode（`\u0061`）、URL 编码、混合编码——针对「哪个字符被过滤」逐个变形验证，不一锅端。
- CSP 绕过评估：分析 `Content-Security-Policy`，判断是否有可滥用点——`unsafe-inline` 直接可执行；可信 CDN 域 + 该域存在可控制的 JS 资源（如 angular 旧版 `ng-includes`、JSONP 回调）构成绕过；`script-src 'nonce-xxx'` 若 nonce 可预测或复用则可绕。**CSP 绕过需实锚点，禁止只写「理论上可绕」**。
- 富文本 sanitizer 绕过：针对 Markdown/HTML 白名单，尝试嵌套标签、属性混淆、`data:` URI、SVG 内联、mutation XSS（解析器与渲染器差异）——以该组件已知 CVE 为线索而非盲试。

## 证据要求

什么才算确认 XSS（禁止仅凭「payload 在响应里出现」下结论）：

1. **真实执行**：必须证明浏览器实际执行了注入代码，而非只在响应源码里出现 payload——用 Headless 浏览器（Playwright/Puppeteer）截图或捕获 `alert` / `console` / 网络回调作为执行证据；纯响应文本匹配只是疑似。
2. **上下文归属**：证据注明该 XSS 属于哪个上下文（HTML/属性/JS/DOM）、存储型还是反射型/DOM 型——不同类型的修复建议与定级不同。
3. **PoC 可复现**：提供完整的触发请求（含 header / body / cookie 脱敏）或 URL，以及「如何看到执行」的步骤（访问哪个页面、点击哪里、预期看到什么）。
4. **影响说明**：注明该 XSS 能访问的边界——是否能窃取 Cookie（注明 HttpOnly/Secure/SameSite 状态）、是否能发起 CSRF 链、是否可操作页面 DOM 伪装用户操作——基于实际探测而非泛泛而谈「可窃取会话」。
5. **证据脱敏**：截图/录屏中遮挡其他用户真实数据；测试用的探测账号 Cookie/Token 不入证据明文。

## 禁止事项

- **仅授权目标**：只在 `scope.yaml` 授权范围且持书面授权时运行；对未授权第三方域发 payload（即使测试用）也属越界。
- **不对真实用户投毒**：存储型 XSS 测试 payload 不得污染线上其他用户可见的内容——优先在自建测试账号、隔离环境验证；若必须在线上验证执行，payload 只能是无害的标记（如向自有受控回调地址发请求），禁止窃取真实用户会话。
- **不扩散影响**：不用 XSS 去探测 scope 外资产、不通过 XSS 建立持久化后门、不在目标系统上植入实际恶意载荷。
- **凭证不落明文**：测试中获取的 Cookie / Token / localStorage 数据，证据只记录类型与是否存在，不存原文。
- **禁止盲信单次弹窗**：单次 `alert` 成功不足以定级，需确认它在「正常用户访问路径」下可触发（如存储型要在他人访问该页面时触发，而非仅作者本人）。
XSS_EOF
echo "=== xss written, lines: $(wc -l < worktree:skills/web/xss/SKILL.md) ==="