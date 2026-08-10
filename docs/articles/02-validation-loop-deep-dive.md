# 标题候选(发布时择一)

1. **让 AI 自己查自己：渗透 Agent 的校验闭环设计**  
2. 从幻觉到可信：渗透测试中双 Agent 独立会话校验架构  
3. 四态输出与规则表收口：构建 AI 渗透工具的确定性边界

---

## 写在最前

> 本文所有检测演示均使用**合成示例数据**(自有测试账号内的误配置靶场),不涉及任何真实目标的漏洞细节。Cain 仅供**授权**安全测试使用。

## 一、痛点：AI 幻觉在渗透测试中的致命风险

AI 大模型在网络安全领域的应用越来越热，但有一个核心问题始终悬而未决：**模型会"幻觉"**。

在对话场景里，幻觉顶多是答非所问。但在渗透测试场景，幻觉意味着：

- 把一个正常的 404 响应解释为 SQL 注入的成功回显；
- 把前端的一个 UI 渲染误判为存在 XSS；
- 把一个超时错误理解为 SSRF 内网探测成功；
- 甚至凭空构造一个根本不存在的凭证泄露。

这些问题如果只停留在实验室里，影响有限。但一旦这类工具进入**授权**评估的生产环境，后果就很严重：

**安全团队会收到大量误报**，耗费大量时间人工排查；而真正的高危漏洞可能淹没在海量假阳性中。更糟的是，如果误报被当作真实漏洞提交，可能导致错误的安全决策——比如因为误以为某个接口可越权，错误地关闭了某个业务功能。

市场上有不少 AI 渗透工具，但能正面回答"AI 报的漏洞能信吗"这个问题的，凤毛麟角。多数工具的逻辑是：模型说有，就有。这相当于把判断权完全交给了概率模型。

Cain 的校验闭环，就是给这个不确定性加上一道工程级防线。

## 二、核心设计：双 Agent 独立会话校验

校验闭环的核心思想很简单：**发现者和验证者必须分离**。

这就像法庭上的控辩双方，不能既是检察官又是法官。在 Cain 的架构里：

- **发现 Agent (Discovery Agent)**：负责侦察、测试、尝试攻击，把每一条可疑发现写成结构化的 Finding 对象；
- **校验 Agent (Validation Agent)**：在报告生成前介入，用完全独立的会话（Session）逐条复核发现 Agent 的输出。

### 2.1 独立会话的必要性

为什么强调"独立会话"？

如果校验 Agent 和发现 Agent 共享同一个对话上下文，校验者会不自觉地被前者的观点影响——模型容易"顺从"之前的判断，这是一种典型的**确认偏误**。

独立会话意味着：

- 两个 Agent 的系统提示词（System Prompt）完全不同；
- 历史对话记录不共享；
- 校验 Agent 看到的是 `[UNTRUSTED_DATA]` 标记的数据包，明确提示这些来自不可信来源。

### 2.2 校验流程

完整的校验流程包含四个步骤：

**第一步：去重指纹计算**

每条 Finding 生成时，系统自动计算一个四元组指纹：

```
(target_host, vulnerability_type, evidence_hash, endpoint)
```

- `target_host`：目标主机标识（脱敏后）；
- `vulnerability_type`：漏洞类型（如 sqli, xss, sst_open_redirect）；
- `evidence_hash`：证据响应的 SHA256 哈希；
- `endpoint`：受影响的端点路径。

同一指纹的重复发现会被合并，避免同一漏洞被反复报告。

**第二步：四状态结构化输出**

校验 Agent 对每条 Finding 输出四种状态之一：

| 状态 | 含义 | 典型场景 |
|------|------|----------|
| `confirmed` | 确认存在 | 证据清晰、复现步骤可重现、符合规则表定义 |
| `false_positive` | 误报 | 证据不足、响应正常、误解析业务逻辑 |
| `inconclusive` | 无法判断 | 数据不完整、需要额外信息、超时 |
| `system_error` | 系统错误 | 校验流程异常、解析失败、模型调用失败 |

只有 `confirmed` 状态的 Finding 才会进入最终报告。

**第三步：规则表收口**

校验 Agent 的判定必须对照规则表 (`rules/validation_rules.yaml`)。规则表明确定义每种漏洞类型的：

- 最小证据要求（例如：SQLi 必须显示错误回显或时间延迟）；
- 误报特征（例如：404 页面的通用错误文本）；
- 严重性映射表（critical/high/medium/low/info 的硬编码规则）。

模型可以提建议，但最终级别以规则表为准。这杜绝了模型"我觉得这很严重"的主观性。

**第四步：容错与幂等**

单条校验失败（例如模型调用超时）不会整条流水线崩塌，标记为 `system_error` 后继续下一条。已确认的 Finding 不会重复校验，支持中断恢复。

## 三、FindingValidator：工程化的校验执行器

FindingValidator 是校验闭环的工程实现，它不是另一个 AI 模型，而是一个**确定性编排器**。

### 3.1 伪代码示意

```python
class FindingValidator:
    def __init__(self, validation_rules_path):
        self.rules = load_rules(validation_rules_path)
        self.validator_client = LLMClient(
            model="validation-model",
            system_prompt=VALIDATOR_SYSTEM_PROMPT
        )
    
    def validate(self, finding: Finding) -> ValidationResult:
        # 1. 计算指纹，检查是否已确认
        fingerprint = self._compute_fingerprint(finding)
        if self._is_already_confirmed(fingerprint):
            return ValidationResult(already_processed=True)
        
        # 2. 加载对应漏洞类型的规则
        rule = self.rules.get(finding.type)
        if not rule:
            return ValidationResult(status="system_error", reason="no_rule")
        
        # 3. 调用校验 Agent（独立会话）
        validation_input = self._prepare_untrusted_input(finding, rule)
        response = self.validator_client.chat(
            messages=[{
                "role": "user",
                "content": validation_input
            }],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "validation_result",
                    "strict": True,
                    "schema": VALIDATION_RESULT_SCHEMA
                }
            }
        )
        
        # 4. 解析四状态输出
        parsed = self._parse_validation_response(response)
        
        # 5. 规则表收口：严重性以规则为准
        if parsed.status == "confirmed":
            parsed.severity = rule.min_severity  # 强制对齐
        
        # 6. 记录指纹
        if parsed.status == "confirmed":
            self._record_fingerprint(fingerprint)
        
        return parsed
```

### 3.2 VALIDATION_RESULT_SCHEMA

```python
VALIDATION_RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "enum": ["confirmed", "false_positive", "inconclusive", "system_error"]
        },
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"]
        },
        "reason": {"type": "string"},
        "suggested_remediation": {"type": "string"}
    },
    "required": ["status", "reason"]
}
```

使用 `response_format` 强制模型输出 JSON Schema 约束的结构，确保解析层无需处理自由文本。

## 四、规则表：收口的最后一道防线

规则表是校验闭环的"法典"。它不是 AI 生成的，而是由安全专家手工编写、版本控制的静态 YAML 文件。

### 4.1 规则表示例（SQLi）

```yaml
sql_injection:
  min_severity: high
  min_evidence_required:
    - error_based: "数据库错误信息回显"
    - time_based: "响应时间延迟 > 5秒"
    - boolean_based: "True/False 条件响应差异"
  false_positive_patterns:
    - "404 Not Found"
    - "Application Error"
    - "请检查输入"
  remediation_template: "使用参数化查询替代字符串拼接"
```

### 4.2 规则表示例（开放重定向）

```yaml
open_redirect:
  min_severity: medium
  min_evidence_required:
    - "Location 头包含外部域名"
    - "URL 参数可控且未做白名单验证"
  false_positive_patterns:
    - "相对路径跳转 (../)"
    - "同域名下路径跳转"
  allowlist_domains: []
  remediation_template: "实现 URL 白名单校验或使用相对路径"
```

规则表的优势：

1. **可审计**：所有判定的依据都在代码仓库里；
2. **可更新**：发现新的误报模式，直接改规则表，无需改模型；
3. **可回滚**：规则变更带版本号，出问题能回退；
4. **可复现**：同一输入在不同时间跑，结果一致。

## 五、真实场景演示（合成数据）

下面用一个合成靶场的检测流程，展示校验闭环的完整路径。

### 场景：发现疑似 SSTI 漏洞

**发现 Agent 输出（未校验）**：

```json
{
  "type": "ssti",
  "target": "example-app.internal",
  "endpoint": "/api/render?template={{7*7}}",
  "evidence": {
    "request": "GET /api/render?template=%7B%7B7*7%7D%7D",
    "response": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n49",
    "payload": "{{7*7}}",
    "expected": "49",
    "actual": "49"
  },
  "severity_suggested": "critical"
}
```

**校验 Agent 处理**：

1. 读取 SSTI 规则表，`min_evidence_required` 要求：
   - 必须显示模板语法执行结果（数学运算回显符合）；
   - 必须排除业务层面的数字返回（需验证不同 Payload）。

2. 校验 Agent 构造验证请求：
   - Payload 1：`{{config}}` → 返回空（非 Jinja2）
   - Payload 2：`${7*7}` → 返回 `49`（疑似 FreeMarker）
   - Payload 3：`<%=7*7%>` → 返回原字符串（非 ERB）

3. 判定：
   - 多种 Payload 测试后，`${7*7}` 稳定返回计算结果，确认存在 FreeMarker 模板引擎注入；
   - 证据充分，复现可重复。

4. 最终输出：

```json
{
  "status": "confirmed",
  "severity": "critical",
  "reason": "FreeMarker 模板引擎注入确认，Payload '${7*7}' 返回 '49'，多 Payload 复现稳定",
  "suggested_remediation": "对用户输入进行严格转义，禁用危险模板函数"
}
```

**指纹记录**：

```
fingerprint("example-app.internal", "ssti", sha256("49"), "/api/render") 
  → 存入 confirmed_fingerprints.db
```

后续如果发现 Agent 再次报同一个端点的 SSTI，会被去重拦截，不再重复校验。

### 反例：误报开放重定向

**发现 Agent 输出**：

```json
{
  "type": "open_redirect",
  "target": "example-app.internal",
  "endpoint": "/login?next=/home",
  "evidence": {
    "request": "GET /login?next=/home",
    "response": "HTTP/1.1 302 Found\nLocation: /home"
  }
}
```

**校验 Agent 判定**：

1. 规则表要求 `Location` 头包含外部域名才算开放重定向；
2. 实际 `Location: /home` 是相对路径，属于同域名跳转；
3. 匹配 `false_positive_patterns` 中的"相对路径跳转"模式。

最终输出：

```json
{
  "status": "false_positive",
  "severity": "info",
  "reason": "Location 头为相对路径 /home，符合业务正常跳转逻辑，非外部域名重定向",
  "suggested_remediation": null
}
```

这条 Finding 不会进入最终报告。

## 六、工程哲学：确定性比"聪明"更重要

很多 AI 安全工具追求"模型越强越好"，Cain 的思路相反：**约束越硬越好**。

校验闭环体现了几个工程原则：

1. **分离关注点**：发现和验证是两种能力，应该由不同的 Agent 承担；
2. **最小信任**：校验 Agent 不信任发现 Agent 的任何输出，必须从零开始验证；
3. **规则收口**：判定标准不能交给模型，必须是人工编写、版本控制的代码；
4. **可审计性**：每一条确认的漏洞都有完整的校验记录链；
5. **容错性**：单点失败不影响整体流程。

这些原则共同构建了一个"虽然 AI 可能说错，但工程保证错误不会蔓延"的系统。

对于**授权**安全测试场景，这意味着交付物里的每一行发现，都经过了双重把关。这不仅仅是技术问题，更是对用户负责——安全测试本身就应该是一件确定性的事情。

## 七、Roadmap 与下一步

校验闭环目前已进入 Phase 3 稳定运行阶段，已集成的能力：

- 双 Agent 独立会话校验（发现/验证分离）
- 四状态结构化输出（confirmed/false_positive/inconclusive/system_error）
- FindingValidator 编排器（去重指纹 + 规则表收口）
- 10+ 漏洞类型规则表（SQLi/XSS/SSRF/SSTI/开放重定向/命令注入等）
- 幂等性支持（中断恢复 + 已确认跳过）

下一步计划：

- **规则表扩展**：覆盖 OWASP Top10 全部 10 大类；
- **校验 Agent 优化**：引入更多边缘案例的误报模式；
- **可视化报表**：在最终报告中标注"已校验"标识；
- **性能优化**：并行校验 + 缓存机制；
- **外部审计**：邀请第三方安全团队对校验逻辑进行评审。

GitHub: **[链接:发布时填入]**

Star 数和 Fork 数会在文章发布时更新，不在此处写死。

## 授权测试法律声明

Cain 仅供**授权**安全测试使用。你必须在拥有书面**授权**的环境中使用它——你自己的资产、你获得**授权**的渗透测试项目、或法律允许的漏洞赏金项目。Cain 的核心检测功能以只读凭证运行，scope 由配置文件强制执行而非依赖 AI 自律。使用者有责任遵从所在地的全部适用法律法规。未经**授权**对他人系统进行渗透测试在多数司法管辖区属于违法行为。
