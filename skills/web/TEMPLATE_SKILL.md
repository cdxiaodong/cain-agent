---
name: <skill-name>
description: <一句话定位（40-60字）>
phase: test
severity_focus: <critical|high|medium|low>
related_skills:
  - <related-skill-1>  # 可选
  - <related-skill-2>
---

# <技能名称>

> 定位：面向**真实授权业务系统**的漏洞检测/验证，不是扫描器出报告。核心在于「识别漏洞触发条件」并「产生可复现 PoC」—— 重点检测特征信号、Payload 构造、利用链推进，而非盲目发送探测包。

## 漏洞原理

[简洁描述漏洞成因、触发条件、影响范围]

**关键判断依据**：[一句话说明如何确认漏洞存在]

## 触发条件

满足以下任一信号即应进入本技能（侦查阶段标注了候选端点）：

- 信号 1：[具体特征]
- 信号 2：[具体特征]
- 信号 3：[具体特征]

## 检测方法

> 流程：信号识别 → Payload 构造 → 响应分析 → 漏洞确认

### 步骤一：信号识别

[如何找到候选测试点]

### 步骤二：Payload 构造

[核心 Payload 示例（编码/格式）]

### 步骤三：响应分析

[如何判断漏洞存在（成功/失败特征）]

### 步骤四：利用链推进（可选）

[如有后续利用步骤，说明]

## 工具

| 工具 | 用途 |
|---|---|
| curl | 命令行测试 |
| Burp Suite | 抓包修改参数 |
| <其他工具> | <用途> |

## 输出格式

| 字段 | 类型 | 描述 |
|---|---|---|
| service | str | 受影响服务（如 web/s3/iam） |
| resource | str | 受影响资源（URL/参数名） |
| issue_type | str | 漏洞类型（如 sqli/xss） |
| severity | str | 严重等级 |
| confirmed | bool | 是否经二次验证 |
| evidence | dict | 证据（响应包/Payload） |
| detail | str | 详细描述 |
