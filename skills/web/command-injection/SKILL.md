---
name: command-injection
description: 命令注入检测技能 —— 面向真实授权系统，以无害差异验证命令边界并产出可复现证据
phase: test
severity_focus: critical
---

# 命令注入漏洞检测技能

## 触发条件

仅在授权端点存在会进入系统命令的主机名、文件名或诊断参数信号时启用本技能。

## 原理

命令注入发生在 Web 应用将用户输入未过滤直接拼接到系统命令中时，攻击者可执行任意系统命令。

**常见成因**：
- 用户输入直接拼接 shell 命令（`ping {user_input}`）
- 未过滤特殊字符（`;` `|` `&&` `$()` 反引号）
- 使用 `system()` `exec()` `popen()` 等危险函数

**常见场景**：
- 网络诊断功能（ping/traceroute/nslookup）
- 文件操作功能（压缩/解压/转换）
- 系统管理接口（重启服务/查看日志）

## 三层测试模型

> 对齐 DESIGN §3.1：L1 探测 → L2 验证 → L3 绕过，每层只做上一层成立后才推进的事。

### L1 探测

目标：用一次无害标记探测判定「该参数是否可能进入系统命令」，不追求确认。

- 唯一标记回显：对候选参数追加 `;echo CAIN_<随机串>`（及 `|` / `&&` / `` ` `` / `$()` 各一次），观察响应是否原样回显该标记——标记必须每次探测唯一，避免与业务数据误判为同一信号。
- 响应结构对比：与不带分隔符的基准请求比较状态码、响应体长度、关键 DOM/JSON 结构，结构塌缩（500、异常页）本身也是候选信号。

> L1 产出「候选参数 + 触发分隔符假设」，写入 `hypothesis`，不直接定级。

### L2 验证

目标：用 `whoami` / `id` / `hostname` 把 L1 假设变成可复现证据，禁止仅凭一次响应下结论。

- 重复验证：同一 payload 重复 ≥3 次，确认 `uid=` / 主机名等标志性输出稳定出现，排除偶然回显（如错误页恰好包含相似字符串）。
- 分隔符收口：记录哪个分隔符（`;` `|` `&&` `` ` `` `$()`）实际生效，其余分隔符的响应作为对照一并保存。
- 基线对照：提供「不含分隔符的基准请求」与「含分隔符的 payload 请求」成对证据，证明差异由命令执行而非参数本身引起。

### L3 绕过

目标：分隔符被过滤/WAF 拦截时，验证注入是否仍可达。

- 空格替代：`${IFS}`、`%09`（Tab）、`<`/`<>`（bash 特性）替代空格。
- 分隔符变形：URL 编码（`%3b` `%7c`）、双重编码、换行注入（`%0a`）。
- 等价构造：`$( )` 与反引号互换；黑名单关键字（如过滤了 `cat`）用通配符（`c?t`）或变量拼接（`c${x}at`）规避。
- 仍只用 `whoami` / `id` / `hostname` 验证，不因为「绕过成功」而升级为破坏性命令。

## 检测方法

### 1. 定位注入点
- Ping 功能：`/api/ping?host=127.0.0.1`
- DNS 查询：`/api/nslookup?domain=example.com`
- 文件转换：`/api/convert?file=test.pdf`

### 2. 构造命令拼接 Payload

**Payload 1 — 分号分隔**:
```bash
curl "http://target/api/ping?host=127.0.0.1;whoami"
```

**Payload 2 — 管道符**:
```bash
curl "http://target/api/ping?host=127.0.0.1|id"
```

**Payload 3 — && 逻辑与**:
```bash
curl "http://target/api/ping?host=127.0.0.1%26%26cat%20/etc/passwd"
```

**Payload 4 — 命令替换**:
```bash
curl "http://target/api/ping?host=\$(hostname)"
curl "http://target/api/ping?host=\`hostname\`"
```

### 3. 验证命令执行

**判断依据**：
- 响应包含 `uid=` → `id` 命令被执行
- 响应包含主机名 → `hostname` 命令被执行
- 响应包含 `/etc/passwd` 内容 → `cat` 命令被执行

**示例响应**：
```
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.042 ms
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 工具

| 工具 | 用途 |
|---|---|
| curl | 命令行测试注入 |
| Burp Suite | 抓包修改参数 |
| Commix | 自动化命令注入工具 |

## 证据要求

什么才算确认命令注入（缺一不可）：

1. **可复现**：同一 payload 重复执行（≥3 次）稳定出现命令执行标志（`uid=`、主机名等）。
2. **对照基线**：提供「含分隔符 payload」与「不含分隔符基准」的成对请求/响应。
3. **分隔符确证**：明确记录哪个分隔符/编码变形实际生效，未生效的尝试作为过滤面证据一并保存。
4. **影响说明**：基于已验证命令（`whoami`/`id`）说明可达的执行上下文（运行用户、是否容器内），不臆测更大影响。
5. **证据脱敏**：命令输出只保留判定所需片段（如 `uid=` 那一行），不落盘完整环境变量或文件内容。

## 输出格式

```json
{
  "finding_id": "command-injection-001",
  "issue_type": "command-injection",
  "severity": "critical",
  "endpoint": "/api/ping",
  "parameter": "host",
  "payload": "127.0.0.1;whoami",
  "evidence": "响应包含 uid=33(www-data)",
  "remediation": "使用参数化命令（subprocess list 形式），过滤特殊字符"
}
```

## 禁止事项

- **只读原则**：仅检测，不执行危险命令（如删除系统文件）
- **无害 Payload**：使用 `whoami` `id` `hostname` 验证
- **零触网**：测试用 mock 或本地环境
