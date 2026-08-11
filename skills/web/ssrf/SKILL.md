---
name: ssrf
description: SSRF 测试技能，覆盖盲 SSRF、内网可达性与七类主流云元数据服务的低影响验证
phase: test
severity_focus: high
---

# 服务端请求伪造测试技能（SSRF）

> 仅用于书面授权的安全测试。目标是用最少请求证明服务端出站能力及其安全影响；元数据响应中的凭证、令牌和证书只记录类型与哈希，不保存或使用原文。

## 触发条件

- 业务接受 URL、主机名或回调地址，例如链接预览、远程图片、文档转换、Webhook 测试、RSS 抓取和远程文件导入。
- `url`、`target`、`src`、`image_url`、`callback` 或 `webhook_url` 等参数会触发服务端请求。
- 错误信息、耗时差异或响应正文能反映目标地址的连接状态。
- DNS 或 HTTP OOB 日志显示请求来自目标系统的服务端出口。
- 资产证据表明应用运行在云实例上，且授权范围明确包含对应的链路本地元数据服务。

## 三层测试模型

### L1：确认服务端出站请求

1. 将参数指向授权测试方控制的 `https://callback.example.com/ssrf/<nonce>`。
2. 记录唯一 nonce、服务端出口地址、时间和请求头；不要仅凭浏览器侧请求下结论。
3. 依次检查 HTTP/HTTPS、重定向和 DNS 解析行为。只有授权明确允许时，才检查非 HTTP 协议。
4. 比较连接成功、拒绝和超时三类结果，但不进行全端口或全网段扫描。

### L2：验证内网或云元数据可达性

先用无敏感信息的元数据路径确认云厂商和实例身份，再请求角色名称。只有取得角色名称且授权允许时，才对凭证路径发起一次验证请求。客户端不能设置必需请求头、HTTP 方法或 IMDSv2 token 时，应记录“防护生效”，不得宣称可读取凭证。

#### 七类云元数据端点矩阵

| 云平台 | 探测 Payload / 必需条件 | 凭证或身份路径 | 预期响应与确认标准 |
|---|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/instance-id`；IMDSv2 先向 `/latest/api/token` 发送 `PUT`，请求头 `X-aws-ec2-metadata-token-ttl-seconds: 60` | `/latest/meta-data/iam/security-credentials/`，再追加返回的角色名；IMDSv2 请求须带 `X-aws-ec2-metadata-token` | 实例 ID 通常以 `i-` 开头；角色列表为文本；凭证 JSON 含 `AccessKeyId`、`SecretAccessKey`、`Token`、`Expiration`。仅 IMDSv1 可读不代表 IMDSv2 可绕过。 |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01`，请求头 `Metadata: true` | `/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F` | 实例响应 JSON 含 `compute`、`network`；托管身份响应含 `access_token`、`expires_in`、`resource`。缺少 `Metadata: true` 时的拒绝响应不是漏洞确认。 |
| GCP | `http://metadata.google.internal/computeMetadata/v1/instance/id`，请求头 `Metadata-Flavor: Google`；也可使用链路本地地址 `169.254.169.254` | `/computeMetadata/v1/instance/service-accounts/default/token` | 实例 ID 为文本；令牌响应 JSON 含 `access_token`、`expires_in`、`token_type`，且响应头通常含 `Metadata-Flavor: Google`。无法注入必需请求头时不得判定可取令牌。 |
| 阿里云 | `http://100.100.100.200/latest/meta-data/instance-id`；加固实例先向 `/latest/api/token` 发送 `PUT`，请求头 `X-aliyun-ecs-metadata-token-ttl-seconds: 60` | `/latest/meta-data/ram/security-credentials/`，再追加角色名；加固模式带 `X-aliyun-ecs-metadata-token` | 实例 ID 为文本；角色列表为文本；凭证 JSON 常含 `AccessKeyId`、`AccessKeySecret`、`SecurityToken`、`Expiration`。应分别记录旧模式与 token 模式结果。 |
| 腾讯云 | `http://metadata.tencentyun.com/latest/meta-data/instance-id`，解析地址通常为 `169.254.0.23` | `/latest/meta-data/cam/security-credentials/`，再追加角色名 | 实例 ID 与角色名为文本；角色凭证 JSON 含 `TmpSecretId`、`TmpSecretKey`、`Token`、`ExpiredTime`。只允许访问链路本地元数据主机，不探测相邻地址。 |
| 华为云 | `http://169.254.169.254/openstack/latest/meta_data.json` | `/openstack/latest/securitykey` | 实例元数据 JSON 含 `uuid`、`name` 等字段；临时安全凭证响应包含 `access`、`secret`、`securitytoken`。若服务返回空值或拒绝，记录实际状态，不重复轰炸。 |
| Oracle Cloud | `http://169.254.169.254/opc/v2/instance/`，请求头 `Authorization: Bearer Oracle` | `/opc/v2/identity/` 下的实例主体材料，仅验证条目是否存在 | 实例响应 JSON 含 `id`、`compartmentId`、`region`；身份目录可能列出证书、私钥或中间证书条目。不得下载私钥或使用实例主体访问云 API。 |

#### 最小化检测方法

以下为“将目标 URL 作为参数传给已确认的 SSRF 入口”的抽象示例，`app.example.com` 是合成域名：

```http
GET /fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Finstance-id HTTP/1.1
Host: app.example.com
```

若入口支持自定义请求头，分别验证 Azure 的 `Metadata: true`、GCP 的 `Metadata-Flavor: Google`、Oracle 的 `Authorization: Bearer Oracle` 以及 AWS/阿里云 token 头。不要把浏览器直连元数据端点的结果当作 SSRF 证据。

盲 SSRF 无正文回显时，先以 `callback.example.com` 的 OOB 记录确认服务端请求。元数据服务不会对公网 OOB 回连，因此仅凭 DNS 回连只能确认 SSRF，不能确认元数据可达；需结合代理返回的状态、长度、稳定时序或授权的响应摘录。

### L3：验证常见防护是否可绕过

- 重定向：受控合成域名返回一次 `302` 到授权内网目标，确认每一跳是否重新执行地址校验。
- 地址规范化：检查 IPv4、IPv6、整数和短地址在“校验器”与“请求库”中的解析是否一致。
- DNS 重绑定：仅在书面授权且有受控 DNS 时验证，固定最小请求次数并保留解析日志。
- URL 解析差异：针对目标实际使用的解析库设计用例，不批量投递混淆 Payload。
- 协议处理：若允许 `file`、`gopher` 或 `dict`，只证明协议可达，不发送写入、持久化或破坏性指令。

## SSRF 利用链与定级

验证链路为：`SSRF 入口 → 链路本地元数据 → 实例/角色身份 → 短期凭证存在性 → 只读权限评估 → 潜在提权路径`。

1. **元数据可达**：获取不敏感的实例 ID，证明请求确实抵达对应云的元数据服务。
2. **角色识别**：读取角色或托管身份名称，不请求无关元数据。
3. **凭证存在性**：响应中出现预期字段即停止；证据仅保存字段名、有效期和原文哈希。
4. **权限评估**：不使用窃取到的凭证。基于已知角色策略、资产侧配置证据或由授权方提供的脱敏策略做离线分析。
5. **提权判断**：只有离线策略证据明确显示可附加高权限策略、传递角色或修改信任关系时，才记录潜在提权路径；不得实际执行提权。

可读取普通实例元数据通常不足以单独定为 critical。能够读取短期凭证且离线证据证明其具有高权限或明确提权路径时，才考虑 critical；否则按已验证的数据暴露和网络边界影响定级。

## 证据要求

1. 记录完整的入口请求、唯一 nonce、时间、服务端响应状态与必要的脱敏摘录。
2. OOB 证据须包含目标服务端出口发起的 DNS/HTTP 请求，而不是测试人员客户端请求。
3. 元数据证据须注明云平台、路径、必需请求头是否可控、实例 ID 或角色名是否返回。
4. 凭证响应只保留字段名称、到期时间和 SHA-256 哈希；凭证原文不得落盘，AK、SK、Token、证书与私钥也不得写入日志。
5. Finding 中区分“SSRF 已确认”“元数据可达”“凭证存在”“潜在提权”四个事实层级，未验证部分明确标注为假设。

```json
{
  "type": "ssrf",
  "severity": "high",
  "endpoint": "https://app.example.com/fetch",
  "cloud": "synthetic-cloud-label",
  "metadata_reachable": true,
  "credential_fields_observed": ["access_key_id", "session_token", "expiration"],
  "credential_value_sha256": "<redacted-hash>",
  "privilege_escalation": "offline-policy-evidence-required"
}
```

## 禁止事项

- 不访问书面授权范围外的主机、网段或云账户；链路本地元数据端点也必须在授权范围内。
- 不保存、回显、导出或使用任何 AK、SK、Token、证书、私钥和连接串原文。
- 不用元数据凭证调用云 API，不执行提权，不创建用户、密钥、策略或持久化入口。
- 不对内网执行全端口、全网段扫描，不通过 SSRF 对内部服务发送写入或破坏性命令。
- 不把超时、DNS 解析成功、通用错误页或客户端直连结果单独作为元数据可达证据。
