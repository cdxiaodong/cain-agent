---
name: webpack-js-analysis
description: Webpack 前端 JS 信息收集技能 —— 发现打包特征、提取 chunk 清单与 sourcemap、批量下载后按规则提取接口/密钥形态/内网信息,产物进端点与资产(敏感串只记类型与哈希)
phase: recon
severity_focus: info
---

# Webpack 前端 JS 信息收集技能

> 定位:信息收集阶段的**前端资产深挖**。现代 SPA 站点的攻击面大半藏在
> 打包 JS 里——未公开接口、调试开关、硬编码凭证形态、内网地址。
> 方法论来源:Webpack_extract(浏览器扩展,红队前端信息收集)与 HaE
> 规则体系的**命令行等价实现**——全部动作只用 Bash/Grep,headless
> Agent 可直接执行,不依赖浏览器。

## 触发条件

- 目标为 SPA/前后端分离站点(响应含大量 `script src` 指向
  `/static/js/`、`/dist/`、`/assets/` 等带 hash 的 chunk);
- 页面源码出现 `webpackChunk`、`__NEXT_DATA__`、`window.__INITIAL_STATE__`
  等打包运行时特征;
- 或普通站点希望从 JS 里补充端点清单与敏感信息面。

## 执行流程(五步,全 Bash/Grep)

### 1. 打包特征确认

```bash
# 首页脚本清单与特征
curl -s https://target.example/ | grep -oE '<script[^>]+src="[^"]+"' | head -30
curl -s https://target.example/ | grep -cE 'webpackChunk|__NEXT_DATA__'
```

命中任一特征即进入 JS 深挖;未命中也建议对已有 JS 资产走 4-5 步。

### 2. 清单与 sourcemap 探测

```bash
for p in webpack-manifest.json asset-manifest.json .map; do :; done
# 常见清单
curl -s -o /dev/null -w '%{http_code}\n' https://target.example/webpack-manifest.json
curl -s -o /dev/null -w '%{http_code}\n' https://target.example/asset-manifest.json
# sourcemap:对每个 JS 逐个试 .map 后缀与 //# sourceMappingURL 注释
curl -s https://target.example/static/js/app.abc123.js | tail -c 200 | grep sourceMappingURL
curl -s -o /dev/null -w '%{http_code}\n' https://target.example/static/js/app.abc123.js.map
```

sourcemap 存在 = 可还原源码(含注释与原始路径),价值最高,优先下载。

### 3. 批量下载 JS

```bash
mkdir -p js && cd js
# 从 script src 提取相对路径后逐个下载(域外 CDN 域名须在 scope 内,
# 出界请求会被 PreToolUse 拦截——不要尝试绕过,报告即可)
curl -s -O https://target.example/static/js/chunk-0.js
```

### 4. 规则提取(HaE 式正则,按类分批)

```bash
# 接口路径 → 端点候选(进 endpoints)
grep -rhoE '"/(api|v[0-9])/[A-Za-z0-9/_-]+"' . | sort -u | head -100
# 密钥/凭证形态 → 只记录**类型+出现文件+计数**,明文一律不得复制进产物
grep -rlE 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]+PRIVATE KEY|eyJ[A-Za-z0-9_-]{20,}\.' .
# 内网/基础设施线索
grep -rhoE '(10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]+\.[0-9]+' . | sort -u
grep -rhoiE '(jdbc|redis|amqp|mongo)://[A-Za-z0-9._:-]+' . | sort -u
# 调试与功能开关
grep -rhoiE '(debug|sentry|track|test)[A-Za-z]*\s*[:=]\s*true' . | sort -u | head -20
```

### 5. 产物归位

- 提取到的接口路径 → 追加进本轮 endpoints 草稿(带 `source: webpack-js`
  标注,供覆盖率门与 Scout 假设生成消费);
- 密钥形态命中 → 记录类型/文件/计数,**证据只做哈希**,明文不落盘
  (产线数据信任边界:明文凭证不进任何产物);
- 内网地址与连接串 → 同上,类型+哈希。

## 误报规避

- chunk 文件名 hash 相同的只下载一次(等值文件);
- `AKIA`/`AIza` 等形态用长度+字符类双重约束,单命中也须标注
  `possible-fp`(测试数据/mock 常见于前端);
- sourcemap 还原后优先搜注释(任务标记、修复标记、`@deprecated` 等)——
  注释里的接口往往未进网关鉴权。

## 与后续阶段的衔接

- 端点补充 → 覆盖率门(Phase 5-A1)统计口径直接受益;
- 密钥形态类型 → test 阶段可设计"凭证有效性验证"假设(只验格式响应,
  不实际使用);
- 本技能只收集不利用:发现的任何接口/凭证都交由 test 阶段在授权范围内
  按技能验证。

## 三层测试模型

> 对齐 DESIGN §3.1:L1 快速确认 → L2 深入提取 → L3 对抗混淆,逐层推进,
> 每层只做上一层成立后才推进的事。

- **L1 快速确认(每个站点必做)**:首页 script 清单 + 打包特征计数
  (`webpackChunk`/`__NEXT_DATA__`),manifest 存在性探测。全部 200/404
  探测不超 10 个请求。
- **L2 深入提取(L1 命中特征后)**:sourcemap 逐 JS 探测与下载,chunk
  清单展开,批量规则提取。请求量与 JS 数量线性相关,同 hash 去重。
- **L3 对抗混淆(L2 有产出且高价值时)**:对 webpack runtime 做模块 id
  还原(常见于自定义 loader 混淆),sourcemap 缺失时对 chunk 做
  `eval`/`Array.prototype.join` 反拼接定位。仅限高价值目标,不做全量。

## 证据要求

- 端点候选:记录 `source: webpack-js` + 命中文件 + 上下文一行(仅路径,
  不带查询值);
- 密钥/凭证形态:**类型 + 文件名 + 计数 + 内容哈希**,明文不进任何产物
  (含 endpoints.json / assets / 日志);单命中标 `possible-fp`;
- 内网地址/连接串:同密钥口径;
- 所有下载的 JS 留在工作区供复核,清单(文件名+sha256)进 assets。

## 禁止事项

- 不利用:发现的接口/凭证一律交 test 阶段在授权范围内验证,本阶段只收集;
- 不扩张:JS 引用的域外 CDN 请求须在 scope 内,出界即止(PreToolUse 会
  拦截,不要重试绕过);
- 不复制明文凭证进任何输出(含给用户的总结文本);
- 不对目标做高频请求:chunk 下载串行或低并发,单站点 JS 下载总量有上限
  (默认 50 个文件)。
