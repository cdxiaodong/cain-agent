# GitHub 仓库元数据建议 · cain-agent

> 用途:为 ROADMAP「GitHub topics/description/homepage 补全」提供**待人工填写**的现成文案。
> 去向:GitHub 仓库 → Settings → General → About 区块(Description / Website / Topics),或用 `gh` 命令一键配置(见文末)。
> 依据:`DESIGN.md §5 推广节奏`(topics 打满 cloud-security/pentest/ai-agent/aliyun...)。
> 日期:2026-08-03。

## 1. Description(一句话简介)

GitHub 限制 350 字符，建议控制在 120 字符内、英文为主(便于国际搜索 + Awesome 列表收录)。

**推荐文案(直接复制):**

```
Real-world AI penetration testing engineer for authorized assessments — built-in cloud module covering AWS/Azure/GCP + Aliyun/Tencent/Huawei clouds. Built on Claude Agent SDK. Not a CTF toy.
```

**中文备选(若主打国内传播期):**

```
实战型 AI 渗透测试工程师:面向真实授权评估，内置覆盖国际云 + 国产云的云渗透模块。基于 Claude Agent SDK。
```

> 定位锚点必须保留两个关键词:**「authorized / 授权」**(合规信号)、**「cloud module / 云渗透模块」**(差异化)。避免出现「framework」等已被放弃的旧定位词。

## 2. Homepage(主页)

Phase 0 暂无独立站点/演示页。

**当前建议:**

```
(留空)
```

> 理由:GitHub 仓库本身会自动展示在 About 区，填仓库 URL 属冗余。待 Phase 1「Docker 一键运行 + 3 分钟演示视频」落地后，再填演示视频链接或 GitHub Pages 地址。

**Phase 1 后可填候选:**

- 演示视频(B 站 / YouTube 链接)
- GitHub Pages 文档站(若启用)

## 3. Topics(话题标签)

GitHub 上限 20 个，本清单给 **12 个推荐**，全部小写、连字符分隔、单主题词优先。

| # | topic | 选入理由 |
|---:|---|---|
| 1 | `cloud-security` | 主赛道，DESIGN 钦点首项 |
| 2 | `pentest` | 核心能力，DESIGN 钦点 |
| 3 | `ai-agent` | 技术形态，DESIGN 钦点 |
| 4 | `aliyun` | 国产云独家卖点，差异化关键词 |
| 5 | `penetration-testing` | `pentest` 的全称变体，扩大搜索召回 |
| 6 | `claude-agent-sdk` | 技术底座，便于 SDK 生态检索 |
| 7 | `red-team` | 攻防/红队圈层检索 |
| 8 | `llm` | LLM Agent 受众覆盖 |
| 9 | `security-tools` | 安全工具收藏夹常逛标签 |
| 10 | `cloud-pentest` | 垂直场景长尾词 |
| 11 | `aws` | 云覆盖广度信号(后续扩 Tencent/Azure 视需要补) |
| 12 | `bug-bounty` | 实战授权评估的受众来源 |

**备选(若需替换，从下列挑):** `tencent-cloud`、`huawei-cloud`、`azure`、`gcp`、`offensive-security`、`vulnerability-assessment`、`automation`、`python`。

> 策略:前 4 个为 DESIGN 强制项，必须保留;国产云标签(`aliyun`)是与同类项目(多只覆盖国际云)划清界限的关键。凑满 10 个左右的下限已满足，多了不影响。

## 4. 一键配置(可选，`gh` 命令)

若已登录 `gh` CLI，可直接套用(替换 `<owner>/<repo>`，topics 用逗号分隔、无空格):

```bash
gh repo edit <owner>/<repo> \
  --description "Real-world AI penetration testing engineer for authorized assessments — built-in cloud module covering AWS/Azure/GCP + Aliyun/Tencent/Huawei clouds. Built on Claude Agent SDK. Not a CTF toy." \
  --add-topic cloud-security,pentest,ai-agent,aliyun,penetration-testing,claude-agent-sdk,red-team,llm,security-tools,cloud-pentest,aws,bug-bounty
```

> homepage 暂不通过命令设置(留空)。`--description` 中若含特殊字符，注意 shell 转义或改在网页后台粘贴。

## 5. 填写检查清单

- [ ] Description 已粘贴(含 authorized + cloud module 关键词)
- [ ] Topics ≥ 10 个，且 `cloud-security`/`pentest`/`ai-agent`/`aliyun` 四项齐全
- [ ] Homepage 暂留空(Phase 1 演示页上线后再补)
- [ ] About 区「Releases」/「Packages」按需开关
- [ ] 确认仓库仍为 Public、LICENSE(Apache-2.0)在根目录可见
