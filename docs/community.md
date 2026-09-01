# 社区参与指引 · Community

欢迎参与 Cain。本项目面向**授权安全测试**场景,贡献同样遵循这一边界。

## 行为准则

- 只讨论与授权测试相关的内容;请求协助攻击未授权目标的内容会被直接关闭。
- 不在 Issue / PR / 讨论中粘贴真实凭证、内网拓扑或未脱敏的证据材料。

## 提 Issue

请选择对应模板(见 `.github/ISSUE_TEMPLATE/`):

| 类型 | 用途 | 必填信息 |
|---|---|---|
| Bug 报告 | 复现行为异常 | 版本(`cain-agent --version`)、复现步骤、期望与实际行为、最小配置 |
| 功能建议 | 新能力 / 改进 | 使用场景、为什么现有能力不够、期望形态 |
| 安全问题 | 检测规则 / 脱敏 / scope 相关缺陷 | **不要在公开 Issue 描述可利用细节**——走 Security Advisory(仓库 Security 页)私下报告 |

通用要求:一个 Issue 一个主题;先搜索是否已有同类 Issue;标题用一句话说清问题。

## 提 PR

1. 从 `main` 拉出独立分支(命名:`feat/<主题>` / `fix/<主题>` / `test/<主题>`);
2. 开发环境:`pip install -e ".[dev,cloud]"`;
3. 提交前本地三绿:
   ```bash
   ruff check src tests
   pytest -q
   python -m bench.run_benchmark --suite vuln-tf --output /tmp/bench.md   # 涉及检测逻辑时
   ```
4. PR 描述包含:改了什么、为什么、怎么验证的(测试输出/报告摘录);
5. 等待 review——涉及安全语义(scope / 只读约束 / 双会话校验)的改动会被重点审查。

## 开发约定

- **测试**:新逻辑必须有测试;修 bug 先写复现测试再修;
- **署名**:commit 使用真实姓名 + noreply 邮箱;不引入他人署名;
- **零凭证**:测试与 fixture 一律 mock,不出现真实 AK/SK/token;
- **零触网**:单元测试不得依赖外网;需要网络的验证放 smoke/bench 且明确标注;
- **依赖**:新增第三方依赖需在 PR 中说明理由;执行链路上保持最小依赖面;
- **文档**:面向用户的行为变更同步更新 `README.md` 与 `README.zh-CN.md`。

## 安全报告

检测绕过、凭证泄露、scope 逃逸类问题请**不要开公开 Issue**:
使用 GitHub Security Advisories(仓库 Security → Report a vulnerability)私下报告,
会在 72 小时内响应。

---

## 项目状态记录

- 增长数据(不定期更新,数据见对应日报):

| 日期 | Star | Fork | 备注 |
|---|---|---|---|
| 2026-08-03 | 21 | 2 | 项目启动(rename 自旧仓库) |
| 2026-08-21 | 284 | 67 | v0.2.0 发布前 |
| 2026-08-23 | 328 | 77 | v0.2.0 发布后一周 |

- 目标:fork ≥ 200(2027.07 窗口,详见 ROADMAP Phase 4)。
