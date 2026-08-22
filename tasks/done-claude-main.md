# done-claude-main · 2026-08-22 · ScopeGuardHook 命令语义误拦修复

> 对应派活单 `tasks/2026-08-21-am.md`(监工补位)· Claude 主力名下任务

## 分支与提交

- 分支:`feat/2026-08-21-scopeguard-fix`(已推送 origin)
- 提交:`0ae44f7` — `fix(scope): ScopeGuardHook 命令语义误拦修复 — 仅真实网络目标参与判定`
- 署名:`cdxiaodong <84082748+cdxiaodong@users.noreply.github.com>`
- 改动:`src/cain_agent/scope.py`(+340/-17)、`tests/test_scope.py`(+13 条回归)

## 修复内容(对应 smoke-2026-08-19 问题 2)

素材误拦形态:grep 正则 `/api/[a-zA-Z0-9_/.-]*`、本地文件路径、chunk 文件名
`10ejbmr6i2_1p.js`、`2>` 重定向、python 模块 `urllib.request` 被误抽为 target
并拒绝整条命令 — recon/test 48 次 deny 全属此类。

1. **引号感知扫描器**:子命令分割与重定向剥离改为单遍引号感知扫描 —
   引号内 `;`/`>` 不再误切(`python -c 'a;b'` 不再裂出未知程序)、
   `2>&1` 不再被 `&` 切坏、重定向目标文件不再成为 host 候选。
2. **程序三分类**:network(permissive+启发式)/ local(白名单)/ unknown —
   仅网络程序位置参数参与 host 判定;grep 模式/文件名/代码片段不参与。
3. **`_looks_like_host` 收紧**:本地路径(`/`、`./`、`../`、`~`)、正则元字符、
   下划线 token、纯数字端口排除;`user@host` 剥离后按 `[A-Za-z0-9.\-]`
   字符集白名单判定。
4. **无 target 新语义**:纯本地命令放行(ls/cat/grep/python 读文件不再拦);
   网络工具无字面目标(`curl $URL`)、`$(...)` 命令替换、未知程序保持默认拒绝。
5. **heredoc**:引号 marker 正文按字面数据处理(JS `$('sel')`/模板字符串不误拦);
   无引号 marker 的 `$(...)` 展开语义保守拒绝。sudo/env/nohup/timeout 等
   wrapper 剥离后按真实程序归类。

## 安全边界核对(16 组对抗用例全过)

- 引号拼接程序名 `cu"rl"`、反斜杠 `\curl`、绝对路径 `/usr/bin/curl` → shlex
  归一后仍正确判定 ✓
- `Host:` 头注入越权域名 → 仍拦截 ✓;CIDR 边界(段内 allow/段外 deny)✓
- local 程序携带 out-of-scope URL(URL 提取全命令覆盖)→ 仍拦截 ✓
- `$()`/反引号拼接隐藏目标 → 保守拒绝 ✓

## 自测

- `tests/test_scope.py` 60 条全绿(新增 13 条钉死素材误拦场景)
- 全量(排除 11 个云端 pre-existing 收集错误文件,属 Codex-A 任务范围):
  `691 passed, 3 skipped`(基线 678 → +13)
- ruff 全绿
