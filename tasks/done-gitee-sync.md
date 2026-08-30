# done — feat/2026-08-29-gitee-sync(gitee-sync 重派,串行接手)

> 交付:2026-08-30(gitee-sync 任务)
> 分支:`feat/2026-08-29-gitee-sync`(Codex-A 08-29 起草的未提交半成品,
> 由 Claude 会话审计补全后交付;工作区改动已平移到 08-30 最新 main=1906175,
> 合并零冲突)

## 交付内容

- **`scripts/gitee_sync.sh`**:mirror push 到 Gitee 的同步脚本
  - 凭证:只读 `GITEE_TOKEN` 环境变量,经一次性 Git credential helper
    注入——令牌零硬编码,不进命令行参数、不进脚本输出、不落仓库;
  - `--dry-run`:完整校验配置(token 存在性与空白检查、host/owner/repo
    格式、git 可用、来源 remote 存在、来源 ref 可解析),打印脱敏后的
    `git push --mirror` 命令后退出,不执行、不触网;
  - `--source-remote`(默认 origin)/ `--source-ref`(默认 main)/
    `--gitee-owner` / `--gitee-repo` / `--gitee-host`(默认 gitee.com)
    均可参数化,环境变量 `GITEE_OWNER` / `GITEE_REPO` / `GITEE_HOST` 同名默认;
  - 真实推送经 `exec git push --mirror`,清理远端多余引用(mirror 语义)。
- **README.zh-CN.md「国内镜像」一节**:环境变量示例、dry-run 先行、
  首推建议由用户手动执行确认覆盖行为、`--mirror` 语义提示。
- **`tests/test_gitee_sync.py` 5 例**(临时 git 仓库 + 隔离 env 驱动,
  零网络):dry-run 校验与命令构造 / 来源 remote 缺失拒绝 / GITEE_TOKEN
  缺失拒绝 / 令牌不外泄静态断言 / 脚本可执行位。
- CHANGELOG 补 2026-08-30 条目。

## 质量门

- ruff check:绿;新测试文件 ruff format 已过;
- pytest:1042 passed + 3 skipped(main 基线 1037 + 5);
- pyright:22 errors 与 main 基线完全一致,新文件零错误。

## 备注

- **真推留用户首推**(按派活单要求未执行任何真实 Gitee 推送);首次真推
  前需在 Gitee 建空仓库并导出 `GITEE_TOKEN` / `GITEE_OWNER` / `GITEE_REPO`;
- 真推的 git 用户名固定为 `oauth2`(token 作密码)——若 Gitee 对该用户名
  拒绝,后续可加 `GITEE_USERNAME` 覆盖(一行改动,未预做);
- `--mirror` 会删除 Gitee 侧多余引用,README 已提示目标仓库仅作镜像;
- ROADMAP「Gitee 同步 + 社区运营」条目含社区运营未启动,未勾选,留给 Lead
  合并时定夺。
