# Codex-B 交付汇报 · 2026-08-05(Day 3 · 任务 3)

> 任务:本地回归靶场 compose + Benchmark 评测方案文档
> 状态:**完成,三绿通过,docker-compose config 零警告,待 21:00 验收**

## 分支

`test/2026-08-05-bench-range`(从 main@4d74363 切出,**未碰 main**)

## 改动文件清单(3 个新文件,322 行新增)

| 提交 | 文件 | 说明 |
|---|---|---|
| `3c1cf85` test(bench) | `bench/docker-compose.yml` | Juice Shop + DVWA,端口均绑 127.0.0.1,healthcheck,官方镜像 |
| `3c1cf85` test(bench) | `tests/test_bench_config.py` | 静态校验:YAML 合法/端口含 127.0.0.1/无 privileged/无敏感挂载/官方镜像不 build |
| `d2c8552` docs(bench) | `docs/benchmark-plan.md` | 两层评测体系:靶场回归(4 指标口径)+ 实战验证(授权渠道与证据留存) |

## 自测结果(三绿)

- `ruff check src tests` → All checks passed
- `pyright` → **0 errors, 0 warnings, 0 informations**(指定 venv 解释器跑全仓库)
- `pytest`(全量)→ **121 passed**(本次新增 6 个 + 既有 115 个全绿)
- `docker-compose -f bench/docker-compose.yml config` → **exit 0,零警告**(渲染确认两服务 host_ip=127.0.0.1)

## 关于 pyright 的环境说明(非任务范围,仅透明披露)

默认调用 pyright 时,`src/cain_agent/cloud/aliyun_oss.py` 的 `import oss2` 报告无法解析——这是 main 上**既有的本地环境发现怪癖**:

- `oss2>=2.18` 已在 `pyproject.toml` 依赖声明、`.venv` 已安装(`import oss2` 运行时成功);
- pyright 默认环境发现未定位到该 venv;显式指定解释器(`--pythonpath .venv/bin/python`)后,**全仓库含 oss2 在内 0 errors**;
- 该问题存在于 main@4d74363,与本 bench 任务无关;`src/` 为冻结区,派活单要求「不动 skills/ 和 src/」,故未修改。建议 Lead 后续在 `[tool.pyright]` 补 `venvPath`/`venv` 让 CI 与本地默认调用一致。

## 验收对照(派活单逐项)

| 要求 | 落实 |
|---|---|
| Juice Shop(SQLi/XSS)+ DVWA(经典漏洞面),官方镜像 | `bkimminich/juice-shop` + `vulnerables/web-dvwa`,无 build |
| 端口仅绑 127.0.0.1,严禁局域网暴露 | 两服务均 `127.0.0.1:HOST:CONTAINER`,测试 `test_all_ports_bind_loopback_only` 钉死 |
| 注明仅用于本地授权回归测试 | compose 顶部注释 + benchmark-plan 两处声明 |
| healthcheck 配上 | juice-shop 用 node http 探活、dvwa 用 curl 探 login.php |
| 不 build 自定义镜像 | 测试 `test_services_use_official_images_not_build` 钉死 |
| 静态校验 YAML 合法/端口 127.0.0.1/无 privileged/无敏感挂载 | 6 个测试覆盖,CI 友好不起容器 |
| 两层评测体系:靶场回归(检出率/误报率/耗时/token 四指标)+ 实战验证 | benchmark-plan §第一层四指标口径定义 + §第二层授权渠道 |
| 指标口径清晰(什么算检出、什么算误报) | TP/FP/FN/TN 与去重口径逐条定义 |
| 实战层仅合法授权渠道 + 授权证据留存 | 漏洞盒子/补天/VDP/自有资产/授权客户五渠道 + 五条证据红线 |
| docker compose config 验证(本机可用则结果入汇报) | 已验证,exit 0 零警告 |
| 不写评测执行脚本、不动 skills/src、不启动真实扫描 | 未触及;diff 仅 3 个新文件 |

## 内容要点

- **指标口径可机械判定**:检出率=TP/(TP+FN),误报率=FP/(FP+TN);inconclusive 单列「待校验」不计误报;同漏洞多 finding 经 `findings.dedup` 去重只计一次(对齐 §3.3)。
- **授权证据红线**:每个实战目标必须有书面授权,scope 由配置强制,披露即脱敏,凭证只哈希不落明文,只读原则。
- **实战层不追求检出率百分比**:真实目标 ground truth 未知,只计 confirmed 且经外部确认的发现。

## 并发隔离

全程独立 git worktree(`cain-agent-wt-bench`)完成,提交后即移除。主工作区当前在 Lead(core)/Codex-A(docker)分支,我未触碰其任何文件。
