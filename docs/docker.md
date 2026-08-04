# Docker 一键运行

## 构建

```bash
docker build -t cain-agent:latest .
```

首次构建会拉取 `python:3.11-slim` 基础镜像并 `pip install .`，后续构建利用层缓存。

## 验证

```bash
docker run --rm cain-agent:latest --version
```

输出形如 `cain-agent 0.1.0` 即镜像可用。

## 镜像特征

| 属性 | 值 |
|------|-----|
| 基础镜像 | `python:3.11-slim` |
| 运行用户 | `cain`（uid 1000，非 root） |
| 工作目录 | `/workspaces/cain` |
| ENTRYPOINT | `cain-agent` |
| 默认 CMD | `--help` |

## 挂载 workspace 卷

workspace（scope.yaml / assets.json / findings.json / 阶段子目录）通过 `-v` 挂载进容器：

```bash
docker run --rm \
  -v "$(pwd)/workspace:/workspaces/cain" \
  cain-agent:latest --help
```

容器内 `/workspaces/cain` 即对应宿主机的 `./workspace` 目录，Orchestrator 读写 workspace 文件不会丢失（文件落在宿主机卷上）。

## 阿里云凭证传入

**严禁将 access key 写进 Dockerfile 或 build-arg。** 凭证只在运行时通过 `-e` 环境变量注入：

```bash
docker run --rm \
  -e ALIBABA_CLOUD_ACCESS_KEY_ID="your-key-id" \
  -e ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-secret" \
  -v "$(pwd)/workspace:/workspaces/cain" \
  cain-agent:latest <command>
```

`OssExposureChecker` 按以下顺序读取凭证：

1. 构造参数 `access_key_id` / `access_key_secret`（代码层传入）
2. 环境变量 `ALIBABA_CLOUD_ACCESS_KEY_ID` / `ALIBABA_CLOUD_ACCESS_KEY_SECRET`
3. 环境变量 `OSS_ACCESS_KEY_ID` / `OSS_ACCESS_KEY_SECRET`

任一来源缺失则抛 `OssCredentialError`，不静默继续。

## 只读原则声明

镜像内的 Cain Agent 遵循只读安全原则：

- 所有云操作（OSS 暴露检测等）仅调用只读 API（`get_bucket_acl` / `get_bucket_policy` / `get_bucket_info`），无写/删操作。
- Scope 白名单强制校验目标授权范围，默认拒绝未授权目标。
- 凭证不落盘、不写日志；`evidence` 字段仅记录 ACL grant 与 Policy 语句的元数据（sid/effect），不含凭证或对象内容。

## .dockerignore 说明

`.dockerignore` 排除以下内容以缩减镜像体积、避免敏感文件泄露：

- `.git` / `.github` — 版本控制元数据
- `.venv` / `__pycache__` / `.pytest_cache` — 本地环境与缓存
- `tests/` / `docs/` — 测试与文档，运行时不需要
- `skills/` — 技能知识库，按需挂载而非内置
- `tasks/` / `done-*.md` — 派活与汇报文件
