# syntax=docker/dockerfile:1
#
# Cain Agent — Docker 一键运行镜像
# Phase 1 收官件:docker build + docker run 即可跑起 CLI。
#
# 安全原则:
#   - 非 root 用户(cain)运行
#   - 阿里云凭证通过 -e 环境变量传入,绝不 BAKE 进镜像
#   - 镜像仅含运行时依赖,不含测试/文档/.git

FROM python:3.11-slim AS runtime

# 元数据
LABEL org.opencontainers.image.title="cain-agent" \
      org.opencontainers.image.description="Real-world AI Penetration Testing Engineer (authorized use only)" \
      org.opencontainers.image.license="Apache-2.0"

# 系统依赖:ca-certificates 用于 HTTPS;创建非 root 用户 cain
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 cain \
    && useradd --system --uid 1000 --gid cain \
       --create-home --home-dir /home/cain --shell /sbin/nologin cain

# 工作目录:workspace 卷将挂载到 /workspaces/cain
WORKDIR /app

# 先拷贝构建元数据,利用层缓存
COPY pyproject.toml README.md ./
COPY src/ src/

# 安装项目(纯安装,不留构建缓存)
RUN pip install --no-cache-dir .

# workspace 挂载点
RUN mkdir -p /workspaces/cain && chown cain:cain /workspaces/cain
WORKDIR /workspaces/cain

# 切换非 root 用户
USER cain

# 入口:CLI,默认显示帮助
ENTRYPOINT ["cain-agent"]
CMD ["--help"]
