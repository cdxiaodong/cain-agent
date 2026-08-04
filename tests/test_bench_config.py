"""本地回归靶场 compose 配置静态校验。

不启动容器(CI 友好),只解析 bench/docker-compose.yml 的结构,确保:
- YAML 合法且为 compose 服务定义;
- 每个服务端口绑定都含 127.0.0.1(严禁暴露到局域网);
- 无 privileged: true;
- 无宿主敏感目录挂载(/, /etc, /root, /home, /var 等)。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

COMPOSE_PATH = Path(__file__).resolve().parent.parent / "bench" / "docker-compose.yml"

# 宿主敏感目录前缀:任何挂载源命中即视为风险挂载
SENSITIVE_HOST_PREFIXES = (
    "/",          # 整盘(根目录)
    "/etc",
    "/root",
    "/home",
    "/var",
    "/usr",
    "/bin",
    "/sbin",
    "/boot",
    "/proc",
    "/sys",
)

# 端口绑定中必须出现的回环地址前缀
LOOPBACK = "127.0.0.1"


def _load_compose() -> dict[str, Any]:
    """加载并返回 compose 顶层字典(YAML 结构动态,用 Any 表达)。"""
    text = COMPOSE_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        pytest.fail(f"{COMPOSE_PATH}: 顶层不是 mapping")
    return data  # type: ignore[return-value]


def _services(data: dict[str, Any]) -> dict[str, Any]:
    services = data.get("services")
    if not isinstance(services, dict):
        pytest.fail(f"{COMPOSE_PATH}: 缺少 services 节或非 mapping")
    return services  # type: ignore[return-value]


def _expand_port(short: Any) -> str:
    """把 compose 端口条目统一成字符串,便于检查回环绑定。"""
    # 形态可能是 "127.0.0.1:3000:3000"、8080:80(裸 int)、或 dict(长语法)
    if isinstance(short, dict):
        host_ip = short.get("host_ip")
        return str(host_ip) if host_ip else ""
    return str(short)


def _volume_source(vol: Any) -> str:
    """提取 volume 的宿主源路径(仅 bind mount 有源;命名卷不算)。"""
    if isinstance(vol, str):
        # 形如 "/host/path:/container/path" 或 "/host/path:/container:ro"
        # 但也可能只是容器路径(匿名卷)——含冒号才可能是 bind mount
        if ":" in vol:
            return vol.split(":", 1)[0]
        return ""
    if isinstance(vol, dict):
        src = vol.get("source")
        vol_type = vol.get("type")
        return str(src) if (src and vol_type == "bind") else ""
    return ""


def _is_sensitive_path(path: str) -> bool:
    normalized = re.sub(r"/+$", "", path) or "/"
    return any(
        normalized == s or normalized.startswith(s + "/") for s in SENSITIVE_HOST_PREFIXES
    )


def test_compose_file_exists() -> None:
    assert COMPOSE_PATH.is_file(), f"缺少 compose 文件: {COMPOSE_PATH}"


def test_compose_has_two_bench_services() -> None:
    """预期两个靶标服务:Juice Shop + DVWA。"""
    services = _services(_load_compose())
    assert len(services) >= 2, f"期望至少 2 个服务,实际 {len(services)}"
    names = [str(n).lower() for n in services]
    # 名称宽松匹配,允许后续重命名但语义保留
    assert any("juice" in n for n in names), f"缺少 Juice Shop 服务: {names}"
    assert any("dvwa" in n for n in names), f"缺少 DVWA 服务: {names}"


def test_all_ports_bind_loopback_only() -> None:
    """每个服务的每个端口绑定都必须含 127.0.0.1,严禁暴露到局域网/外网。"""
    services = _services(_load_compose())
    violations: list[str] = []
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        ports = svc.get("ports", []) or []
        if not ports:
            violations.append(f"{name}: 无端口映射")
            continue
        for port in ports:
            expanded = _expand_port(port)
            if LOOPBACK not in expanded:
                violations.append(f"{name}: 端口 {port!r} 未绑定 {LOOPBACK}")
    assert not violations, "存在非回环端口绑定(安全红线):\n" + "\n".join(violations)


def test_no_privileged_service() -> None:
    """任何服务都不得启用 privileged: true。"""
    services = _services(_load_compose())
    for name, svc in services.items():
        if isinstance(svc, dict) and svc.get("privileged") is True:
            pytest.fail(f"{name}: 禁止 privileged: true")


def test_no_sensitive_host_mounts() -> None:
    """禁止挂载宿主敏感目录(根、/etc、/root、/home、/var 等)。"""
    services = _services(_load_compose())
    violations: list[str] = []
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        volumes = svc.get("volumes", []) or []
        for vol in volumes:
            src = _volume_source(vol)
            if src and _is_sensitive_path(src):
                violations.append(f"{name}: 挂载敏感宿主目录 {src!r}")
    assert not violations, "存在宿主敏感目录挂载(安全红线):\n" + "\n".join(violations)


def test_services_use_official_images_not_build() -> None:
    """靶场用官方镜像,不构建自定义镜像(派活单要求:不要 build)。"""
    services = _services(_load_compose())
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        assert "build" not in svc, f"{name}: 禁止 build,必须用官方镜像(image:)"
        assert svc.get("image"), f"{name}: 缺少 image(必须用官方镜像)"
