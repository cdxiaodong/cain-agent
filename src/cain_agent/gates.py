"""阶段门控 — recon 覆盖率退出门(Phase 5-A1)。

经验吸收(匿名化):阶段退出条件必须由**代码裁决**,不依赖模型自评
「我探完了」——端点数与探测计数不达标时,后续阶段降级而非盲跑。

纯函数零 IO:输入端点草稿与探测计数,输出门控判定;接线层
(handlers)负责把判定写进 caveats/state 并据此降级。probe 计数数据源
接入前,缺省阈值取宽松值(0),保证既有链路零行为变化。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CoverageConfig:
    """覆盖率门阈值(缺省全宽松:零变化原则,显式配置才拦截)。"""

    min_endpoints: int = 0
    min_probes_per_endpoint: int = 0
    min_probed_ratio: float = 0.0


@dataclass(frozen=True)
class CoverageVerdict:
    """门控判定:pass 与否 + 人类可读原因链。"""

    passed: bool
    reasons: tuple[str, ...] = ()
    endpoint_count: int = 0
    probed_ratio: float = 0.0


def check_coverage(
    endpoints: list[Any],
    probes: Mapping[str, int],
    config: CoverageConfig | None = None,
) -> CoverageVerdict:
    """校验 recon 产出是否达到进入 test 阶段的覆盖率门槛。

    - 端点数下限:endpoints 数量不足 → blocked;
    - 每端点最小探测数:存在探测记录的端点中,有端点计数低于阈值 → blocked
      (阈值 0 时跳过该维度);
    - 探测覆盖率:已探测端点 / 总端点 低于比率阈值 → blocked。
    probes 键匹配端点 url 字段;端点缺 url 的条目按未探测计。
    """
    cfg = config or CoverageConfig()
    urls = [
        str(ep.get("url")) for ep in endpoints if isinstance(ep, Mapping) and ep.get("url")
    ]
    count = len(urls)
    reasons: list[str] = []

    if count < cfg.min_endpoints:
        reasons.append(f"端点数 {count} 低于下限 {cfg.min_endpoints}")

    probed = [u for u in urls if probes.get(u, 0) > 0]
    ratio = (len(probed) / count) if count else 0.0
    if cfg.min_probes_per_endpoint > 0:
        starved = [u for u in probed if probes.get(u, 0) < cfg.min_probes_per_endpoint]
        if starved:
            reasons.append(
                f"{len(starved)} 个端点探测数低于 {cfg.min_probes_per_endpoint}"
            )
    if cfg.min_probed_ratio > 0 and ratio < cfg.min_probed_ratio:
        reasons.append(
            f"探测覆盖率 {ratio:.0%} 低于阈值 {cfg.min_probed_ratio:.0%}"
        )

    return CoverageVerdict(
        passed=not reasons,
        reasons=tuple(reasons),
        endpoint_count=count,
        probed_ratio=ratio,
    )


__all__ = ["CoverageConfig", "CoverageVerdict", "check_coverage"]
