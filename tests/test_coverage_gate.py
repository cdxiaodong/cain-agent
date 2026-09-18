"""Phase 5-A1 覆盖率退出门测试 — 纯函数 + recon/test 接线(零触网零 token)。

经验吸收(匿名化):阶段退出由代码裁决,不信任模型自评;不达标时后续
阶段降级 dry-run 而非盲跑。
"""

from __future__ import annotations

import json
from pathlib import Path

from cain_agent.gates import CoverageConfig, CoverageVerdict, check_coverage
from cain_agent.handlers import (
    RECON_GATE_FILE,
    SkillLoader,
    make_recon_handler,
    make_test_handler,
)
from cain_agent.workspace import Workspace
from tests.test_handlers import _RECON_OUTPUT, SKILLS_ROOT, FakeExecutor, _ctx, _seed_recon_endpoints


def _ep(url: str) -> dict:
    return {"url": url}


# -- 纯函数 ------------------------------------------------------------------------


def test_default_config_fully_lenient() -> None:
    """零变化原则:缺省阈值全宽松,空端点也不拦截(显式配置才拦截)。"""
    v = check_coverage([], {}, CoverageConfig())
    assert v.passed and v.endpoint_count == 0


def test_zero_endpoints_below_explicit_floor() -> None:
    v = check_coverage([], {}, CoverageConfig(min_endpoints=1))
    assert not v.passed and v.endpoint_count == 0
    assert any("端点数" in r for r in v.reasons)


def test_single_endpoint_passes_explicit_floor() -> None:
    v = check_coverage([_ep("https://a.example/")], {}, CoverageConfig(min_endpoints=1))
    assert v.passed


def test_exact_floor_boundary_passes() -> None:
    v = check_coverage([_ep("u1"), _ep("u2")], {}, CoverageConfig(min_endpoints=2))
    assert v.passed


def test_below_floor_blocked_with_reason() -> None:
    v = check_coverage([_ep("u1")], {}, CoverageConfig(min_endpoints=2))
    assert not v.passed
    assert any("低于下限" in r for r in v.reasons)


def test_min_probes_per_endpoint_enforced() -> None:
    eps = [_ep("u1"), _ep("u2")]
    probes = {"u1": 3, "u2": 1}
    v = check_coverage(eps, probes, CoverageConfig(min_probes_per_endpoint=2))
    assert not v.passed
    assert any("探测数低于" in r for r in v.reasons)


def test_probed_ratio_enforced() -> None:
    eps = [_ep("u1"), _ep("u2"), _ep("u3"), _ep("u4")]
    v = check_coverage(eps, {"u1": 1}, CoverageConfig(min_probed_ratio=0.5))
    assert not v.passed
    assert any("覆盖率" in r for r in v.reasons)


def test_probed_ratio_pass_when_met() -> None:
    eps = [_ep("u1"), _ep("u2")]
    v = check_coverage(eps, {"u1": 1, "u2": 2}, CoverageConfig(min_probed_ratio=1.0))
    assert v.passed and v.probed_ratio == 1.0


def test_endpoints_without_url_count_as_unprobed_only() -> None:
    """缺 url 的条目不计入端点数(保守),也不炸。"""
    v = check_coverage([{"method": "GET"}, _ep("u1")], {}, CoverageConfig())
    assert v.passed and v.endpoint_count == 1


def test_default_config_is_lenient_for_probes() -> None:
    """probe 数据源未接入:缺省阈值 0 不因 probes 缺失拦截。"""
    v = check_coverage([_ep("u1")], {}, CoverageConfig())
    assert v.passed


def test_verdict_is_frozen_dataclass() -> None:
    v = check_coverage([_ep("u")], {}, CoverageConfig())
    assert isinstance(v, CoverageVerdict)
    try:
        v.passed = False  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError("verdict 应为 frozen")


# -- recon 接线 -------------------------------------------------------------------


def test_recon_writes_gate_pass(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    result = make_recon_handler(
        FakeExecutor(_RECON_OUTPUT), SkillLoader(SKILLS_ROOT), coverage_gate=True
    )(_ctx(ws, "recon"))
    gate = json.loads((ws.root / RECON_GATE_FILE).read_text(encoding="utf-8"))
    assert gate["recon_gate"] == "pass"  # 2 端点 ≥ 显式下限 1
    assert result.data["recon_gate"] == "pass"


def test_recon_writes_gate_blocked_on_empty(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    result = make_recon_handler(
        FakeExecutor("无可解析输出"),
        SkillLoader(SKILLS_ROOT),
        coverage_gate=True,
        coverage_config=CoverageConfig(min_endpoints=1),
    )(_ctx(ws, "recon"))
    gate = json.loads((ws.root / RECON_GATE_FILE).read_text(encoding="utf-8"))
    assert gate["recon_gate"] == "blocked"
    assert any("coverage_insufficient" in c for c in result.data["caveats"])


def test_recon_gate_default_off_writes_off(tmp_path: Path) -> None:
    """缺省关(零变化):gate.json 写 off,caveats 无覆盖率标记。"""
    ws = Workspace(tmp_path / "ws")
    result = make_recon_handler(FakeExecutor("无可解析输出"), SkillLoader(SKILLS_ROOT))(
        _ctx(ws, "recon")
    )
    gate = json.loads((ws.root / RECON_GATE_FILE).read_text(encoding="utf-8"))
    assert gate["recon_gate"] == "off"
    assert not any("coverage_insufficient" in c for c in result.data["caveats"])


def test_recon_gate_off_skips_check(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    handler = make_recon_handler(
        FakeExecutor("无可解析输出"), SkillLoader(SKILLS_ROOT), coverage_gate=False
    )
    result = handler(_ctx(ws, "recon"))
    gate = json.loads((ws.root / RECON_GATE_FILE).read_text(encoding="utf-8"))
    assert gate["recon_gate"] == "off"
    assert not any("coverage_insufficient" in c for c in result.data["caveats"])


# -- test 接线 --------------------------------------------------------------------


def test_test_handler_degrades_when_gate_blocked(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    (ws.root / RECON_GATE_FILE).write_text(
        json.dumps({"recon_gate": "blocked", "reasons": ["端点数 0 低于下限 1"]}),
        encoding="utf-8",
    )
    executor = FakeExecutor("不应被调用")
    result = make_test_handler(executor, SkillLoader(SKILLS_ROOT))(_ctx(ws, "test"))
    assert result.data["skipped_reason"] == "recon_gate_blocked"
    assert executor.prompts == []  # 降级 dry-run:Agent 根本不启动
    assert (ws.root / "test/gate-skipped.txt").exists()


def test_test_handler_runs_when_gate_pass(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    _seed_recon_endpoints(ws)
    (ws.root / RECON_GATE_FILE).write_text(json.dumps({"recon_gate": "pass"}), encoding="utf-8")
    executor = FakeExecutor("[]")  # 空发现,合法 JSON
    result = make_test_handler(executor, SkillLoader(SKILLS_ROOT))(_ctx(ws, "test"))
    assert len(executor.prompts) == 1  # 正常启动
    assert "skipped_reason" not in result.data


def test_test_handler_gate_missing_means_pass(tmp_path: Path) -> None:
    """旧工作区无 gate.json:向后兼容,正常执行。"""
    ws = Workspace(tmp_path / "ws")
    _seed_recon_endpoints(ws)
    executor = FakeExecutor("[]")
    make_test_handler(executor, SkillLoader(SKILLS_ROOT))(_ctx(ws, "test"))
    assert len(executor.prompts) == 1


def test_test_handler_gate_corrupted_means_pass(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    _seed_recon_endpoints(ws)
    (ws.root / RECON_GATE_FILE).write_text("{not json", encoding="utf-8")
    executor = FakeExecutor("[]")
    make_test_handler(executor, SkillLoader(SKILLS_ROOT))(_ctx(ws, "test"))
    assert len(executor.prompts) == 1  # 损坏降级 pass,不炸
