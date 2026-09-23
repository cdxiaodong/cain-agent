"""Phase 5-A 组合回归(09-20-pm 任务1/09-23 顺延)——三件合入件的组合语义。

链式语义(不改 src/,发现缺陷仅记录,按 09-09 任务3 先例):
- coverage gate blocked → test 降级 dry-run → 空 findings → 报告 caveats
  且无重放清单
- finding 带 replay + 验证池分歧 → model_dissent 与重放清单同现且互不污染
- gate 缺失/损坏 + 旧数据无 replay 键 → 全链兼容
"""

from __future__ import annotations

import json
from pathlib import Path

from cain_agent.handlers import (
    RECON_GATE_FILE,
    SkillLoader,
    make_recon_handler,
    make_test_handler,
)
from cain_agent.report_markdown import ExecutionMeta, render_report_markdown
from cain_agent.workspace import Workspace
from tests.test_handlers import (
    _RECON_OUTPUT,
    _TEST_OUTPUT,
    SKILLS_ROOT,
    FakeExecutor,
    _ctx,
    _seed_recon_endpoints,
)

_META = ExecutionMeta(
    scope_in=("example.com",),
    generated_at="2026-09-23T10:00:00+08:00",
)


def _gate(ws: Workspace, value: str) -> None:
    (ws.root / RECON_GATE_FILE).write_text(
        json.dumps({"recon_gate": value, "reasons": []}), encoding="utf-8"
    )


def _report(conclusions: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "summary": {
            "total": len(conclusions),
            "results": {"confirmed": 0, "likely": 0, "rejected": 0,
                        "inconclusive": len(conclusions)},
        },
        "conclusions": conclusions,
    }


def _concl(**over: object) -> dict:
    base: dict = {
        "finding_id": "f-i1",
        "result": "inconclusive",
        "consensus": "contested",
        "severity": "high",
        "cloud": "web",
        "service": "http",
        "resource": "http://example.com/api/x?id=1",
        "issue_type": "sqli",
        "evidence_hash": "sha256:" + "c" * 64,
        "confidence": 0.8,
        "basis": [{"source": "solver", "detail": "d", "score": 1.0}],
        "memory_hits": [],
        "solver": "t",
        "model_dissent": [],
    }
    base.update(over)
    return base


# -- 链式:gate blocked → dry-run → 空 findings → 报告无重放清单 ----------------------


def test_gate_blocked_chain_empty_findings_no_replay_section(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    _gate(ws, "blocked")
    executor = FakeExecutor("不应被调用")
    result = make_test_handler(executor, SkillLoader(SKILLS_ROOT))(_ctx(ws, "test"))
    assert executor.prompts == []  # dry-run:Agent 未启动
    # 空结论报告:无重放清单、法律声明在位(报告链路自身不因 gate 崩)
    md = render_report_markdown(_report([]), _META)
    assert "重放清单" not in md
    assert "## 法律声明" in md
    assert result.data["skipped_reason"] == "recon_gate_blocked"


def test_gate_blocked_leaves_gate_skipped_artifact(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    _gate(ws, "blocked")
    make_test_handler(FakeExecutor("x"), SkillLoader(SKILLS_ROOT))(_ctx(ws, "test"))
    assert (ws.root / "test/gate-skipped.txt").exists()  # 留痕在位


# -- replay × dissent 同现不污染 ----------------------------------------------------


def test_replay_and_dissent_coexist_without_pollution() -> None:
    concl = _concl(
        replay={
            "method": "GET",
            "url": "http://example.com/api/x",
            "param_names": ["id"],
            "header_names": [],
        },
        model_dissent=[
            {"voter": "verify-2", "verdict": "rejected", "reason": "哈希与资源不符"}
        ],
    )
    md = render_report_markdown(_report([concl]), _META)
    assert "## 重放清单" in md and "id" in md  # replay 节在位
    assert "分歧意见" in md and "verify-2" in md  # dissent 子块在位
    # 互不污染:重放清单**表格行**不含 dissent 理由(节后其他章节允许)
    replay_section = md.split("## 重放清单")[1].split("## ")[0]
    for row in (ln for ln in replay_section.splitlines() if ln.startswith("| f-i1")):
        assert "verify-2" not in row and "哈希与资源不符" not in row
    md.find("分歧意见")
    replay_row_idx = md.find("| f-i1 | GET |")
    assert replay_row_idx != -1


def test_dissent_only_still_renders_without_replay_section() -> None:
    md = render_report_markdown(_report([_concl()]), _META)
    assert "分歧意见" not in md  # 空 dissent 不渲染
    assert "重放清单" not in md


def test_replay_only_no_dissent_block() -> None:
    concl = _concl(
        replay={"method": "GET", "url": "u", "param_names": [], "header_names": []},
    )
    md = render_report_markdown(_report([concl]), _META)
    assert "重放清单" in md and "分歧意见" not in md


# -- 兼容:gate 缺失/损坏 × 旧数据无 replay 键 ---------------------------------------


def test_gate_missing_and_old_finding_dict_full_chain_compat(tmp_path: Path) -> None:
    """旧工作区(无 gate.json)+ 旧 conclusion(无 replay 键):全链不炸。"""
    ws = Workspace(tmp_path / "ws")
    _seed_recon_endpoints(ws)
    executor = FakeExecutor("[]")
    make_test_handler(executor, SkillLoader(SKILLS_ROOT))(_ctx(ws, "test"))
    assert len(executor.prompts) == 1  # gate 缺失=pass,Agent 正常启动
    md = render_report_markdown(_report([_concl()]), _META)  # 无 replay 键
    assert "# Cain 渗透测试报告" in md


def test_gate_corrupted_means_pass_chain(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    _seed_recon_endpoints(ws)
    (ws.root / RECON_GATE_FILE).write_text("{broken", encoding="utf-8")
    executor = FakeExecutor("[]")
    make_test_handler(executor, SkillLoader(SKILLS_ROOT))(_ctx(ws, "test"))
    assert len(executor.prompts) == 1


# -- side_effect_gate × likely × 报告(第三件合入件接线) -----------------------------


def test_likely_conclusion_renders_with_dissent_and_gate_context() -> None:
    """likely 结论(缺副作用证据)+ 分歧同现:三件 Phase5-A 产物齐上报告。"""
    concl = _concl(
        result="likely",
        replay={"method": "POST", "url": "http://example.com/api/x",
                "param_names": ["id"], "header_names": []},
        model_dissent=[{"voter": "verify-1", "verdict": "inconclusive",
                        "reason": "无副作用证据"}],
    )
    md = render_report_markdown(_report([concl]), _META)
    assert "很可能" in md  # likely 标签
    assert "重放清单" in md and "分歧意见" in md  # 三产物同现
    assert "副作用" in md


def test_recon_gate_pass_writes_report_chain_ready(tmp_path: Path) -> None:
    """显式开 gate 且达标:recon 正常 → test 正常(不降级)全链。"""
    ws = Workspace(tmp_path / "ws")
    recon = make_recon_handler(
        FakeExecutor(_RECON_OUTPUT), SkillLoader(SKILLS_ROOT), coverage_gate=True
    )(_ctx(ws, "recon"))
    assert recon.data["recon_gate"] == "pass"
    _seed_recon_endpoints(ws)  # test 依赖 recon 端点,种子补齐(合成链)
    executor = FakeExecutor(_TEST_OUTPUT)
    result = make_test_handler(executor, SkillLoader(SKILLS_ROOT))(_ctx(ws, "test"))
    assert len(executor.prompts) == 1
    assert "skipped_reason" not in result.data
