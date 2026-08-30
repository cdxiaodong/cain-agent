"""report.md 人类可读报告的渲染测试(纯函数,零 token 零触网)。

覆盖派活单要求的三态:空 findings / 单 finding / 多 severity;
外加元数据采集容错与表格单元格转义。
"""

from __future__ import annotations

import json
from pathlib import Path

from cain_agent.findings import hash_evidence
from cain_agent.report_markdown import (
    REMEDIATION_ADVICE,
    ExecutionMeta,
    StageTiming,
    collect_execution_meta,
    render_report_markdown,
)
from cain_agent.workspace import Workspace


def _conclusion(
    finding_id: str,
    severity: str,
    *,
    issue_type: str = "ssti",
    resource: str = "http://example.com/render?tpl=x",
    result: str = "confirmed",
    consensus: str | None = "confirmed",
    confidence: float = 0.9,
    with_memory: bool = True,
) -> dict:
    basis = [
        {"source": "solver", "detail": "solver 上报", "score": 1.0},
        {"source": "verification", "detail": "验证池多数表决: confirmed=3 rejected=0", "score": 1.0},
    ]
    memory_hits: list[dict] = []
    if with_memory:
        basis.append({"source": "memory", "detail": "相似记录 context::k", "score": 0.7})
        memory_hits.append({"record_id": "r-1", "kind": "context", "key": "k", "score": 0.7})
    return {
        "finding_id": finding_id,
        "result": result,
        "consensus": consensus,
        "severity": severity,
        "cloud": "web",
        "service": "http",
        "resource": resource,
        "issue_type": issue_type,
        "evidence_hash": hash_evidence(f"evidence of {finding_id}"),
        "confidence": confidence,
        "basis": basis,
        "memory_hits": memory_hits,
        "solver": "test-agent",
    }


def _report(conclusions: list[dict]) -> dict:
    results = {
        "confirmed": sum(1 for c in conclusions if c["result"] == "confirmed"),
        "false_positive": sum(1 for c in conclusions if c["result"] == "false_positive"),
        "validation_system_error": 0,
        "validation_inconclusive": sum(1 for c in conclusions if c["result"] == "validation_inconclusive"),
    }
    return {
        "schema_version": 1,
        "route": "multi_agent",
        "summary": {"total": len(conclusions), "results": results},
        "conclusions": conclusions,
    }


_META = ExecutionMeta(
    scope_in=("example.com",),
    scope_out=("secret.example.com",),
    stage_timings=(
        StageTiming("recon", "2026-08-30T02:00:00+00:00", "2026-08-30T02:03:10+00:00", 190.0),
        StageTiming("test", "2026-08-30T02:03:10+00:00", "2026-08-30T02:20:00+00:00", 1010.0),
    ),
    generated_at="2026-08-30T02:25:00+00:00",
)


class TestEmptyFindings:
    def test_empty_report_keeps_all_sections(self) -> None:
        text = render_report_markdown(_report([]), _META)

        for section in (
            "# Cain 渗透测试报告",
            "## 执行摘要",
            "## Findings 一览",
            "## 证据哈希索引",
            "## 修复建议",
            "## 法律声明",
        ):
            assert section in text, f"空 findings 仍需保留章节: {section}"
        assert "0 条发现" in text
        assert "本轮未产出任何发现" in text

    def test_empty_report_renders_meta(self) -> None:
        text = render_report_markdown(_report([]), _META)

        assert "example.com" in text
        assert "secret.example.com" in text
        assert "| recon |" in text and "| test |" in text
        assert "190.0" in text and "1010.0" in text


class TestSingleFinding:
    def test_single_finding_renders_every_section(self) -> None:
        conclusion = _conclusion("f-1", "high")
        text = render_report_markdown(_report([conclusion]), _META)

        assert "🟠 **HIGH**" in text, "severity 着色标记应出现在表格"
        assert "90.0%" in text, "confidence 应以百分比渲染"
        assert "solver+verification+memory×1" in text, "依据链摘要应压缩 sources"
        assert conclusion["evidence_hash"] in text, "证据哈希必须可引用"
        assert "已确认" in text and "池表决: 确认" in text
        assert REMEDIATION_ADVICE["ssti"] in text, "已知 issue_type 应给具体修复建议"
        assert "f-1" in text

    def test_evidence_plaintext_never_appears(self) -> None:
        conclusion = _conclusion("f-1", "high")
        text = render_report_markdown(_report([conclusion]), _META)

        assert "evidence of f-1" not in text, "证据原文不得出现在报告任何位置"
        assert text.count(conclusion["evidence_hash"]) >= 2, "详情与索引两处引用哈希"


class TestMultipleSeverities:
    def test_table_orders_severity_high_to_low(self) -> None:
        conclusions = [
            _conclusion("f-low", "low"),
            _conclusion("f-crit", "critical"),
            _conclusion("f-mid", "medium"),
            _conclusion("f-high", "high"),
            _conclusion("f-info", "info"),
        ]
        text = render_report_markdown(_report(conclusions), _META)

        table = text.split("## Findings 一览")[1].split("## 发现详情")[0]
        rows = [line for line in table.splitlines() if line.startswith("| ")]
        # rows[0] 表头,其后为数据行(分隔行 "|---|" 不匹配 "| " 前缀)
        markers = [row.split("|")[2].strip() for row in rows[1:]]
        assert markers == [
            "🔴 **CRITICAL**",
            "🟠 **HIGH**",
            "🟡 **MEDIUM**",
            "🔵 **LOW**",
            "⚪ **INFO**",
        ]

    def test_same_severity_breaks_tie_by_confidence(self) -> None:
        conclusions = [
            _conclusion("f-weak", "high", confidence=0.6, resource="http://ex.com/weak"),
            _conclusion("f-strong", "high", confidence=0.95, resource="http://ex.com/strong"),
        ]
        text = render_report_markdown(_report(conclusions), _META)

        table = text.split("## Findings 一览")[1].split("## 发现详情")[0]
        resources = [
            row.split("|")[4].strip()
            for row in table.splitlines()
            if row.startswith("| ") and "问题类型" not in row
        ]
        assert resources == [
            "http://ex.com/strong",
            "http://ex.com/weak",
        ], "同级应按置信度降序"

    def test_unknown_severity_falls_back_to_neutral_marker(self) -> None:
        conclusion = _conclusion("f-odd", "extreme")
        text = render_report_markdown(_report([conclusion]), _META)

        assert "· **EXTREME**" in text, "未知定级回落中性标记而非崩溃"

    def test_details_order_matches_table(self) -> None:
        conclusions = [
            _conclusion("f-low", "low"),
            _conclusion("f-crit", "critical"),
        ]
        text = render_report_markdown(_report(conclusions), _META)

        assert text.index("🔴 [CRITICAL]") < text.index("🔵 [LOW]")


class TestRemediation:
    def test_known_issue_types_have_specific_advice(self) -> None:
        for issue_type in ("public-read", "metadata-endpoint-reachable", "sqli"):
            assert issue_type in REMEDIATION_ADVICE
            assert len(REMEDIATION_ADVICE[issue_type]) > 10

    def test_unknown_issue_type_falls_back_to_severity_advice(self) -> None:
        conclusion = _conclusion("f-x", "critical", issue_type="brand-new-vuln")
        text = render_report_markdown(_report([conclusion]), _META)

        assert "立即处置" in text, "未知类型按 severity 回落通用建议"
        assert "brand-new-vuln" in text


class TestCellEscaping:
    def test_pipe_and_newline_in_resource_do_not_break_table(self) -> None:
        conclusion = _conclusion("f-1", "high", resource="http://ex.com/a|b\nc")
        text = render_report_markdown(_report([conclusion]), _META)

        table = text.split("## Findings 一览")[1].split("## 发现详情")[0]
        data_rows = [line for line in table.splitlines() if line.startswith("|")]
        assert len(data_rows) == 3, "表头+分隔+单行,注入不得增行"
        assert "a\\|b c" in text, "竖线转义、换行压平"


class TestCollectExecutionMeta:
    def _workspace(self, tmp_path: Path) -> Workspace:
        return Workspace(tmp_path / "ws")

    def test_collects_scope_and_timings(self, tmp_path: Path) -> None:
        ws = self._workspace(tmp_path)
        (ws.root / "scope.yaml").write_text(
            "in_scope:\n  - example.com\n  - 10.0.0.0/24\nout_of_scope:\n  - secret.example.com\n",
            encoding="utf-8",
        )
        ws.write_json(
            "state.json",
            {
                "current_stage": "test",
                "completed_stages": ["recon", "test"],
                "history": [
                    {
                        "stage": "recon",
                        "started_at": "2026-08-30T02:00:00+00:00",
                        "finished_at": "2026-08-30T02:01:40+00:00",
                        "summary": "s",
                        "artifacts": [],
                    },
                    {
                        "stage": "test",
                        "started_at": "2026-08-30T02:01:40+00:00",
                        "finished_at": "2026-08-30T02:04:40+00:00",
                        "summary": "s",
                        "artifacts": [],
                    },
                ],
            },
        )

        meta = collect_execution_meta(ws)

        assert meta.scope_in == ("example.com", "10.0.0.0/24")
        assert meta.scope_out == ("secret.example.com",)
        assert [t.stage for t in meta.stage_timings] == ["recon", "test"]
        assert meta.stage_timings[0].duration_seconds == 100.0
        assert meta.stage_timings[1].duration_seconds == 180.0
        assert meta.generated_at  # 采集即打时间戳
        assert not meta.scope_note and not meta.timings_note

    def test_missing_scope_and_state_degrades_to_notes(self, tmp_path: Path) -> None:
        meta = collect_execution_meta(self._workspace(tmp_path))

        assert meta.scope_in == () and meta.scope_out == ()
        assert "scope.yaml" in meta.scope_note
        assert meta.stage_timings == ()
        assert "state.json" in meta.timings_note or "阶段历史" in meta.timings_note

    def test_corrupt_state_degrades_without_raising(self, tmp_path: Path) -> None:
        ws = self._workspace(tmp_path)
        (ws.root / "state.json").write_text("{ broken json", encoding="utf-8")

        meta = collect_execution_meta(ws)

        assert meta.stage_timings == ()
        assert "state.json" in meta.timings_note

    def test_unparseable_timestamps_render_placeholder(self, tmp_path: Path) -> None:
        ws = self._workspace(tmp_path)
        ws.write_json(
            "state.json",
            {
                "history": [
                    {
                        "stage": "recon",
                        "started_at": "not-a-time",
                        "finished_at": "also-not-a-time",
                        "summary": "",
                        "artifacts": [],
                    }
                ],
            },
        )

        text = render_report_markdown(
            _report([]),
            collect_execution_meta(ws),
        )

        assert "| recon |" in text
        assert "| — |" in text, "起止时间不可解析时耗时列显示占位符"


class TestDeterminism:
    def test_same_input_same_output(self) -> None:
        conclusions = [_conclusion("f-1", "high")]
        first = render_report_markdown(_report(conclusions), _META)
        second = render_report_markdown(_report(conclusions), _META)

        assert first == second


class TestJsonSchemaCompat:
    def test_renders_from_real_aggregated_report_shape(self, tmp_path: Path) -> None:
        """聚合报告真源(schema_version 1)整包喂入可直接渲染。"""

        payload = {
            "schema_version": 1,
            "route": "multi_agent",
            "summary": {
                "total": 1,
                "results": {
                    "confirmed": 1,
                    "false_positive": 0,
                    "validation_system_error": 0,
                    "validation_inconclusive": 0,
                },
            },
            "manager": {"dispatched_tasks": 2, "aggregate_count": 1},
            "conclusions": [_conclusion("f-real", "high")],
        }
        assert json.dumps(payload)  # 真源可序列化

        text = render_report_markdown(payload, ExecutionMeta())

        assert "## 执行摘要" in text and "## 法律声明" in text
        assert "(未配置)" in text, "元数据缺失时授权范围显示占位而非崩溃"
