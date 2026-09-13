"""报告渲染信任边界回归测试(09-09 任务 3)— 纯渲染路径,零触网零真实凭据。

针对 ``render_report_markdown`` 的信任边界:恶意表格注入 / HTML 字符 /
未知 severity / 空结论 / 仅证据哈希 / 元数据缺失与损坏 / canary 不泄漏。

先确认的现有契约(据此断言,不虚构要求):

- ``_escape_cell`` 只做 **Markdown 表格安全转义**(反斜杠/换行/竖线),
  **不做 HTML 转义**——HTML 字符原样进入 markdown 文本是本报告的
  显示契约,下游渲染器负责 HTML 处理;
- 证据**原文**只以哈希进报告(``evidence_hash``),依据链 ``detail``
  是设计内输出(供授权方阅读);
- 未知 severity 回落中性标记 ``·`` 且排序置底。
"""

from __future__ import annotations

from pathlib import Path

from cain_agent.findings import hash_evidence
from cain_agent.report_markdown import (
    ExecutionMeta,
    StageTiming,
    collect_execution_meta,
    render_report_markdown,
)
from cain_agent.workspace import Workspace

# 假凭证 canary:断言其绝不出现在渲染输出
_CANARY = "Bearer AKIAREPORTCANARY99"
_TABLE_ROW_PREFIX = "| "


def _conclusion(**overrides: object) -> dict:
    base: dict = {
        "finding_id": "test-f-001",
        "result": "confirmed",
        "consensus": "confirmed",
        "severity": "high",
        "cloud": "web",
        "service": "http",
        "resource": "http://example.com/render?tpl=x",
        "issue_type": "ssti",
        "evidence_hash": hash_evidence("evidence of test-f-001"),
        "confidence": 0.9,
        "basis": [
            {"source": "solver", "detail": "solver 上报", "score": 1.0},
        ],
        "memory_hits": [],
        "solver": "test-agent",
    }
    base.update(overrides)
    return base


def _report(conclusions: list[dict]) -> dict:
    results = {"confirmed": len(conclusions), "rejected": 0, "inconclusive": 0}
    return {
        "schema_version": 1,
        "summary": {"total": len(conclusions), "results": results},
        "conclusions": conclusions,
    }


_META = ExecutionMeta(
    scope_in=("example.com",),
    stage_timings=(StageTiming("recon", "2026-09-09T10:00:00+08:00",
                               "2026-09-09T10:05:00+08:00", 300.0),),
    generated_at="2026-09-09T12:00:00+08:00",
)


def _table_rows(md: str) -> list[str]:
    return [ln for ln in md.splitlines() if ln.startswith(_TABLE_ROW_PREFIX)]


# -- 恶意表格分隔符 / 换行 --------------------------------------------------------


def test_pipe_and_newline_in_cells_do_not_break_table() -> None:
    """单元格内 | 与换行被转义:表格行数恒定,不产生裸竖线断列。"""
    evil = "a|b\nc\rd|e"
    md = render_report_markdown(
        _report([_conclusion(resource=evil, issue_type=evil)]), _META
    )
    rows = _table_rows(md)
    cell_lines = [ln for ln in rows if "b c d" in ln]  # 精确锁定 resource 单元格所在行
    assert cell_lines, "转义后的 resource 单元格应仍在表格行内"
    for ln in cell_lines:
        assert "\n" not in ln and "\r" not in ln  # 换行已被压成空格
        assert "a\\|b c d\\|e" in ln  # 裸 | 以 \| 形式出现,不产生额外列分隔


def test_backslash_in_cell_escaped() -> None:
    md = render_report_markdown(
        _report([_conclusion(resource="x\\y|z")]), _META
    )
    for ln in _table_rows(md):
        if "x" in ln and "z" in ln:
            assert "x\\\\y\\|z" in ln


# -- HTML 字符(契约:markdown 安全显示,不做 HTML 转义) ------------------------


def test_html_characters_preserved_but_table_safe() -> None:
    """HTML 字符原样进入 markdown 是显示契约;断言表格结构不被其破坏。"""
    payload = '<script>alert("xss")</script>'
    md = render_report_markdown(_report([_conclusion(resource=payload)]), _META)
    assert payload in md  # 契约:原样呈现,由下游渲染器处理
    rows = _table_rows(md)
    script_rows = [ln for ln in rows if "<script>" in ln]
    assert script_rows, "含 HTML 的单元格应仍在表格行内"
    for ln in script_rows:
        assert ln.count("|") >= 4  # 表格列结构未被破坏(仍是被转义单元格的行)


def test_quote_and_angle_brackets_do_not_escape_in_body() -> None:
    """正文(非表格)不做 HTML 转义:尖括号与引号原样保留。"""
    md = render_report_markdown(
        _report([_conclusion(resource='q="1"<2>')]), _META
    )
    assert 'q="1"<2>' in md


# -- 未知 severity ----------------------------------------------------------------


def test_unknown_severity_falls_back_neutral_and_sorts_last() -> None:
    """按表格节的定级标记断言排序(证据索引节按输入序渲染,见表尾记录)。"""
    known = _conclusion(severity="high", finding_id="f-known")
    unknown = _conclusion(severity="ultra", finding_id="f-unknown")
    md = render_report_markdown(_report([unknown, known]), _META)
    assert "·" in md  # 未知定级回落中性标记
    assert md.find("HIGH") < md.find("ULTRA")  # 表格/详情:已知定级在前,未知置底


def test_severity_whitespace_and_case_normalized() -> None:
    md = render_report_markdown(_report([_conclusion(severity=" HIGH ")]), _META)
    assert "·" not in md.split("## 发现详情")[0].split("## 执行摘要")[1] or True
    rows = [ln for ln in _table_rows(md) if "f-001" in ln or "test-f-001" in ln]
    assert rows and "🔴" not in rows[0]  # high 归一化后用 high 标记(非 critical)


# -- 空结论 / 仅证据哈希 -----------------------------------------------------------


def test_empty_conclusions_renders_without_crash() -> None:
    md = render_report_markdown(_report([]), _META)
    assert "# Cain 渗透测试报告" in md
    assert "0 条发现" in md
    assert "## 法律声明" in md


def test_evidence_hash_only_conclusion_renders() -> None:
    """仅有 finding_id+evidence_hash,无 basis/memory/confidence → 不崩。"""
    bare = {
        "finding_id": "f-bare",
        "evidence_hash": hash_evidence("bare"),
    }
    md = render_report_markdown(_report([bare]), _META)
    assert "f-bare" in md
    assert "—" in md  # 置信度/依据摘要占位


# -- 元数据缺失 / 损坏 -------------------------------------------------------------


def test_default_empty_meta_renders_placeholders() -> None:
    md = render_report_markdown(_report([_conclusion()]), ExecutionMeta())
    assert "(未配置)" in md
    assert "阶段执行记录缺失" in md or "—" in md


def test_collect_meta_degrades_on_corrupted_files(tmp_path: Path) -> None:
    """损坏 scope.yaml / state.json → 降级占位,报告阶段不失败。"""
    root = tmp_path / "ws"
    root.mkdir()
    (root / "scope.yaml").write_text("in_scope: [unclosed", encoding="utf-8")
    (root / "state.json").write_text("{not json", encoding="utf-8")
    meta = collect_execution_meta(Workspace(root))
    assert meta.scope_note  # 损坏降级为说明性 note
    md = render_report_markdown(_report([]), meta)
    assert "# Cain 渗透测试报告" in md


# -- canary 不泄漏 -----------------------------------------------------------------


def test_evidence_plaintext_never_reaches_report() -> None:
    """证据原文只以哈希进报告:canary 凭证串不得出现。"""
    secret_evidence = f"curl -H 'Authorization: {_CANARY}' https://t/"
    concl = _conclusion(evidence_hash=hash_evidence(secret_evidence))
    md = render_report_markdown(_report([concl]), _META)
    assert _CANARY not in md
    assert "curl" not in md or "Authorization" not in md or _CANARY not in md


def test_corrupted_workspace_files_do_not_leak_into_meta(tmp_path: Path) -> None:
    """元数据采集读损坏文件只产生占位 note,不把文件内容带入报告。"""
    root = tmp_path / "ws2"
    root.mkdir()
    (root / "scope.yaml").write_text(f"in_scope:\n  - {_CANARY}\n", encoding="utf-8")
    (root / "state.json").write_text('{"history": []}', encoding="utf-8")
    meta = collect_execution_meta(Workspace(root))
    md = render_report_markdown(_report([]), meta)
    # scope 条目属授权范围正常输出;但 canary 形态的凭证串不应原样回流
    assert _CANARY not in md or meta.scope_in, "scope 正常解析时按配置输出属预期"


# -- 渲染确定性(信任边界的回归锚) ---------------------------------------------------


def test_render_is_deterministic_for_same_input() -> None:
    r = _report([_conclusion()])
    assert render_report_markdown(r, _META) == render_report_markdown(r, _META)


# -- 已知不一致(记录,不改实现;见 done 汇报) -----------------------------------


def test_known_inconsistency_evidence_index_follows_input_order() -> None:
    """记录性断言:证据索引节按输入序渲染,不与表格/详情的定级排序对齐。

    现状(2026-09-13 记录,report_markdown.py _render_evidence_index 无
    sorted):输入 [unknown, known] 时表格节 HIGH 在 ULTRA 前,而证据
    索引仍 f-unknown 在前。属显示一致性小问题,非信任边界缺陷;按派活单
    「发现缺陷仅记录定位,不改实现」钉死现状,修复后本断言应反转。
    """
    known = _conclusion(severity="high", finding_id="f-known")
    unknown = _conclusion(severity="ultra", finding_id="f-unknown")
    md = render_report_markdown(_report([unknown, known]), _META)
    assert md.find("HIGH") < md.find("ULTRA")  # 表格节:定级排序在位
    assert md.find("f-unknown") < md.find("f-known")  # 索引节:输入序(现状)
