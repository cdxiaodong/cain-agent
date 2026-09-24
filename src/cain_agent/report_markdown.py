"""Report 阶段的人类可读 markdown 报告渲染。

DESIGN 核心承诺「可审计证据链报告」的最后一环:在 ``aggregated-report.json``
(机器可读)之外,把同一份聚合结论渲染成 ``report.md``(人类可读)——

- 执行摘要:授权范围(目标)、阶段耗时、发现统计;
- findings 表:severity 着色标记 / 置信度 / 依据链摘要,详情逐条展开;
- 证据哈希索引:只引用 ``sha256:`` 哈希,证据原文不落明文(DESIGN §3.2);
- 修复建议:按 issue_type 查 ``REMEDIATION_ADVICE`` 常量表,未知类型回落
  按 severity 的通用建议——与定级规则表同思路,代码常量、模型不可绕过;
- 法律声明尾部:与 README 授权声明对齐。

渲染为纯函数(``render_report_markdown``),输入即聚合报告 dict(复用
``ManagerConclusion.to_dict`` 链路产物)+ 执行元数据,纯 Python 字符串拼接,
零新依赖;``collect_execution_meta`` 从 Workspace 真源(scope.yaml /
state.json)容错采集元数据,缺失时降级为占位说明而非让报告阶段失败。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import yaml

from cain_agent.workspace import SCOPE_FILE, STATE_FILE, Workspace

__all__ = [
    "REMEDIATION_ADVICE",
    "ExecutionMeta",
    "StageTiming",
    "collect_execution_meta",
    "render_report_markdown",
]


# -- 定级着色标记 ---------------------------------------------------------------
# markdown 无原生颜色,用 emoji 圆点做 severity 视觉分级;未知值回落「·」。

_SEVERITY_MARKERS: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_RESULT_LABELS: dict[str, str] = {
    "confirmed": "已确认",
    "false_positive": "误报",
    "validation_system_error": "校验异常",
    "validation_inconclusive": "证据不足",
}

_CONSENSUS_LABELS: dict[str, str] = {
    "confirmed": "确认",
    "contested": "有分歧",
    "rejected": "否决",
}


# -- 修复建议常量表 -------------------------------------------------------------
# 与 ``findings.SEVERITY_RULES`` 同思路:代码常量数据,按 issue_type 归一化
# (小写 + 去首尾空白)精确匹配;未命中回落按 severity 的通用建议。

REMEDIATION_ADVICE: dict[str, str] = {
    # 云场景(对齐 SEVERITY_RULES 五类)
    "public-write-storage": (
        "收紧存储写权限:关闭匿名/公开写,改为按主体的最小权限写策略,并审计历史写入记录排查是否已被投毒。"
    ),
    "public-read-sensitive": (
        "立即将对象改为私有并轮换已暴露的凭证;调取访问日志评估泄露面,保留取证记录后再处置。"
    ),
    "public-read": (
        "关闭匿名公开读:ACL 与存储策略收敛为按需授权,敏感对象改私有,复核是否有凭证或敏感数据曾被匿名拉取。"
    ),
    "metadata-endpoint-reachable": (
        "元数据端点加固:强制 IMDSv2/会话 token、限制 Hop Limit,并修复可触达元数据端点的入口漏洞(如 SSRF)。"
    ),
    "misconfiguration": (
        "按安全基线复核配置:最小权限、关闭非常用端口与管理面暴露,纳入周期性配置巡检防回退。"
    ),
    # Web 场景(对齐 skills/web 技能命名)
    "sqli": (
        "全部改参数化查询/预编译语句,输入按白名单校验,数据库账号收敛到最小权限;排查日志确认是否已被注入利用。"
    ),
    "xss": ("按上下文做输出编码并启用 CSP,富文本走净化白名单;复核 Cookie 的 HttpOnly/SameSite 策略。"),
    "ssti": (
        "禁止用户输入直渲染模板:模板逻辑与数据分离、输入白名单净化,"
        "并启用模板引擎沙箱(如 autoescape/沙箱执行器)。"
    ),
    "ssrf": ("出网目标走白名单校验,禁止重定向跟进内网,隔离元数据端点(IMDSv2),对回显与盲打通道分别设防。"),
    "command-injection": (
        "避免拼接 shell:改参数数组调用,输入白名单校验,执行账户收敛到最小权限并限制可执行程序面。"
    ),
    "file-upload": ("上传目录禁执行权限,文件名随机化存储,类型校验基于内容而非扩展名,隔离存储并病毒扫描。"),
    "path-traversal": (
        "路径拼接前规范化并校验根目录约束,拒绝 ``..`` 与绝对路径,下载/读取接口按白名单映射资源。"
    ),
    "deserialization": (
        "避免对不可信数据反序列化:改签名验证的 JSON 等安全格式,或用只含基础类型的受限反序列化器。"
    ),
    "xxe": ("XML 解析器禁用外部实体与 DTD(Xerces、libxml 按对应开关关闭),必要时改 JSON 交换格式。"),
    "csrf": ("状态变更操作强制 CSRF token 并校验 Origin/Referer,SameSite=Cookie 默认防跨站携带。"),
    "open-redirect": ("跳转目标走白名单/相对路径校验,禁止把用户可控参数直接拼进 Location 响应头。"),
    "info-disclosure": ("下线暴露的敏感端点/文件,清理错误页与响应头中的实现细节,复核备份文件与调试开关。"),
    "file-inclusion": ("包含路径禁止用户可控:改固定映射白名单,关闭远程包含,最小权限运行账户限制可读面。"),
}

_SEVERITY_GENERIC_ADVICE: dict[str, str] = {
    "critical": ("立即处置:先控制暴露面(下线/收敛权限),再排查是否已被利用,处置过程留存取证记录。"),
    "high": "优先排期修复,修复前用临时缓解(收敛权限/加访问控制)降低暴露面。",
    "medium": "纳入近期修复排期,修复后回归验证。",
    "low": "列入技术债清单,随迭代修复。",
    "info": "作为加固建议参考,不构成漏洞处置项。",
}


# -- 执行元数据 -----------------------------------------------------------------


@dataclass(frozen=True)
class StageTiming:
    """单个阶段的历史执行记录(state.json history 条目)。"""

    stage: str
    started_at: str
    finished_at: str
    duration_seconds: float


@dataclass(frozen=True)
class ExecutionMeta:
    """执行摘要的元数据:授权范围 + 阶段耗时 + 生成时间。

    全部字段容错可空——报告阶段不允许因元数据缺失而失败。
    """

    scope_in: tuple[str, ...] = ()
    scope_out: tuple[str, ...] = ()
    stage_timings: tuple[StageTiming, ...] = ()
    generated_at: str = ""
    scope_note: str = ""
    timings_note: str = ""


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _format_duration(seconds: float) -> str:
    """NaN(起止时间解析失败)显示为「—」而非污染表格。"""
    return f"{seconds:.1f}" if seconds == seconds else "—"


def collect_execution_meta(workspace: Workspace) -> ExecutionMeta:
    """从 Workspace 真源容错采集执行元数据。

    - 授权范围:直接读 ``scope.yaml`` 原始条目(而非 Scope 归一化桶),
      保留用户配置原文;缺失/损坏时降级为占位说明;
    - 阶段耗时:读 ``state.json`` 的 history(本阶段自身在 handler 返回后
      才落账,报告里只含此前已完成阶段);缺失时降级为占位说明。
    """

    scope_in: tuple[str, ...] = ()
    scope_out: tuple[str, ...] = ()
    scope_note = ""
    try:
        with workspace.path(SCOPE_FILE).open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        raw_in = data.get("in_scope") or []
        raw_out = data.get("out_of_scope") or []
        if isinstance(raw_in, list) and isinstance(raw_out, list):
            scope_in = tuple(str(item) for item in raw_in)
            scope_out = tuple(str(item) for item in raw_out)
        else:
            scope_note = "scope.yaml 结构异常,授权范围未渲染"
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        scope_note = "scope.yaml 缺失或不可读,授权范围未渲染"

    timings: list[StageTiming] = []
    timings_note = ""
    try:
        state = workspace.read_json(STATE_FILE)
        history = state.get("history") if isinstance(state, dict) else None
        if isinstance(history, list):
            for entry in history:
                if not isinstance(entry, dict):
                    continue
                started = _parse_iso(entry.get("started_at"))
                finished = _parse_iso(entry.get("finished_at"))
                duration = (
                    round((finished - started).total_seconds(), 1)
                    if started is not None and finished is not None
                    else float("nan")
                )
                timings.append(
                    StageTiming(
                        stage=str(entry.get("stage", "?")),
                        started_at=str(entry.get("started_at", "?")),
                        finished_at=str(entry.get("finished_at", "?")),
                        duration_seconds=duration,
                    )
                )
        if not timings:
            timings_note = "无阶段历史记录(如直接运行 report 阶段或断点后重建)"
    except Exception:  # state.json 缺失/损坏一律降级,报告阶段不因此失败
        timings_note = "state.json 缺失或不可读,阶段耗时未渲染"

    return ExecutionMeta(
        scope_in=scope_in,
        scope_out=scope_out,
        stage_timings=tuple(timings),
        generated_at=_utc_now_iso(),
        scope_note=scope_note,
        timings_note=timings_note,
    )


# -- 渲染 -----------------------------------------------------------------------


def _escape_cell(value: object) -> str:
    """表格单元格转义:反斜杠/换行/竖线,防注入破坏表格结构。"""
    text = str(value)
    return text.replace("\\", "\\\\").replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def _severity_marker(severity: str) -> str:
    return _SEVERITY_MARKERS.get(severity.strip().lower(), "·")


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.strip().lower(), len(_SEVERITY_RANK))


def _conclusion_sort_key(conclusion: dict[str, Any]) -> tuple[int, float]:
    """表格与详情共用的排序键:severity 从高到低,同级按置信度降序。"""
    confidence = conclusion.get("confidence")
    numeric = float(confidence) if isinstance(confidence, (int, float)) else 0.0
    return (_severity_rank(str(conclusion.get("severity", ""))), -numeric)


def _format_confidence(value: object) -> str:
    if isinstance(value, (int, float)):
        return f"{float(value):.1%}"
    return "—"


def _basis_summary(conclusion: dict[str, Any]) -> str:
    """依据链摘要:solver+verification+memory×N 形式。"""
    parts: list[str] = []
    memory_count = 0
    for basis in conclusion.get("basis") or []:
        source = str(basis.get("source", "?"))
        if source == "memory":
            memory_count += 1
        else:
            parts.append(source)
    if memory_count:
        parts.append(f"memory×{memory_count}")
    return "+".join(parts) if parts else "—"


def _remediation_for(conclusion: dict[str, Any]) -> str:
    issue_type = str(conclusion.get("issue_type", "")).strip().lower()
    if issue_type in REMEDIATION_ADVICE:
        return REMEDIATION_ADVICE[issue_type]
    severity = str(conclusion.get("severity", "info")).strip().lower()
    return _SEVERITY_GENERIC_ADVICE.get(severity, _SEVERITY_GENERIC_ADVICE["info"])


def _render_summary(meta: ExecutionMeta, report: dict[str, Any]) -> list[str]:
    summary = report.get("summary") or {}
    results = summary.get("results") or {}
    total = summary.get("total", 0)

    lines = ["## 执行摘要", ""]
    if meta.scope_note:
        lines.append(f"- 授权范围: _{meta.scope_note}_")
    else:
        scope_text = ", ".join(meta.scope_in) if meta.scope_in else "(未配置)"
        lines.append(f"- 目标(授权范围): {scope_text}")
        if meta.scope_out:
            lines.append(f"- 明确排除: {', '.join(meta.scope_out)}")

    lines.append(f"- 生成时间: {meta.generated_at or '—'}(UTC)")
    lines.append(f"- 编排路线: {report.get('route', '?')}")

    lines += ["", "### 阶段耗时", ""]
    if meta.stage_timings:
        lines.append("| 阶段 | 开始(UTC) | 结束(UTC) | 耗时(秒) |")
        lines.append("|---|---|---|---|")
        for timing in meta.stage_timings:
            lines.append(
                f"| {_escape_cell(timing.stage)} | {_escape_cell(timing.started_at)} "
                f"| {_escape_cell(timing.finished_at)} | {_format_duration(timing.duration_seconds)} |"
            )
        lines.append("")
        lines.append("> 注: report 阶段自身耗时在其完成后的 state.json 落账,本表不含。")
    else:
        lines.append(f"_{meta.timings_note or '无阶段历史记录'}_")

    parts = [f"{_RESULT_LABELS.get(state, state)} {count}" for state, count in results.items() if count]
    lines += ["", f"- 发现统计: 共 {total} 条" + (f"({', '.join(parts)})" if parts else ""), ""]
    return lines


def _render_findings_table(report: dict[str, Any]) -> list[str]:
    conclusions = report.get("conclusions") or []
    lines = ["## Findings 一览", ""]
    if not conclusions:
        lines += ["_本轮未产出任何发现(0 findings)。_", ""]
        return lines

    lines += [
        "| # | 定级 | 问题类型 | 资源 | 校验结果 | 置信度 | 依据链 |",
        "|---|---|---|---|---|---|---|",
    ]
    ordered = sorted(conclusions, key=_conclusion_sort_key)
    for index, conclusion in enumerate(ordered, start=1):
        severity = str(conclusion.get("severity", "?"))
        result = str(conclusion.get("result", "?"))
        lines.append(
            f"| {index} | {_severity_marker(severity)} **{severity.upper()}** "
            f"| {_escape_cell(conclusion.get('issue_type', '?'))} "
            f"| {_escape_cell(conclusion.get('resource', '?'))} "
            f"| {_RESULT_LABELS.get(result, result)} "
            f"| {_format_confidence(conclusion.get('confidence'))} "
            f"| {_escape_cell(_basis_summary(conclusion))} |"
        )
    lines.append("")
    return lines


def _render_details(report: dict[str, Any]) -> list[str]:
    conclusions = report.get("conclusions") or []
    if not conclusions:
        return []
    lines = ["## 发现详情", ""]
    ordered = sorted(conclusions, key=_conclusion_sort_key)
    for conclusion in ordered:
        severity = str(conclusion.get("severity", "?"))
        result = str(conclusion.get("result", "?"))
        consensus = conclusion.get("consensus")
        consensus_text = _CONSENSUS_LABELS.get(str(consensus), str(consensus)) if consensus else "未表决"
        lines.append(
            f"### {_severity_marker(severity)} [{severity.upper()}] "
            f"{_escape_cell(conclusion.get('issue_type', '?'))} — "
            f"{_RESULT_LABELS.get(result, result)}"
        )
        lines.append(f"- 资源: `{_escape_cell(conclusion.get('resource', '?'))}`")
        lines.append(
            f"- 云/服务: {_escape_cell(conclusion.get('cloud', '?'))} / "
            f"{_escape_cell(conclusion.get('service', '?'))}"
        )
        lines.append(f"- 校验结论: {_RESULT_LABELS.get(result, result)}(池表决: {consensus_text})")
        lines.append(f"- 置信度: {_format_confidence(conclusion.get('confidence'))}")
        lines.append(f"- 证据哈希: `{conclusion.get('evidence_hash', '?')}`(证据原文仅哈希落盘)")
        lines.append("- 依据链:")
        for basis in conclusion.get("basis") or []:
            lines.append(
                f"  1. {_escape_cell(basis.get('source', '?'))} — {_escape_cell(basis.get('detail', ''))}"
            )
        memory_hits = conclusion.get("memory_hits") or []
        if memory_hits:
            hits_text = ", ".join(
                f"{_escape_cell(hit.get('kind', '?'))}::{_escape_cell(hit.get('key', '?'))}"
                f"({hit.get('score', '?')})"
                for hit in memory_hits
            )
            lines.append(f"- 记忆旁证: {hits_text}")
        lines.append("")
    return lines


def _render_evidence_index(report: dict[str, Any]) -> list[str]:
    conclusions = report.get("conclusions") or []
    lines = ["## 证据哈希索引", ""]
    if not conclusions:
        lines += ["_无发现,无证据哈希。_", ""]
        return lines
    lines += [
        "> 证据原文不落盘、不进本报告(数据信任边界);下表哈希可与 `findings.json` 及审计日志逐条比对溯源。",
        "",
        "| finding_id | 证据哈希 |",
        "|---|---|",
    ]
    for conclusion in conclusions:
        lines.append(
            f"| {_escape_cell(conclusion.get('finding_id', '?'))} "
            f"| `{conclusion.get('evidence_hash', '?')}` |"
        )
    lines.append("")
    return lines


def _render_remediation(report: dict[str, Any]) -> list[str]:
    conclusions = report.get("conclusions") or []
    lines = ["## 修复建议", ""]
    if not conclusions:
        lines += ["_本轮无发现,无修复项;可参考报告内合规与基线建议。_", ""]
        return lines

    ordered = sorted(
        conclusions,
        key=lambda item: (
            _severity_rank(str(item.get("severity", ""))),
            str(item.get("issue_type", "")).lower(),
        ),
    )
    current_type: str | None = None
    for conclusion in ordered:
        issue_type = str(conclusion.get("issue_type", "?"))
        severity = str(conclusion.get("severity", "?"))
        if issue_type != current_type:
            current_type = issue_type
            lines.append(f"### {_severity_marker(severity)} {issue_type}({severity.upper()})")
        lines.append(
            f"- {_escape_cell(conclusion.get('resource', '?'))}"
            f"(finding: `{_escape_cell(conclusion.get('finding_id', '?'))}`): "
            f"{_remediation_for(conclusion)}"
        )
    lines.append("")
    lines.append("> 建议按定级从高到低排期处置;修复后复测验证并更新本报告结论。")
    lines.append("")
    return lines


_LEGAL_DISCLAIMER = """## 法律声明

本报告由 Cain 在**已获书面授权**的安全测试范围内生成。测试全程以只读凭证
运行,授权范围由配置强制校验(非 AI 自律);证据原文仅以哈希留存,本报告
不含敏感明文。报告仅限授权方在授权用途内使用,不得用于未授权第三方系统;
使用者须遵守所在地区与目标系统适用的全部法律法规,作者不承担任何因滥用
产生的法律责任。"""


def _render_report_english(report: dict[str, Any], meta: ExecutionMeta) -> str:
    """Render a compact English report from the same machine-readable source."""
    summary = report.get("summary") or {}
    conclusions = sorted(report.get("conclusions") or [], key=_conclusion_sort_key)
    total = summary.get("total", 0)
    lines = [
        "# Cain Penetration Test Report",
        "",
        f"> {total} finding(s) · Machine-readable version: `aggregated-report.json`",
        "",
        "## Executive summary",
        "",
        f"- Authorized target(s): {', '.join(meta.scope_in) if meta.scope_in else '(not configured)'}",
        f"- Generated: {meta.generated_at or '—'} (UTC)",
        f"- Orchestration route: {report.get('route', '?')}",
        "",
        "## Stage timing",
        "",
    ]
    if meta.stage_timings:
        lines += [
            "| Stage | Started (UTC) | Finished (UTC) | Seconds |",
            "|---|---|---|---|",
        ]
        for timing in meta.stage_timings:
            lines.append(
                f"| {_escape_cell(timing.stage)} | {_escape_cell(timing.started_at)} | "
                f"{_escape_cell(timing.finished_at)} | {_format_duration(timing.duration_seconds)} |"
            )
    else:
        lines.append(f"_{meta.timings_note or 'No stage history available.'}_")
    lines += ["", "## Findings", ""]
    if not conclusions:
        lines += ["_No findings were produced._", ""]
    else:
        lines += [
            "| # | Severity | Type | Resource | Result | Confidence |",
            "|---|---|---|---|---|---|",
        ]
        for index, item in enumerate(conclusions, 1):
            severity = str(item.get("severity", "?"))
            lines.append(
                f"| {index} | {_severity_marker(severity)} {severity.upper()} | "
                f"{_escape_cell(item.get('issue_type', '?'))} | "
                f"{_escape_cell(item.get('resource', '?'))} | "
                f"{_escape_cell(item.get('result', '?'))} | "
                f"{_format_confidence(item.get('confidence'))} |"
            )
        lines.append("")
        for item in conclusions:
            severity = str(item.get("severity", "?"))
            lines += [
                f"### {_severity_marker(severity)} [{severity.upper()}] "
                f"{_escape_cell(item.get('issue_type', '?'))}",
                "",
                f"- Resource: `{_escape_cell(item.get('resource', '?'))}`",
                f"- Result: {_escape_cell(item.get('result', '?'))}",
                f"- Evidence hash: `{item.get('evidence_hash', '?')}`",
            ]
            invalid = item.get("invalid_reasons") or []
            if invalid:
                lines.append(f"- Invalidity markers: {', '.join(map(str, invalid))}")
            provenance = item.get("provenance")
            if provenance:
                lines.append(
                    f"- Executed request: {provenance.get('method', '?')} "
                    f"{provenance.get('url', '?')} → HTTP {provenance.get('status_code', '?')}"
                )
            lines += [
                "- Context chain (auxiliary only): " + _basis_summary(item),
                "",
            ]
    lines += [
        "## Legal notice",
        "",
        "This report is for an explicitly authorized, read-only security assessment. "
        "Scope is enforced by configuration. Evidence plaintext is not persisted, and "
        "consensus or semantic memory never substitutes for executed-request evidence.",
        "",
    ]
    return "\n".join(lines)


def render_report_markdown(
    report: dict[str, Any], meta: ExecutionMeta, *, language: str = "zh"
) -> str:
    """把聚合报告 dict + 执行元数据渲染为人类可读 markdown。

    纯函数、纯 Python 字符串拼接:同一输入恒定输出(生成时间由
    ``meta.generated_at`` 显式携带),便于渲染测试钉死三态
    (空 / 单条 / 多 severity)。
    """

    if language == "en":
        return _render_report_english(report, meta)

    total = (report.get("summary") or {}).get("total", 0)
    lines = [
        "# Cain 渗透测试报告",
        "",
        f"> 本轮共 {total} 条发现 · 机器可读版见 `aggregated-report.json`",
        "",
    ]
    lines += _render_summary(meta, report)
    lines += _render_findings_table(report)
    lines += _render_details(report)
    lines += _render_evidence_index(report)
    lines += _render_remediation(report)
    lines += [_LEGAL_DISCLAIMER, ""]
    return "\n".join(lines)
