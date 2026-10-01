"""Scout 假设生成(Phase 5-B2)——recon→test 间的零 token 规则匹配。

经验吸收(匿名化):把方向性知识固化为浓缩模式库,在 recon 与 test 之间
按"模式×端点特征"纯规则产定点假设清单,test 阶段注入假设替代全量技能
注入——省 token 且防单体上下文过早收敛。匹配全程无 LLM 调用。

特征词表:``target_kind`` 中的稳定关键词到端点信号(路径/参数/方法)的
映射是启发式的、保守的(宁漏勿滥);匹配不出的端点不产假设。
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from cain_agent.patternlib import load_patterns

# target_kind 关键词 → 端点路径/参数特征(小写包含匹配,保守映射)
_KIND_SIGNALS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("SQL", "数据库"), ("query", "sql", "search", "sort", "order", "id", "page",
                      "list", "filter", "report", "export", "select", "view")),
    (("回显", "渲染", "XSS", "模板"), ("name", "title", "comment", "content", "msg",
                                    "message", "search", "q", "keyword", "tpl",
                                    "template", "render", "preview", "echo")),
    (("URL", "取数", "SSRF", "内网", "跳转"), ("url", "link", "redirect", "next",
                                         "callback", "target", "fetch", "proxy",
                                         "src", "dest", "goto", "return", "returnurl",
                                         "feed", "webhook", "avatar", "img")),
    (("命令", "系统"), ("ping", "cmd", "exec", "run", "shell", "task", "job", "debug",
                    "trace", "ip", "host", "domain", "dns", "lookup")),
    (("上传", "文件", "路径", "遍历", "压缩"), ("upload", "file", "download", "path",
                                          "attach", "import", "export", "doc",
                                          "image", "avatar", "zip", "unzip", "name")),
    (("序列化", "反序列化"), ("token", "session", "state", "data", "payload",
                         "ticket", "auth", "sso", "remember")),
    (("错误", "泄露", "调试", "备份"), ("debug", "test", "dev", "admin", "config",
                                  "backup", "old", "phpinfo", "status", "health",
                                  "trace", "log", "error", ".bak", ".git", ".env")),
    (("CSRF", "状态变更", "幂等"), ("delete", "update", "edit", "create", "add",
                               "modify", "remove", "save", "setting", "profile",
                               "password", "pay", "transfer", "order")),
    (("XML", "实体"), ("xml", "soap", "wsdl", "import", "rss", "feed", "saml")),
    (("宽字节", "GBK"), ("search", "name", "keyword", "q", "title", "sort")),
)


@dataclass(frozen=True)
class Hypothesis:
    """一条定点假设:该端点值得按该 pattern 检验。"""

    endpoint_url: str
    pattern_id: str
    priority: float
    signal: str
    """命中的端点特征词(审计用)。"""


def _signals_for(target_kind: str) -> tuple[str, ...]:
    """target_kind → 特征词集(多组命中时并集);无命中返回空(不产假设)。"""
    merged: set[str] = set()
    for keywords, signals in _KIND_SIGNALS:
        if any(k.lower() in target_kind.lower() for k in keywords):
            merged.update(signals)
    return tuple(sorted(merged))


def generate_hypotheses(
    endpoints: Iterable[Mapping[str, Any]],
    patterns: Iterable[Mapping[str, Any]] | None = None,
    *,
    patterns_path: str | None = None,
) -> list[Hypothesis]:
    """对 recon 端点按 patterns 产定点假设(纯函数,零 LLM 调用)。

    patterns 二选一:显式传入(测试注入)或 ``patterns_path`` 加载(经
    patternlib 校验,坏行立即抛错——坏库不静默降级)。
    """
    if patterns is None:
        if patterns_path is None:
            return []
        patterns = load_patterns(patterns_path)
    pattern_list = list(patterns)

    hypotheses: list[Hypothesis] = []
    for endpoint in endpoints:
        url = str(endpoint.get("url") or "")
        if not url:
            continue
        haystack = url.lower()
        for param in endpoint.get("params") or []:
            if isinstance(param, str):
                haystack += " " + param.lower()
        method = str(endpoint.get("method") or "GET").lower()
        if method not in ("get", "head"):
            haystack += " " + method

        for index, pattern in enumerate(pattern_list):
            signals = _signals_for(str(pattern.get("target_kind", "")))
            hit = next((s for s in signals if s in haystack), None)
            if hit is None:
                continue
            pid = str(pattern.get("id") or f"pattern-{index}")
            hypotheses.append(
                Hypothesis(
                    endpoint_url=url,
                    pattern_id=pid,
                    priority=float(pattern.get("confidence_prior", 0.5)),
                    signal=hit,
                )
            )
    hypotheses.sort(key=lambda h: (-h.priority, h.endpoint_url, h.pattern_id))
    return hypotheses


def render_hypotheses(hypotheses: Iterable[Hypothesis], limit: int = 30) -> str:
    """假设清单渲染为 prompt 片段(供 test 阶段定点注入;空清单返回空串)。"""
    items = list(hypotheses)[:limit]
    if not items:
        return ""
    lines = [
        "### Scout 定点假设(Phase 5-B2:按模式×端点特征预筛,优先检验)",
        "",
    ]
    lines += [
        f"- `{h.endpoint_url}` ← pattern `{h.pattern_id}`(命中特征 {h.signal},"
        f"优先级 {h.priority:.2f})"
        for h in items
    ]
    lines.append("")
    lines.append(
        "> 优先对上述假设点位做定点检验;未列出的端点按通用方法论兜底,"
        "假设只是预筛不是结论。"
    )
    return "\n".join(lines)


__all__ = ["Hypothesis", "generate_hypotheses", "render_hypotheses"]
