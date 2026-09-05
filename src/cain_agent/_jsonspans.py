"""顶层括号平衡 JSON span 扫描 — 模型输出中定位全部候选 JSON 片段。

背景(issue #9):模型输出常在最终 JSON 前后裹散文、markdown 围栏、甚至
一份写坏的草稿对象;naive 的「首个 ``{`` 到末个 ``}``」切片在这种场景下
要么解析失败(``json_parse_failed`` 假阳性),要么截到错误片段。本模块扫描
**所有**顶层括号平衡的候选 span(字符串/转义感知,JSON 字符串内的括号
不计入深度),调用方取「最后一个可解析」的 span —— 模型终稿几乎总在末尾。
"""

from __future__ import annotations

from collections.abc import Iterator

_OPENERS = {"{": "}", "[": "]"}
_CLOSERS = {"}", "]"}


def iter_json_spans(text: str) -> Iterator[str]:
    """按出现顺序产出所有顶层括号平衡的候选 span。

    深度计数对 ``{``/``[`` 混合嵌套保持平衡(``{"a": [1]}`` 正确闭合);
    未闭合的起点直接放弃;span 是否真为合法 JSON 由调用方 ``json.loads``
    判定,本函数只负责"括号上自洽"的切片。
    """
    n = len(text)
    i = 0
    while i < n:
        if text[i] not in _OPENERS:
            i += 1
            continue
        span = _balanced_span(text, i)
        if span is not None:
            yield span
            i += len(span)
        else:
            i += 1


def _balanced_span(text: str, start: int) -> str | None:
    """从 ``start``(必须是开括号)起取一段括号平衡的切片;未闭合返回 None。"""
    depth = 0
    in_str = False
    esc = False
    for j in range(start, len(text)):
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in _OPENERS:
            depth += 1
        elif ch in _CLOSERS:
            depth -= 1
            if depth == 0:
                return text[start : j + 1]
            if depth < 0:  # 类型错配(如 "{]"),此起点不可救
                return None
    return None
