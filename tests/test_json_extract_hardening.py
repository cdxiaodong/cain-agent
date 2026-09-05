"""_extract_json 硬化测试(issue #9)— 多对象/围栏/坏草稿场景取末尾终稿。

修复前:naive 首-``{``/末-``}`` 切片在这些场景返回 None 或错误对象,
造成 recon/test 阶段 ``json_parse_failed`` 假阳性。
"""

from __future__ import annotations

from cain_agent._jsonspans import iter_json_spans
from cain_agent.handlers import _extract_json as extract_any
from cain_agent.multi_agent.orchestration import _extract_json as extract_orch
from cain_agent.validator import _extract_json as extract_dict

# 模型典型输出:先吐一份写坏的草稿,再给终稿
DRAFT_THEN_FINAL = (
    "侦察结论如下。\n"
    '草稿 {"endpoints": [ {"url": "https://t.example/a", "method": "GET", "note": '  # 写坏的字符串
    ']}  作废。\n'
    "最终结果:\n"
    '{"endpoints": [{"url": "https://t.example/final", "method": "GET"}]}'
)

FENCED = "结论:\n```json\n{\"ok\": true, \"n\": 1}\n```\n完"

PROSE_WITH_BRACES = "函数 f(x) 的输出 {非 JSON} 无对象可取"

STRING_BRACES = '{"payload": "含括号 ] 与 { 的字符串", "ok": true}'


class TestIterJsonSpans:
    def test_single_object(self) -> None:
        assert list(iter_json_spans('{"a": 1}')) == ['{"a": 1}']

    def test_two_objects_in_order(self) -> None:
        spans = list(iter_json_spans('{"a":1} 中间散文 {"b":2}'))
        assert spans == ['{"a":1}', '{"b":2}']

    def test_braces_inside_string_do_not_count(self) -> None:
        # 字符串里的 ] { 必须被跳过,不能把 span 提前截断
        assert list(iter_json_spans(STRING_BRACES)) == [STRING_BRACES]

    def test_unclosed_span_dropped(self) -> None:
        spans = list(iter_json_spans('{"a": 1} 未闭合 {"b": 2'))
        assert spans == ['{"a": 1}']

    def test_nested_mixed_brackets(self) -> None:
        text = '{"a": [1, {"b": 2}]}'
        assert list(iter_json_spans(text)) == [text]


class TestExtractAnyHandlers:
    def test_draft_then_final_picks_final(self) -> None:
        payload = extract_any(DRAFT_THEN_FINAL)
        assert isinstance(payload, dict)
        assert payload["endpoints"][0]["url"] == "https://t.example/final"

    def test_plain_json_untouched(self) -> None:
        assert extract_any('{"a": 1}') == {"a": 1}
        assert extract_any("[1, 2]") == [1, 2]

    def test_fenced_json_extracted(self) -> None:
        assert extract_any(FENCED) == {"ok": True, "n": 1}

    def test_no_json_returns_none(self) -> None:
        assert extract_any(PROSE_WITH_BRACES) is None  # {非 JSON} 不可解析 → None
        assert extract_any("") is None

    def test_array_final_wins_over_broken_object(self) -> None:
        text = '坏 {"a": [1,} 后 [{"b": 2}]'
        assert extract_any(text) == [{"b": 2}]


class TestExtractDictVariants:
    """validator 与 orchestration 版要求 dict;末尾非 dict 对象不得顶替。"""

    def test_draft_then_final_dict(self) -> None:
        for fn in (extract_dict, extract_orch):
            payload = fn(DRAFT_THEN_FINAL)
            assert payload is not None
            assert payload["endpoints"][0]["url"] == "https://t.example/final"

    def test_trailing_non_dict_not_forced(self) -> None:
        # 末尾是数组,前面有合法 dict → dict 版应取 dict 而非 None/数组
        text = '{"a": 1} 然后 [1, 2]'
        for fn in (extract_dict, extract_orch):
            assert fn(text) == {"a": 1}

    def test_top_level_array_only_returns_none(self) -> None:
        for fn in (extract_dict, extract_orch):
            assert fn("[1, 2]") is None
