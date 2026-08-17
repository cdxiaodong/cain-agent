"""Format checks for the fourth architecture article."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ARTICLE_PATH = (
    Path(__file__).resolve().parent.parent / "docs" / "articles" / "04-orchestration.md"
)

FORBIDDEN_TERMS = (
    "平安",
    "pingan",
    "BreachWeave",
    "Cairn",
    "OpenAI-HF",
    "LangGraph",
    "AutoGen",
    "CrewAI",
    "MetaGPT",
    "Claude Code",
    "pentest-agent-mvp",
)

PUBLIC_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

DOMAIN = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|cn|dev|ai|me|co|xyz|top|info|tech|app)\b",
    re.IGNORECASE,
)
ALLOWED_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
}

REQUIRED_CONCEPTS = (
    "Orchestrator",
    "VerificationPool",
    "SemanticMemory",
    "Blackboard",
    "Manager",
    "recon",
    "test",
    "report",
)

UNTESTED_TOPICS = (
    "端到端效果",
    "误报率收益",
    "token 节省",
    "恢复成功率",
)


def _read_article() -> str:
    if not ARTICLE_PATH.is_file():
        pytest.fail(f"Article is missing: {ARTICLE_PATH}")
    return ARTICLE_PATH.read_text(encoding="utf-8")


def _word_count(text: str) -> int:
    cjk = len(re.findall(r"[\u4e00-\u9fff]", text))
    english = len(re.findall(r"\b[a-zA-Z]{3,}\b", text))
    return cjk + english


def _title_section(text: str) -> str:
    match = re.search(r"^# 标题候选.*?^---$", text, re.MULTILINE | re.DOTALL)
    assert match is not None, "article must start with a title-candidate section"
    return match.group(0)


def _legal_section(text: str) -> str:
    match = re.search(r"^## 授权测试法律声明\s*$", text, re.MULTILINE)
    assert match is not None, "article must contain the legal notice heading"
    return text[match.start() :]


def test_article_exists_and_is_readable() -> None:
    text = _read_article()
    assert text.strip()


def test_article_length_is_publishable() -> None:
    text = _read_article()
    assert 1800 <= _word_count(text) <= 3500
    assert 100 <= len(text.splitlines()) <= 500


def test_article_has_three_numbered_title_candidates() -> None:
    titles = re.findall(r"^\d+\.\s+\*\*(.+?)\*\*\s*$", _title_section(_read_article()), re.MULTILINE)
    assert len(titles) == 3
    assert all(len(re.findall(r"[\u4e00-\u9fff]", title)) >= 5 for title in titles)


def test_article_has_numbered_sections() -> None:
    text = _read_article()
    headers = re.findall(r"^##\s+[一二三四五六七八九]+、.+$", text, re.MULTILINE)
    assert len(headers) >= 8


@pytest.mark.parametrize("concept", REQUIRED_CONCEPTS)
def test_core_architecture_concepts_are_covered(concept: str) -> None:
    assert concept in _read_article()


def test_stage_order_is_documented() -> None:
    assert re.search(r"recon\s*->\s*test\s*->\s*report", _read_article())


def test_verification_states_and_consensus_are_documented() -> None:
    text = _read_article()
    for term in ("confirmed", "rejected", "inconclusive", "contested"):
        assert term in text
    assert "多数表决" in text
    assert "finding_id" in text


def test_semantic_memory_is_bounded_evidence() -> None:
    text = _read_article()
    assert "top_k" in text
    assert "min_score" in text
    assert "旁证" in text
    assert "不能单独证明" in text


@pytest.mark.parametrize("topic", UNTESTED_TOPICS)
def test_unmeasured_effects_are_marked_untested(topic: str) -> None:
    text = _read_article()
    assert topic in text
    assert text.count("未测") + text.count("未测量") >= 4


def test_parallel_work_is_not_claimed_as_merged() -> None:
    text = _read_article()
    assert "尚未合入" in text
    assert "并行推进中" in text


def test_legal_notice_requires_authorization() -> None:
    legal = _legal_section(_read_article())
    assert "授权" in legal
    assert "未经授权" in legal


@pytest.mark.parametrize("term", FORBIDDEN_TERMS)
def test_forbidden_terms_are_absent(term: str) -> None:
    assert term.lower() not in _read_article().lower()


def test_no_public_ip_addresses() -> None:
    ips = {match.group() for match in PUBLIC_IP.finditer(_read_article())}
    assert ips - {"127.0.0.1", "0.0.0.0"} == set()


def test_no_external_domains() -> None:
    domains = {match.group().lower() for match in DOMAIN.finditer(_read_article())}
    assert domains <= ALLOWED_DOMAINS


def test_no_placeholder_markers() -> None:
    text = _read_article()
    assert not re.search(r"\b(?:TODO|FIXME|TBD|XXX)\b", text)
    assert "[待填写]" not in text
    assert "[发布时填" not in text


def test_article_has_technical_blocks_and_closing() -> None:
    text = _read_article()
    assert len(re.findall(r"^```", text, re.MULTILINE)) >= 6
    assert re.search(r"^##\s+[一二三四五六七八九]+、.*(?:总结|演进|下一步)", text, re.MULTILINE)


def test_no_broken_markdown_links() -> None:
    text = re.sub(r"```.*?```", "", _read_article(), flags=re.DOTALL)
    assert not re.search(r"\[[^\]]+\]\(", text)
