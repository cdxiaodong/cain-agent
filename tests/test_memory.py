"""Semantic memory tests: deterministic indexing, retrieval, and Blackboard integration."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from cain_agent.multi_agent.blackboard import Blackboard
from cain_agent.multi_agent.memory import (
    LocalHashEmbedding,
    MemoryKind,
    SemanticMemory,
    finding_text,
)
from cain_agent.multi_agent.types import Finding, Severity


class KeywordEmbedding:
    """Minimal provider used to pin the embedding abstraction."""

    def embed(self, text: str) -> Sequence[float]:
        words = text.casefold().split()
        return (
            float("sql" in words or "sqli" in words),
            float("upload" in words),
        )


def _finding(**overrides: object) -> Finding:
    kwargs: dict[str, object] = {
        "cloud": "web",
        "service": "http",
        "resource": "https://example.com/login",
        "issue_type": "sqli",
        "severity": Severity.HIGH,
        "detail": "SQL injection in login parameter",
        "evidence": {"parameter": "username"},
    }
    kwargs.update(overrides)
    return Finding(**kwargs)  # type: ignore[arg-type]


def test_finding_similarity_search_ranks_relevant_record_first() -> None:
    memory = SemanticMemory()
    sql = _finding()
    upload = _finding(
        resource="https://example.com/upload",
        issue_type="file-upload",
        severity=Severity.CRITICAL,
        detail="Unrestricted file upload",
    )
    memory.post_finding(upload, "solver-upload")
    memory.post_finding(sql, "solver-sql")

    results = memory.search("SQL injection login", top_k=2)

    assert len(results) == 2
    assert results[0].record.payload is sql
    assert results[0].record.solver_id == "solver-sql"
    assert results[0].record.kind is MemoryKind.FINDING
    assert results[0].score > results[1].score
    assert memory.read_findings() == [upload, sql]
    assert memory.stats() == {
        "findings": 2,
        "contexts": 0,
        "total": 2,
        "dimension": 128,
    }


def test_blackboard_publishes_and_searches_shared_findings_and_context() -> None:
    blackboard = Blackboard()
    finding = _finding()
    blackboard.post_finding(finding, "discoverer")
    blackboard.set_fact("recon:example.com", {"stack": "nginx", "login_path": "/login"})

    results = blackboard.search("login sql injection", top_k=2)
    context = blackboard.get_fact("recon:example.com")

    assert {result.record.kind for result in results} == {
        MemoryKind.FINDING,
        MemoryKind.CONTEXT,
    }
    assert blackboard.read_findings() == [finding]
    assert context == {"stack": "nginx", "login_path": "/login"}
    assert blackboard.semantic_memory.stats()["total"] == 2


def test_context_key_replaces_its_previous_vector_record() -> None:
    memory = SemanticMemory()
    memory.set_fact("target", "login SQL injection", "solver-1")
    memory.set_fact("target", "file upload endpoint", "solver-2")
    memory.set_fact("other", "login SQL injection", "solver-3")

    upload_results = memory.search("upload endpoint", kinds=(MemoryKind.CONTEXT,))
    login_results = memory.search("login SQL injection", top_k=1)

    assert memory.get_fact("target") == "file upload endpoint"
    assert memory.get_fact("missing", "fallback") == "fallback"
    assert upload_results[0].record.key == "target"
    assert upload_results[0].record.solver_id == "solver-2"
    assert login_results[0].record.key == "other"
    assert memory.stats() == {
        "findings": 0,
        "contexts": 2,
        "total": 2,
        "dimension": 128,
    }


def test_local_embedding_is_deterministic_and_normalized() -> None:
    embedding = LocalHashEmbedding(dimension=16)
    first = embedding.embed("SQL injection 登录接口")
    second = embedding.embed("SQL injection 登录接口")

    assert first == second
    assert len(first) == 16
    assert 0.999 <= sum(value * value for value in first) <= 1.001
    assert LocalHashEmbedding(dimension=16).embed("different") != first


def test_local_embedding_expands_domain_abbreviations() -> None:
    embedding = LocalHashEmbedding(dimension=32)
    sqli_vector = embedding.embed("sqli")
    query_vector = embedding.embed("sql injection")
    similarity = sum(left * right for left, right in zip(sqli_vector, query_vector, strict=True))

    assert similarity > 0.5


def test_custom_embedding_provider_and_search_filter() -> None:
    provider = KeywordEmbedding()
    memory = SemanticMemory(provider)
    sql = _finding()
    upload = _finding(
        resource="https://example.com/upload",
        issue_type="file-upload",
        detail="upload endpoint",
    )
    memory.post_finding(sql)
    memory.post_finding(upload)
    memory.set_fact("context", "upload")

    results = memory.search("sql", min_score=0.5, kinds=(MemoryKind.FINDING,))

    assert provider.embed("") == (0.0, 0.0)
    assert [result.record.payload for result in results] == [sql]
    assert results[0].score == 1.0


def test_provider_dimension_and_values_are_enforced() -> None:
    class BrokenEmbedding:
        def embed(self, text: str) -> Sequence[float]:
            return (1.0, 2.0, float("nan")) if text else (1.0, 2.0, 3.0)

    memory = SemanticMemory(BrokenEmbedding())
    with pytest.raises(ValueError, match="embedding values must be finite"):
        memory.post_finding(_finding())


def test_search_arguments_and_context_keys_are_validated() -> None:
    memory = SemanticMemory()
    with pytest.raises(ValueError, match="top_k"):
        memory.search("query", top_k=0)
    with pytest.raises(ValueError, match="min_score"):
        memory.search("query", min_score=1.1)
    with pytest.raises(ValueError, match="context key"):
        memory.set_fact(" ", "value")


def test_finding_text_includes_searchable_evidence() -> None:
    finding = _finding(evidence={"parameter": "redirect_url"})

    text = finding_text(finding)

    assert "https://example.com/login" in text
    assert "sqli" in text
    assert "redirect_url" in text
