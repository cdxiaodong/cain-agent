"""Retrievable semantic memory shared by multi-agent solvers.

The store is logic-only and keeps the Blackboard write/read vocabulary. A
dependency-free local embedding is used by default; callers can replace it with
any deterministic provider without changing the persistence interface.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from cain_agent.multi_agent.types import Finding


class EmbeddingProvider(Protocol):
    """Embedding boundary for local or caller-supplied vector implementations."""

    def embed(self, text: str) -> Sequence[float]:
        """Return one fixed-dimension vector for ``text``."""


class MemoryKind(StrEnum):
    """Record types stored in semantic memory."""

    FINDING = "finding"
    CONTEXT = "context"


@dataclass(frozen=True)
class MemoryRecord:
    """One indexed item and the vector used to retrieve it."""

    record_id: str
    kind: MemoryKind
    key: str
    text: str
    vector: tuple[float, ...]
    payload: object
    solver_id: str
    timestamp: float


@dataclass(frozen=True)
class MemorySearchResult:
    """A retrieval result with its cosine similarity score."""

    record: MemoryRecord
    score: float


_WORD_RE = re.compile(r"[a-z0-9]+|[\u4e00-\u9fff]+")
_SYNONYMS = {
    "sqli": "sql injection",
    "xss": "cross site scripting",
    "ssrf": "server side request forgery",
    "xxe": "xml external entity",
    "rce": "remote code execution",
    "unauth": "unauthenticated access",
}


class LocalHashEmbedding:
    """Deterministic word and character n-gram embedding with no dependencies."""

    def __init__(self, *, dimension: int = 128, ngram_size: int = 3) -> None:
        if dimension < 1:
            raise ValueError("dimension must be positive")
        if ngram_size < 1:
            raise ValueError("ngram_size must be positive")
        self.dimension = dimension
        self.ngram_size = ngram_size

    def embed(self, text: str) -> tuple[float, ...]:
        features: list[str] = []
        for raw_token in self._tokens(text):
            tokens = _SYNONYMS.get(raw_token, raw_token).split()
            for token in tokens:
                features.append(token)
                if len(token) > self.ngram_size and token.isascii() and token.isalnum():
                    features.extend(
                        token[index : index + self.ngram_size]
                        for index in range(len(token) - self.ngram_size + 1)
                    )
                elif len(token) > 1:
                    features.extend(token[index : index + 2] for index in range(len(token) - 1))

        vector = [0.0] * self.dimension
        for feature in features:
            digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
            index = int.from_bytes(digest, "little") % self.dimension
            vector[index] += 1.0
        return _normalize(vector)

    @staticmethod
    def _tokens(text: str) -> list[str]:
        normalized = unicodedata.normalize("NFKC", text).casefold()
        return _WORD_RE.findall(normalized)


class SemanticMemory:
    """Thread-safe finding and context index with similarity retrieval."""

    def __init__(
        self,
        embedding: EmbeddingProvider | None = None,
        *,
        dimension: int | None = None,
    ) -> None:
        if embedding is None:
            self.embedding: EmbeddingProvider = LocalHashEmbedding(
                dimension=dimension or 128,
            )
        elif dimension is not None:
            raise ValueError("dimension cannot be set when an embedding provider is supplied")
        else:
            self.embedding = embedding

        self._dimension = self._provider_dimension()
        self._lock = threading.RLock()
        self._records: list[MemoryRecord] = []
        self._record_ids: set[str] = set()
        self._context_keys: dict[str, str] = {}

    def post_finding(self, finding: Finding, solver_id: str = "") -> MemoryRecord:
        """Index a Finding using Blackboard-compatible posting semantics."""

        return self._append(
            kind=MemoryKind.FINDING,
            key=finding.finding_id,
            text=finding_text(finding),
            payload=finding,
            solver_id=solver_id or finding.solver_id,
            timestamp=finding.timestamp,
        )

    def set_fact(self, key: str, value: object, solver_id: str = "") -> MemoryRecord:
        """Index context under a stable key, replacing the previous value."""

        if not key.strip():
            raise ValueError("context key cannot be blank")
        record_id = f"context:{hashlib.sha256(key.encode('utf-8')).hexdigest()}"
        record = self._build_record(
            record_id=record_id,
            kind=MemoryKind.CONTEXT,
            key=key,
            text=context_text(key, value),
            payload=value,
            solver_id=solver_id,
        )
        with self._lock:
            previous_id = self._context_keys.get(key)
            if previous_id is not None:
                self._records = [record for record in self._records if record.record_id != previous_id]
                self._record_ids.discard(previous_id)
            self._records.append(record)
            self._record_ids.add(record.record_id)
            self._context_keys[key] = record.record_id
        return record

    def read_findings(self) -> list[Finding]:
        with self._lock:
            return [
                record.payload
                for record in self._records
                if record.kind is MemoryKind.FINDING and isinstance(record.payload, Finding)
            ]

    def get_fact(self, key: str, default: object = None) -> object:
        with self._lock:
            record_id = self._context_keys.get(key)
            if record_id is not None:
                for record in reversed(self._records):
                    if record.record_id == record_id:
                        return record.payload
        return default

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float = 0.0,
        kinds: Sequence[MemoryKind] | None = None,
    ) -> list[MemorySearchResult]:
        """Return the most similar records, ordered by descending cosine score."""

        if top_k < 1:
            raise ValueError("top_k must be positive")
        if not 0.0 <= min_score <= 1.0:
            raise ValueError("min_score must be between 0 and 1")

        allowed = set(kinds) if kinds is not None else None
        query_vector = self._embed(query)
        with self._lock:
            candidates = [
                MemorySearchResult(
                    record=record,
                    score=_cosine(query_vector, record.vector),
                )
                for record in self._records
                if allowed is None or record.kind in allowed
            ]
        candidates.sort(key=lambda result: (-result.score, result.record.record_id))
        return [result for result in candidates if result.score >= min_score][:top_k]

    def stats(self) -> dict[str, int]:
        with self._lock:
            findings = sum(record.kind is MemoryKind.FINDING for record in self._records)
            contexts = sum(record.kind is MemoryKind.CONTEXT for record in self._records)
            return {
                "findings": findings,
                "contexts": contexts,
                "total": len(self._records),
                "dimension": self._dimension,
            }

    def _append(
        self,
        *,
        kind: MemoryKind,
        key: str,
        text: str,
        payload: object,
        solver_id: str,
        timestamp: float,
    ) -> MemoryRecord:
        record_id = f"{kind.value}:{key}"
        record = self._build_record(
            record_id=record_id,
            kind=kind,
            key=key,
            text=text,
            payload=payload,
            solver_id=solver_id,
            timestamp=timestamp,
        )
        with self._lock:
            suffix = 0
            candidate_id = record_id
            while candidate_id in self._record_ids:
                suffix += 1
                candidate_id = f"{record_id}#{suffix}"
            unique_record = MemoryRecord(
                record_id=candidate_id,
                kind=record.kind,
                key=record.key,
                text=record.text,
                vector=record.vector,
                payload=record.payload,
                solver_id=record.solver_id,
                timestamp=record.timestamp,
            )
            self._records.append(unique_record)
            self._record_ids.add(candidate_id)
        return unique_record

    def _build_record(
        self,
        *,
        record_id: str,
        kind: MemoryKind,
        key: str,
        text: str,
        payload: object,
        solver_id: str,
        timestamp: float | None = None,
    ) -> MemoryRecord:
        vector = self._embed(text)
        return MemoryRecord(
            record_id=record_id,
            kind=kind,
            key=key,
            text=text,
            vector=vector,
            payload=payload,
            solver_id=solver_id,
            timestamp=timestamp if timestamp is not None else time.time(),
        )

    def _provider_dimension(self) -> int:
        vector = self.embedding.embed("")
        dimension = len(vector)
        if dimension < 1:
            raise ValueError("embedding provider dimension must be positive")
        return dimension

    def _embed(self, text: str) -> tuple[float, ...]:
        vector = tuple(self.embedding.embed(text))
        if len(vector) != self._dimension:
            raise ValueError(
                f"embedding dimension changed: expected {self._dimension}, got {len(vector)}",
            )
        if any(not math.isfinite(value) for value in vector):
            raise ValueError("embedding values must be finite")
        return _normalize(vector)


def finding_text(finding: Finding) -> str:
    """Build the searchable representation of a multi-agent Finding."""

    fields = [
        finding.cloud,
        finding.service,
        finding.resource,
        finding.issue_type,
        finding.severity.value,
        finding.detail,
        _stable_json(finding.evidence),
    ]
    return " ".join(str(field) for field in fields if field)


def context_text(key: str, value: object) -> str:
    return f"{key} {_stable_json(value)}"


def _stable_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    except (TypeError, ValueError):
        return str(value)


def _normalize(vector: Sequence[float]) -> tuple[float, ...]:
    norm = math.sqrt(sum(float(value) * float(value) for value in vector))
    if norm == 0.0:
        return tuple(0.0 for _ in vector)
    return tuple(float(value) / norm for value in vector)


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right):
        raise ValueError("cannot compare vectors with different dimensions")
    left_norm = _normalize(left)
    right_norm = _normalize(right)
    return sum(a * b for a, b in zip(left_norm, right_norm, strict=True))
