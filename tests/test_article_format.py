"""传播文章初稿 + 演示分镜的静态格式校验。

红线检查(对应 tasks/2026-08-08.md 任务 3 验收):
- 文章初稿存在、字数 1800-3500、含 3 个标题候选、含"授权"法律声明关键词;
- 无"平安 / pingan"等内部敏感字样;
- 无外露真实 IP(除 127.0.0.1)/ 域名(除 example.com)。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parent.parent / "docs"
ARTICLE = DOCS / "articles" / "2026-08-draft-1-ai-pen-aliyun.md"
DEMO = DOCS / "demo-script.md"

# 公网 IPv4(排除回环 127.0.0.1 与 0.0.0.0)
PUBLIC_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_ALLOWED_IPS = {"127.0.0.1", "0.0.0.0"}

# 常见 TLD 域名(排除 example.com)
_DOMAIN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    r"\.(?:com|net|org|io|cn|gov|dev|ai|me|co|xyz|top|info|"
    r"club|tech|cc|tv|store|online|site|app)(?:\.[a-z]{2,3})?",
    re.IGNORECASE,
)

# 内部敏感字样
SENSITIVE = re.compile(r"平安|pingan", re.IGNORECASE)


def _read(path: Path) -> str:
    if not path.is_file():
        pytest.fail(f"缺少文件: {path}")
    return path.read_text(encoding="utf-8")


def _word_count(text: str) -> int:
    """粗略字数:中文字符数 + 英文词数。"""
    cjk = len(re.findall(r"[\u4e00-\u9fff]", text))
    eng = len(re.findall(r"[a-zA-Z]+", text))
    return cjk + eng


# -- 文章存在性与字数 ---------------------------------------------------------


def test_article_exists() -> None:
    assert ARTICLE.is_file(), "文章初稿不存在"


def test_article_word_count_in_range() -> None:
    text = _read(ARTICLE)
    count = _word_count(text)
    assert 1800 <= count <= 3500, f"文章字数 {count} 不在 1800-3500 区间"


# -- 标题候选 ----------------------------------------------------------------


def test_article_has_three_title_candidates() -> None:
    text = _read(ARTICLE)
    # 文章顶部"标题候选"段应列出至少 3 个编号标题
    candidates = re.findall(r"^\d+\.\s+\*\*(.+?)\*\*", text, re.MULTILINE)
    assert len(candidates) >= 3, f"标题候选不足 3 个(实际 {len(candidates)})"


# -- 法律声明 ----------------------------------------------------------------


def test_article_has_authorization_clause() -> None:
    text = _read(ARTICLE)
    assert "授权" in text, "文章缺少'授权'法律声明关键词"


# -- 敏感信息红线(文章 + 分镜均检查)------------------------------------------


@pytest.mark.parametrize("path", [ARTICLE, DEMO])
def test_no_sensitive_keywords(path: Path) -> None:
    text = _read(path)
    hits = SENSITIVE.findall(text)
    assert not hits, f"{path.name} 含内部敏感字样: {hits}"


@pytest.mark.parametrize("path", [ARTICLE, DEMO])
def test_no_public_ip_except_localhost(path: Path) -> None:
    text = _read(path)
    ips = {m.group() for m in PUBLIC_IP.finditer(text)}
    leaked = ips - _ALLOWED_IPS
    assert not leaked, f"{path.name} 含外露公网 IP(非 127.0.0.1): {leaked}"


@pytest.mark.parametrize("path", [ARTICLE, DEMO])
def test_no_external_domain_except_example(path: Path) -> None:
    text = _read(path)
    domains = {m.group().lower() for m in _DOMAIN.finditer(text)}
    leaked = domains - {"example.com"}
    assert not leaked, f"{path.name} 含外露域名(非 example.com): {leaked}"


# -- 分镜存在性 --------------------------------------------------------------


def test_demo_script_exists() -> None:
    assert DEMO.is_file(), "演示分镜脚本不存在"
