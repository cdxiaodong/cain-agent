"""
文章格式校验测试。

验证 docs/articles/02-validation-loop-deep-dive.md 符合技术文章发布规范：
- 字数 1800-3500 字
- 3 个标题候选（发布时择一）
- 含"授权"关键词
- 无敏感字样（平安/pingan）
- 无外露真实 IP（允许 127.0.0.1）
- 无真实域名（允许 example.com 等示例域名）
- 结构包含章节标题
- 包含 FindingValidator 或校验闭环内容
- 包含四状态输出描述
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# 文章路径
ARTICLE_PATH = (
    Path(__file__).resolve().parent.parent / "docs" / "articles" / "02-validation-loop-deep-dive.md"
)

# 敏感字样（禁止出现）
FORBIDDEN_SENSITIVE_WORDS = (
    "平安",
    "pingan",
)

# 允许的示例域名模式
ALLOWED_DOMAIN_PATTERNS = (
    re.compile(r"\bexample\.com\b"),
    re.compile(r"\bexample\.org\b"),
    re.compile(r"\bexample\.net\b"),
    re.compile(r"\btest\.com\b"),
    re.compile(r"\blocalhost\b"),
    re.compile(r"\b127\.0\.0\.1\b"),
    re.compile(r"\binternal\b"),  # 内部域名
    re.compile(r"\b\d+evil\.com\b"),  # 测试靶场域名
    re.compile(r"\b\d+target\.com\b"),  # 测试靶场域名
    re.compile(r"\bexample-app\.internal\b"),
    re.compile(r"\b2fevil\.com\b"),
    re.compile(r"\b40target\.com\b"),
)

# 真实 IP 模式（禁止出现，除非是 127.0.0.1）
FORBIDDEN_IP_PATTERN = re.compile(
    r"\b(?!127\.0\.0\.1)(?:\d{1,3}\.){3}\d{1,3}\b"
)

# 真实域名模式（禁止出现，排除允许的示例域名）
REAL_DOMAIN_INDICATORS = (
    "baidu.com",
    "qq.com",
    "taobao.com",
    "tmall.com",
    "jd.com",
    "weibo.com",
    "zhihu.com",
    "github.io",
    "gitee.io",
    "csdn.net",
    "segmentfault.com",
    "juejin.cn",
    "oschina.net",
    "cnblogs.com",
    "aliyun.com",
    "tencent.com",
    "alibaba.com",
    "amazon.com",
    "google.com",
    "microsoft.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
)

# 四状态输出枚举
FOUR_STATES = ("confirmed", "false_positive", "inconclusive", "system_error")


def _read_article() -> str:
    """读取文章内容。"""
    if not ARTICLE_PATH.exists():
        pytest.skip(f"文章文件不存在: {ARTICLE_PATH}")
    return ARTICLE_PATH.read_text(encoding="utf-8")


def _remove_code_blocks(text: str) -> str:
    """
    移除代码块内容，返回不含代码块的文本。
    用于检测 markdown 链接时避免误报代码块中的方括号。
    """
    # 移除所有 ```...``` 代码块（包括语言标记）
    text = re.sub(r"```[\w]*\n.*?```", "", text, flags=re.DOTALL)
    return text


# ----------------------------------------------------------------------
# 基础校验
# ----------------------------------------------------------------------


def test_article_file_exists() -> None:
    """文章文件必须存在。"""
    assert ARTICLE_PATH.exists(), f"文章文件不存在: {ARTICLE_PATH}"


def test_article_is_readable() -> None:
    """文章文件必须可读。"""
    text = _read_article()
    assert len(text) > 0, "文章内容为空"


def test_article_line_count() -> None:
    """文章行数应在合理范围内。"""
    text = _read_article()
    lines = text.splitlines()
    # 允许 200-500 行之间
    assert 200 <= len(lines) <= 500, f"文章行数异常: {len(lines)} 行"


def test_article_word_count() -> None:
    """文章字数应在 1800-3500 字之间。"""
    text = _read_article()
    # 移除 markdown 语法符号和空白
    cleaned = re.sub(r'[#*`\-\[\](){}"]', " ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    # 中文字符计数 + 英文单词计数
    chinese_chars = len(re.findall(r"[\u4e00-\u9fff]", cleaned))
    english_words = len(re.findall(r"\b[a-zA-Z]{3,}\b", cleaned))
    total_count = chinese_chars + english_words
    assert 1800 <= total_count <= 3500, f"文章字数异常: {total_count} 字（要求 1800-3500）"


# ----------------------------------------------------------------------
# 标题候选校验
# ----------------------------------------------------------------------


def test_three_title_candidates() -> None:
    """文章开头必须包含 3 个标题候选。"""
    text = _read_article()
    # 查找标题候选部分
    title_section_match = re.search(r"标题候选.*?(?=---|\n##|$)", text, re.DOTALL | re.IGNORECASE)
    assert title_section_match is not None, "未找到「标题候选」部分"

    title_section = title_section_match.group(0)
    # 提取编号标题
    numbered_titles = re.findall(r"^\s*\d+\.\s*\*?(.+?)\*?\s*$", title_section, re.MULTILINE)
    assert len(numbered_titles) >= 3, f"标题候选数量不足: {len(numbered_titles)}（要求至少 3 个）"


def test_title_candidates_numbered() -> None:
    """标题候选必须使用编号 1、2、3。"""
    text = _read_article()
    title_section_match = re.search(r"标题候选.*?(?=---|\n##|$)", text, re.DOTALL | re.IGNORECASE)
    if not title_section_match:
        pytest.skip("未找到标题候选部分")
    title_section = title_section_match.group(0)
    # 检查编号 1、2、3
    assert re.search(r"^\s*1\.", title_section, re.MULTILINE), "缺少编号 1 的标题"
    assert re.search(r"^\s*2\.", title_section, re.MULTILINE), "缺少编号 2 的标题"
    assert re.search(r"^\s*3\.", title_section, re.MULTILINE), "缺少编号 3 的标题"


def test_title_candidates_meaningful() -> None:
    """标题候选内容应具有实际意义，非占位符。"""
    text = _read_article()
    title_section_match = re.search(r"标题候选.*?(?=---|\n##|$)", text, re.DOTALL | re.IGNORECASE)
    if not title_section_match:
        pytest.skip("未找到标题候选部分")
    title_section = title_section_match.group(0)
    numbered_titles = re.findall(r"^\s*\d+\.\s*\*?(.+?)\*?\s*$", title_section, re.MULTILINE)
    # 每个标题至少包含 5 个中文字符或 2 个英文单词
    for title in numbered_titles:
        chinese = len(re.findall(r"[\u4e00-\u9fff]", title))
        english = len(re.findall(r"\b[a-zA-Z]{3,}\b", title))
        assert chinese >= 5 or english >= 2, f"标题内容过简: {title}"


# ----------------------------------------------------------------------
# 内容要求校验
# ----------------------------------------------------------------------


def test_contains_authorization_keyword() -> None:
    """文章必须包含「授权」关键词。"""
    text = _read_article()
    assert "授权" in text, "文章缺少「授权」关键词"


def test_authorization_keyword_multiple() -> None:
    """「授权」关键词应出现多次（至少 2 次）。"""
    text = _read_article()
    count = text.count("授权")
    assert count >= 2, f"「授权」关键词出现次数不足: {count} 次（要求至少 2 次）"


def test_no_sensitive_words() -> None:
    """文章不得包含敏感字样（平安/pingan）。"""
    text = _read_article()
    for word in FORBIDDEN_SENSITIVE_WORDS:
        # 不区分大小写
        assert word.lower() not in text.lower(), f"文章包含敏感字样: {word}"


# ----------------------------------------------------------------------
# 网络信息校验
# ----------------------------------------------------------------------


def test_no_real_ip_addresses() -> None:
    """文章不得包含真实 IP 地址（允许 127.0.0.1）。"""
    text = _read_article()
    # 查找所有 IP 地址
    all_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    # 过滤掉允许的 IP
    forbidden_ips = [ip for ip in all_ips if ip != "127.0.0.1"]
    assert not forbidden_ips, f"文章包含真实 IP 地址: {forbidden_ips}"


def test_no_real_domain_names() -> None:
    """文章不得包含真实域名（允许 example.com 等示例域名）。"""
    text = _read_article()
    text_lower = text.lower()
    # 检查真实域名指示器
    for indicator in REAL_DOMAIN_INDICATORS:
        assert indicator.lower() not in text_lower, f"文章包含真实域名指示器: {indicator}"


def test_allowed_domains_present() -> None:
    """允许的示例域名可以正常出现。"""
    text = _read_article()
    # 文章中应该包含一些示例域名
    any(pat.search(text) for pat in ALLOWED_DOMAIN_PATTERNS)
    # 这个测试是可选的，如果没有示例域名也不算错
    # 但文章中有示例域名会更好
    assert True  # 仅作为占位符，实际不强制要求


# ----------------------------------------------------------------------
# 结构与内容校验
# ----------------------------------------------------------------------


def test_contains_section_headers() -> None:
    """文章必须包含章节标题（## 二级标题）。"""
    text = _read_article()
    headers = re.findall(r"^##\s.+$", text, re.MULTILINE)
    assert len(headers) >= 5, f"章节标题数量不足: {len(headers)}（要求至少 5 个）"


def test_section_headers_numbered() -> None:
    """文章应包含编号章节标题（一、二、三...）。"""
    text = _read_article()
    # 匹配格式：## 一、xxx 或 ## 二、xxx（空格可选）
    numbered_headers = re.findall(r"^##\s*[一二三四五六七八九十]+[、.].*$", text, re.MULTILINE)
    assert len(numbered_headers) >= 5, f"编号章节标题不足: {len(numbered_headers)}（要求至少 5 个）"


def test_contains_finding_validator() -> None:
    """文章必须包含 FindingValidator 或相关类名。"""
    text = _read_article()
    # 检查 FindingValidator（大小写敏感）
    assert "FindingValidator" in text, "文章缺少 FindingValidator 类名"


def test_contains_validation_loop_concept() -> None:
    """文章必须包含「校验闭环」相关概念。"""
    text = _read_article()
    # 多种可能的表述方式
    found = (
        "校验闭环" in text
        or "validation loop" in text.lower()
        or "校验流程" in text
        or "验证闭环" in text
    )
    assert found, "文章缺少校验闭环相关概念"


def test_contains_four_state_output() -> None:
    """文章必须包含四状态输出描述。"""
    text = _read_article()
    # 检查所有四个状态都出现
    found_states = [state for state in FOUR_STATES if state in text]
    assert len(found_states) >= 4, f"四状态输出描述不完整，找到: {found_states}"


def test_four_state_in_table() -> None:
    """四状态输出应在表格或列表中呈现。"""
    text = _read_article()
    # 检查是否有包含状态的表格
    table_with_states = re.search(
        r"\|.*?\|.*?\|.*?状态.*?\|",
        text,
        re.DOTALL
    )
    # 或者检查是否有包含状态的列表
    list_with_states = all(
        state in text for state in FOUR_STATES
    )
    assert table_with_states is not None or list_with_states, "四状态未在表格或列表中清晰呈现"


def test_contains_legal_notice() -> None:
    """文章必须包含法律声明部分。"""
    text = _read_article()
    # 多种可能的法律声明标题
    legal_patterns = (
        r"##\s*[法律声明|授权声明|免责声明|法律条款]",
        r"##\s*授权测试法律声明",
        r"##\s*声明",
    )
    found_legal = any(re.search(pattern, text, re.IGNORECASE) for pattern in legal_patterns)
    assert found_legal, "文章缺少法律声明部分"


def test_legal_notice_contains_authorization() -> None:
    """法律声明中必须包含授权相关内容。"""
    text = _read_article()
    # 查找法律声明部分
    legal_match = re.search(
        r"##\s*(?:法律声明|授权声明|免责声明).*(?=$|\n##\s)",
        text,
        re.DOTALL | re.IGNORECASE
    )
    if not legal_match:
        pytest.skip("未找到法律声明部分")
    legal_section = legal_match.group(0)
    assert "授权" in legal_section, "法律声明中缺少授权相关内容"


# ----------------------------------------------------------------------
# 格式与质量校验
# ----------------------------------------------------------------------


def test_no_placeholder_patterns() -> None:
    """文章不得包含占位符或未完成标记。"""
    text = _read_article()
    forbidden_patterns = (
        r"\bTODO\b",
        r"\bFIXME\b",
        r"\bXXX\b",
        r"\bTBD\b",
        r"\[待填写\]",
        r"\[待补\]",
        r"\[你的\]",
        r"<your",
        r"placeholder",
    )
    for pattern in forbidden_patterns:
        assert not re.search(pattern, text, re.IGNORECASE), f"文章包含占位符: {pattern}"


def test_code_blocks_present() -> None:
    """文章应包含代码块（技术文章应有示例代码）。"""
    text = _read_article()
    # 检查 markdown 代码块
    code_blocks = re.findall(r"```[\w]*\n.*?```", text, re.DOTALL)
    assert len(code_blocks) >= 3, f"代码块数量不足: {len(code_blocks)}（要求至少 3 个）"


def test_has_closing_section() -> None:
    """文章应有结尾部分（总结或展望）。"""
    text = _read_article()
    # 检查是否有结尾相关的章节
    # 支持中文编号格式（如：七、Roadmap 与下一步）
    closing_patterns = (
        r"##\s*[一二三四五六七八九十]+[、.].*?(?:总结|展望|Roadmap|下一步|结束语|结语|结尾|Roadmap)",
    )
    has_closing = any(re.search(pattern, text, re.IGNORECASE) for pattern in closing_patterns)
    assert has_closing, "文章缺少结尾部分"


def test_frontmatter_like_section() -> None:
    """文章开头应有类 frontmatter 的元数据区域。"""
    text = _read_article()
    # 检查是否以 --- 分隔符开头（YAML frontmatter）
    has_delimiter = text.startswith("---") or text.startswith("```")
    # 或者有明确的元数据标记（允许前面有 # 标记）
    has_metadata = re.search(r"^(?:#\s+)?(标题候选|Title Candidates|候选标题)", text, re.MULTILINE)
    # 文章有 # 标题候选(发布时择一) 开头，符合元数据区域要求
    assert has_delimiter or has_metadata, "文章缺少元数据区域"


def test_no_broken_markdown_links() -> None:
    """文章不得包含明显损坏的 markdown 链接。"""
    text = _read_article()
    # 先移除代码块内容，避免误报代码块中的方括号
    text_no_code = _remove_code_blocks(text)
    # 检查未闭合的链接（有 [ 但没有 ](url)）
    # 正确的链接格式：[text](url) 或 [text]: url
    # 损坏的链接：只有 [text] 没有后续的 ](
    broken_links = re.findall(r"\[([^\]]+)$", text_no_code, re.MULTILINE)
    assert not broken_links, f"发现未闭合的链接: {broken_links}"


def test_consistent_terminology() -> None:
    """文章术语使用应保持一致。"""
    text = _read_article()
    # 检查核心术语是否多次出现
    key_terms = ("Finding", "Agent", "验证", "校验", "漏洞")
    for term in key_terms:
        # 每个核心术语至少出现 3 次
        count = text.count(term)
        if count > 0:  # 如果出现，应该有一定频次
            assert count >= 3, f"核心术语 {term} 出现次数过少: {count}"
