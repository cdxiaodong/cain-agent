"""
开放重定向检测技能文档的静态格式校验。

校验内容(对应 tasks/2026-08-08.md Day 7 验收标准):
- SKILL.md 文件存在;
- YAML frontmatter 完整(name/description/phase/severity_focus);
- 必需章节齐全(漏洞原理/检测方法/工具/输出格式/证据要求/禁止事项);
- 标题层级合理(有 ## 级章节);
- 代码块格式正确(成对 ```);
- 无内部敏感字样(平安/pingan);
- 中文核心关键词覆盖(开放重定向/Location/redirect/参数/验证);
- Finding 结构示例存在(json 代码块含 open-redirect type)。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent / "skills" / "web" / "open-redirect"
SKILL_FILE = SKILL_DIR / "SKILL.md"

# 内部敏感字样
SENSITIVE = re.compile(r"平安|pingan", re.IGNORECASE)

# YAML frontmatter
FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)

# 必需的 frontmatter 字段
REQUIRED_FM_KEYS = {"name", "description", "phase", "severity_focus"}

# 必需的章节标题(## 级)
REQUIRED_SECTIONS = {
    "漏洞原理",
    "检测方法",
    "工具",
    "输出格式",
    "证据要求",
    "禁止事项",
}


def _read(path: Path) -> str:
    if not path.is_file():
        pytest.fail(f"缺少文件: {path}")
    return path.read_text(encoding="utf-8")


# -- 文件存在性 ---------------------------------------------------------------


def test_skill_file_exists() -> None:
    assert SKILL_FILE.is_file(), f"开放重定向技能文档不存在: {SKILL_FILE}"


def test_skill_file_not_empty() -> None:
    text = _read(SKILL_FILE)
    assert len(text.strip()) > 0, "SKILL.md 内容为空"


# -- YAML frontmatter --------------------------------------------------------


def test_frontmatter_exists() -> None:
    text = _read(SKILL_FILE)
    match = FRONTMATTER_RE.match(text)
    assert match is not None, "缺少 YAML frontmatter (--- ... ---)"


def test_frontmatter_keys() -> None:
    text = _read(SKILL_FILE)
    match = FRONTMATTER_RE.match(text)
    assert match is not None
    fm = match.group(1)
    keys = {line.split(":")[0].strip() for line in fm.splitlines() if ":" in line}
    missing = REQUIRED_FM_KEYS - keys
    assert not missing, f"frontmatter 缺少字段: {missing}"


def test_frontmatter_name_is_open_redirect() -> None:
    text = _read(SKILL_FILE)
    match = FRONTMATTER_RE.match(text)
    assert match is not None
    fm = match.group(1)
    name_match = re.search(r"^name:\s*(.+)$", fm, re.MULTILINE)
    assert name_match is not None
    assert name_match.group(1).strip() == "open-redirect"


def test_frontmatter_phase_is_test() -> None:
    text = _read(SKILL_FILE)
    match = FRONTMATTER_RE.match(text)
    assert match is not None
    fm = match.group(1)
    phase_match = re.search(r"^phase:\s*(.+)$", fm, re.MULTILINE)
    assert phase_match is not None
    assert phase_match.group(1).strip() == "test"


def test_frontmatter_severity_focus() -> None:
    text = _read(SKILL_FILE)
    match = FRONTMATTER_RE.match(text)
    assert match is not None
    fm = match.group(1)
    severity_match = re.search(r"^severity_focus:\s*(.+)$", fm, re.MULTILINE)
    assert severity_match is not None
    severity = severity_match.group(1).strip()
    assert severity in {"critical", "high", "medium", "low"}, \
        f"severity_focus 应为标准级别，实际: {severity}"


# -- 必需章节 ------------------------------------------------------------------


def test_required_sections_present() -> None:
    text = _read(SKILL_FILE)
    headings = re.findall(r"^##\s+(.+)$", text, re.MULTILINE)
    heading_set = {h.strip() for h in headings}
    missing = REQUIRED_SECTIONS - heading_set
    assert not missing, f"缺少必需章节: {missing}"


def test_has_top_level_title() -> None:
    text = _read(SKILL_FILE)
    titles = re.findall(r"^#\s+(.+)$", text, re.MULTILINE)
    assert len(titles) >= 1, "缺少 # 级主标题"


def test_section_hierarchy_valid() -> None:
    """### 级子标题必须出现在 ## 级标题之下,不孤立。"""
    text = _read(SKILL_FILE)
    lines = text.splitlines()
    in_frontmatter = False
    h2_count = 0
    h3_before_h2 = False
    for line in lines:
        if line.strip() == "---":
            in_frontmatter = not in_frontmatter
            continue
        if in_frontmatter:
            continue
        if re.match(r"^##\s+", line):
            h2_count += 1
        elif re.match(r"^###\s+", line) and h2_count == 0:
            h3_before_h2 = True
    assert not h3_before_h2, "存在 ### 标题出现在第一个 ## 标题之前"
    assert h2_count >= 6, f"## 级章节数不足(实际 {h2_count},要求 >= 6)"


# -- 代码块格式 ---------------------------------------------------------------


def test_code_blocks_balanced() -> None:
    text = _read(SKILL_FILE)
    fence_count = text.count("```")
    assert fence_count % 2 == 0, f"代码块不成对(``` 出现 {fence_count} 次)"


def test_has_curl_examples() -> None:
    text = _read(SKILL_FILE)
    assert "curl" in text, "技能文档应包含 curl 命令示例"


def test_has_finding_json_example() -> None:
    text = _read(SKILL_FILE)
    assert '"type": "open-redirect"' in text or '"type":"open-redirect"' in text, \
        "输出格式中应包含开放重定向 Finding JSON 示例"


# -- 内容覆盖 ------------------------------------------------------------------


def test_covers_open_redirect_principles() -> None:
    """
文档应覆盖开放重定向漏洞原理。"""
    text = _read(SKILL_FILE)
    assert "开放重定向" in text or "Open Redirect" in text, "应覆盖开放重定向漏洞定义"
    assert "重定向" in text, "应提及重定向功能"


def test_covers_redirect_parameters() -> None:
    """
文档应提及重定向参数。"""
    text = _read(SKILL_FILE)
    redirect_params = ["redirect", "url", "next", "return", "return_to", "goto"]
    found = sum(1 for p in redirect_params if p in text)
    assert found >= 4, f"应提及至少 4 种重定向参数(实际 {found})"


def test_covers_location_header() -> None:
    """
文档应提及 Location 响应头。"""
    text = _read(SKILL_FILE)
    assert "Location" in text, "应提及 Location 响应头"


def test_covers_external_domain_redirect() -> None:
    """
文档应描述外部域名重定向。"""
    text = _read(SKILL_FILE)
    assert "evil.com" in text or "外部域名" in text, "应描述外部域名重定向测试"


def test_covers_redirect_status_codes() -> None:
    """
文档应提及重定向状态码。"""
    text = _read(SKILL_FILE)
    status_codes = ["301", "302", "307", "308"]
    found = sum(1 for code in status_codes if code in text)
    assert found >= 2, f"应提及至少 2 种重定向状态码(实际 {found})"


def test_covers_protocol_relative_urls() -> None:
    """
文档应提及协议相对 URL 绕过。"""
    text = _read(SKILL_FILE)
    assert "//evil.com" in text or "协议相对" in text, "应提及协议相对 URL 绕过方法"


def test_covers_subdomain_bypass() -> None:
    """
文档应提及子域名绕过。"""
    text = _read(SKILL_FILE)
    assert "子域名" in text or "绕过" in text, "应提及子域名绕过方法"


def test_covers_url_encoding_bypass() -> None:
    """
文档应提及 URL 编码绕过。"""
    text = _read(SKILL_FILE)
    assert "编码" in text or "编码绕过" in text, "应提及 URL 编码绕过方法"


def test_covers_crlf_injection() -> None:
    """
文档应提及 CRLF 注入。"""
    text = _read(SKILL_FILE)
    assert "CRLF" in text or "crlf" in text.lower(), "应提及 CRLF 注入绕过方法"


def test_covers_phishing_poc() -> None:
    """
文档应包含钓鱼 PoC 构造方法。"""
    text = _read(SKILL_FILE)
    assert "钓鱼" in text or "phishing" in text.lower(), "应包含钓鱼 PoC 说明"
    assert "PoC" in text or "poc" in text.lower(), "应提及 PoC 构造"


def test_covers_three_layer_testing() -> None:
    """
文档应包含三层测试模型。"""
    text = _read(SKILL_FILE)
    assert "L1" in text or "探测" in text, "应包含 L1 探测层"
    assert "L2" in text or "验证" in text, "应包含 L2 验证层"
    assert "L3" in text or "绕过" in text, "应包含 L3 绕过层"


def test_covers_oauth_redirect() -> None:
    """
文档应提及 OAuth 回调重定向。"""
    text = _read(SKILL_FILE)
    assert "OAuth" in text or "oauth" in text.lower() or "回调" in text, \
        "应提及 OAuth/OpenID Connect 回调重定向"


def test_covers_javascript_redirect() -> None:
    """
文档应提及 JavaScript 跳转。"""
    text = _read(SKILL_FILE)
    assert "JavaScript" in text or "javascript" in text.lower() or "window.location" in text, \
        "应提及 JavaScript 跳转检测"


def test_covers_success_criteria() -> None:
    """
文档应说明漏洞成功的判断依据。"""
    text = _read(SKILL_FILE)
    assert "Location" in text, "应说明 Location 头作为成功判断"
    assert "302" in text or "301" in text, "应提及重定向状态码"


# -- 红线检查 ------------------------------------------------------------------


def test_no_sensitive_words() -> None:
    text = _read(SKILL_FILE)
    matches = SENSITIVE.findall(text)
    assert not matches, f"文档包含内部敏感字样: {matches}"


def test_no_real_ip_addresses() -> None:
    """不应包含真实公网 IP(127.0.0.1 与文档内网示例除外)。"""
    text = _read(SKILL_FILE)
    ip_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    allowed = {"127.0.0.1", "0.0.0.0", "169.254.169.254", "100.100.100.200"}
    real_ips = {ip for ip_str in ip_pattern.finditer(text) 
                if (ip := ip_str.group(0)) not in allowed}
    assert not real_ips, f"文档包含非允许 IP: {real_ips}"


def test_no_real_domain_names() -> None:
    """不应包含真实域名示例(使用 evil.com/attacker.com 等占位符)。"""
    text = _read(SKILL_FILE)
    # 允许的示例域名
    allowed = {"evil.com", "attacker.com", "malicious.site", "example.com", 
               "target.com", "test.local", "localhost"}
    # 查找可能的域名
    domain_pattern = re.compile(r"\b[a-z0-9-]+\.[a-z]{2,}\b", re.IGNORECASE)
    domains = set()
    for match in domain_pattern.finditer(text):
        domain = match.group(0).lower()
        if domain not in allowed and not domain.endswith(".local"):
            domains.add(domain)
    # 过滤掉技术术语
    tech_terms = {"oauth.net", "openid.net", "window.location", "location.href", 
                  "location.replace", "endpoints.json", "2fevil.com", "40target.com"}
    domains = domains - tech_terms
    assert not domains, f"文档包含疑似真实域名: {domains}"


def test_mentions_security_impact() -> None:
    """
文档应说明安全影响。"""
    text = _read(SKILL_FILE)
    impact_keywords = ["钓鱼", "phishing", "窃取", "凭证", "会话"]
    assert any(kw in text for kw in impact_keywords), \
        "应说明开放重定向的安全影响(钓鱼/窃取凭证)"


def test_mentions_remediation() -> None:
    """
文档应包含修复建议。"""
    text = _read(SKILL_FILE)
    assert "白名单" in text or "验证" in text, "应提出白名单验证作为修复建议"
