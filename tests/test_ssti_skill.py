"""SSTI 检测技能文档的静态格式校验。

校验内容(对应 tasks/2026-08-08.md Day 7 验收标准):
- SKILL.md 文件存在;
- YAML frontmatter 完整(name/description/phase/severity_focus);
- 必需章节齐全(漏洞原理/检测方法/工具/输出格式/证据要求/禁止事项);
- 标题层级合理(有 ## 级章节);
- 代码块格式正确(成对 ```);
- 无内部敏感字样(平安/pingan);
- 中文核心关键词覆盖(SSTI/模板引擎/注入/Payload/渲染);
- Finding 结构示例存在(json 代码块含 ssti type)。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent / "skills" / "web" / "ssti"
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
    assert SKILL_FILE.is_file(), f"SSTI 技能文档不存在: {SKILL_FILE}"


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


def test_frontmatter_name_is_ssti() -> None:
    text = _read(SKILL_FILE)
    match = FRONTMATTER_RE.match(text)
    assert match is not None
    fm = match.group(1)
    name_match = re.search(r"^name:\s*(.+)$", fm, re.MULTILINE)
    assert name_match is not None
    assert name_match.group(1).strip() == "ssti"


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
    assert '"type": "ssti"' in text or '"type":"ssti"' in text, \
        "输出格式中应包含 SSTI Finding JSON 示例"


# -- 内容覆盖 ------------------------------------------------------------------


def test_covers_ssti_principles() -> None:
    """
文档应覆盖 SSTI 漏洞原理。"""
    text = _read(SKILL_FILE)
    assert "SSTI" in text or "服务端模板注入" in text, "应覆盖 SSTI 漏洞定义"
    assert "模板引擎" in text, "应提及模板引擎"


def test_covers_template_syntax_injection() -> None:
    """
文档应提及模板语法注入方法。"""
    text = _read(SKILL_FILE)
    keywords = ["{{7*7}}", "${7*7}", "<%=7*7%>"]
    assert any(kw in text for kw in keywords), "应包含模板语法 Payload 示例"


def test_covers_jinja2_engine() -> None:
    """
文档应提及 Jinja2 模板引擎。"""
    text = _read(SKILL_FILE)
    assert "Jinja2" in text, "应提及 Jinja2 模板引擎"


def test_covers_multiple_engines() -> None:
    """
文档应覆盖多种模板引擎。"""
    text = _read(SKILL_FILE)
    engines = ["Jinja2", "Freemarker", "Velocity", "Smarty", "ERB"]
    found = sum(1 for e in engines if e in text)
    assert found >= 3, f"应覆盖至少 3 种模板引擎(实际 {found})"


def test_covers_rce_payloads() -> None:
    """
文档应包含 RCE Payload 示例。"""
    text = _read(SKILL_FILE)
    rce_keywords = ["popen", "system", "exec", "Runtime", "Execute"]
    assert any(kw in text for kw in rce_keywords), "应包含 RCE Payload 示例"


def test_covers_tplmap_tool() -> None:
    """
文档应提及 tplmap 工具。"""
    text = _read(SKILL_FILE)
    assert "tplmap" in text, "应提及 tplmap SSTI 检测工具"


def test_covers_rendering_detection() -> None:
    """
文档应描述渲染检测方法。"""
    text = _read(SKILL_FILE)
    assert "渲染" in text or "render" in text.lower(), "应描述模板渲染检测"
    assert "49" in text, "应提及 {{7*7}} 渲染为 49 的检测方法"


def test_covers_engine_fingerprinting() -> None:
    """
文档应描述模板引擎指纹识别。"""
    text = _read(SKILL_FILE)
    assert "指纹" in text or "识别" in text, "应描述模板引擎指纹识别方法"


def test_covers_sandbox_bypass() -> None:
    """
文档应提及沙箱绕过。"""
    text = _read(SKILL_FILE)
    assert "沙箱" in text or "bypass" in text.lower(), "应提及沙箱绕过方法"


def test_covers_three_layer_testing() -> None:
    """
文档应包含三层测试模型。"""
    text = _read(SKILL_FILE)
    assert "L1" in text or "探测" in text, "应包含 L1 探测层"
    assert "L2" in text or "验证" in text, "应包含 L2 验证层"
    assert "L3" in text or "绕过" in text, "应包含 L3 绕过层"


def test_covers_success_criteria() -> None:
    """
文档应说明漏洞成功的判断依据。"""
    text = _read(SKILL_FILE)
    assert "49" in text, "应说明 {{7*7}} 渲染为 49 作为成功判断"
    assert "200" in text, "应提及响应状态码"


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
    tech_terms = {"jinja2.com", "python.org", "freemarker.apache.org", 
                  "rubyonrails.org", "smarty.net", "php.net", "context.render",
                  "java.lang", "freemarker.template", "config.items", 
                  "x.class", "utility.execute", "endpoints.json"}
    domains = domains - tech_terms
    assert not domains, f"文档包含疑似真实域名: {domains}"
