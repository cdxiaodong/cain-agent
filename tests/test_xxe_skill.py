"""XXE 检测技能文档的静态格式校验。

校验内容:
- SKILL.md 文件存在;
- YAML frontmatter 完整(name/description/phase/severity_focus);
- 必需章节齐全(漏洞原理/检测方法/工具/输出格式/证据要求/禁止事项);
- 标题层级合理(有 ## 级章节);
- 代码块格式正确(成对 ```);
- 无内部敏感字样(平安/pingan);
- 中文核心关键词覆盖(XXE/XML/实体/外部实体);
- Finding 结构示例存在(json 代码块含 xxe type)。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent / "skills" / "web" / "xxe"
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
    assert SKILL_FILE.is_file(), f"XXE 技能文档不存在: {SKILL_FILE}"


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


def test_frontmatter_name_is_xxe() -> None:
    text = _read(SKILL_FILE)
    match = FRONTMATTER_RE.match(text)
    assert match is not None
    fm = match.group(1)
    name_match = re.search(r"^name:\s*(.+)$", fm, re.MULTILINE)
    assert name_match is not None
    assert name_match.group(1).strip() == "xxe"


def test_frontmatter_phase_is_test() -> None:
    text = _read(SKILL_FILE)
    match = FRONTMATTER_RE.match(text)
    assert match is not None
    fm = match.group(1)
    phase_match = re.search(r"^phase:\s*(.+)$", fm, re.MULTILINE)
    assert phase_match is not None
    assert phase_match.group(1).strip() == "test"


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
    assert '"type": "xxe"' in text or '"type":"xxe"' in text, \
        "输出格式中应包含 XXE Finding JSON 示例"


# -- 内容覆盖 ------------------------------------------------------------------


def test_covers_xxe_principles() -> None:
    """文档应覆盖 XXE 核心原理。"""
    text = _read(SKILL_FILE)
    assert "外部实体" in text, "应覆盖外部实体原理"
    assert "DOCTYPE" in text, "应覆盖 DOCTYPE 声明"


def test_covers_entity_declaration() -> None:
    """文档应展示 ENTITY 声明语法。"""
    text = _read(SKILL_FILE)
    assert "<!ENTITY" in text, "应包含 ENTITY 声明示例"


def test_covers_file_read() -> None:
    """文档应覆盖文件读取利用。"""
    text = _read(SKILL_FILE)
    assert "file:///" in text, "应包含 file:// 协议实体示例"
    assert "/etc/passwd" in text, "应包含 /etc/passwd 文件读取示例"


def test_covers_blind_xxe_oob() -> None:
    """文档应覆盖 Blind XXE / OOB 外带。"""
    text = _read(SKILL_FILE)
    assert "OOB" in text or "Out-of-Band" in text, "应涉及 OOB 外带"
    assert "参数实体" in text or "parameter entity" in text.lower() or "%xxe" in text, \
        "应涉及参数实体"


def test_covers_ssrf_via_xxe() -> None:
    """文档应覆盖通过 XXE 触发 SSRF。"""
    text = _read(SKILL_FILE)
    assert "SSRF" in text, "应涉及 SSRF 利用"
    assert "169.254.169.254" in text, "应包含云元数据端点示例"


def test_covers_poc_construction() -> None:
    """文档应包含 PoC 构造方法。"""
    text = _read(SKILL_FILE)
    assert "Payload" in text or "payload" in text, "应包含 Payload 构造说明"


def test_covers_success_criteria() -> None:
    """文档应说明漏洞成功的判断依据。"""
    text = _read(SKILL_FILE)
    assert "root:x:0:0" in text, "应描述 /etc/passwd 特征作为成功判断"
    assert "200" in text, "应提及状态码 200"


def test_covers_content_type_detection() -> None:
    """文档应覆盖 Content-Type 探测方法。"""
    text = _read(SKILL_FILE)
    assert "application/xml" in text or "text/xml" in text, \
        "应涉及 XML Content-Type 探测"


# -- 红线检查 ------------------------------------------------------------------


def test_no_sensitive_words() -> None:
    text = _read(SKILL_FILE)
    matches = SENSITIVE.findall(text)
    assert not matches, f"文档包含内部敏感字样: {matches}"


def test_no_real_ip_addresses() -> None:
    """不应包含真实公网 IP(127.0.0.1 / 169.254.169.254 / 100.100.100.200 与文档示例除外)。"""
    text = _read(SKILL_FILE)
    ip_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    allowed = {"127.0.0.1", "0.0.0.0", "169.254.169.254", "100.100.100.200"}
    real_ips = {ip for ip_str in ip_pattern.finditer(text)
                if (ip := ip_str.group(0)) not in allowed}
    assert not real_ips, f"文档包含非允许 IP: {real_ips}"
