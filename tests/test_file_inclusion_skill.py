"""文件包含检测技能文档的静态格式校验。

校验内容:
- SKILL.md 文件存在;
- YAML frontmatter 完整(name/description/phase/severity_focus);
- 必需章节齐全(漏洞原理/检测方法/工具/输出格式/证据要求/禁止事项);
- 标题层级合理(有 ## 级章节);
- 代码块格式正确(成对 ```);
- 无内部敏感字样(平安/pingan);
- 中文核心关键词覆盖(LFI/RFI/文件包含/路径遍历);
- Finding 结构示例存在(json 代码块含 file-inclusion type)。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent / "skills" / "web" / "file-inclusion"
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
    assert SKILL_FILE.is_file(), f"文件包含技能文档不存在: {SKILL_FILE}"


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


def test_frontmatter_name_is_file_inclusion() -> None:
    text = _read(SKILL_FILE)
    match = FRONTMATTER_RE.match(text)
    assert match is not None
    fm = match.group(1)
    name_match = re.search(r"^name:\s*(.+)$", fm, re.MULTILINE)
    assert name_match is not None
    assert name_match.group(1).strip() == "file-inclusion"


def test_frontmatter_phase_is_test() -> None:
    text = _read(SKILL_FILE)
    match = FRONTMATTER_RE.match(text)
    assert match is not None
    fm = match.group(1)
    phase_match = re.search(r"^phase:\s*(.+)$", fm, re.MULTILINE)
    assert phase_match is not None
    assert phase_match.group(1).strip() == "test"


def test_frontmatter_severity_focus_is_high() -> None:
    text = _read(SKILL_FILE)
    match = FRONTMATTER_RE.match(text)
    assert match is not None
    fm = match.group(1)
    severity_match = re.search(r"^severity_focus:\s*(.+)$", fm, re.MULTILINE)
    assert severity_match is not None
    assert severity_match.group(1).strip() in ("high", "critical"), \
        f"severity_focus 应为 high 或 critical，实际: {severity_match.group(1).strip()}"


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
    assert '"type": "file-inclusion"' in text or '"type":"file-inclusion"' in text, \
        "输出格式中应包含文件包含 Finding JSON 示例"


def test_finding_json_has_required_fields() -> None:
    """Finding JSON 示例应包含必需字段。"""
    text = _read(SKILL_FILE)
    # 提取 json 代码块
    json_blocks = re.findall(r"```json\n(.*?)\n```", text, re.DOTALL)
    assert len(json_blocks) >= 1, "应至少有一个 JSON 代码块示例"
    
    # 检查第一个 JSON 块是否包含必需字段
    finding_block = json_blocks[0]
    required_fields = {"id", "type", "severity", "status", "title", "endpoint", 
                      "description", "payload", "verification_steps", "evidence", "remediation"}
    for field in required_fields:
        assert f'"{field}"' in finding_block or f"'{field}'" in finding_block, \
            f"Finding JSON 缺少字段: {field}"


# -- 内容覆盖 ------------------------------------------------------------------


def test_covers_lfi_principles() -> None:
    """文档应覆盖 LFI 核心原理。"""
    text = _read(SKILL_FILE)
    assert "本地文件包含" in text, "应覆盖本地文件包含原理"
    assert "路径遍历" in text, "应覆盖路径遍历原理"


def test_covers_rfi_principles() -> None:
    """文档应覆盖 RFI 核心原理。"""
    text = _read(SKILL_FILE)
    assert "远程文件包含" in text, "应覆盖远程文件包含原理"
    assert "http://" in text, "应包含 http:// 协议示例"


def test_covers_path_traversal() -> None:
    """文档应覆盖路径遍历利用。"""
    text = _read(SKILL_FILE)
    assert "../" in text, "应包含 ../ 路径遍历示例"
    assert "/etc/passwd" in text, "应包含 /etc/passwd 文件读取示例"


def test_covers_php_wrapper() -> None:
    """文档应覆盖 PHP Wrapper 利用。"""
    text = _read(SKILL_FILE)
    assert "php://filter" in text, "应包含 php://filter 伪协议示例"
    assert "convert.base64-encode" in text, "应包含 Base64 编码读取示例"


def test_covers_rfi_detection() -> None:
    """文档应覆盖 RFI 检测方法。"""
    text = _read(SKILL_FILE)
    assert "RFI" in text, "应涉及 RFI 检测"
    assert "远程文件" in text, "应涉及远程文件加载"


def test_covers_log_injection() -> None:
    """文档应覆盖日志注入利用。"""
    text = _read(SKILL_FILE)
    assert "日志注入" in text, "应涉及日志注入代码执行"
    assert "access.log" in text or "error.log" in text, "应提及日志文件路径"


def test_covers_path_truncation() -> None:
    """文档应覆盖路径截断绕过。"""
    text = _read(SKILL_FILE)
    assert "%00" in text, "应包含空字节截断示例"
    assert "截断" in text, "应提及路径截断绕过"


def test_covers_encoding_bypass() -> None:
    """文档应覆盖编码绕过。"""
    text = _read(SKILL_FILE)
    assert "编码" in text, "应提及编码绕过"
    assert "双编码" in text or "%25" in text, "应包含双编码绕过示例"


def test_covers_poc_construction() -> None:
    """文档应包含 PoC 构造方法。"""
    text = _read(SKILL_FILE)
    assert "Payload" in text or "payload" in text, "应包含 Payload 构造说明"


def test_covers_success_criteria() -> None:
    """文档应说明漏洞成功的判断依据。"""
    text = _read(SKILL_FILE)
    assert "root:x:0:0" in text, "应描述 /etc/passwd 特征作为成功判断"
    assert "200" in text, "应提供状态码 200"


def test_covers_parameter_identification() -> None:
    """文档应覆盖参数识别方法。"""
    text = _read(SKILL_FILE)
    assert "file" in text, "应提及 file 参数"
    assert "page" in text, "应提及 page 参数"
    assert "include" in text, "应提及 include 参数"


def test_covers_three_layer_testing() -> None:
    """文档应覆盖三层测试模型。"""
    text = _read(SKILL_FILE)
    assert "L1" in text, "应提及 L1 探测"
    assert "L2" in text, "应提及 L2 验证"
    assert "L3" in text, "应提及 L3 绕过"


def test_covers_windows_targets() -> None:
    """文档应覆盖 Windows 目标测试。"""
    text = _read(SKILL_FILE)
    assert "Windows" in text or "C:/" in text, "应提及 Windows 目标"
    assert "win.ini" in text, "应包含 win.ini 示例"


def test_covers_evidence_requirements() -> None:
    """文档应说明证据要求。"""
    text = _read(SKILL_FILE)
    assert "证据要求" in text, "应有证据要求章节"
    assert "文件内容" in text, "应说明需要回显文件内容作为证据"


def test_covers_prohibited_actions() -> None:
    """文档应说明禁止事项。"""
    text = _read(SKILL_FILE)
    assert "禁止事项" in text, "应有禁止事项章节"
    assert "敏感" in text, "应提及敏感文件读取限制"


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
    assert not real_ips, f"文档包含非许可 IP: {real_ips}"


def test_no_real_domains() -> None:
    """不应包含真实域名，应使用占位符。"""
    text = _read(SKILL_FILE)
    # 允许的示例域名
    allowed = {"target.com", "example.com", "attacker_server", "attackerserver.com"}
    # 排除 localhost、127.0.0.1 等
    domain_pattern = re.compile(
        r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b"
    )
    found_domains = set()
    for match in domain_pattern.finditer(text):
        domain = match.group(0).lower()
        # 跳过常见技术词汇和允许的示例
        if domain in {"localhost", "php", "json", "xml", "http", "https", "ftp"}:
            continue
        if domain not in allowed and not domain.startswith("attacker"):
            found_domains.add(domain)
    
    # 进一步过滤技术相关的词
    tech_keywords = {"filter", "convert", "base64", "encode", "resource", "wrapper",
                    "user-agent", "content-type", "application", "text", "apache", "nginx",
                    # Common example filenames used in LFI/RFI security documentation
                    "index.php", "config.php", "home.php", "view.php", "evil.php",
                    "header.php", "test.txt", "dirtraversal.txt", "endpoints.json",
                    "default.html", "win.ini", "access.log", "00.jpg",
                    "convert.base64-encode", "fs.readfile", "node.js",
                    "5.3.4", "3.1"}
    found_domains = {d for d in found_domains if d not in tech_keywords}
    
    assert not found_domains, f"文档包含真实域名或非占位符: {found_domains}"


def test_evidence_section_mentions_data_sanitization() -> None:
    """证据要求章节应提及数据脱敏。"""
    text = _read(SKILL_FILE)
    # 提取"证据要求"章节内容
    evidence_match = re.search(r"## 证据要求\s*\n(.*?)(?=##|$)", text, re.DOTALL)
    assert evidence_match is not None, "应有证据要求章节"
    evidence_content = evidence_match.group(1)
    assert "脱敏" in evidence_content or "截断" in evidence_content or "不完整" in evidence_content, \
        "证据要求应说明数据脱敏/截断"


def test_prohibited_section_mentions_real_credentials() -> None:
    """禁止事项章节应提及不读取真实凭据文件。"""
    text = _read(SKILL_FILE)
    # 提取"禁止事项"章节内容
    prohibited_match = re.search(r"## 禁止事项\s*\n(.*?)(?=##|$)", text, re.DOTALL)
    assert prohibited_match is not None, "应有禁止事项章节"
    prohibited_content = prohibited_match.group(1)
    assert "凭据" in prohibited_content or "敏感" in prohibited_content or "私钥" in prohibited_content, \
        "禁止事项应提及不读取敏感凭据"


def test_has_trigger_conditions_section() -> None:
    """文档应包含触发条件章节（虽然不在必需6章节中，但建议有）。"""
    text = _read(SKILL_FILE)
    # 检查是否有"触发条件"或类似的章节
    has_trigger = "触发条件" in text or "候选端点" in text or "识别端点" in text
    assert has_trigger, "建议包含触发条件/端点识别相关内容"


def test_finding_json_matches_skill_type() -> None:
    """Finding JSON 的 type 字段应与技能名称一致。"""
    text = _read(SKILL_FILE)
    json_blocks = re.findall(r"```json\n(.*?)\n```", text, re.DOTALL)
    assert len(json_blocks) >= 1, "应至少有一个 JSON 代码块示例"
    
    finding_block = json_blocks[0]
    # 检查 type 字段
    type_match = re.search(r'"type"\s*:\s*"([^"]+)"', finding_block)
    assert type_match is not None, "Finding JSON 应包含 type 字段"
    assert type_match.group(1) == "file-inclusion", \
        f"Finding type 应为 'file-inclusion'，实际: {type_match.group(1)}"


def test_curl_examples_are_realistic() -> None:
    """curl 示例应包含真实的文件包含 Payload。"""
    text = _read(SKILL_FILE)
    # 检查 curl 命令是否包含典型的 LFI Payload
    has_lfi_payload = ("../" in text and "etc/passwd" in text) or "file=.." in text
    assert has_lfi_payload, "curl 示例应包含 LFI 路径遍历 Payload"
    
    # 检查是否包含 PHP Wrapper 示例
    has_php_wrapper = "php://filter" in text
    assert has_php_wrapper, "curl 示例应包含 PHP Wrapper Payload"


def test_documentation_language_consistency() -> None:
    """文档应使用中文为主，技术术语可保留英文。"""
    text = _read(SKILL_FILE)
    # 统计中文字符（不包括标点）
    chinese_chars = len(re.findall(r"[\u4e00-\u9fff]", text))
    # 文档应该有足够的中文字符
    assert chinese_chars > 500, f"文档中文字符过少（{chinese_chars} 字），可能未使用中文编写"


def test_detection_method_has_steps() -> None:
    """检测方法章节应包含步骤说明。"""
    text = _read(SKILL_FILE)
    # 提取"检测方法"章节内容
    detection_match = re.search(r"## 检测方法\s*\n(.*?)(?=##|$)", text, re.DOTALL)
    assert detection_match is not None, "应有检测方法章节"
    detection_content = detection_match.group(1)
    # 检查是否有步骤标记（如 "步骤" 或 "步骤" 后跟数字/中文数字）
    has_steps = "步骤" in detection_content or "Step" in detection_content
    assert has_steps, "检测方法应包含步骤说明"
    # 检查是否有至少3个步骤
    step_count = len(re.findall(r"步骤[一二三四五六七八九十0-9]", detection_content))
    assert step_count >= 3, f"检测方法应至少包含3个步骤，实际找到 {step_count} 个"


def test_tools_section_covers_multiple_tools() -> None:
    """工具章节应覆盖多种工具。"""
    text = _read(SKILL_FILE)
    # 提取"工具"章节内容
    tools_match = re.search(r"## 工具\s*\n(.*?)(?=##|$)", text, re.DOTALL)
    assert tools_match is not None, "应有工具章节"
    tools_content = tools_match.group(1)
    # 检查是否包含 curl 和至少一个其他工具
    has_curl = "curl" in tools_content
    has_other_tool = "Burp" in tools_content or "wfuzz" in tools_content or "sqlmap" in tools_content
    assert has_curl, "工具章节应包含 curl"
    assert has_other_tool, "工具章节应包含除 curl 外的其他工具（如 Burp Suite、wfuzz 等）"


def test_remédiation_section_present_in_finding() -> None:
    """Finding JSON 应包含修复建议（remediation 字段）。"""
    text = _read(SKILL_FILE)
    json_blocks = re.findall(r"```json\n(.*?)\n```", text, re.DOTALL)
    assert len(json_blocks) >= 1, "应至少有一个 JSON 代码块示例"
    
    finding_block = json_blocks[0]
    assert "remediation" in finding_block.lower(), "Finding JSON 应包含 remediation 字段"
    # 检查 remediation 字段是否有内容
    remediation_match = re.search(r'"remediation"\s*:\s*"([^"]+)"', finding_block)
    assert remediation_match is not None, "remediation 字段应有值"
    assert len(remediation_match.group(1)) > 20, "remediation 内容应详细（至少20字符）"


def test_severity_in_finding_is_high_or_critical() -> None:
    """Finding JSON 的 severity 应为 high 或 critical。"""
    text = _read(SKILL_FILE)
    json_blocks = re.findall(r"```json\n(.*?)\n```", text, re.DOTALL)
    assert len(json_blocks) >= 1, "应至少有一个 JSON 代码块示例"
    
    finding_block = json_blocks[0]
    severity_match = re.search(r'"severity"\s*:\s*"([^"]+)"', finding_block)
    assert severity_match is not None, "Finding JSON 应包含 severity 字段"
    assert severity_match.group(1) in ("high", "critical"), \
        f"severity 应为 high 或 critical，实际: {severity_match.group(1)}"
