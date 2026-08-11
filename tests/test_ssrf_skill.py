"""SSRF 技能文档的静态格式与七类云元数据覆盖校验。"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

SKILL_FILE = Path(__file__).resolve().parent.parent / "skills" / "web" / "ssrf" / "SKILL.md"
REQUIRED_FRONTMATTER = {"name", "description", "phase", "severity_focus"}
REQUIRED_SECTIONS = {"触发条件", "三层测试模型", "SSRF 利用链与定级", "证据要求", "禁止事项"}
CLOUD_MARKERS = {
    "AWS": ("169.254.169.254", "X-aws-ec2-metadata-token", "AccessKeyId"),
    "Azure": ("Metadata: true", "metadata/identity/oauth2/token", "access_token"),
    "GCP": ("metadata.google.internal", "Metadata-Flavor: Google", "service-accounts/default/token"),
    "阿里云": ("100.100.100.200", "X-aliyun-ecs-metadata-token", "AccessKeySecret"),
    "腾讯云": ("metadata.tencentyun.com", "169.254.0.23", "TmpSecretId"),
    "华为云": ("openstack/latest/meta_data.json", "openstack/latest/securitykey", "securitytoken"),
    "Oracle Cloud": ("/opc/v2/instance/", "Authorization: Bearer Oracle", "/opc/v2/identity/"),
}


def _read() -> str:
    if not SKILL_FILE.is_file():
        pytest.fail(f"缺少 SSRF 技能文档: {SKILL_FILE}")
    return SKILL_FILE.read_text(encoding="utf-8")


def _frontmatter(text: str) -> dict[str, object]:
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert match is not None, "缺少合法 YAML frontmatter"
    data = yaml.safe_load(match.group(1))
    assert isinstance(data, dict), "frontmatter 必须为映射"
    return data


def test_skill_file_and_frontmatter() -> None:
    text = _read()
    data = _frontmatter(text)
    assert data.keys() >= REQUIRED_FRONTMATTER
    assert data["name"] == "ssrf"
    assert data["phase"] == "test"


def test_required_sections_and_balanced_fences() -> None:
    text = _read()
    headings = set(re.findall(r"^##\s+(.+)$", text, re.MULTILINE))
    assert headings >= REQUIRED_SECTIONS
    assert text.count("```") % 2 == 0


@pytest.mark.parametrize(("cloud", "markers"), CLOUD_MARKERS.items())
def test_cloud_metadata_coverage(cloud: str, markers: tuple[str, ...]) -> None:
    text = _read()
    assert cloud in text
    missing = [marker for marker in markers if marker not in text]
    assert not missing, f"{cloud} 缺少元数据检测要素: {missing}"


def test_exploitation_chain_is_bounded_and_evidence_driven() -> None:
    text = _read()
    for marker in ("元数据可达", "角色识别", "凭证存在性", "权限评估", "提权判断"):
        assert marker in text
    assert "不使用窃取到的凭证" in text
    assert "离线分析" in text


def test_finding_example_and_credential_redaction() -> None:
    text = _read()
    assert '"type": "ssrf"' in text
    assert '"credential_value_sha256"' in text
    assert "凭证原文不得落盘" in text


def test_no_shell_heredoc_residue_or_internal_words() -> None:
    text = _read()
    assert "SSRF_EOF" not in text
    assert not re.search(r"平安|pingan", text, re.IGNORECASE)


def test_only_documented_ip_literals_are_used() -> None:
    text = _read()
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    allowed = {"169.254.169.254", "100.100.100.200", "169.254.0.23"}
    assert set(ip_pattern.findall(text)) <= allowed
