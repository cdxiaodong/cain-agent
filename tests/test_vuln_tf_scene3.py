"""阿里云 vulnerable-terraform 靶场场景三静态校验。

场景三 = 管理员权限 RAM 用户(挂内置 AdministratorAccess 系统策略),与场景二互补:
- 场景二用自定义过度授权策略验证「规则精确匹配」;
- 场景三用管理员全权限验证「管理员账户完整识别」——Action "*" 命中
  RamPrivescAnalyzer 全部 5 条规则(3 critical + 2 high)且 is_admin=true。

不执行任何 terraform init/apply(派活单红线:严禁碰真实云)。只做配置文件结构静态检查:
- scene3-main.tf / scene3-outputs.tf / scene3-variables.tf 三个文件存在且含必需块;
- 靶标用户挂 AdministratorAccess(System)、对照用户挂 AliyunReadOnlyAccess(System);
- 两个用户带 Purpose = "vuln-benchmark" 标签;
- 无硬编码 AccessKey、无 RAM AccessKey 资源、无 LoginProfile;
- scene3-main.tf 头五行含红字声明(仅授权测试 / 当天 destroy)。
若本机 terraform 可用,顺带跑 terraform fmt -check;不可用则 skip(CI 不红)。
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

TF_DIR = Path(__file__).resolve().parent.parent / "bench" / "aliyun-vuln-tf"
SCENE3_MAIN_TF = TF_DIR / "scene3-main.tf"
SCENE3_OUTPUTS_TF = TF_DIR / "scene3-outputs.tf"
SCENE3_VARIABLES_TF = TF_DIR / "scene3-variables.tf"

# 疑似真实阿里云 AccessKey 模式:LTAI 前缀 + 至少 12 位字母数字(真实 AK 通常 24-30 位)。
LTAI_PATTERN = re.compile(r"LTAI[A-Za-z0-9]{12,}")


def _read(path: Path) -> str:
    if not path.is_file():
        pytest.fail(f"缺少靶场场景三文件: {path}")
    return path.read_text(encoding="utf-8")


def test_scene3_files_exist() -> None:
    """场景三三个文件齐全(main/outputs/variables)。"""
    assert SCENE3_MAIN_TF.is_file()
    assert SCENE3_OUTPUTS_TF.is_file()
    assert SCENE3_VARIABLES_TF.is_file()


def test_scene3_main_has_redline_header() -> None:
    """文件头 5 行内含红字声明(仅授权测试 / 当天 destroy)。"""
    text = _read(SCENE3_MAIN_TF)
    head = "\n".join(text.splitlines()[:8])
    assert "授权" in head and "destroy" in head, (
        "scene3-main.tf 头部缺少红字声明(授权测试 + 当天 destroy)"
    )


def test_scene3_has_admin_user_and_readonly_control() -> None:
    """场景三:靶标管理员用户 + 对照只读用户,各带一个策略挂载。"""
    text = _read(SCENE3_MAIN_TF)
    assert 'resource "alicloud_ram_user" "vuln_admin_user"' in text, "缺少靶标用户 vuln_admin_user"
    assert 'resource "alicloud_ram_user" "safe_readonly_user"' in text, "缺少对照用户 safe_readonly_user"
    assert 'resource "alicloud_ram_user_policy_attachment" "vuln_admin_attach"' in text
    assert 'resource "alicloud_ram_user_policy_attachment" "safe_readonly_attach"' in text


def test_vuln_admin_attaches_administrator_access() -> None:
    """靶标用户挂 AdministratorAccess 系统策略(管理员全权限)。

    以挂载 resource 块为单位切片,确保 AdministratorAccess 绑定在靶标用户。
    """
    text = _read(SCENE3_MAIN_TF)
    start = text.index('resource "alicloud_ram_user_policy_attachment" "vuln_admin_attach"')
    end = text.find("resource", start + 1)
    block = text[start : end if end != -1 else len(text)]
    assert "AdministratorAccess" in block, "靶标用户应挂 AdministratorAccess 管理员策略"
    assert 'policy_type = "System"' in block, "靶标用户应为 System 系统策略(内置管理员策略)"


def test_safe_readonly_attaches_aliyun_read_only() -> None:
    """对照用户挂 AliyunReadOnlyAccess 系统策略(全局只读,零提权权限)。"""
    text = _read(SCENE3_MAIN_TF)
    start = text.index('resource "alicloud_ram_user_policy_attachment" "safe_readonly_attach"')
    end = text.find("resource", start + 1)
    block = text[start : end if end != -1 else len(text)]
    assert "AliyunReadOnlyAccess" in block, "对照用户应挂 AliyunReadOnlyAccess 只读策略"
    assert 'policy_type = "System"' in block, "对照用户应为 System 系统策略"
    # 对照挂载块里不应出现任何 RAM 写 Action / 管理员策略
    assert "ram:AttachPolicy" not in block, "对照用户不应含 ram:AttachPolicy*"
    assert "ram:CreateAccessKey" not in block, "对照用户不应含 ram:CreateAccessKey"
    assert "AdministratorAccess" not in block, "对照用户不应误挂 AdministratorAccess"


def test_scene3_users_have_purpose_tag() -> None:
    """两个 RAM 用户资源各带 Purpose = vuln-benchmark 标签。"""
    text = _read(SCENE3_MAIN_TF)
    assert 'Purpose   = "vuln-benchmark"' in text or 'Purpose = "vuln-benchmark"' in text
    user_resource_count = text.count('resource "alicloud_ram_user"')
    purpose_count = text.count('"vuln-benchmark"')
    assert purpose_count >= user_resource_count, (
        f"Purpose 标签数({purpose_count})少于 RAM user resource 数({user_resource_count})"
    )


def test_scene3_no_ram_access_key_resource() -> None:
    """安全红线:严禁创建 RAM AccessKey 资源(防 apply 后泄出可用 AK)。"""
    text = _read(SCENE3_MAIN_TF)
    assert "alicloud_ram_access_key" not in text, (
        "检测到 RAM AccessKey 资源——靶场严禁创建真实 AccessKey(安全设计)"
    )


def test_scene3_no_ram_login_profile() -> None:
    """用户为纯 API 实体,不设控制台登录密码(不创建 LoginProfile)。"""
    text = _read(SCENE3_MAIN_TF)
    assert "alicloud_ram_login_profile" not in text, (
        "检测到 RAM LoginProfile——靶场用户应为纯 API 实体,不设登录密码"
    )


def test_scene3_outputs_have_detection_contrast() -> None:
    """scene3-outputs.tf 含用户名输出与预期检出对照(管理员全命中)。"""
    text = _read(SCENE3_OUTPUTS_TF)
    assert 'output "vuln_admin_user"' in text, "outputs 缺少 vuln_admin_user"
    assert 'output "safe_readonly_user"' in text, "outputs 缺少 safe_readonly_user"
    assert "expected_detection_scene3" in text, "outputs 缺少场景三预期检出对照"
    # 管理员用户应命中全部 5 条规则(至少标注 AttachPolicyToSelf)且 is_admin
    assert "ram:AttachPolicyToSelf" in text, "outputs 应标注命中 AttachPolicyToSelf 规则"
    assert "AdministratorAccess" in text, "outputs 应标注 AdministratorAccess 策略"
    assert "is_admin" in text, "outputs 应标注 is_admin 标志"
    assert '"critical"' in text or 'expect     = "critical"' in text, "管理员用户预期应为 critical"
    # 对照用户应零命中
    assert "safe_readonly_user" in text


def test_scene3_variables_have_user_suffix() -> None:
    """scene3-variables.tf 含 scene3_user_suffix 变量(避免与主变量同名冲突)。"""
    text = _read(SCENE3_VARIABLES_TF)
    assert 'variable "scene3_user_suffix"' in text
    assert "scene3_admin_policy" in text, "应提供管理员策略名变量(默认 AdministratorAccess)"
    assert 'default     = "AdministratorAccess"' in text or 'default = "AdministratorAccess"' in text
    assert "scene3_readonly_policy" in text, "应提供只读策略名变量(默认 AliyunReadOnlyAccess)"


def test_scene3_no_hardcoded_access_key() -> None:
    """场景三三个文件不得含疑似真实 AccessKey(LTAI + 长串)。"""
    offenders: list[Path] = []
    for path in (SCENE3_MAIN_TF, SCENE3_OUTPUTS_TF, SCENE3_VARIABLES_TF):
        if LTAI_PATTERN.search(path.read_text(encoding="utf-8")):
            offenders.append(path)
    assert not offenders, f"检测到疑似真实硬编码 AK(LTAI+长串): {offenders}"


@pytest.mark.skipif(shutil.which("terraform") is None, reason="本机无 terraform,跳过 fmt 检查")
def test_scene3_terraform_fmt_check() -> None:
    """若本机有 terraform,顺带跑 fmt -check(不修改文件)。CI 友好。"""
    result = subprocess.run(  # noqa: S603,S607 - 仅调用已知 terraform 二进制做格式检查
        ["terraform", "fmt", "-check", "-diff"],
        cwd=TF_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(
            "terraform fmt -check 未通过(配置需格式化):\n"
            + result.stdout
            + result.stderr
        )
