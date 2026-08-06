"""阿里云 vulnerable-terraform 靶场静态校验。

不执行任何 terraform init/apply(派活单红线:严禁碰真实云)。
只做配置文件结构静态检查,确保:
- 三个 tf 文件存在且含必需块(provider / resource / output);
- 公开桶 acl = public-read(靶标语义钉死)、对照桶 acl = private;
- 资源含 Purpose = "vuln-benchmark" 标签;
- 无硬编码 AccessKey(扫描疑似真实 AK 模式 LTAI 后跟长串字符);
- 文件头含红字声明(仅授权测试 / 当天 destroy)。
若本机 terraform 可用,顺带跑 terraform fmt -check;不可用则 skip(CI 不红)。
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

TF_DIR = Path(__file__).resolve().parent.parent / "bench" / "aliyun-vuln-tf"
MAIN_TF = TF_DIR / "main.tf"
VARIABLES_TF = TF_DIR / "variables.tf"
OUTPUTS_TF = TF_DIR / "outputs.tf"
README_MD = TF_DIR / "README.md"

# 疑似真实阿里云 AccessKey 模式:LTAI 前缀 + 至少 12 位字母数字(真实 AK 通常 24-30 位)。
# 裸 "LTAI" 字样(如教学注释提及前缀名)不算泄漏;只有"像真 AK 的串"才算。
LTAI_PATTERN = re.compile(r"LTAI[A-Za-z0-9]{12,}")


def _read(path: Path) -> str:
    if not path.is_file():
        pytest.fail(f"缺少靶场文件: {path}")
    return path.read_text(encoding="utf-8")


def test_tf_files_exist() -> None:
    """四个靶场文件齐全(main/variables/outputs/README)。"""
    assert MAIN_TF.is_file()
    assert VARIABLES_TF.is_file()
    assert OUTPUTS_TF.is_file()
    assert README_MD.is_file()


def test_main_tf_has_required_blocks() -> None:
    """main.tf 含 provider / terraform / resource 必需块。"""
    text = _read(MAIN_TF)
    assert 'provider "alicloud"' in text, "缺少 alicloud provider 块"
    assert "required_providers" in text, "缺少 required_providers 声明"
    assert "resource \"alicloud_oss_bucket\"" in text, "缺少 OSS bucket resource 块"


def test_main_tf_has_two_buckets_vuln_and_control() -> None:
    """靶标桶(public-read)+ 对照桶(private)各一。"""
    text = _read(MAIN_TF)
    assert "vuln_public_read" in text, "缺少靶标桶 vuln_public_read"
    assert "control_private" in text, "缺少对照桶 control_private"


def test_vuln_bucket_acl_is_public_read() -> None:
    """靶标语义钉死:vuln_public_read 桶的 acl 必须是 public-read。

    以 resource 块为单位切片,确保 public-read 绑定在靶标桶而非对照桶。
    """
    text = _read(MAIN_TF)
    # 切出 vuln_public_read 这个 resource 块(到下一个 resource 或文件尾)
    start = text.index('resource "alicloud_oss_bucket" "vuln_public_read"')
    end = text.find("resource", start + 1)
    block = text[start : end if end != -1 else len(text)]
    assert 'acl = "public-read"' in block, "靶标桶 acl 不是 public-read(靶标语义丢失)"
    # 确认靶标块里没有 private(避免误把对照桶当靶标)
    assert 'acl = "private"' not in block


def test_control_bucket_acl_is_private() -> None:
    """对照桶 control_private 的 acl 必须是 private。"""
    text = _read(MAIN_TF)
    start = text.index('resource "alicloud_oss_bucket" "control_private"')
    block = text[start:]
    assert 'acl = "private"' in block, "对照桶 acl 不是 private"


def test_buckets_have_purpose_tag() -> None:
    """所有 OSS 桶资源带 Purpose = vuln-benchmark 标签。"""
    text = _read(MAIN_TF)
    assert 'Purpose   = "vuln-benchmark"' in text or 'Purpose = "vuln-benchmark"' in text
    # 两个 resource 各应带标签块;统计 resource 数应 == Purpose 出现次数
    resource_count = text.count('resource "alicloud_oss_bucket"')
    purpose_count = text.count('"vuln-benchmark"')
    assert purpose_count >= resource_count, (
        f"Purpose 标签数({purpose_count})少于 OSS resource 数({resource_count})"
    )


def test_main_tf_has_redline_header() -> None:
    """文件头 5 行内含红字声明(仅授权测试 / 当天 destroy)。"""
    text = _read(MAIN_TF)
    head = "\n".join(text.splitlines()[:8])
    assert "授权" in head and "destroy" in head, (
        "main.tf 头部缺少红字声明(授权测试 + 当天 destroy)"
    )


def test_outputs_tf_has_expected_detection_outputs() -> None:
    """outputs.tf 含两个桶名输出与预期检出对照。"""
    text = _read(OUTPUTS_TF)
    assert "output \"vuln_public_read_bucket\"" in text
    assert "output \"control_private_bucket\"" in text
    assert "expected_detection" in text
    # 预期:public-read → high,private → info
    assert '"high"' in text or "expect  = \"high\"" in text
    assert '"info"' in text or "expect  = \"info\"" in text


def test_variables_tf_has_region_and_bucket_prefix() -> None:
    """variables.tf 含 region 与 bucket_prefix 变量。"""
    text = _read(VARIABLES_TF)
    assert 'variable "region"' in text
    assert 'variable "bucket_prefix"' in text
    assert "cn-hangzhou" in text, "region 默认值应为 cn-hangzhou"


def test_no_hardcoded_access_key() -> None:
    """所有 tf / tfvars / md 文件不得含疑似真实 AccessKey(LTAI + 长串)或 tfvars 文件。"""
    offenders: list[Path] = []
    for path in sorted(TF_DIR.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix in {".tfvars", ".tfvars.json"}:
            # tfvars 文件本身就不该出现在靶场目录(凭证走环境变量)
            offenders.append(path)
            continue
        if path.suffix in {".tf", ".md"}:
            text = path.read_text(encoding="utf-8")
            if LTAI_PATTERN.search(text):
                offenders.append(path)
    assert not offenders, (
        f"检测到疑似真实硬编码 AK(LTAI+长串)或 tfvars 文件: {offenders}"
    )


def test_readme_has_three_step_usage() -> None:
    """README 含 apply / verify / destroy 三步用法与清理警告。"""
    text = _read(README_MD)
    assert "terraform init" in text
    assert "terraform apply" in text
    assert "terraform destroy" in text
    assert "ALICLOUD_ACCESS_KEY" in text, "README 应说明凭证用环境变量传入"
    assert "destroy" in text and ("当天" in text or "立即" in text or "用完即清" in text)


@pytest.mark.skipif(shutil.which("terraform") is None, reason="本机无 terraform,跳过 fmt 检查")
def test_terraform_fmt_check() -> None:
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


# ===========================================================================
# 场景二:RAM 过度授权用户(给 Day4 RAM 提权分析模块做端到端回归)
# 不动上方场景一已有用例;以下均为场景二静态校验。
# ===========================================================================


def test_main_tf_has_scene2_ram_resources() -> None:
    """场景二:自定义过度授权策略 + vuln/safe 两个 RAM 用户 + 两个挂载。"""
    text = _read(MAIN_TF)
    assert 'resource "alicloud_ram_policy" "vuln_overpriv"' in text, "缺少靶标自定义策略 vuln_overpriv"
    assert 'resource "alicloud_ram_user" "vuln_ram_user"' in text, "缺少靶标用户 vuln_ram_user"
    assert 'resource "alicloud_ram_user" "safe_ram_user"' in text, "缺少对照用户 safe_ram_user"
    assert 'resource "alicloud_ram_user_policy_attachment" "vuln_attach"' in text
    assert 'resource "alicloud_ram_user_policy_attachment" "safe_attach"' in text


def test_vuln_ram_policy_has_two_privesc_actions() -> None:
    """靶标策略含 ram:AttachPolicyToUser + ram:CreateAccessKey,Resource *。

    以策略 resource 块为单位切片,确保两条 Action 绑定在靶标策略(而非别处)。
    """
    text = _read(MAIN_TF)
    start = text.index('resource "alicloud_ram_policy" "vuln_overpriv"')
    end = text.find("resource", start + 1)
    block = text[start : end if end != -1 else len(text)]
    assert '"ram:AttachPolicyToUser"' in block, "靶标策略缺少 ram:AttachPolicyToUser"
    assert '"ram:CreateAccessKey"' in block, "靶标策略缺少 ram:CreateAccessKey"
    assert 'Resource = "*"' in block, "靶标策略 Resource 应为 *(全资源)"


def test_safe_ram_user_only_system_readonly() -> None:
    """对照用户只挂 AliyunOSSReadOnlyAccess 系统策略,零提权权限。"""
    text = _read(MAIN_TF)
    start = text.index('resource "alicloud_ram_user_policy_attachment" "safe_attach"')
    end = text.find("resource", start + 1)
    block = text[start : end if end != -1 else len(text)]
    assert "AliyunOSSReadOnlyAccess" in block, "对照用户应只挂 AliyunOSSReadOnlyAccess"
    assert 'policy_type = "System"' in block, "对照用户应为 System 系统策略(非自定义)"
    # 对照挂载块里不应出现任何 RAM 写 Action
    assert "ram:AttachPolicy" not in block, "对照用户不应含 ram:AttachPolicy*"
    assert "ram:CreateAccessKey" not in block, "对照用户不应含 ram:CreateAccessKey"


def test_vuln_ram_user_has_purpose_tag() -> None:
    """靶标 RAM 用户带 Purpose = vuln-benchmark 标签。"""
    text = _read(MAIN_TF)
    start = text.index('resource "alicloud_ram_user" "vuln_ram_user"')
    end = text.find("resource", start + 1)
    block = text[start : end if end != -1 else len(text)]
    assert (
        'Purpose   = "vuln-benchmark"' in block or 'Purpose = "vuln-benchmark"' in block
    ), "靶标 RAM 用户缺少 Purpose = vuln-benchmark 标签"


def test_no_ram_access_key_resource() -> None:
    """安全红线:严禁创建 RAM AccessKey 资源(防 apply 后泄出可用 AK)。

    靶标只验证权限配置能否被检出,不需要真实可用凭证。
    """
    text = _read(MAIN_TF)
    assert "alicloud_ram_access_key" not in text, (
        "检测到 RAM AccessKey 资源——靶场严禁创建真实 AccessKey(安全设计)"
    )


def test_no_ram_login_profile() -> None:
    """vuln 用户为纯 API 实体,不设控制台登录密码(不创建 LoginProfile)。"""
    text = _read(MAIN_TF)
    assert "alicloud_ram_login_profile" not in text, (
        "检测到 RAM LoginProfile——靶场用户应为纯 API 实体,不设登录密码"
    )


def test_outputs_tf_has_scene2_detection_outputs() -> None:
    """outputs.tf 含场景二用户名输出与预期检出对照。"""
    text = _read(OUTPUTS_TF)
    assert 'output "vuln_ram_user"' in text, "outputs 缺少 vuln_ram_user"
    assert 'output "safe_ram_user"' in text, "outputs 缺少 safe_ram_user"
    assert "expected_detection_scene2" in text, "outputs 缺少场景二预期检出对照"
    # vuln 用户应命中 AttachPolicyToSelf + CreateAccessKey-for-HighPriv 两条 critical
    assert "ram:AttachPolicyToSelf" in text, "outputs 应标注命中 AttachPolicyToSelf 规则"
    assert "ram:CreateAccessKey-for-HighPriv" in text, "outputs 应标注命中 CreateAccessKey-for-HighPriv 规则"
    # 对照用户应零命中
    assert "safe_ram_user" in text


def test_readme_has_scene2_section() -> None:
    """README 含场景二说明(用途 / 不建真 AK 理由 / apply-destroy 警告)。"""
    text = _read(README_MD)
    assert "场景二" in text, "README 缺少场景二章节"
    assert "RAM" in text
    assert "AliyunOSSReadOnlyAccess" in text, "README 应说明对照用户挂 AliyunOSSReadOnlyAccess"
    # 为什么不用真实 AK 资源
    assert "AccessKey" in text, "README 应说明不创建真实 AccessKey 的理由"
    # apply/destroy 警告复述
    assert "destroy" in text
    assert "当天" in text or "用完即清" in text
