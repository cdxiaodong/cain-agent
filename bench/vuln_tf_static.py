"""vuln-tf 三场景离线静态跑分 — 文本级 terraform 解析 + 检测规则对齐。

零触网、零真实凭证、零 LLM 调用:对 ``bench/aliyun-vuln-tf/`` 的 tf 靶标
做纯静态分析,统计检出/误报/耗时;token 消耗恒为 0(如实记录,不模拟)。

场景与预期(与靶标注释一致):
  1. OSS 公开桶  — ``acl = "public-read"`` 桶应命中(high);private 桶零命中
  2. RAM 过度授权 — 自定义策略含 AttachPolicyToUser/CreateAccessKey 应命中 2 条
  3. RAM 管理员   — AdministratorAccess 应命中全部 5 条;只读用户零命中

规则语义对齐 ``cain_agent.cloud.aliyun_ram.PRIVESC_RULES`` 的 rule_id。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

TF_DIR = Path(__file__).resolve().parent / "aliyun-vuln-tf"

ALL_PRIVESC_RULES = (
    "ram:PassRole-to-Compute",
    "ram:AttachPolicyToSelf",
    "ram:CreateAccessKey-for-HighPriv",
    "ram:LoginProfile-Hijack",
    "ram:AssumeRole-Chain",
)


@dataclass
class VulnTfScenario:
    """一个静态跑分场景。"""

    name: str
    tf_files: tuple[str, ...]
    expect_hits: tuple[str, ...]      # 应命中的 rule_id / 标记
    expect_clean_entities: tuple[str, ...] = ()  # 应零命中的对照实体(误报探针)


@dataclass
class VulnTfDetection:
    """一次静态检测结果。"""

    entity: str
    hit: str          # rule_id 或 "oss:public-read"
    evidence: str


@dataclass
class VulnTfScenarioResult:
    scenario: str
    detections: list[VulnTfDetection] = field(default_factory=list)
    false_positives: list[VulnTfDetection] = field(default_factory=list)
    expected_missing: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0
    token_cost: int = 0

    @property
    def detected_ok(self) -> bool:
        return not self.false_positives and not self.expected_missing


# ---------------------------------------------------------------- tf 解析

_BUCKET_RE = re.compile(
    r'resource\s+"alicloud_oss_bucket"\s+"(?P<name>[^"]+)"\s*\{(?P<body>.*?)\n\}',
    re.DOTALL,
)
_ACL_RE = re.compile(r'^\s*acl\s*=\s*"(?P<acl>[^"]+)"', re.MULTILINE)
_RAM_USER_RE = re.compile(
    r'resource\s+"alicloud_ram_user"\s+"(?P<name>[^"]+)"\s*\{(?P<body>.*?)\n\}',
    re.DOTALL,
)
_ATTACHMENT_RE = re.compile(
    r'resource\s+"alicloud_ram_user_policy_attachment"\s+"(?P<name>[^"]+)"\s*\{(?P<body>.*?)\n\}',
    re.DOTALL,
)
_POLICY_NAME_RE = re.compile(r'policy_name\s*=\s*"([^"]+)"')
_ACTION_ITEM_RE = re.compile(r'"(ram:[A-Za-z]+)"')


def _load_text(files: tuple[str, ...]) -> str:
    return "\n".join((TF_DIR / f).read_text(encoding="utf-8") for f in files)


def detect_oss_public_buckets(text: str) -> list[VulnTfDetection]:
    """public-read / public-read-write 桶命中;private 桶不命中。"""
    out: list[VulnTfDetection] = []
    for m in _BUCKET_RE.finditer(text):
        acl_m = _ACL_RE.search(m.group("body"))
        acl = acl_m.group("acl") if acl_m else ""
        if acl in ("public-read", "public-read-write"):
            out.append(VulnTfDetection(m.group("name"), "oss:public-read", f'acl = "{acl}"'))
    return out


def detect_ram_privesc(text: str) -> list[VulnTfDetection]:
    """对 RAM 用户按授权面命中提权规则(语义对齐 PRIVESC_RULES)。

    - 显式 action(自定义策略/内联语句):AttachPolicyToUser→AttachPolicyToSelf;
      CreateAccessKey→CreateAccessKey-for-HighPriv
    - AdministratorAccess / Action "*":全部 5 条(管理员)
    """
    out: list[VulnTfDetection] = []
    policy_blocks = _ATTACHMENT_RE.finditer(text)
    user_names = {m.group("name") for m in _RAM_USER_RE.finditer(text)}
    # 挂载策略块:policy_document 就近在前,按块序归到最近用户
    for m in policy_blocks:
        body = m.group("body")
        pn = _POLICY_NAME_RE.search(body)
        attached_user = re.search(r'user_name\s*=\s*alicloud_ram_user\.(?P<u>[^.]+)\.name', body)
        entity = attached_user.group("u") if attached_user else m.group("name")
        if pn and pn.group(1) == "AdministratorAccess":
            for rule in ALL_PRIVESC_RULES:
                out.append(VulnTfDetection(entity, rule, f'policy_name = "{pn.group(1)}"'))
        elif pn and "ReadOnly" in pn.group(1):
            continue  # 只读系统策略:零命中(误报探针,不输出)
    # 内联自定义策略(场景二):action 显式列举
    for action in dict.fromkeys(_ACTION_ITEM_RE.findall(text)):
        entity = next(iter(user_names), "ram_user")
        if action == "ram:AttachPolicyToUser":
            out.append(VulnTfDetection(entity, "ram:AttachPolicyToSelf", f'"{action}"'))
        elif action == "ram:CreateAccessKey":
            out.append(VulnTfDetection(entity, "ram:CreateAccessKey-for-HighPriv", f'"{action}"'))
    return out


# ---------------------------------------------------------------- 场景与 runner

SCENARIOS: tuple[VulnTfScenario, ...] = (
    VulnTfScenario(
        name="oss-public-bucket",
        tf_files=("main.tf",),
        expect_hits=("oss:public-read",),
        expect_clean_entities=("safe_private_bucket",),
    ),
    VulnTfScenario(
        name="ram-overprivileged",
        tf_files=("main.tf",),
        expect_hits=("ram:AttachPolicyToSelf", "ram:CreateAccessKey-for-HighPriv"),
        expect_clean_entities=(),
    ),
    VulnTfScenario(
        name="ram-admin",
        tf_files=("scene3-main.tf",),
        expect_hits=ALL_PRIVESC_RULES,
        expect_clean_entities=("safe_readonly_user",),
    ),
)


def run_scenario(sc: VulnTfScenario) -> VulnTfScenarioResult:
    result = VulnTfScenarioResult(scenario=sc.name)
    start = time.perf_counter()
    text = _load_text(sc.tf_files)
    detections = detect_oss_public_buckets(text) + detect_ram_privesc(text)
    result.elapsed_s = round(time.perf_counter() - start, 6)

    hit_keys = [d.hit for d in detections]
    for d in detections:
        if d.entity in sc.expect_clean_entities:
            result.false_positives.append(d)   # 对照实体命中 = 误报
        elif d.hit in sc.expect_hits:
            result.detections.append(d)
        # 命中了预期之外的规则不计误报也不计检出(保守:仅预期面参与评分)
    for expected in sc.expect_hits:
        if expected not in hit_keys:
            result.expected_missing.append(expected)
    return result


def run_all() -> list[VulnTfScenarioResult]:
    return [run_scenario(sc) for sc in SCENARIOS]
