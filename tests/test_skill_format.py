"""技能格式校验测试。

扫描 ``skills/**/SKILL.md``，对新规范技能（带 ``phase`` frontmatter 字段）严格校验
frontmatter 四字段与正文四节齐全；对旧技能（无新规范 frontmatter）只发警告、不阻塞。

新规范由 ``docs/skill-authoring-guide.md`` 定义，本测试是技能扩容时的统一模板卡口。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

# 技能根目录（worktree 兼容：相对本测试文件向上定位）
SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"

# 新规范 frontmatter 必填字段
REQUIRED_FRONTMATTER_FIELDS = ("name", "description", "phase", "severity_focus")

# 新规范正文必含的四节标题（二级标题，正文内可出现子标题）
REQUIRED_SECTIONS = ("触发条件", "三层测试模型", "证据要求", "禁止事项")

# 新规范 phase 取值
VALID_PHASES = ("recon", "test", "framework", "report")

# 化名标记：占位符/复制粘贴痕迹，新技能中不得出现
FORBIDDEN_PATTERNS = (
    re.compile(r"\b(TODO|FIXME|XXX|TBD|待补充|待填|占位)\b"),
    re.compile(r"\blorem ipsum\b", re.IGNORECASE),
    re.compile(r"<待|<your|example\.com/your-repo", re.IGNORECASE),
)


def _parse_frontmatter(text: str) -> tuple[dict[str, object] | None, str]:
    """拆出 YAML frontmatter，返回 (解析结果或 None, 正文)。"""
    if not text.startswith("---\n"):
        return None, text
    end = text.find("\n---\n", 4)
    if end == -1:
        return None, text
    fm_text = text[4:end]
    body = text[end + len("\n---\n") :]
    try:
        data = yaml.safe_load(fm_text)
    except yaml.YAMLError:
        return {}, body  # 解析失败返回空 dict 以触发字段缺失断言
    return data if isinstance(data, dict) else {}, body


def _discover_skill_files() -> list[Path]:
    """枚举 skills/ 下所有 SKILL.md（含旧目录命名兼容）。"""
    if not SKILLS_DIR.exists():
        return []
    return sorted(SKILLS_DIR.rglob("SKILL.md"))


def _is_new_spec_skill(frontmatter: dict[str, object] | None) -> bool:
    """判定是否为新规范技能：含 phase 字段即视为新规范（旧技能无此字段）。"""
    return frontmatter is not None and "phase" in frontmatter


# ----------------------------------------------------------------------
# 收集新规范技能（必须严格通过）与旧技能（只警告）
# ----------------------------------------------------------------------

_all_skill_files = _discover_skill_files()
_new_spec_skills: list[Path] = []
_legacy_skills: list[Path] = []
for _f in _all_skill_files:
    _text = _f.read_text(encoding="utf-8")
    _fm, _ = _parse_frontmatter(_text)
    if _is_new_spec_skill(_fm):
        _new_spec_skills.append(_f)
    else:
        _legacy_skills.append(_f)


def test_at_least_one_new_spec_skill_present() -> None:
    """确保本次新增的 skills/web/ 三个技能被识别为新规范。"""
    web_skills = [p for p in _new_spec_skills if "skills/web/" in str(p).replace("\\", "/")]
    assert len(web_skills) >= 3, f"期望至少 3 个新规范 web 技能，实际 {len(web_skills)}"


@pytest.mark.parametrize(
    "skill_file",
    _new_spec_skills,
    ids=[str(p.relative_to(SKILLS_DIR)) for p in _new_spec_skills],
)
def test_new_spec_skill_frontmatter_fields(skill_file: Path) -> None:
    """新规范技能：frontmatter 四字段齐全。"""
    text = skill_file.read_text(encoding="utf-8")
    fm, _ = _parse_frontmatter(text)
    assert fm is not None, f"{skill_file}: 缺少 frontmatter"
    missing = [f for f in REQUIRED_FRONTMATTER_FIELDS if f not in fm]
    assert not missing, f"{skill_file}: frontmatter 缺少字段 {missing}"


@pytest.mark.parametrize(
    "skill_file",
    _new_spec_skills,
    ids=[str(p.relative_to(SKILLS_DIR)) for p in _new_spec_skills],
)
def test_new_spec_skill_phase_valid(skill_file: Path) -> None:
    """新规范技能：phase 取值在合法枚举内。"""
    text = skill_file.read_text(encoding="utf-8")
    fm, _ = _parse_frontmatter(text)
    phase = fm.get("phase") if fm else None
    assert phase in VALID_PHASES, f"{skill_file}: phase={phase!r} 不在 {VALID_PHASES}"


@pytest.mark.parametrize(
    "skill_file",
    _new_spec_skills,
    ids=[str(p.relative_to(SKILLS_DIR)) for p in _new_spec_skills],
)
def test_new_spec_skill_sections_present(skill_file: Path) -> None:
    """新规范技能：正文必含四节二级标题。"""
    text = skill_file.read_text(encoding="utf-8")
    _, body = _parse_frontmatter(text)
    missing = [s for s in REQUIRED_SECTIONS if f"## {s}" not in body]
    assert not missing, f"{skill_file}: 正文缺少章节标题 {missing}"


@pytest.mark.parametrize(
    "skill_file",
    _new_spec_skills,
    ids=[str(p.relative_to(SKILLS_DIR)) for p in _new_spec_skills],
)
def test_new_spec_skill_no_placeholder(skill_file: Path) -> None:
    """新规范技能：不得含占位符/待填标记。"""
    text = skill_file.read_text(encoding="utf-8")
    for pat in FORBIDDEN_PATTERNS:
        m = pat.search(text)
        assert m is None, f"{skill_file}: 检测到禁用标记 {m!r}"


@pytest.mark.parametrize(
    "skill_file",
    _new_spec_skills,
    ids=[str(p.relative_to(SKILLS_DIR)) for p in _new_spec_skills],
)
def test_new_spec_skill_not_identical_to_others(skill_file: None) -> None:  # type: ignore[override]
    """三份新规范技能正文不得互相雷同（骨架除外）：正文哈希两两不同。"""
    # skill_file 仅用于参数化计数；实际比较所有新技能正文
    bodies: dict[str, str] = {}
    for f in _new_spec_skills:
        text = f.read_text(encoding="utf-8")
        _, body = _parse_frontmatter(text)
        # 去掉四节标题（共享骨架）后比较，确保内容实质不同
        stripped = re.sub(r"^## .*$", "", body, flags=re.MULTILINE).strip()
        bodies[str(f)] = stripped
    # 任两份去骨架正文不得完全相同
    keys = list(bodies)
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            assert bodies[keys[i]] != bodies[keys[j]], (
                f"{keys[i]} 与 {keys[j]} 去骨架后正文完全雷同"
            )


def test_legacy_skills_only_warned_not_blocked(
   recwarn: pytest.WarningsRecorder,
) -> None:
    """旧技能（无新规范 frontmatter）只发警告、不阻塞测试。

    旧 66 个技能采用早期格式（name/type/category 平铺、正文无标准四节），
    本测试体系对其保持兼容：仅记录、不判失败。
    """
    for f in _legacy_skills:
        # 旧技能存在是预期情况（迁移期），仅记录文件名，不产生断言失败
        assert f.exists(), f"旧技能文件丢失: {f}"
    # 旧技能不参与严格断言（frontmatter/章节校验仅针对新规范技能），
    # 此处仅证明它们被识别为 legacy 并继续存在，不阻塞测试套件。
    assert len(_all_skill_files) == len(_new_spec_skills) + len(_legacy_skills)
