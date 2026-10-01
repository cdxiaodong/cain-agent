"""Phase 5-B3 技能 validation_seed 质量门测试(零 LLM 零触网)。"""

from __future__ import annotations

from pathlib import Path

from cain_agent.handlers import Skill, SkillLoader, _parse_validation_seed, _seed_self_consistent


def _skill_file(tmp_path: Path, seed_yaml: str) -> Path:
    root = tmp_path / "skills"
    root.mkdir(exist_ok=True)
    (root / "web").mkdir(exist_ok=True)
    body = "检测方法:布尔盲注对照 AND 1=1/AND 1=2 观察响应差异。\n"
    (root / "web" / "SKILL.md").write_text(
        f"---\nname: seed-skill\nphase: test\n{seed_yaml}---\n\n{body}", encoding="utf-8"
    )
    return root


# -- _parse_validation_seed -----------------------------------------------------------


def test_none_returns_empty_no_issue() -> None:
    seed, issue = _parse_validation_seed(None, Path("x"))
    assert seed == () and issue is None


def test_valid_seed_parsed() -> None:
    raw = [{"input": "?id=1' AND 1=1", "expected_signal": "布尔盲注"}]
    seed, issue = _parse_validation_seed(raw, Path("x"))
    assert issue is None and seed[0]["expected_signal"] == "布尔盲注"


def test_non_list_rejected() -> None:
    seed, issue = _parse_validation_seed("not-a-list", Path("x"))
    assert seed == ()
    assert issue is not None and "非空列表" in issue


def test_empty_list_rejected() -> None:
    _, issue = _parse_validation_seed([], Path("x"))
    assert issue is not None and "非空列表" in issue


def test_missing_input_rejected() -> None:
    raw = [{"expected_signal": "s"}]
    _, issue = _parse_validation_seed(raw, Path("x"))
    assert issue is not None and "input" in issue


def test_blank_signal_rejected() -> None:
    raw = [{"input": "i", "expected_signal": "  "}]
    _, issue = _parse_validation_seed(raw, Path("x"))
    assert issue is not None and "expected_signal" in issue


def test_non_dict_entry_rejected() -> None:
    _, issue = _parse_validation_seed(["str"], Path("x"))
    assert issue is not None and "对象" in issue


# -- 自洽 --------------------------------------------------------------------------


def test_self_consistent_when_signal_in_body() -> None:
    seed = ({"input": "i", "expected_signal": "布尔盲注"},)
    assert _seed_self_consistent(seed, "方法:布尔盲注对照...")


def test_inconsistent_signal_flagged() -> None:
    seed = ({"input": "i", "expected_signal": "完全无关的信号词"},)
    assert not _seed_self_consistent(seed, "正文只讲 SQL")


# -- SkillLoader 集成 ---------------------------------------------------------------


def test_loader_valid_seed_no_issue(tmp_path: Path) -> None:
    root = _skill_file(
        tmp_path,
        "validation_seed:\n  - input: \"?id=1' AND 1=1\"\n    expected_signal: 布尔盲注\n",
    )
    loader = SkillLoader(root)
    skills = loader.load("test")
    assert len(skills) == 1 and skills[0].validation_seed
    assert not any("seed" in i for i in loader.issues)


def test_loader_inconsistent_seed_into_issues(tmp_path: Path) -> None:
    root = _skill_file(
        tmp_path,
        "validation_seed:\n  - input: x\n    expected_signal: 不存在的信号xyzabc\n",
    )
    loader = SkillLoader(root)
    loader.load("test")
    assert any("不自洽" in i for i in loader.issues)


def test_loader_bad_seed_structure_into_issues(tmp_path: Path) -> None:
    root = _skill_file(tmp_path, "validation_seed: \"oops\"\n")
    loader = SkillLoader(root)
    loader.load("test")
    assert any("结构非法" in i for i in loader.issues)


def test_loader_no_seed_silent_ok(tmp_path: Path) -> None:
    """无 seed 的技能不产生 issue(可选字段,存量技能零影响)。"""
    root = _skill_file(tmp_path, "")
    loader = SkillLoader(root)
    assert len(loader.load("test")) == 1
    assert not any("seed" in i for i in loader.issues)


def test_skill_dataclass_defaults_empty() -> None:
    s = Skill(name="n", phase="test", path="p", content="c")
    assert s.validation_seed == ()


# -- bench 占位入口 ------------------------------------------------------------------


def test_bench_seed_stats_placeholder() -> None:
    from bench.local_finding_fixture import run_seed_reproduction

    stats = run_seed_reproduction()
    with_seed: int = stats["with_seed"]  # type: ignore[assignment]
    without_seed: int = stats["without_seed"]  # type: ignore[assignment]
    assert with_seed + without_seed >= 1  # 仓库技能可枚举
    assert without_seed >= 1  # 存量技能尚未补 seed(如实盘点)
