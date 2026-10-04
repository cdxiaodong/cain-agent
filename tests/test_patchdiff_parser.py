"""C1 补丁 diff 解析层测试(纯函数,零 IO)。"""

from __future__ import annotations

import pytest

from cain_agent.patchdiff import ChangeSet, Hunk, PatchDiffError, parse_unified_diff


def _diff(*body: str) -> str:
    return "\n".join([
        "diff --git a/app.py b/app.py",
        "index 111..222 100644",
        "--- a/app.py",
        "+++ b/app.py",
        *body,
    ])


# -- 正常解析 ------------------------------------------------------------------------


def test_simple_hunk_parsed() -> None:
    cs = parse_unified_diff(_diff(
        "@@ -10,4 +10,5 @@",
        " context",
        "-old = unsafe(user_input)",
        "+if not is_safe(user_input):",
        "+    raise ValueError('bad')",
    ))
    assert len(cs.hunks) == 1
    h = cs.hunks[0]
    assert h.file_path == "app.py" and h.old_start == 10 and h.new_start == 10


def test_signature_change_extracted() -> None:
    cs = parse_unified_diff(_diff(
        "@@ -1,3 +1,4 @@",
        "-def validate(data):",
        "+def validate(data: dict) -> bool:",
        "+    if not isinstance(data, dict):",
        "+        raise TypeError",
    ))
    assert "validate" in cs.hunks[0].signature_changes


def test_class_signature_extracted() -> None:
    cs = parse_unified_diff(_diff(
        "@@ -5,2 +5,3 @@",
        "-class Handler:",
        "+class SafeHandler:",
    ))
    assert "SafeHandler" in cs.hunks[0].signature_changes


def test_added_check_extracted() -> None:
    cs = parse_unified_diff(_diff(
        "@@ -3,2 +3,3 @@",
        " ctx",
        "+    if len(path) > MAX:",
        "+        raise ValueError('too long')",
    ))
    assert any("MAX" in c for c in cs.hunks[0].added_checks)


def test_removed_path_extracted() -> None:
    cs = parse_unified_diff(_diff(
        "@@ -7,3 +7,2 @@",
        "-    if not user.is_admin:",
        "-        raise PermissionError",
        "     do_action()",
    ))
    assert any("is_admin" in r for r in cs.hunks[0].removed_paths)


def test_multiple_files_multiple_hunks() -> None:
    text = "\n".join([
        "diff --git a/x.py b/x.py", "--- a/x.py", "+++ b/x.py",
        "@@ -1,2 +1,2 @@", "-a", "+b",
        "diff --git a/y.py b/y.py", "--- a/y.py", "+++ b/y.py",
        "@@ -5,2 +5,2 @@", "-c", "+d",
    ])
    cs = parse_unified_diff(text)
    assert [h.file_path for h in cs.hunks] == ["x.py", "y.py"]


def test_symbols_union() -> None:
    cs = parse_unified_diff(_diff(
        "@@ -1,4 +1,5 @@",
        "-def check_range(n):",
        "+def check_range(n: int) -> bool:",
        "+    if not (0 <= n <= LIMIT):",
        "+        raise ValueError('range')",
    ))
    syms = cs.symbols()
    assert "check_range" in syms and "LIMIT" in syms


# -- 边界与非法 ----------------------------------------------------------------------


def test_empty_diff_yields_empty_changeset() -> None:
    assert parse_unified_diff("") == ChangeSet()


def test_binary_files_skipped() -> None:
    cs = parse_unified_diff("Binary files a/x.png and b/x.png differ\n")
    assert cs.hunks == ()


def test_bad_line_rejected_with_lineno() -> None:
    with pytest.raises(PatchDiffError, match="line 1"):
        parse_unified_diff("this is not a diff at all\n")


def test_hunk_before_file_header_rejected() -> None:
    with pytest.raises(PatchDiffError, match="文件头之前"):
        parse_unified_diff("@@ -1,2 +1,2 @@\n-a\n+b\n")


def test_minus_without_plus_rejected() -> None:
    with pytest.raises(PatchDiffError, match=r"\+\+\+"):
        parse_unified_diff("--- a/x.py\nsome garbage\n")


def test_no_newline_marker_ignored() -> None:
    cs = parse_unified_diff(_diff(
        "@@ -1,2 +1,2 @@",
        "-old",
        "+new",
        "\\ No newline at end of file",
    ))
    assert len(cs.hunks) == 1


def test_rename_only_no_hunks() -> None:
    cs = parse_unified_diff(
        "diff --git a/old.py b/new.py\n"
        "similarity index 100%\nrename from old.py\nrename to new.py\n"
    )
    assert cs.hunks == () or all(h.file_path for h in cs.hunks)


def test_hunk_dataclass_frozen() -> None:
    h = Hunk(file_path="x", old_start=1, new_start=1)
    with pytest.raises(AttributeError):
        h.file_path = "y"  # type: ignore[misc]
