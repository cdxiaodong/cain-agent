"""Workspace 单元测试 —— 纯临时目录,不触网不烧 token。

覆盖派活单自测要求:assets/findings 原子写、JSON 损坏抛明确异常、
阶段子目录自动创建、scope.yaml 经 Scope.from_file 加载。
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cain_agent.scope import Scope
from cain_agent.workspace import (
    STAGE_DIRS,
    Workspace,
    WorkspaceCorruptError,
    WorkspaceError,
)


@pytest.fixture
def ws_root(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    (root).mkdir()
    (root / "scope.yaml").write_text(
        "in_scope:\n  - example.com\nout_of_scope: []\n", encoding="utf-8"
    )
    return root


def test_init_creates_stage_dirs_and_seed_json(ws_root: Path) -> None:
    Workspace(ws_root)
    for name in STAGE_DIRS:
        assert (ws_root / name).is_dir(), f"缺少阶段子目录 {name}"
    assert json.loads((ws_root / "assets.json").read_text(encoding="utf-8")) == []
    assert json.loads((ws_root / "findings.json").read_text(encoding="utf-8")) == []


def test_init_does_not_overwrite_existing_files(ws_root: Path) -> None:
    (ws_root / "assets.json").write_text('[{"host": "a.example.com"}]', encoding="utf-8")
    ws = Workspace(ws_root)
    assert ws.load_assets() == [{"host": "a.example.com"}]


def test_scope_loaded_via_scope_from_file(ws_root: Path) -> None:
    scope = Workspace(ws_root).scope
    assert isinstance(scope, Scope)
    assert scope.is_allowed("www.example.com")
    assert not scope.is_allowed("other.com")


def test_missing_scope_yaml_raises(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)  # 不造 scope.yaml
    with pytest.raises(WorkspaceError, match="scope.yaml"):
        _ = ws.scope


def test_write_json_is_atomic_no_temp_left(ws_root: Path) -> None:
    ws = Workspace(ws_root)
    ws.write_json("assets.json", [{"host": "b.example.com"}])
    leftovers = [p for p in ws_root.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == [], f"原子写后残留临时文件: {leftovers}"
    assert ws.load_assets() == [{"host": "b.example.com"}]


def test_write_json_failure_cleans_temp_and_keeps_target(
    ws_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = Workspace(ws_root)
    ws.write_json("assets.json", [{"ok": 1}])
    before = (ws_root / "assets.json").read_bytes()

    def boom(fd: int, mode: str, encoding: str):  # type: ignore[no-untyped-def]
        os.close(fd)
        raise OSError("disk full")

    monkeypatch.setattr(os, "fdopen", boom)
    with pytest.raises(OSError, match="disk full"):
        ws.write_json("assets.json", [{"bad": 2}])
    assert (ws_root / "assets.json").read_bytes() == before, "目标文件被半写污染"
    assert [p for p in ws_root.iterdir() if p.name.endswith(".tmp")] == []


def test_corrupt_json_raises_explicit_error(ws_root: Path) -> None:
    (ws_root / "findings.json").write_text("{not json", encoding="utf-8")
    ws = Workspace(ws_root)
    with pytest.raises(WorkspaceCorruptError, match="findings.json"):
        ws.load_findings()


def test_json_top_level_must_be_list(ws_root: Path) -> None:
    (ws_root / "assets.json").write_text('{"host": "x"}', encoding="utf-8")
    ws = Workspace(ws_root)
    with pytest.raises(WorkspaceCorruptError, match="顶层必须是列表"):
        ws.load_assets()


def test_unknown_stage_dir_rejected(ws_root: Path) -> None:
    ws = Workspace(ws_root)
    with pytest.raises(WorkspaceError, match="未知阶段目录"):
        ws.stage_dir("exfil")
