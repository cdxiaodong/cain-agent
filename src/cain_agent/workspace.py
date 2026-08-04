"""Workspace —— 文件系统外置记忆(真源),Orchestrator 的状态底座。

DESIGN.md §2:Workspace 文件系统 = 真源。本模块把一个目录收敛为
cain-agent 的工作区抽象:

- 根下固定三件:``scope.yaml``(授权范围,经 ``Scope.from_file`` 加载)、
  ``assets.json``(资产清单)、``findings.json``(发现清单)。
- 分阶段子目录 ``recon/`` / ``test/`` / ``report/`` 自动创建,阶段产物落在各自目录。
- 所有 JSON 写入走「临时文件 + os.replace」原子写,杜绝半写状态。
- JSON 损坏抛 ``WorkspaceCorruptError`` 明确异常,绝不静默吞掉返回空。
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from cain_agent.scope import Scope

__all__ = ["Workspace", "WorkspaceCorruptError", "WorkspaceError"]

SCOPE_FILE = "scope.yaml"
ASSETS_FILE = "assets.json"
FINDINGS_FILE = "findings.json"
STATE_FILE = "state.json"

STAGE_DIRS = ("recon", "test", "report")
"""与 Orchestrator 硬编码阶段一一对应的子目录名。"""


class WorkspaceError(RuntimeError):
    """Workspace 层的所有显式异常的基类。"""


class WorkspaceCorruptError(WorkspaceError):
    """工作区内 JSON 文件损坏(无法解析)时抛出,带文件路径定位。"""


class Workspace:
    """以目录为根的工作区,承载 scope / assets / findings 的真源状态。

    构造时自动建目录骨架并把缺失的 ``assets.json`` / ``findings.json``
    初始化为空列表;``scope.yaml`` 不自动造——授权范围必须显式给出,
    缺失时访问 ``scope`` 属性才报错(惰性,便于先建仓再补配置)。
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        for name in STAGE_DIRS:
            self.stage_dir(name)  # 建目录骨架
        for name in (ASSETS_FILE, FINDINGS_FILE):
            path = self.root / name
            if not path.exists():
                self.write_json(name, [])

    # -- 路径 ------------------------------------------------------------------
    def path(self, name: str) -> Path:
        """工作区根下的文件路径。"""
        return self.root / name

    def stage_dir(self, stage: str) -> Path:
        """阶段子目录(自动创建);未知阶段名抛错,防产物散落根目录。"""
        if stage not in STAGE_DIRS:
            raise WorkspaceError(f"未知阶段目录: {stage!r}(合法值: {list(STAGE_DIRS)})")
        path = self.root / stage
        path.mkdir(parents=True, exist_ok=True)
        return path

    # -- scope -----------------------------------------------------------------
    @property
    def scope(self) -> Scope:
        """从 ``scope.yaml`` 加载授权范围(每次现读,文件即真源)。"""
        path = self.path(SCOPE_FILE)
        if not path.exists():
            raise WorkspaceError(f"缺少授权范围文件: {path}")
        return Scope.from_file(path)

    # -- JSON 原子读写 ----------------------------------------------------------
    def read_json(self, name: str) -> Any:
        """读取工作区根下的 JSON 文件;损坏时抛 ``WorkspaceCorruptError``。"""
        path = self.path(name)
        try:
            with path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except json.JSONDecodeError as exc:
            raise WorkspaceCorruptError(f"工作区文件损坏,无法解析 JSON: {path}({exc})") from exc

    def write_json(self, name: str, data: Any) -> None:
        """原子写 JSON:先写同目录临时文件再 os.replace,防半写状态。"""
        path = self.path(name)
        fd, tmp_name = tempfile.mkstemp(dir=self.root, prefix=f".{name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
            os.replace(tmp_name, path)
        except BaseException:
            # 失败时清理临时文件,绝不留半成品在目标路径上。
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise

    # -- assets / findings 便捷封装 ---------------------------------------------
    def load_assets(self) -> list[Any]:
        data = self.read_json(ASSETS_FILE)
        if not isinstance(data, list):
            raise WorkspaceCorruptError(f"{ASSETS_FILE} 顶层必须是列表: {self.path(ASSETS_FILE)}")
        return data

    def save_assets(self, assets: list[Any]) -> None:
        self.write_json(ASSETS_FILE, assets)

    def load_findings(self) -> list[Any]:
        data = self.read_json(FINDINGS_FILE)
        if not isinstance(data, list):
            raise WorkspaceCorruptError(
                f"{FINDINGS_FILE} 顶层必须是列表: {self.path(FINDINGS_FILE)}"
            )
        return data

    def save_findings(self, findings: list[Any]) -> None:
        self.write_json(FINDINGS_FILE, findings)
