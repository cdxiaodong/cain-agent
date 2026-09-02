"""Workspace 扩展 —— 集成 Blackboard（Agent 通信板）

在现有 Workspace 基础上添加 Blackboard 功能，保持向后兼容。
"""

from __future__ import annotations

import sys
from pathlib import Path

from cain_agent.multi_agent.blackboard import Blackboard
from cain_agent.multi_agent.types import Finding, Idea
from cain_agent.workspace import Workspace as BaseWorkspace

# board Finding 支持的构造字段(过滤 pipeline 侧多余字段,见 multi_agent.types)
_BOARD_FINDING_FIELDS = (
    "cloud", "service", "resource", "issue_type", "severity", "detail",
    "evidence", "confirmed", "finding_id", "timestamp", "solver_id",
)


def _to_board_finding(item: object) -> Finding | None:
    """把 pipeline Finding / dict / 其他对象收敛为 board Finding;不可收敛返回 None。"""
    if isinstance(item, Finding):
        return item
    if not isinstance(item, dict):
        return None
    kwargs = {k: v for k, v in item.items() if k in _BOARD_FINDING_FIELDS}
    try:
        return Finding(**kwargs)
    except TypeError:
        return None


class WorkspaceWithBoard(BaseWorkspace):
    """
集成 Blackboard 的 Workspace（Phase 2 升级）。

    新增功能：
    - Agent 通信黑板（Blackboard）
    - Idea/Memory 持久化
    - 与现有 Workspace API 完全兼容
    """

    BLACKBOARD_FILE = "blackboard.json"
    IDEAS_FILE = "ideas.json"

    def __init__(self, root: str | Path) -> None:
        super().__init__(root)
        self.blackboard = Blackboard()
        self._load_blackboard_state()

    # -- Blackboard 持久化 ----------------------------------------

    def _load_blackboard_state(self) -> None:
        """从 Workspace 加载 Blackboard 状态。"""
        ideas_path = self.path(self.IDEAS_FILE)
        if ideas_path.exists():
            try:
                data = self.read_json(self.IDEAS_FILE)
                if not isinstance(data, list):
                    raise TypeError(f"ideas.json 顶层应为 list,实际 {type(data).__name__}")
                for item in data:
                    if not isinstance(item, dict):
                        raise TypeError(f"ideas.json 条目应为 dict,实际 {type(item).__name__}")
                    idea = Idea(**item)
                    self.blackboard._ideas[idea.idea_id] = idea
            except (ValueError, TypeError, KeyError) as exc:
                # 损坏时降级为空状态,但必须留下可诊断信号(不再静默吞掉)
                print(
                    f"[workspace] blackboard 状态加载失败,已从空状态启动: {exc}",
                    file=sys.stderr,
                )

    def save_blackboard(self) -> None:
        """持久化 Blackboard 到 Workspace。"""
        # 保存 Ideas
        ideas_data = []
        for idea in self.blackboard._ideas.values():
            ideas_data.append({
                "hypothesis": idea.hypothesis,
                "plan": idea.plan,
                "priority": idea.priority,
                "status": idea.status,
                "parent_task_id": idea.parent_task_id,
                "idea_id": idea.idea_id,
                "timestamp": idea.timestamp,
                "solver_id": idea.solver_id,
            })
        self.write_json(self.IDEAS_FILE, ideas_data)

        # 保存 Findings（复用现有 findings.json）
        findings_data = []
        for f in self.blackboard._memory.findings:
            findings_data.append({
                "cloud": f.cloud,
                "service": f.service,
                "resource": f.resource,
                "issue_type": f.issue_type,
                "severity": f.severity.value,
                "detail": f.detail,
                "evidence": f.evidence,
                "confirmed": f.confirmed,
                "finding_id": f.finding_id,
                "timestamp": f.timestamp,
                "solver_id": f.solver_id,
            })
        self.write_json("findings.json", findings_data)

    # -- 兼容现有 API：将 Finding 同步到 Blackboard -----------------

    def save_findings(self, findings: list[object]) -> None:
        """
重写：保存 Finding 到文件 + Blackboard。"""
        super().save_findings(findings)
        # 同步到 Blackboard:查重(finding_id 已存在则跳过,防重复 run 双写)
        existing_ids = {fd.finding_id for fd in self.blackboard.read_findings()}
        for f in findings:
            finding = _to_board_finding(f)
            if finding is None:
                continue
            if finding.finding_id in existing_ids:
                continue
            self.blackboard.post_finding(finding, solver_id=finding.solver_id or "workspace")
