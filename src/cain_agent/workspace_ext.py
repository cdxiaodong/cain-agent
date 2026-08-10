"""Workspace 扩展 —— 集成 Blackboard（Agent 通信板）

在现有 Workspace 基础上添加 Blackboard 功能，保持向后兼容。
"""

from __future__ import annotations

from pathlib import Path

from cain_agent.multi_agent.blackboard import Blackboard
from cain_agent.multi_agent.types import Finding, Idea
from cain_agent.workspace import Workspace as BaseWorkspace


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
                for item in data:
                    idea = Idea(**item)
                    self.blackboard._ideas[idea.idea_id] = idea
            except Exception:  # noqa: BLE001
                # 损坏时忽略，从空状态开始
                pass

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
        # 同步到 Blackboard
        for f in findings:
            finding = Finding(**f) if isinstance(f, dict) else f
            self.blackboard.post_finding(finding, solver_id="legacy")
