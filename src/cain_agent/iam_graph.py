"""IAM/RAM 提权路径图建模(纯逻辑,零触网)。

将 ``cloud.aliyun_ram`` / ``cloud.tencent_cam`` 分析器产出的 Finding
(``RamFinding`` / ``CamFinding``)建成**有向提权路径图**:

- **节点**三类:
  - ``entity``   —— 被扫描出的实体(用户/角色/用户组,resource ARN/Uin)
  - ``rule``     —— 命中的提权规则(rule_id,即"提权动作"本身)
  - ``target``   —— 提权后的目标权限状态(``admin`` / ``elevated``)
- **边**两类:
  - ``entity --[via rule_id]--> rule``   实体经某规则发起提权
  - ``rule   --[grants]--> target``      该规则抵达的目标权限

设计约定
--------
* 纯数据建模,不引入第三方图库(networkx 等),零新依赖。
* severity 决定目标节点:critical → ``admin``,high/medium → ``elevated``。
* ``to_dot`` 导出 Graphviz DOT,``to_json``/``from_json`` 供前端渲染与持久化,
  round-trip 无损。
* ``paths_to_privilege`` 用 BFS 求"任一实体 → 高权目标"的全部最短路径,
  供报告层直接展示提权链路。
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "IamGraph",
    "IamGraphError",
    "Edge",
    "Node",
    "build_graph",
]

# 目标节点固定 ID:critical 提权抵达 admin,其余抵达 elevated。
TARGET_ADMIN = "target:admin"
TARGET_ELEVATED = "target:elevated"

# severity → 目标节点。critical 视为拿到管理员,其余仅"权限提升"。
_SEVERITY_TARGET = {
    "critical": TARGET_ADMIN,
    "high": TARGET_ELEVATED,
    "medium": TARGET_ELEVATED,
    "low": TARGET_ELEVATED,
    "info": TARGET_ELEVATED,
}

_NODE_KINDS = ("entity", "rule", "target")


class IamGraphError(ValueError):
    """图数据非法(未知节点、重复 ID、非法 JSON 结构等)时抛出。"""


@dataclass(frozen=True)
class Node:
    """有向图节点。``kind`` 限定 entity/rule/target 三类。"""

    node_id: str
    kind: str  # "entity" | "rule" | "target"
    label: str = ""
    severity: str = ""  # rule/target 节点携带,供前端着色
    cloud: str = ""  # entity 节点来源云(aliyun/tencent)

    def __post_init__(self) -> None:
        if self.kind not in _NODE_KINDS:
            raise IamGraphError(f"非法节点类型: {self.kind!r}(合法: {_NODE_KINDS})")
        if not self.node_id:
            raise IamGraphError("node_id 不能为空")


@dataclass(frozen=True)
class Edge:
    """有向边 ``source -> target``,``action`` 为触发该边的提权动作。"""

    source: str
    target: str
    action: str = ""  # 提权动作描述(通常是 rule_id 或 "grants")
    kind: str = "via"  # "via"(实体→规则) | "grants"(规则→目标)


@dataclass
class IamGraph:
    """提权路径有向图:节点表 + 邻接表(保序)。"""

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    # -- 构建 ---------------------------------------------------------------

    def add_node(self, node: Node) -> None:
        """加入节点;同 ID 已存在则忽略(幂等),冲突定义则报错。"""
        existing = self.nodes.get(node.node_id)
        if existing is not None:
            if existing != node:
                raise IamGraphError(
                    f"节点 ID 冲突: {node.node_id!r} 已定义为 {existing!r}"
                )
            return
        self.nodes[node.node_id] = node

    def add_edge(self, edge: Edge) -> None:
        """加入边;两端节点必须先存在。"""
        for endpoint in (edge.source, edge.target):
            if endpoint not in self.nodes:
                raise IamGraphError(f"边引用了不存在的节点: {endpoint!r}")
        if edge not in self.edges:
            self.edges.append(edge)

    # -- 查询 ---------------------------------------------------------------

    def _adjacency(self) -> dict[str, list[Edge]]:
        adj: dict[str, list[Edge]] = {nid: [] for nid in self.nodes}
        for e in self.edges:
            adj[e.source].append(e)
        return adj

    def paths_to_privilege(self, target: str = TARGET_ADMIN) -> list[list[str]]:
        """BFS 求所有"实体节点 → 指定高权目标"的最短路径(节点 ID 序列)。

        返回的是**最短**路径集合:多条等长最短路径都保留,便于报告层并列
        展示同实体的多条提权通道。无路径时返回空列表。
        """
        if target not in self.nodes:
            return []
        adj = self._adjacency()
        out: list[list[str]] = []
        for nid, node in self.nodes.items():
            if node.kind != "entity":
                continue
            out.extend(self._bfs_shortest(adj, nid, target))
        return out

    @staticmethod
    def _bfs_shortest(
        adj: dict[str, list[Edge]], start: str, goal: str
    ) -> list[list[str]]:
        """标准 BFS 求 start→goal 的全部最短路径。"""
        if start == goal:
            return [[start]]
        # 层序遍历,记录到达每个节点的最短距离与前驱。
        dist: dict[str, int] = {start: 0}
        preds: dict[str, list[str]] = {}
        queue: deque[str] = deque([start])
        best: int | None = None
        while queue:
            cur = queue.popleft()
            # 已超过已知最短路径长度则剪枝。
            if best is not None and dist[cur] >= best:
                continue
            for e in adj.get(cur, []):
                nxt = e.target
                nd = dist[cur] + 1
                if nxt == goal:
                    best = nd if best is None else min(best, nd)
                    preds.setdefault(nxt, [])
                    if cur not in preds[nxt]:
                        preds[nxt].append(cur)
                    continue
                if nxt not in dist:
                    dist[nxt] = nd
                    preds.setdefault(nxt, [])
                    if cur not in preds[nxt]:
                        preds[nxt].append(cur)
                    queue.append(nxt)
                elif dist[nxt] == nd:
                    if cur not in preds.setdefault(nxt, []):
                        preds[nxt].append(cur)
        if goal not in preds:
            return []
        # 回溯前驱重建全部最短路径。trail 以"从 goal 往回走"的顺序积累,
        # 到达 start 时整体反转即得 start→goal 正序路径。
        paths: list[list[str]] = []

        def _backtrack(node: str, trail: list[str]) -> None:
            # trail 为空表示当前 node 即路径末端(goal)。
            path = trail + [node]
            if node == start:
                paths.append(path[::-1])
                return
            for p in preds.get(node, []):
                _backtrack(p, path)

        _backtrack(goal, [])
        return paths

    # -- 导出 ---------------------------------------------------------------

    def to_dot(self) -> str:
        """导出 Graphviz DOT。rule/target 节点按 severity 着色。"""
        color = {
            "critical": "#d62728",
            "high": "#ff7f0e",
            "medium": "#e6b800",
            "low": "#2ca02c",
            "info": "#7f7f7f",
        }
        shape = {"entity": "box", "rule": "ellipse", "target": "doubleoctagon"}
        lines = ["digraph iam_privesc {", "  rankdir=LR;", "  node [fontname=Helvetica];"]
        for nid, node in self.nodes.items():
            attrs = [f'shape={shape.get(node.kind, "ellipse")}']
            label = node.label or nid
            attrs.append(f'label="{_dot_escape(label)}"')
            fill = color.get(node.severity)
            if fill:
                attrs.append(f'style=filled fillcolor="{fill}"')
            lines.append(f'  "{_dot_escape(nid)}" [{", ".join(attrs)}];')
        for e in self.edges:
            label = f' [label="{_dot_escape(e.action)}"]' if e.action else ""
            lines.append(
                f'  "{_dot_escape(e.source)}" -> "{_dot_escape(e.target)}"{label};'
            )
        lines.append("}")
        return "\n".join(lines)

    def to_json(self) -> str:
        """导出 JSON(供前端渲染/持久化),round-trip 无损。"""
        payload = {
            "nodes": [
                {
                    "node_id": n.node_id,
                    "kind": n.kind,
                    "label": n.label,
                    "severity": n.severity,
                    "cloud": n.cloud,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "action": e.action,
                    "kind": e.kind,
                }
                for e in self.edges
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, text: str) -> IamGraph:
        """从 ``to_json`` 的产出还原图;结构非法一律抛 ``IamGraphError``。"""
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, TypeError) as exc:
            raise IamGraphError(f"非法 JSON: {exc}") from None
        if not isinstance(payload, dict):
            raise IamGraphError("图 JSON 顶层必须是对象")
        graph = cls()
        for nd in payload.get("nodes", []):
            try:
                graph.add_node(Node(**nd))
            except (TypeError, IamGraphError) as exc:
                raise IamGraphError(f"非法节点: {nd!r}({exc})") from None
        for ed in payload.get("edges", []):
            try:
                graph.add_edge(Edge(**ed))
            except (TypeError, IamGraphError) as exc:
                raise IamGraphError(f"非法边: {ed!r}({exc})") from None
        return graph


# --------------------------------------------------------------------------- #
# 构建入口:从 Finding 列表建图
# --------------------------------------------------------------------------- #


def build_graph(findings: Iterable[Any]) -> IamGraph:
    """把 RAM/CAM 分析结果(RamFinding/CamFinding)建成提权路径图。

    只依赖 Finding 的鸭子类型字段:``resource`` / ``rule_id`` /
    ``severity`` / ``cloud``(可缺省)/ ``evidence.entity_name``。两类
    Finding 结构对齐,统一处理;``error`` 非空的 Finding(扫描失败)跳过。

    建图规则:
      entity(cloud:resource) --[via rule_id]--> rule(rule_id)
      rule(rule_id)          --[grants]------> target(admin/elevated)
    """
    graph = IamGraph()

    # 目标节点预置,保证即使无 critical 也有 elevated 汇点存在定义。
    graph.add_node(
        Node(TARGET_ADMIN, "target", label="管理员权限 (admin)", severity="critical")
    )
    graph.add_node(
        Node(TARGET_ELEVATED, "target", label="权限提升 (elevated)", severity="high")
    )

    for f in findings:
        if getattr(f, "error", None):
            continue  # 扫描失败的 Finding 不进图
        resource = getattr(f, "resource", "") or ""
        rule_id = getattr(f, "rule_id", "") or getattr(f, "issue_type", "") or ""
        severity = str(getattr(f, "severity", "info") or "info").lower()
        if not resource or not rule_id:
            continue

        cloud = getattr(f, "cloud", "") or _infer_cloud(rule_id)
        evidence = getattr(f, "evidence", {}) or {}
        entity_name = evidence.get("entity_name", resource)
        entity_type = evidence.get("entity_type", "entity")

        entity_id = f"entity:{cloud}:{resource}"
        rule_node_id = f"rule:{rule_id}"

        graph.add_node(
            Node(
                entity_id,
                "entity",
                label=f"{entity_name}\n({entity_type})",
                cloud=cloud,
            )
        )
        graph.add_node(
            Node(rule_node_id, "rule", label=rule_id, severity=severity)
        )
        graph.add_edge(Edge(entity_id, rule_node_id, action=rule_id, kind="via"))

        target = _SEVERITY_TARGET.get(severity, TARGET_ELEVATED)
        graph.add_edge(Edge(rule_node_id, target, action="grants", kind="grants"))

    return graph


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _infer_cloud(rule_id: str) -> str:
    """从 rule_id 前缀推断来源云(``ram:`` → aliyun,``cam:`` → tencent)。"""
    prefix = rule_id.split(":", 1)[0].lower()
    return {"ram": "aliyun", "cam": "tencent", "iam": "aws"}.get(prefix, "unknown")


def _dot_escape(text: str) -> str:
    """转义 DOT 字符串中的引号与换行。"""
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
