"""IAM/RAM 提权路径图模块单元测试。

纯逻辑零触网:直接构造 RamFinding/CamFinding(或轻量 stub)喂给
``build_graph``,校验节点/边结构、severity→目标映射、DOT/JSON 导出
round-trip、BFS 最短路径查找、以及非法输入的容错。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from cain_agent.cloud.aliyun_ram import RamFinding
from cain_agent.cloud.tencent_cam import CamFinding
from cain_agent.iam_graph import (
    TARGET_ADMIN,
    TARGET_ELEVATED,
    Edge,
    IamGraph,
    IamGraphError,
    Node,
    build_graph,
)

# ── helpers ────────────────────────────────────────────────────────────────


def _ram_finding(
    resource: str = "acs:ram::1:user/dev",
    rule_id: str = "ram:AttachPolicyToSelf",
    severity: str = "critical",
    name: str = "dev",
    error: str | None = None,
) -> RamFinding:
    return RamFinding(
        rule_id=rule_id,
        resource=resource,
        issue_type=rule_id,
        severity=severity,
        description="d",
        evidence={"entity_type": "user", "entity_name": name},
        error=error,
    )


def _cam_finding(
    resource: str = "uin:10001",
    rule_id: str = "cam:PassRole",
    severity: str = "critical",
    name: str = "ops",
) -> CamFinding:
    return CamFinding(
        cloud="tencent",
        service="cam",
        rule_id=rule_id,
        resource=resource,
        issue_type="user_privesc",
        severity=severity,
        description="d",
        evidence={"entity_type": "user", "entity_name": name},
    )


# ── node / edge validation ─────────────────────────────────────────────────


class TestNodeEdgeValidation:
    def test_invalid_node_kind(self) -> None:
        with pytest.raises(IamGraphError):
            Node("x", "bogus")

    def test_empty_node_id(self) -> None:
        with pytest.raises(IamGraphError):
            Node("", "entity")

    def test_edge_requires_existing_nodes(self) -> None:
        g = IamGraph()
        g.add_node(Node("a", "entity"))
        with pytest.raises(IamGraphError):
            g.add_edge(Edge("a", "ghost"))

    def test_conflicting_node_id_rejected(self) -> None:
        g = IamGraph()
        g.add_node(Node("a", "entity"))
        with pytest.raises(IamGraphError):
            g.add_node(Node("a", "rule"))  # 同 ID 不同定义

    def test_idempotent_node_add(self) -> None:
        g = IamGraph()
        g.add_node(Node("a", "entity", label="x"))
        g.add_node(Node("a", "entity", label="x"))  # 完全相同 → 幂等
        assert len(g.nodes) == 1


# ── build_graph structure ─────────────────────────────────────────────────


class TestBuildGraph:
    def test_ram_critical_reaches_admin(self) -> None:
        g = build_graph([_ram_finding()])
        assert "entity:aliyun:acs:ram::1:user/dev" in g.nodes
        assert "rule:ram:AttachPolicyToSelf" in g.nodes
        # critical → admin 汇点
        assert ("rule:ram:AttachPolicyToSelf", TARGET_ADMIN) in {
            (e.source, e.target) for e in g.edges
        }

    def test_cam_high_reaches_elevated(self) -> None:
        g = build_graph([_cam_finding(severity="high", rule_id="cam:AssumeRole")])
        assert ("rule:cam:AssumeRole", TARGET_ELEVATED) in {
            (e.source, e.target) for e in g.edges
        }
        # high 不应抵达 admin
        assert ("rule:cam:AssumeRole", TARGET_ADMIN) not in {
            (e.source, e.target) for e in g.edges
        }

    def test_two_targets_precreated(self) -> None:
        g = build_graph([])
        assert g.nodes[TARGET_ADMIN].kind == "target"
        assert g.nodes[TARGET_ELEVATED].kind == "target"

    def test_error_finding_skipped(self) -> None:
        g = build_graph([_ram_finding(error="AccessDenied")])
        # 仅剩两个预置 target 节点
        assert len([n for n in g.nodes.values() if n.kind == "entity"]) == 0

    def test_entity_label_uses_name(self) -> None:
        g = build_graph([_ram_finding(name="alice")])
        node = g.nodes["entity:aliyun:acs:ram::1:user/dev"]
        assert "alice" in node.label

    def test_mixed_clouds(self) -> None:
        g = build_graph([_ram_finding(), _cam_finding()])
        kinds = {n.cloud for n in g.nodes.values() if n.kind == "entity"}
        assert kinds == {"aliyun", "tencent"}

    def test_dedup_same_rule_two_entities(self) -> None:
        """两个实体命中同一规则 → 规则节点只建一次,两条 via 边。"""
        findings = [
            _ram_finding(resource="acs:ram::1:user/a", name="a"),
            _ram_finding(resource="acs:ram::1:user/b", name="b"),
        ]
        g = build_graph(findings)
        assert len([n for n in g.nodes.values() if n.kind == "rule"]) == 1
        via = [e for e in g.edges if e.kind == "via"]
        assert len(via) == 2


# ── path finding ───────────────────────────────────────────────────────────


class TestPathsToPrivilege:
    def test_simple_path(self) -> None:
        g = build_graph([_ram_finding()])
        paths = g.paths_to_privilege(TARGET_ADMIN)
        assert [
            "entity:aliyun:acs:ram::1:user/dev",
            "rule:ram:AttachPolicyToSelf",
            TARGET_ADMIN,
        ] in paths

    def test_no_path_when_only_high(self) -> None:
        g = build_graph([_cam_finding(severity="high", rule_id="cam:AssumeRole")])
        assert g.paths_to_privilege(TARGET_ADMIN) == []
        # 但 elevated 有路径
        assert len(g.paths_to_privilege(TARGET_ELEVATED)) == 1

    def test_unknown_target_returns_empty(self) -> None:
        g = build_graph([_ram_finding()])
        assert g.paths_to_privilege("target:nowhere") == []

    def test_multiple_entities_all_found(self) -> None:
        findings = [
            _ram_finding(resource="acs:ram::1:user/a", name="a"),
            _cam_finding(resource="uin:9", rule_id="cam:CreateAccessKey", name="b"),
        ]
        g = build_graph(findings)
        paths = g.paths_to_privilege(TARGET_ADMIN)
        starts = {p[0] for p in paths}
        assert "entity:aliyun:acs:ram::1:user/a" in starts
        assert "entity:tencent:uin:9" in starts

    def test_paths_are_node_id_sequences(self) -> None:
        g = build_graph([_ram_finding()])
        for path in g.paths_to_privilege(TARGET_ADMIN):
            assert path[-1] == TARGET_ADMIN
            for nid in path:
                assert nid in g.nodes


# ── DOT export ─────────────────────────────────────────────────────────────


class TestDot:
    def test_dot_structure(self) -> None:
        g = build_graph([_ram_finding()])
        dot = g.to_dot()
        assert dot.startswith("digraph iam_privesc {")
        assert dot.endswith("}")
        assert "rankdir=LR" in dot
        # 实体与规则、规则与目标的有向边
        assert '"entity:aliyun:acs:ram::1:user/dev" -> "rule:ram:AttachPolicyToSelf"' in dot
        assert f'"rule:ram:AttachPolicyToSelf" -> "{TARGET_ADMIN}"' in dot

    def test_dot_severity_coloring(self) -> None:
        g = build_graph([_ram_finding(severity="critical")])
        dot = g.to_dot()
        assert "#d62728" in dot  # critical 红

    def test_dot_escapes_quotes_and_newlines(self) -> None:
        g = IamGraph()
        g.add_node(Node("n", "entity", label='he said "hi"\nbye'))
        dot = g.to_dot()
        assert '\\"' in dot
        assert "\\n" in dot
        assert 'he said "hi"' not in dot  # 原始换行/引号已被转义


# ── JSON round-trip ────────────────────────────────────────────────────────


class TestJson:
    def test_round_trip_lossless(self) -> None:
        g = build_graph([_ram_finding(), _cam_finding()])
        restored = IamGraph.from_json(g.to_json())
        assert restored.nodes == g.nodes
        assert restored.edges == g.edges

    def test_json_is_valid_and_has_keys(self) -> None:
        import json as _json

        g = build_graph([_ram_finding()])
        payload = _json.loads(g.to_json())
        assert set(payload) == {"nodes", "edges"}
        assert all("node_id" in n for n in payload["nodes"])
        assert all("source" in e and "target" in e for e in payload["edges"])

    def test_from_json_rejects_garbage(self) -> None:
        with pytest.raises(IamGraphError):
            IamGraph.from_json("not json{{{")

    def test_from_json_rejects_non_dict(self) -> None:
        with pytest.raises(IamGraphError):
            IamGraph.from_json('["a"]')

    def test_from_json_rejects_bad_node(self) -> None:
        bad = '{"nodes": [{"node_id": "x", "kind": "nope"}], "edges": []}'
        with pytest.raises(IamGraphError):
            IamGraph.from_json(bad)


# ── duck-typed stub (非 RamFinding/CamFinding 也可建图) ────────────────────


@dataclass
class _StubFinding:
    rule_id: str
    resource: str
    severity: str
    cloud: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class TestDuckTyping:
    def test_stub_finding_accepted(self) -> None:
        stub = _StubFinding(
            rule_id="ram:AssumeRole-Chain",
            resource="acs:ram::1:role/x",
            severity="high",
            evidence={"entity_name": "x", "entity_type": "role"},
        )
        g = build_graph([stub])
        # 无 cloud 字段时按 rule_id 前缀推断 aliyun
        assert "entity:aliyun:acs:ram::1:role/x" in g.nodes

    def test_empty_resource_skipped(self) -> None:
        stub = _StubFinding(rule_id="ram:X", resource="", severity="high")
        g = build_graph([stub])
        assert len([n for n in g.nodes.values() if n.kind == "entity"]) == 0
