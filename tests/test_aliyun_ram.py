"""阿里云 RAM 提权路径分析模块单元测试。

全 mock:monkeypatch ``RamPrivescAnalyzer._call_api`` 返回构造好的策略 JSON,
零触网、零真实凭证。覆盖:5 条规则各命中、通配 ``*`` 判定、管理员 ram:*
直接标 critical、无权用户容错、凭证缺失报错、policy 解析失败不炸。
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cain_agent.cloud.aliyun_ram import (
    PRIVESC_RULES,
    RamCredentialError,
    RamFinding,
    RamPrivescAnalyzer,
    _extract_allowed_actions,
)

# ── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def creds(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """提供测试用假凭证;清除真实环境变量防泄漏。"""
    for var in (
        "ALIBABA_CLOUD_ACCESS_KEY_ID",
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
        "ALICLOUD_ACCESS_KEY",
        "ALICLOUD_SECRET_KEY",
        "ALIBABA_CLOUD_REGION",
    ):
        monkeypatch.delenv(var, raising=False)
    return {"access_key_id": "FAKE_AK", "access_key_secret": "FAKE_SK"}


def _policy(actions: str | list[str], effect: str = "Allow") -> str:
    """构造一个 RAM policy document JSON 字符串。"""
    return json.dumps({
        "Version": "1",
        "Statement": [{"Effect": effect, "Action": actions, "Resource": "*"}],
    })


def _make_api_router(
    responses: dict[str, Any],
) -> Any:
    """创建一个 fake _call_api,按 Action 名路由到预设响应。"""

    def fake_call_api(action: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        key = action
        # GetPolicyVersion: 返回策略文档
        if action == "GetPolicyVersion":
            policy_name = (params or {}).get("PolicyName", "")
            doc = responses.get(f"doc:{policy_name}", _policy([]))
            return {"PolicyVersion": {"PolicyDocument": doc}}
        if action == "GetPolicy":
            policy_name = (params or {}).get("PolicyName", "")
            return {
                "PolicyName": policy_name,
                "DefaultPolicyVersionId": "v1",
            }
        if key in responses:
            return responses[key]
        return {}

    return fake_call_api


def _analyzer_with(
    creds: dict[str, str],
    responses: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> RamPrivescAnalyzer:
    """构造一个带 fake API 的 analyzer。"""
    az = RamPrivescAnalyzer(**creds)
    monkeypatch.setattr(az, "_call_api", _make_api_router(responses))
    return az


# ── credential tests ────────────────────────────────────────────────────────


class TestCredentials:
    def test_missing_creds_raises(self, creds: dict[str, str]) -> None:
        with pytest.raises(RamCredentialError):
            RamPrivescAnalyzer(access_key_id=None, access_key_secret=None)

    def test_env_creds_work(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "ENV_AK")
        monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ENV_SK")
        az = RamPrivescAnalyzer()
        assert az.access_key_id == "ENV_AK"
        assert az.access_key_secret == "ENV_SK"


# ── five rules each hit ─────────────────────────────────────────────────────


class TestPrivescRules:
    """每条提权规则至少有一个命中用例。"""

    def test_passrole_to_compute(
        self,
        creds: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ram:PassRole + fc:CreateFunction -> critical。"""
        responses = {
            "ListUsers": {"Users": {"User": [{"UserName": "dev", "Arn": "acs:ram::1:user/dev"}]}},
            "ListRoles": {"Roles": {"Role": []}},
            "ListPoliciesForUser": {"Policies": {"Policy": [{"PolicyName": "p1", "PolicyType": "Custom"}]}},
            "doc:p1": _policy(["ram:PassRole", "fc:CreateFunction"]),
        }
        az = _analyzer_with(creds, responses, monkeypatch)
        findings = az.analyze()
        hits = [f for f in findings if f.rule_id == "ram:PassRole-to-Compute"]
        assert len(hits) == 1
        assert hits[0].severity == "critical"

    def test_attach_policy_to_self(
        self,
        creds: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ram:AttachPolicyToUser -> critical。"""
        responses = {
            "ListUsers": {"Users": {"User": [{"UserName": "dev", "Arn": "acs:ram::1:user/dev"}]}},
            "ListRoles": {"Roles": {"Role": []}},
            "ListPoliciesForUser": {"Policies": {"Policy": [{"PolicyName": "p1", "PolicyType": "Custom"}]}},
            "doc:p1": _policy(["ram:AttachPolicyToUser"]),
        }
        az = _analyzer_with(creds, responses, monkeypatch)
        findings = az.analyze()
        hits = [f for f in findings if f.rule_id == "ram:AttachPolicyToSelf"]
        assert len(hits) == 1
        assert hits[0].severity == "critical"

    def test_create_access_key(
        self,
        creds: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ram:CreateAccessKey -> critical。"""
        responses = {
            "ListUsers": {"Users": {"User": [{"UserName": "dev", "Arn": "acs:ram::1:user/dev"}]}},
            "ListRoles": {"Roles": {"Role": []}},
            "ListPoliciesForUser": {"Policies": {"Policy": [{"PolicyName": "p1", "PolicyType": "Custom"}]}},
            "doc:p1": _policy(["ram:CreateAccessKey"]),
        }
        az = _analyzer_with(creds, responses, monkeypatch)
        findings = az.analyze()
        hits = [f for f in findings if f.rule_id == "ram:CreateAccessKey-for-HighPriv"]
        assert len(hits) == 1
        assert hits[0].severity == "critical"

    def test_login_profile_hijack(
        self,
        creds: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ram:CreateLoginProfile -> high。"""
        responses = {
            "ListUsers": {"Users": {"User": [{"UserName": "dev", "Arn": "acs:ram::1:user/dev"}]}},
            "ListRoles": {"Roles": {"Role": []}},
            "ListPoliciesForUser": {"Policies": {"Policy": [{"PolicyName": "p1", "PolicyType": "Custom"}]}},
            "doc:p1": _policy(["ram:CreateLoginProfile"]),
        }
        az = _analyzer_with(creds, responses, monkeypatch)
        findings = az.analyze()
        hits = [f for f in findings if f.rule_id == "ram:LoginProfile-Hijack"]
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_assume_role_chain(
        self,
        creds: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """sts:AssumeRole -> high。"""
        responses = {
            "ListUsers": {"Users": {"User": []}},
            "ListRoles": {"Roles": {"Role": [{"RoleName": "cross", "Arn": "acs:ram::1:role/cross"}]}},
            "ListPoliciesForRole": {"Policies": {"Policy": [{"PolicyName": "p1", "PolicyType": "Custom"}]}},
            "doc:p1": _policy(["sts:AssumeRole"]),
        }
        az = _analyzer_with(creds, responses, monkeypatch)
        findings = az.analyze()
        hits = [f for f in findings if f.rule_id == "ram:AssumeRole-Chain"]
        assert len(hits) == 1
        assert hits[0].severity == "high"


# ── wildcard * / admin ──────────────────────────────────────────────────────


class TestWildcard:
    def test_admin_star_hits_all_rules(
        self,
        creds: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ram:* 或 * 的策略 → 命中所有规则,全部 critical(或其规则 severity)。"""
        responses = {
            "ListUsers": {"Users": {"User": [{"UserName": "admin", "Arn": "acs:ram::1:user/admin"}]}},
            "ListRoles": {"Roles": {"Role": []}},
            "ListPoliciesForUser": {"Policies": {"Policy": [{"PolicyName": "p1", "PolicyType": "Custom"}]}},
            "doc:p1": _policy("*"),
        }
        az = _analyzer_with(creds, responses, monkeypatch)
        findings = az.analyze()
        assert len(findings) == len(PRIVESC_RULES)
        for f in findings:
            assert f.severity in ("critical", "high")
            assert f.evidence["is_admin"] is True

    def test_ram_admin_star(self, creds: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
        """ram:* → 所有 ram 规则命中。"""
        responses = {
            "ListUsers": {"Users": {"User": [{"UserName": "power", "Arn": "acs:ram::1:user/power"}]}},
            "ListRoles": {"Roles": {"Role": []}},
            "ListPoliciesForUser": {"Policies": {"Policy": [{"PolicyName": "p1", "PolicyType": "Custom"}]}},
            "doc:p1": _policy("ram:*"),
        }
        az = _analyzer_with(creds, responses, monkeypatch)
        findings = az.analyze()
        # ram:* covers all pure-RAM rules; PassRole-to-Compute also needs
        # fc/ecs permission, AssumeRole-Chain needs sts, so they don't fire
        rule_ids = {f.rule_id for f in findings}
        assert "ram:AttachPolicyToSelf" in rule_ids
        assert "ram:CreateAccessKey-for-HighPriv" in rule_ids
        assert "ram:LoginProfile-Hijack" in rule_ids
        assert "ram:PassRole-to-Compute" not in rule_ids


# ── no-hit / clean ──────────────────────────────────────────────────────────


class TestCleanPrincipal:
    def test_readonly_no_hits(
        self,
        creds: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """只有只读权限 → 无命中。"""
        responses = {
            "ListUsers": {"Users": {"User": [{"UserName": "auditor", "Arn": "acs:ram::1:user/auditor"}]}},
            "ListRoles": {"Roles": {"Role": []}},
            "ListPoliciesForUser": {"Policies": {"Policy": [{"PolicyName": "p1", "PolicyType": "Custom"}]}},
            "doc:p1": _policy(["ram:GetUser", "ram:GetPolicy", "ram:ListUsers"]),
        }
        az = _analyzer_with(creds, responses, monkeypatch)
        findings = az.analyze()
        assert findings == []


# ── fault tolerance ─────────────────────────────────────────────────────────


class TestFaultTolerance:
    def test_permission_denied_user_skipped(
        self,
        creds: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ListPoliciesForUser 报错 → 用户被跳过,不炸全局。"""
        call_count = {"n": 0}
        responses = {
            "ListUsers": {"Users": {"User": [{"UserName": "noperm", "Arn": "acs:ram::1:user/noperm"}]}},
            "ListRoles": {"Roles": {"Role": []}},
        }

        def flaky_call_api(action: str, params: dict[str, str] | None = None) -> dict[str, Any]:
            call_count["n"] += 1
            if action == "ListPoliciesForUser":
                raise RuntimeError("NoPermission: You are not authorized")
            router = _make_api_router(responses)
            return router(action, params)

        az = RamPrivescAnalyzer(**creds)
        monkeypatch.setattr(az, "_call_api", flaky_call_api)
        # should not raise
        findings = az.analyze()
        assert findings == []

    def test_bad_policy_doc_skipped(
        self,
        creds: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Policy Document 非法 JSON → 跳过该策略,不炸。"""
        responses = {
            "ListUsers": {"Users": {"User": [{"UserName": "u1", "Arn": "acs:ram::1:user/u1"}]}},
            "ListRoles": {"Roles": {"Role": []}},
            "ListPoliciesForUser": {"Policies": {"Policy": [{"PolicyName": "p1", "PolicyType": "Custom"}]}},
            "doc:p1": "this is { not valid json",
        }
        az = _analyzer_with(creds, responses, monkeypatch)
        findings = az.analyze()
        assert findings == []

    def test_get_policy_failure_skipped(
        self,
        creds: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """GetPolicy 报错 → 策略被跳过。"""
        _pol = {"PolicyName": "broken", "PolicyType": "Custom"}
        responses = {
            "ListUsers": {"Users": {"User": [{"UserName": "u1", "Arn": "acs:ram::1:user/u1"}]}},
            "ListRoles": {"Roles": {"Role": []}},
            "ListPoliciesForUser": {"Policies": {"Policy": [_pol]}},
        }

        def failing_policy(action: str, params: dict[str, str] | None = None) -> dict[str, Any]:
            if action == "GetPolicy":
                raise RuntimeError("EntityNotExist.Policy")
            return _make_api_router(responses)(action, params)

        az = RamPrivescAnalyzer(**creds)
        monkeypatch.setattr(az, "_call_api", failing_policy)
        findings = az.analyze()
        assert findings == []


# ── _extract_allowed_actions ────────────────────────────────────────────────


class TestExtractActions:
    def test_single_string_action(self) -> None:
        doc = _policy("ram:CreateAccessKey")
        assert "ram:createaccesskey" in _extract_allowed_actions(doc)

    def test_list_actions(self) -> None:
        doc = _policy(["ram:PassRole", "ecs:RunInstances"])
        actions = _extract_allowed_actions(doc)
        assert "ram:passrole" in actions
        assert "ecs:runinstances" in actions

    def test_deny_excluded(self) -> None:
        doc = _policy(["ram:CreateAccessKey"], effect="Deny")
        assert _extract_allowed_actions(doc) == set()

    def test_star(self) -> None:
        doc = _policy("*")
        assert "*" in _extract_allowed_actions(doc)

    def test_none_doc(self) -> None:
        assert _extract_allowed_actions(None) == set()

    def test_bad_json(self) -> None:
        assert _extract_allowed_actions("garbage") == set()

    def test_mixed_effect_statements(self) -> None:
        """Allow 和 Deny 混合 → 只收集 Allow。"""
        doc = json.dumps({
            "Version": "1",
            "Statement": [
                {"Effect": "Allow", "Action": "ram:CreateAccessKey", "Resource": "*"},
                {"Effect": "Deny", "Action": "ram:DeleteUser", "Resource": "*"},
            ],
        })
        actions = _extract_allowed_actions(doc)
        assert "ram:createaccesskey" in actions
        assert "ram:deleteuser" not in actions


# ── RamFinding structure ────────────────────────────────────────────────────


class TestRamFindingStructure:
    def test_finding_fields_align_findings_model(
        self,
        creds: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """RamFinding 的字段可映射到 findings.Finding(cloud=aliyun, service=ram)。"""
        responses = {
            "ListUsers": {"Users": {"User": [{"UserName": "dev", "Arn": "acs:ram::1:user/dev"}]}},
            "ListRoles": {"Roles": {"Role": []}},
            "ListPoliciesForUser": {"Policies": {"Policy": [{"PolicyName": "p1", "PolicyType": "Custom"}]}},
            "doc:p1": _policy(["ram:AttachPolicyToUser"]),
        }
        az = _analyzer_with(creds, responses, monkeypatch)
        findings = az.analyze()
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, RamFinding)
        assert f.resource.startswith("acs:ram::")
        assert f.issue_type == f.rule_id
        assert f.severity in ("critical", "high", "medium", "low", "info")
        assert "entity_name" in f.evidence
