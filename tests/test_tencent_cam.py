"""Unit tests for tencent_cam module (fully mocked, no network calls)."""

import json
from unittest.mock import patch

import pytest

from cain_agent.cloud.tencent_cam import (
    PRIVESC_RULES,
    CamCredentialError,
    CamFinding,
    CamPrivescAnalyzer,
    PrivescRule,
    _extract_allowed_actions,
    _first_env,
)

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def mock_secret_id():
    return "test_secret_id_12345"


@pytest.fixture
def mock_secret_key():
    return "test_secret_key_67890"


@pytest.fixture
def mock_region():
    return "ap-guangzhou"


@pytest.fixture
def sample_user_list():
    """Sample response from ListUsers API."""
    return {
        "Response": {
            "Data": {
                "Users": [
                    {"Uin": 1001, "Name": "dev-user", "Remark": "Dev account"},
                    {"Uin": 1002, "Name": "admin-user", "Remark": "Admin account"},
                ]
            }
        }
    }


@pytest.fixture
def sample_group_list():
    """Sample response from ListGroups API."""
    return {
        "Response": {
            "Data": {
                "Groups": [
                    {"GroupId": 2001, "GroupName": "Developers", "Remark": "Dev group"},
                    {"GroupId": 2002, "GroupName": "Admins", "Remark": "Admin group"},
                ]
            }
        }
    }


@pytest.fixture
def sample_policy_list():
    """Sample response from ListPolicies API."""
    return {
        "Response": {
            "Data": {
                "Policies": [
                    {
                        "PolicyId": "policy-111",
                        "PolicyName": "ReadOnlyPolicy",
                        "Description": "Read only access",
                    },
                    {
                        "PolicyId": "policy-222",
                        "PolicyName": "AdminPolicy",
                        "Description": "Admin access",
                    },
                ]
            }
        }
    }


@pytest.fixture
def sample_attached_user_policies():
    """Sample response from ListAttachedUserPolicies API."""
    return {
        "Response": {
            "Data": {
                "List": [
                    {
                        "PolicyId": "policy-111",
                        "PolicyName": "ReadOnlyPolicy",
                        "AttachTime": "2024-01-01T00:00:00Z",
                    }
                ]
            }
        }
    }


@pytest.fixture
def sample_policy_version_readonly():
    """Sample policy document with read-only permissions."""
    return {
        "Response": {
            "Data": {
                "PolicyVersion": {
                    "PolicyId": "policy-111",
                    "VersionId": 0,
                    "PolicyDocument": json.dumps({
                        "version": "2.0",
                        "statement": [
                            {
                                "effect": "allow",
                                "action": [
                                    "cam:GetUser",
                                    "cam:ListUsers",
                                    "cos:GetBucket",
                                    "cos:HeadObject",
                                ],
                                "resource": "*",
                            }
                        ],
                    }),
                }
            }
        }
    }


@pytest.fixture
def sample_policy_version_admin():
    """Sample policy document with admin permissions (including privesc paths)."""
    return {
        "Response": {
            "Data": {
                "PolicyVersion": {
                    "PolicyId": "policy-222",
                    "VersionId": 0,
                    "PolicyDocument": json.dumps({
                        "version": "2.0",
                        "statement": [
                            {
                                "effect": "allow",
                                "action": [
                                    "cam:*",
                                    "sts:*",
                                    "cos:*",
                                ],
                                "resource": "*",
                            }
                        ],
                    }),
                }
            }
        }
    }


@pytest.fixture
def sample_policy_version_with_privesc():
    """Sample policy document with specific privesc permissions."""
    return {
        "Response": {
            "Data": {
                "PolicyVersion": {
                    "PolicyId": "policy-333",
                    "VersionId": 0,
                    "PolicyDocument": json.dumps({
                        "version": "2.0",
                        "statement": [
                            {
                                "effect": "allow",
                                "action": [
                                    "cam:AttachUserPolicy",
                                    "cam:CreateAccessKey",
                                    "cam:UpdateLoginProfile",
                                ],
                                "resource": "*",
                            }
                        ],
                    }),
                }
            }
        }
    }


@pytest.fixture
def sample_user_groups():
    """Sample response from ListGroupsForUser API."""
    return {
        "Response": {
            "Data": {
                "GroupInfo": [
                    {"GroupId": 2001, "GroupName": "Developers"},
                    {"GroupId": 2002, "GroupName": "Admins"},
                ]
            }
        }
    }


@pytest.fixture
def sample_attached_group_policies():
    """Sample response from ListAttachedGroupPolicies API."""
    return {
        "Response": {
            "Data": {
                "List": [
                    {
                        "PolicyId": "policy-333",
                        "PolicyName": "PrivescPolicy",
                        "AttachTime": "2024-01-01T00:00:00Z",
                    }
                ]
            }
        }
    }


# --------------------------------------------------------------------------- #
# Test 1: CredentialError raised when no credentials provided
# --------------------------------------------------------------------------- #

def test_credential_error_no_credentials():
    """Test that CamCredentialError is raised when no credentials are provided."""
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(CamCredentialError) as exc_info:
            CamPrivescAnalyzer()
        assert "CAM 凭证缺失" in str(exc_info.value)
        assert "TENCENTCLOUD_SECRET_ID" in str(exc_info.value)


# --------------------------------------------------------------------------- #
# Test 2: Analyzer initialized with constructor parameters
# --------------------------------------------------------------------------- #

def test_analyzer_init_with_params(mock_secret_id, mock_secret_key, mock_region):
    """Test that analyzer can be initialized with constructor parameters."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
        region=mock_region,
    )
    assert analyzer.secret_id == mock_secret_id
    assert analyzer.secret_key == mock_secret_key
    assert analyzer.region == mock_region


# --------------------------------------------------------------------------- #
# Test 3: Analyzer initialized from environment variables
# --------------------------------------------------------------------------- #

def test_analyzer_init_from_env(mock_secret_id, mock_secret_key):
    """Test that analyzer can be initialized from environment variables."""
    env = {
        "TENCENTCLOUD_SECRET_ID": mock_secret_id,
        "TENCENTCLOUD_SECRET_KEY": mock_secret_key,
    }
    with patch.dict("os.environ", env, clear=False):
        analyzer = CamPrivescAnalyzer()
        assert analyzer.secret_id == mock_secret_id
        assert analyzer.secret_key == mock_secret_key
        assert analyzer.region == "ap-guangzhou"  # default


# --------------------------------------------------------------------------- #
# Test 4: Environment variable fallback priority
# --------------------------------------------------------------------------- #

def test_env_variable_fallback_priority():
    """Test that environment variables are checked in the correct priority order."""
    # TENCENTCLOUD_SECRET_ID should be preferred over CAM_SECRET_ID
    env = {
        "CAM_SECRET_ID": "lower_priority_id",
        "TENCENTCLOUD_SECRET_ID": "higher_priority_id",
        "TENCENTCLOUD_SECRET_KEY": "secret_key",
    }
    with patch.dict("os.environ", env, clear=False):
        assert _first_env(("TENCENTCLOUD_SECRET_ID", "CAM_SECRET_ID")) == "higher_priority_id"


# --------------------------------------------------------------------------- #
# Test 5: List users API call
# --------------------------------------------------------------------------- #

def test_list_users(mock_secret_id, mock_secret_key, sample_user_list):
    """Test listing users via mocked API."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    with patch.object(analyzer, "_call_api", return_value=sample_user_list["Response"]) as mock_call:
        users = analyzer.list_users()
        mock_call.assert_called_once_with("ListUsers")
        assert len(users) == 2
        assert users[0]["Uin"] == 1001
        assert users[0]["Name"] == "dev-user"


# --------------------------------------------------------------------------- #
# Test 6: List groups API call
# --------------------------------------------------------------------------- #

def test_list_groups(mock_secret_id, mock_secret_key, sample_group_list):
    """Test listing groups via mocked API."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    with patch.object(analyzer, "_call_api", return_value=sample_group_list["Response"]) as mock_call:
        groups = analyzer.list_groups()
        mock_call.assert_called_once_with("ListGroups")
        assert len(groups) == 2
        assert groups[0]["GroupId"] == 2001
        assert groups[0]["GroupName"] == "Developers"


# --------------------------------------------------------------------------- #
# Test 7: List attached user policies API call
# --------------------------------------------------------------------------- #

def test_list_attached_user_policies(mock_secret_id, mock_secret_key, sample_attached_user_policies):
    """Test listing policies attached to a user."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    mock_ret = sample_attached_user_policies["Response"]
    with patch.object(analyzer, "_call_api", return_value=mock_ret) as mock_call:
        policies = analyzer.list_attached_user_policies(1001)
        mock_call.assert_called_once_with("ListAttachedUserPolicies", {"TargetUin": 1001})
        assert len(policies) == 1
        assert policies[0]["PolicyId"] == "policy-111"


# --------------------------------------------------------------------------- #
# Test 8: Get policy version API call
# --------------------------------------------------------------------------- #

def test_get_policy_version(mock_secret_id, mock_secret_key, sample_policy_version_readonly):
    """Test getting a policy version document."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    mock_ret = sample_policy_version_readonly["Response"]
    with patch.object(analyzer, "_call_api", return_value=mock_ret) as mock_call:
        policy_data = analyzer.get_policy_version("policy-111")
        mock_call.assert_called_once()
        call_args = mock_call.call_args
        assert call_args[0][0] == "GetPolicyVersion"
        assert call_args[0][1]["PolicyId"] == "policy-111"
        assert policy_data is not None
        assert "PolicyVersion" in policy_data


# --------------------------------------------------------------------------- #
# Test 9: Analyze with read-only user (no privesc findings)
# --------------------------------------------------------------------------- #

def test_analyze_readonly_user(
    mock_secret_id,
    mock_secret_key,
    sample_user_list,
    sample_attached_user_policies,
    sample_policy_version_readonly,
):
    """Test analysis of a read-only user produces no privesc findings."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    api_responses = {
        "ListUsers": sample_user_list["Response"],
        "ListAttachedUserPolicies": sample_attached_user_policies["Response"],
        "GetPolicyVersion": sample_policy_version_readonly["Response"],
    }
    
    def mock_api_call(action, params=None):
        if action == "ListUsers":
            return api_responses["ListUsers"]
        elif action == "ListAttachedUserPolicies":
            return api_responses["ListAttachedUserPolicies"]
        elif action == "GetPolicyVersion":
            return api_responses["GetPolicyVersion"]
        return {"Response": {"Data": {}}}
    
    with patch.object(analyzer, "_call_api", side_effect=mock_api_call):
        findings = analyzer.analyze()
    
    assert len(findings) == 0


# --------------------------------------------------------------------------- #
# Test 10: Analyze with admin user (wildcard permissions)
# --------------------------------------------------------------------------- #

def test_analyze_admin_user_wildcard(
    mock_secret_id,
    mock_secret_key,
    sample_user_list,
    sample_attached_user_policies,
    sample_policy_version_admin,
):
    """Test analysis of an admin user with wildcard permissions finds all privesc paths."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    # Modify attached policies to use admin policy
    admin_attached = {
        "Response": {
            "Data": {
                "List": [
                    {
                        "PolicyId": "policy-222",
                        "PolicyName": "AdminPolicy",
                        "AttachTime": "2024-01-01T00:00:00Z",
                    }
                ]
            }
        }
    }
    
    api_responses = {
        "ListUsers": sample_user_list["Response"],
        "ListAttachedUserPolicies": admin_attached["Response"],
        "GetPolicyVersion": sample_policy_version_admin["Response"],
    }
    
    def mock_api_call(action, params=None):
        if action == "ListUsers":
            return api_responses["ListUsers"]
        elif action == "ListAttachedUserPolicies":
            return api_responses["ListAttachedUserPolicies"]
        elif action == "GetPolicyVersion":
            return api_responses["GetPolicyVersion"]
        return {"Response": {"Data": {}}}
    
    with patch.object(analyzer, "_call_api", side_effect=mock_api_call):
        findings = analyzer.analyze()
    
    # Admin user with cam:* should trigger all privesc rules
    assert len(findings) > 0
    
    # Check that findings have correct structure
    for finding in findings:
        assert isinstance(finding, CamFinding)
        assert finding.cloud == "tencent"
        assert finding.service == "cam"
        assert finding.rule_id in [r.rule_id for r in PRIVESC_RULES]
        assert finding.severity in ("critical", "high", "medium")
        assert "entity_type" in finding.evidence
        assert "entity_name" in finding.evidence
        assert "matched_perms" in finding.evidence


# --------------------------------------------------------------------------- #
# Test 11: Analyze with specific privesc permissions
# --------------------------------------------------------------------------- #

def test_analyze_specific_privesc_permissions(
    mock_secret_id,
    mock_secret_key,
    sample_user_list,
    sample_policy_version_with_privesc,
):
    """Test analysis of a user with specific privesc permissions."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    # Attached policies with privesc permissions
    privesc_attached = {
        "Response": {
            "Data": {
                "List": [
                    {
                        "PolicyId": "policy-333",
                        "PolicyName": "PrivescPolicy",
                        "AttachTime": "2024-01-01T00:00:00Z",
                    }
                ]
            }
        }
    }
    
    api_responses = {
        "ListUsers": sample_user_list["Response"],
        "ListAttachedUserPolicies": privesc_attached["Response"],
        "GetPolicyVersion": sample_policy_version_with_privesc["Response"],
    }
    
    def mock_api_call(action, params=None):
        if action == "ListUsers":
            return api_responses["ListUsers"]
        elif action == "ListAttachedUserPolicies":
            return api_responses["ListAttachedUserPolicies"]
        elif action == "GetPolicyVersion":
            return api_responses["GetPolicyVersion"]
        return {"Response": {"Data": {}}}
    
    with patch.object(analyzer, "_call_api", side_effect=mock_api_call):
        findings = analyzer.analyze()
    
    # Should find privesc paths for AttachUserPolicy, CreateAccessKey, UpdateLoginProfile
    assert len(findings) >= 3
    
    rule_ids = {f.rule_id for f in findings}
    assert "cam:AttachUserPolicy" in rule_ids
    assert "cam:CreateAccessKey" in rule_ids
    assert "cam:UpdateLoginProfile" in rule_ids


# --------------------------------------------------------------------------- #
# Test 12: Evidence does not contain sensitive credential data
# --------------------------------------------------------------------------- #

def test_evidence_no_credential_leak(
    mock_secret_id,
    mock_secret_key,
    sample_user_list,
    sample_attached_user_policies,
    sample_policy_version_admin,
):
    """Test that findings evidence does not contain credential information."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    api_responses = {
        "ListUsers": sample_user_list["Response"],
        "ListAttachedUserPolicies": sample_attached_user_policies["Response"],
        "GetPolicyVersion": sample_policy_version_admin["Response"],
    }
    
    def mock_api_call(action, params=None):
        if action == "ListUsers":
            return api_responses["ListUsers"]
        elif action == "ListAttachedUserPolicies":
            return api_responses["ListAttachedUserPolicies"]
        elif action == "GetPolicyVersion":
            return api_responses["GetPolicyVersion"]
        return {"Response": {"Data": {}}}
    
    with patch.object(analyzer, "_call_api", side_effect=mock_api_call):
        findings = analyzer.analyze()
    
    for finding in findings:
        evidence_str = json.dumps(finding.evidence, default=str)
        assert mock_secret_id not in evidence_str
        assert mock_secret_key not in evidence_str
        assert "secret" not in evidence_str.lower()
        assert "password" not in evidence_str.lower()
        assert "token" not in evidence_str.lower()


# --------------------------------------------------------------------------- #
# Test 13: Group-level privesc analysis
# --------------------------------------------------------------------------- #

def test_analyze_group_level_privesc(
    mock_secret_id,
    mock_secret_key,
    sample_group_list,
    sample_attached_group_policies,
    sample_policy_version_with_privesc,
):
    """Test that group-level permissions are analyzed for privesc paths."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    api_responses = {
        "ListUsers": {"Response": {"Data": {"Users": []}}},  # No users
        "ListGroups": sample_group_list["Response"],
        "ListAttachedGroupPolicies": sample_attached_group_policies["Response"],
        "GetPolicyVersion": sample_policy_version_with_privesc["Response"],
    }
    
    def mock_api_call(action, params=None):
        if action == "ListUsers":
            return api_responses["ListUsers"]
        elif action == "ListGroups":
            return api_responses["ListGroups"]
        elif action == "ListAttachedGroupPolicies":
            return api_responses["ListAttachedGroupPolicies"]
        elif action == "GetPolicyVersion":
            return api_responses["GetPolicyVersion"]
        return {"Response": {"Data": {}}}
    
    with patch.object(analyzer, "_call_api", side_effect=mock_api_call):
        findings = analyzer.analyze()
    
    # Should find privesc paths at group level
    assert len(findings) >= 3
    
    # Check that findings are correctly attributed to groups
    for finding in findings:
        if finding.evidence.get("entity_type") == "group":
            assert finding.resource.startswith("group:")


# --------------------------------------------------------------------------- #
# Test 14: User inherits permissions from groups
# --------------------------------------------------------------------------- #

def test_user_inherits_group_permissions(
    mock_secret_id,
    mock_secret_key,
    sample_user_list,
    sample_user_groups,
    sample_attached_group_policies,
    sample_policy_version_with_privesc,
):
    """Test that users inherit permissions from their groups."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    api_responses = {
        "ListUsers": sample_user_list["Response"],
        "ListAttachedUserPolicies": {"Response": {"Data": {"List": []}}},  # No direct policies
        "ListGroupsForUser": sample_user_groups["Response"],
        "ListAttachedGroupPolicies": sample_attached_group_policies["Response"],
        "GetPolicyVersion": sample_policy_version_with_privesc["Response"],
    }
    
    def mock_api_call(action, params=None):
        if action == "ListUsers":
            return api_responses["ListUsers"]
        elif action == "ListAttachedUserPolicies":
            return api_responses["ListAttachedUserPolicies"]
        elif action == "ListGroupsForUser":
            return api_responses["ListGroupsForUser"]
        elif action == "ListAttachedGroupPolicies":
            return api_responses["ListAttachedGroupPolicies"]
        elif action == "GetPolicyVersion":
            return api_responses["GetPolicyVersion"]
        return {"Response": {"Data": {}}}
    
    with patch.object(analyzer, "_call_api", side_effect=mock_api_call):
        findings = analyzer.analyze()
    
    # User should have privesc paths inherited from group
    assert len(findings) >= 3


# --------------------------------------------------------------------------- #
# Test 15: Error handling - API failures don't crash analysis
# --------------------------------------------------------------------------- #

def test_api_error_handling_isolation(mock_secret_id, mock_secret_key):
    """Test that API errors are isolated and don't crash the entire analysis."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    call_count = {"count": 0}
    
    def mock_api_call(action, params=None):
        call_count["count"] += 1
        # First call (ListUsers) succeeds, second fails, third succeeds
        if call_count["count"] == 1:
            return {
                "Response": {
                    "Data": {
                        "Users": [
                            {"Uin": 1001, "Name": "user1"},
                            {"Uin": 1002, "Name": "user2"},
                        ]
                    }
                }
            }
        elif call_count["count"] == 2:
            # Simulate API error for user 1001
            raise Exception("API Error: AccessDenied")
        else:
            # Return empty for other calls
            return {"Response": {"Data": {"List": []}}}
    
    with patch.object(analyzer, "_call_api", side_effect=mock_api_call):
        findings = analyzer.analyze()
    
    # Should complete without crashing despite API errors
    assert isinstance(findings, list)
    # May have findings from user2 or empty, but should not raise


# --------------------------------------------------------------------------- #
# Test 16: PrivescRule matching with wildcard permissions
# --------------------------------------------------------------------------- #

def test_privesc_rule_wildcard_matching():
    """Test that PrivescRule.matches works with wildcard permissions."""
    rule = PrivescRule(
        rule_id="test-rule",
        required_perms=(("cam:AttachUserPolicy",),),
        description="Test rule",
        severity="high",
    )
    
    # Exact match
    assert rule.matches({"cam:attachuserpolicy"})
    
    # Wildcard match
    assert rule.matches({"cam:*"})
    
    # Global wildcard
    assert rule.matches({"*"})
    
    # No match
    assert not rule.matches({"cam:GetUser"})


# --------------------------------------------------------------------------- #
# Test 17: PrivescRule matching with multiple permission sets (OR logic)
# --------------------------------------------------------------------------- #

def test_privesc_rule_or_logic():
    """Test that PrivescRule.required_perms uses OR logic across sets."""
    rule = PrivescRule(
        rule_id="test-or-rule",
        required_perms=(
            ("cam:AttachUserPolicy",),  # Set 1
            ("cam:PassRole", "scf:CreateFunction"),  # Set 2
        ),
        description="Test OR logic",
        severity="high",
    )
    
    # Match first set
    assert rule.matches({"cam:attachuserpolicy"})
    
    # Match second set (both required)
    assert rule.matches({"cam:passrole", "scf:createfunction"})
    
    # Partial match on second set (should not match)
    assert not rule.matches({"cam:passrole"})
    
    # No match at all
    assert not rule.matches({"cam:getuser"})


# --------------------------------------------------------------------------- #
# Test 18: Extract allowed actions from policy document
# --------------------------------------------------------------------------- #

def test_extract_allowed_actions():
    """Test _extract_allowed_actions parses policy documents correctly."""
    # Simple policy
    policy = json.dumps({
        "version": "2.0",
        "statement": [
            {
                "effect": "allow",
                "action": "cam:GetUser",
                "resource": "*",
            }
        ],
    })
    actions = _extract_allowed_actions(policy)
    assert "cam:getuser" in actions
    
    # List of actions
    policy = json.dumps({
        "version": "2.0",
        "statement": [
            {
                "effect": "allow",
                "action": ["cam:GetUser", "cam:ListUsers", "cos:GetBucket"],
                "resource": "*",
            }
        ],
    })
    actions = _extract_allowed_actions(policy)
    assert "cam:getuser" in actions
    assert "cam:listusers" in actions
    assert "cos:getbucket" in actions
    
    # Deny statement should be ignored
    policy = json.dumps({
        "version": "2.0",
        "statement": [
            {
                "effect": "deny",
                "action": "cam:DeleteUser",
                "resource": "*",
            },
            {
                "effect": "allow",
                "action": "cam:GetUser",
                "resource": "*",
            },
        ],
    })
    actions = _extract_allowed_actions(policy)
    assert "cam:deleteuser" not in actions
    assert "cam:getuser" in actions
    
    # Invalid JSON returns empty set
    actions = _extract_allowed_actions("invalid json")
    assert actions == set()
    
    # Empty/None returns empty set
    actions = _extract_allowed_actions("")
    assert actions == set()
    actions = _extract_allowed_actions(None)  # type: ignore[arg-type]
    assert actions == set()


# --------------------------------------------------------------------------- #
# Test 19: Verify all required privesc paths are covered
# --------------------------------------------------------------------------- #

def test_all_required_privesc_paths_covered():
    """Test that all required privesc paths (AttachUserPolicy, CreateAccessKey, etc.) are covered."""
    rule_ids = {rule.rule_id for rule in PRIVESC_RULES}
    
    required_paths = [
        "cam:AttachUserPolicy",
        "cam:CreateAccessKey",
        "cam:PassRole",
        "cam:UpdateLoginProfile",
        "cam:AssumeRole",
    ]
    
    for path in required_paths:
        assert any(path in rule_id for rule_id in rule_ids), f"Missing privesc path: {path}"


# --------------------------------------------------------------------------- #
# Test 20: Verify CamFinding structure matches expected format
# --------------------------------------------------------------------------- #

def test_cam_finding_structure():
    """Test that CamFinding has all required fields."""
    finding = CamFinding(
        cloud="tencent",
        service="cam",
        rule_id="test-rule",
        resource="uin:1234",
        issue_type="test-issue",
        severity="high",
        description="Test finding",
        evidence={"test": "data"},
    )
    
    assert finding.cloud == "tencent"
    assert finding.service == "cam"
    assert finding.rule_id == "test-rule"
    assert finding.resource == "uin:1234"
    assert finding.issue_type == "test-issue"
    assert finding.severity == "high"
    assert finding.description == "Test finding"
    assert finding.evidence == {"test": "data"}
    assert finding.error is None
    
    # Test with error
    finding_with_error = CamFinding(error="Test error")
    assert finding_with_error.error == "Test error"


# --------------------------------------------------------------------------- #
# Test 21: Severity levels are valid
# --------------------------------------------------------------------------- #

def test_valid_severity_levels():
    """Test that all rules have valid severity levels."""
    valid_severities = {"critical", "high", "medium", "low", "info"}
    for rule in PRIVESC_RULES:
        assert rule.severity in valid_severities, f"Invalid severity: {rule.severity}"


# --------------------------------------------------------------------------- #
# Test 22: Finding severity matches rule severity
# --------------------------------------------------------------------------- #

def test_finding_severity_matches_rule(
    mock_secret_id,
    mock_secret_key,
    sample_user_list,
    sample_attached_user_policies,
    sample_policy_version_with_privesc,
):
    """Test that findings inherit severity from their matched rules."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    api_responses = {
        "ListUsers": sample_user_list["Response"],
        "ListAttachedUserPolicies": sample_attached_user_policies["Response"],
        "GetPolicyVersion": sample_policy_version_with_privesc["Response"],
    }
    
    def mock_api_call(action, params=None):
        if action == "ListUsers":
            return api_responses["ListUsers"]
        elif action == "ListAttachedUserPolicies":
            return api_responses["ListAttachedUserPolicies"]
        elif action == "GetPolicyVersion":
            return api_responses["GetPolicyVersion"]
        return {"Response": {"Data": {}}}
    
    with patch.object(analyzer, "_call_api", side_effect=mock_api_call):
        findings = analyzer.analyze()
    
    # Build a mapping of rule_id to expected severity
    rule_severity = {rule.rule_id: rule.severity for rule in PRIVESC_RULES}
    
    for finding in findings:
        expected_severity = rule_severity.get(finding.rule_id)
        if expected_severity:
            assert finding.severity == expected_severity, (
                f"Finding for {finding.rule_id} has severity {finding.severity}, "
                f"expected {expected_severity}"
            )


# --------------------------------------------------------------------------- #
# Test 23: Safe list helper handles exceptions
# --------------------------------------------------------------------------- #

def test_safe_list_handles_exceptions(mock_secret_id, mock_secret_key):
    """Test that _safe_list returns empty list on exceptions."""
    analyzer = CamPrivescAnalyzer(
        secret_id=mock_secret_id,
        secret_key=mock_secret_key,
    )
    
    # Function that raises an exception
    def failing_func():
        raise Exception("Test exception")
    
    result = analyzer._safe_list(failing_func)
    assert result == []
    
    # Function that returns a valid list
    def working_func():
        return [1, 2, 3]
    
    result = analyzer._safe_list(working_func)
    assert result == [1, 2, 3]
    
    # Function that returns non-list
    def non_list_func():
        return {"not": "a list"}
    
    result = analyzer._safe_list(non_list_func)
    assert result == []
