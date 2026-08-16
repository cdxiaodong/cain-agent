"""Tests for the scope guard: matching semantics, Bash target extraction, and
the PreToolUse hook. Async hook calls are driven with asyncio.run to avoid
pulling in pytest-asyncio as a dependency.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from cain_agent.scope import Scope, ScopeConfigError, ScopeGuardHook

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_SCOPE = REPO_ROOT / "templates" / "scope.example.yaml"


def _hook_decision(
    scope: Scope, tool_name: str, tool_input: dict[str, object]
) -> dict[str, object]:
    """Invoke the hook synchronously and return its decision dict."""
    hook = ScopeGuardHook(scope)
    return asyncio.run(hook({"tool_name": tool_name, "tool_input": tool_input}, "tu-1", None))


def _is_deny(decision: dict[str, object]) -> bool:
    out = decision.get("hookSpecificOutput")
    return isinstance(out, dict) and out.get("permissionDecision") == "deny"


# --- wildcard domain matching -------------------------------------------------
def test_wildcard_matches_strict_subdomains() -> None:
    scope = Scope(in_scope=["*.example.com"], out_of_scope=[])
    assert scope.is_allowed("a.example.com")
    assert scope.is_allowed("x.y.example.com")
    # the apex itself never matches a *.wildcard entry
    assert not scope.is_allowed("example.com")
    # and an unrelated domain is denied (default-deny)
    assert not scope.is_allowed("example.org")


def test_bare_domain_matches_itself_and_subdomains() -> None:
    scope = Scope(in_scope=["example.com"], out_of_scope=[])
    assert scope.is_allowed("example.com")
    assert scope.is_allowed("sub.example.com")
    assert scope.is_allowed("deep.sub.example.com")
    # a domain that merely ends with the same letters is not a match
    assert not scope.is_allowed("notexample.com")
    assert not scope.is_allowed("evilexample.com")


# --- CIDR containment ---------------------------------------------------------
def test_cidr_containment() -> None:
    scope = Scope(in_scope=["10.0.0.0/24"], out_of_scope=[])
    assert scope.is_allowed("10.0.0.1")
    assert scope.is_allowed("10.0.0.254")
    assert not scope.is_allowed("10.0.1.1")
    assert not scope.is_allowed("10.1.0.0/24")  # adjacent, not contained


def test_bare_ip_is_slash32() -> None:
    scope = Scope(in_scope=["10.1.2.3"], out_of_scope=[])
    assert scope.is_allowed("10.1.2.3")
    assert not scope.is_allowed("10.1.2.4")


def test_cidr_out_of_scope_overlap_denies() -> None:
    # out_of_scope /25 sits inside the allowed /24; any overlap blocks the host.
    scope = Scope(in_scope=["10.0.0.0/24"], out_of_scope=["10.0.0.128/25"])
    assert scope.is_allowed("10.0.0.5")
    assert not scope.is_allowed("10.0.0.200")
    # a scanned /24 that overlaps the excluded /25 is denied outright (conservative)
    assert not scope.is_allowed("10.0.0.0/24")


# --- deny priority ------------------------------------------------------------
def test_deny_priority_over_broader_allow() -> None:
    scope = Scope(in_scope=["example.com"], out_of_scope=["evil.example.com"])
    assert not scope.is_allowed("evil.example.com")
    assert scope.is_allowed("good.example.com")
    assert scope.is_allowed("example.com")


def test_deny_priority_ipv6_overlap() -> None:
    scope = Scope(in_scope=["2001:db8::/32"], out_of_scope=["2001:db8:dead::/48"])
    assert not scope.is_allowed("2001:db8:dead::1")
    assert scope.is_allowed("2001:db8:1::1")


# --- default deny -------------------------------------------------------------
def test_empty_scope_denies_everything() -> None:
    scope = Scope(in_scope=[], out_of_scope=[])
    assert not scope.is_allowed("example.com")
    assert not scope.is_allowed("10.0.0.1")
    assert not scope.is_allowed("https://example.com/")


def test_unlisted_target_is_denied() -> None:
    scope = Scope(in_scope=["example.com"], out_of_scope=[])
    assert not scope.is_allowed("attacker.com")


# --- normalization: URLs, host:port, userinfo, IPv6 --------------------------
def test_url_and_port_normalization() -> None:
    scope = Scope(in_scope=["example.com"], out_of_scope=[])
    assert scope.is_allowed("https://example.com/path?q=1")
    assert scope.is_allowed("http://example.com:8080/")
    assert scope.is_allowed("example.com:443")


def test_userinfo_stripped() -> None:
    scope = Scope(in_scope=["git.example.com"], out_of_scope=[])
    assert scope.is_allowed("https://user:pass@git.example.com:8443/repo")


def test_ipv6_literal_handling() -> None:
    scope = Scope(in_scope=["2001:db8::1"], out_of_scope=[])
    assert scope.is_allowed("[2001:db8::1]:443")
    assert scope.is_allowed("2001:db8::1")
    assert not scope.is_allowed("[2001:db8::2]")


# --- Bash target extraction ---------------------------------------------------
def test_extract_curl_url() -> None:
    scope = Scope(in_scope=[], out_of_scope=[])
    assert scope.extract_targets("Bash", {"command": "curl -s https://example.com/api"}) == [
        "https://example.com/api"
    ]


def test_extract_nmap_cidr() -> None:
    scope = Scope(in_scope=[], out_of_scope=[])
    assert scope.extract_targets("Bash", {"command": "nmap -sV -p 80 10.0.0.0/24"}) == [
        "10.0.0.0/24"
    ]


def test_extract_direct_url_only() -> None:
    scope = Scope(in_scope=[], out_of_scope=[])
    assert scope.extract_targets("Bash", {"command": "echo see https://example.com/x"}) == [
        "https://example.com/x"
    ]


def test_extract_value_flag_value_is_not_a_target() -> None:
    scope = Scope(in_scope=[], out_of_scope=[])
    # -o consumes out.html; only the real URL is a target
    targets = scope.extract_targets("Bash", {"command": "curl -o out.html https://example.com"})
    assert targets == ["https://example.com"]
    assert "out.html" not in targets


def test_extract_nmap_port_not_a_target() -> None:
    scope = Scope(in_scope=[], out_of_scope=[])
    targets = scope.extract_targets("Bash", {"command": "nmap -p 1-1000 10.0.0.5"})
    assert targets == ["10.0.0.5"]


def test_extract_host_header_override() -> None:
    scope = Scope(in_scope=[], out_of_scope=[])
    cmd = 'curl -H "Host: internal.example.com" http://10.0.0.1/'
    targets = scope.extract_targets("Bash", {"command": cmd})
    # both the URL host and the overridden Host header are captured
    assert "http://10.0.0.1/" in targets
    assert "internal.example.com" in targets


def test_extract_curl_http_method_is_not_target() -> None:
    scope = Scope(in_scope=["103.236.66.228"], out_of_scope=[])
    command = (
        'curl -s -i --max-time 10 -X POST '
        '"http://103.236.66.228:3333/api/wishes" '
        "-H 'Content-Type: application/json' -d '{\"name\":\"probe\"}'"
    )
    targets = scope.extract_targets("Bash", {"command": command})
    assert targets == ["http://103.236.66.228:3333/api/wishes"]
    assert scope.is_allowed(targets[0])


def test_extract_curl_request_target_is_not_target() -> None:
    scope = Scope(in_scope=["103.236.66.228"], out_of_scope=[])
    command = (
        "curl --request-target /api/wishes -X POST "
        '"http://103.236.66.228:3333/api/wishes"'
    )
    targets = scope.extract_targets("Bash", {"command": command})
    assert targets == ["http://103.236.66.228:3333/api/wishes"]


def test_extract_multiple_subcommands() -> None:
    scope = Scope(in_scope=[], out_of_scope=[])
    targets = scope.extract_targets(
        "Bash", {"command": "nmap 10.0.0.0/24 && curl https://example.com"}
    )
    assert set(targets) == {"10.0.0.0/24", "https://example.com"}


def test_extract_wget() -> None:
    scope = Scope(in_scope=[], out_of_scope=[])
    targets = scope.extract_targets("Bash", {"command": "wget -O page.html http://example.com/"})
    assert targets == ["http://example.com/"]


# --- non-Bash extraction ------------------------------------------------------
def test_extract_non_bash_scalar_fields() -> None:
    scope = Scope(in_scope=[], out_of_scope=[])
    assert scope.extract_targets("WebFetch", {"url": "https://example.com"}) == [
        "https://example.com"
    ]
    assert scope.extract_targets("Custom", {"host": "example.com"}) == ["example.com"]
    assert scope.extract_targets("Custom", {"ip": "10.0.0.1"}) == ["10.0.0.1"]


def test_extract_non_bash_list_field() -> None:
    scope = Scope(in_scope=[], out_of_scope=[])
    assert scope.extract_targets("Custom", {"host": ["a.example.com", "b.example.com"]}) == [
        "a.example.com",
        "b.example.com",
    ]


# --- hook behavior ------------------------------------------------------------
def test_hook_bash_extraction_failure_blocks() -> None:
    # A Bash command with no recognizable target host is blocked outright.
    scope = Scope(in_scope=["example.com"], out_of_scope=[])
    for cmd in ("ls -la", "echo hello world", "cat /etc/passwd"):
        decision = _hook_decision(scope, "Bash", {"command": cmd})
        assert _is_deny(decision), cmd
        reason = decision["hookSpecificOutput"]["permissionDecisionReason"]  # type: ignore[index]
        assert isinstance(reason, str) and reason


def test_hook_non_bash_without_target_passes_through() -> None:
    scope = Scope(in_scope=["example.com"], out_of_scope=[])
    decision = _hook_decision(scope, "Read", {"file_path": "/etc/passwd"})
    assert decision == {}


def test_hook_allows_in_scope_bash() -> None:
    scope = Scope(in_scope=["example.com"], out_of_scope=[])
    decision = _hook_decision(scope, "Bash", {"command": "curl https://example.com/"})
    assert decision == {}


def test_hook_denies_out_of_scope_bash() -> None:
    scope = Scope(in_scope=["example.com"], out_of_scope=[])
    decision = _hook_decision(scope, "Bash", {"command": "curl https://attacker.com/"})
    assert _is_deny(decision)


def test_hook_denies_if_any_target_out_of_scope() -> None:
    scope = Scope(in_scope=["example.com"], out_of_scope=[])
    # one allowed + one disallowed target -> whole call denied
    decision = _hook_decision(
        scope, "Bash", {"command": "nscan example.com && curl https://attacker.com/"}
    )
    # 'nscan' is not permissive so 'example.com' may or may not extract, but the
    # URL definitely does and is out of scope, so the decision must be a deny.
    assert _is_deny(decision)


def test_hook_allows_all_in_scope_multi() -> None:
    scope = Scope(in_scope=["example.com", "10.0.0.0/24"], out_of_scope=[])
    decision = _hook_decision(
        scope, "Bash", {"command": "curl https://example.com/ && nmap 10.0.0.5"}
    )
    assert decision == {}


def test_hook_non_bash_in_scope_allowed() -> None:
    scope = Scope(in_scope=["example.com"], out_of_scope=[])
    decision = _hook_decision(scope, "WebFetch", {"url": "https://example.com/"})
    assert decision == {}


def test_hook_non_bash_out_of_scope_denied() -> None:
    scope = Scope(in_scope=["example.com"], out_of_scope=[])
    decision = _hook_decision(scope, "WebFetch", {"url": "https://attacker.com/"})
    assert _is_deny(decision)


# --- loading & validation -----------------------------------------------------
def test_from_file_loads_example_template() -> None:
    scope = Scope.from_file(EXAMPLE_SCOPE)
    assert "app.target-corp.com" in scope.in_plain
    assert "api.target-corp.com" in scope.in_wild
    assert len(scope.in_nets) == 3
    # admin backend is explicitly out of scope -> denied even though parent is allowed
    assert not scope.is_allowed("admin.app.target-corp.com")
    assert scope.is_allowed("app.target-corp.com")


def test_from_dict_defaults_empty() -> None:
    scope = Scope.from_dict({})
    assert scope.in_plain == [] and scope.out_plain == []
    assert not scope.is_allowed("example.com")


@pytest.mark.parametrize(
    "data",
    [
        "not a mapping",
        {"in_scope": "example.com"},          # string instead of list
        {"in_scope": [""]},                    # empty entry
        {"in_scope": [" example.com"]},        # leading whitespace
        {"in_scope": ["exa mple.com"]},        # embedded whitespace
        {"in_scope": ["example com"]},         # illegal domain
        {"in_scope": ["*example.com"]},        # malformed wildcard
        {"in_scope": [123]},                   # non-string entry
    ],
)
def test_invalid_config_raises(data: object) -> None:
    with pytest.raises(ScopeConfigError):
        Scope.from_dict(data)  # type: ignore[arg-type]


# --- regression: bare-host in_scope must match host:port request targets ------
# Bug context: a smoke run stored the bare IP ``103.236.66.228`` in in_scope but
# the agent requested ``103.236.66.228:3333``; the default-deny posture then
# blocked every probe and the test phase reported zero findings. These cases pin
# the host-extraction normalization so a port/scheme suffix can never split an
# otherwise in-scope target away from its whitelist entry.
def test_ip_scope_entry_matches_port_request() -> None:
    scope = Scope(in_scope=["103.236.66.228"], out_of_scope=[])
    assert scope.is_allowed("103.236.66.228:3333")
    assert scope.is_allowed("http://103.236.66.228:3333/")
    assert scope.is_allowed("http://103.236.66.228:3333/upload")


def test_domain_scope_entry_matches_port_request() -> None:
    scope = Scope(in_scope=["example.com"], out_of_scope=[])
    assert scope.is_allowed("example.com:8080")
    assert scope.is_allowed("https://example.com:8443/a?b=1")
    assert scope.is_allowed("sub.example.com:9000")


def test_ipv6_scope_entry_matches_bracketed_port_request() -> None:
    scope = Scope(in_scope=["::1"], out_of_scope=[])
    assert scope.is_allowed("[::1]:8080")
    assert scope.is_allowed("http://[::1]:9000/x")


def test_port_request_still_denied_when_host_out_of_scope() -> None:
    # Port stripping must not widen scope: a different host stays denied.
    scope = Scope(in_scope=["103.236.66.228"], out_of_scope=[])
    assert not scope.is_allowed("103.236.66.229:3333")
    assert not scope.is_allowed("http://evil.com:3333/")


def test_hook_allows_curl_against_port_target() -> None:
    # End-to-end through the PreToolUse hook: the exact shape of the smoke probe
    # that was previously denied.
    scope = Scope(in_scope=["103.236.66.228"], out_of_scope=[])
    for cmd in (
        "curl -s http://103.236.66.228:3333/",
        'curl -s http://103.236.66.228:3333/upload -F "file=@x.png"',
        "curl http://103.236.66.228:3333/api",
    ):
        decision = _hook_decision(scope, "Bash", {"command": cmd})
        assert not _is_deny(decision), cmd
