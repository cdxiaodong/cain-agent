"""CredRedactHook 凭证脱敏模块单元测试。

**严禁真实凭证**:全部使用构造的假串(LTAI + 重复 A、AKIA + 重复 X 等)。
覆盖:每类模式命中脱敏、同一凭证两次出现哈希一致、示例白名单不误伤、
短串不误伤、嵌套 dict 递归、hook 结构非法放行、hook 无内容放行。
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any

from cain_agent.redact import (
    REDACT_PATTERNS,
    CredRedactHook,
    redact,
    redact_dict,
)

# ── fake credential strings (NOT real — constructed for testing) ───────────

FAKE_ALIYUN_AK = "LTAI" + "A" * 20  # LTAI + 20 chars, well above 16-char floor
FAKE_AWS_AK = "AKIA" + "X" * 16  # AKIA + 16 chars
FAKE_AWS_SK = "A" * 40  # 40-char base64-style fake secret
FAKE_API_KEY = "sk-" + "B" * 30  # sk- + 30 chars
FAKE_JWT = "eyJ" + "X" * 30 + "." + "Y" * 30 + "." + "Z" * 30
FAKE_BEARER = "Bearer " + "T" * 30
FAKE_PASSWORD = "SuperSecretPass123456"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]


# ── pattern coverage ────────────────────────────────────────────────────────


class TestPatternCoverage:
    """每类模式命中后应被脱敏,且替换为正确格式的占位符。"""

    def test_aliyun_ak(self) -> None:
        text = f"key={FAKE_ALIYUN_AK} end"
        result = redact(text)
        assert FAKE_ALIYUN_AK not in result
        assert f"<REDACTED:aliyun_ak:{_hash(FAKE_ALIYUN_AK)}>" in result

    def test_aws_ak(self) -> None:
        text = f"using key {FAKE_AWS_AK} now"
        result = redact(text)
        assert FAKE_AWS_AK not in result
        assert f"<REDACTED:aws_ak:{_hash(FAKE_AWS_AK)}>" in result

    def test_aws_secret_key(self) -> None:
        text = f'aws_secret_access_key = "{FAKE_AWS_SK}"'
        result = redact(text)
        assert FAKE_AWS_SK not in result
        assert "REDACTED:aws_sk" in result

    def test_api_key_sk(self) -> None:
        text = f"Authorization: {FAKE_API_KEY}"
        result = redact(text)
        assert FAKE_API_KEY not in result
        assert f"<REDACTED:api_key:{_hash(FAKE_API_KEY)}>" in result

    def test_jwt_token(self) -> None:
        text = f"auth header has {FAKE_JWT} embedded"
        result = redact(text)
        assert FAKE_JWT not in result
        assert "REDACTED:jwt" in result

    def test_bearer_token(self) -> None:
        text = f"Auth: {FAKE_BEARER}"
        result = redact(text)
        assert FAKE_BEARER.split()[1] not in result
        assert "REDACTED:bearer" in result
        # Bearer prefix should be preserved.
        assert "Bearer " in result

    def test_pem_private_key(self) -> None:
        fake_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA" + "A" * 200 + "\n"
            "-----END RSA PRIVATE KEY-----"
        )
        text = f"cert: {fake_key}"
        result = redact(text)
        assert "BEGIN RSA PRIVATE KEY" not in result
        assert "END RSA PRIVATE KEY" not in result
        assert "REDACTED:pem_private_key" in result

    def test_password_pair(self) -> None:
        text = f"password={FAKE_PASSWORD}"
        result = redact(text)
        assert FAKE_PASSWORD not in result
        assert "REDACTED:password" in result

    def test_secret_colon_pair(self) -> None:
        text = f"secret: {FAKE_PASSWORD}"
        result = redact(text)
        assert FAKE_PASSWORD not in result
        assert "REDACTED:password" in result

    def test_token_equals_pair(self) -> None:
        text = f"token={FAKE_PASSWORD}"
        result = redact(text)
        assert FAKE_PASSWORD not in result
        assert "REDACTED:password" in result


# ── hash consistency ────────────────────────────────────────────────────────


class TestHashConsistency:
    """同一凭证两次出现 → 哈希一致(可关联审计)。"""

    def test_same_credential_same_hash(self) -> None:
        text1 = f"first={FAKE_ALIYUN_AK}"
        text2 = f"second={FAKE_ALIYUN_AK}"
        r1 = redact(text1)
        r2 = redact(text2)
        h = _hash(FAKE_ALIYUN_AK)
        assert f"<REDACTED:aliyun_ak:{h}>" in r1
        assert f"<REDACTED:aliyun_ak:{h}>" in r2
        # The placeholder appears identically in both.
        placeholder = f"<REDACTED:aliyun_ak:{h}>"
        assert placeholder in r1 and placeholder in r2

    def test_different_credentials_different_hash(self) -> None:
        other_ak = "LTAI" + "B" * 20
        text = f"a={FAKE_ALIYUN_AK} b={other_ak}"
        result = redact(text)
        h1 = _hash(FAKE_ALIYUN_AK)
        h2 = _hash(other_ak)
        assert f"<REDACTED:aliyun_ak:{h1}>" in result
        assert f"<REDACTED:aliyun_ak:{h2}>" in result
        assert h1 != h2


# ── whitelist / false-positive control ──────────────────────────────────────


class TestWhitelist:
    """文档示例串不脱敏。"""

    def test_aws_example_not_redacted(self) -> None:
        text = "see AKIAIOSFODNN7EXAMPLE in docs"
        result = redact(text)
        assert "AKIAIOSFODNN7EXAMPLE" in result
        assert "REDACTED" not in result

    def test_aws_example_ak_whitelisted(self) -> None:
        """AWS doc example AK IDs are whitelisted; secret keys are not."""
        text = "access_key_id = AKIAIOSFODNN7EXAMPLE"
        result = redact(text)
        assert "AKIAIOSFODNN7EXAMPLE" in result
        assert "REDACTED:aws_ak" not in result


# ── short token protection ──────────────────────────────────────────────────


class TestShortToken:
    """短于 16 位的疑似命中不脱敏。"""

    def test_short_aliyun_ak_not_redacted(self) -> None:
        short = "LTAI" + "A" * 5  # only 9 chars total
        text = f"found {short} here"
        result = redact(text)
        assert short in result
        assert "REDACTED" not in result

    def test_short_password_not_redacted(self) -> None:
        text = "password=abc"  # too short
        result = redact(text)
        assert "password=abc" in result
        assert "REDACTED" not in result


# ── clean text passthrough ──────────────────────────────────────────────────


class TestCleanText:
    """无凭证的文本原样返回。"""

    def test_normal_text_unchanged(self) -> None:
        text = "This is a normal log line with no credentials."
        assert redact(text) == text

    def test_empty_string(self) -> None:
        assert redact("") == ""

    def test_non_string_passthrough(self) -> None:
        assert redact(42) == 42  # type: ignore[arg-type]
        assert redact(None) is None  # type: ignore[arg-type]


# ── redact_dict recursive ───────────────────────────────────────────────────


class TestRedactDict:
    """嵌套 dict/list/str 结构递归脱敏。"""

    def test_nested_dict(self) -> None:
        data = {
            "user": "admin",
            "config": {
                "ak": FAKE_ALIYUN_AK,
                "nested": [FAKE_AWS_AK, "clean"],
            },
        }
        result = redact_dict(data)
        assert isinstance(result, dict)
        assert FAKE_ALIYUN_AK not in str(result)
        assert FAKE_AWS_AK not in str(result)
        assert "REDACTED" in str(result)
        assert result["user"] == "admin"
        assert result["config"]["nested"][1] == "clean"

    def test_list_of_strings(self) -> None:
        data = [FAKE_ALIYUN_AK, "normal", f"key={FAKE_API_KEY}"]
        result = redact_dict(data)
        assert isinstance(result, list)
        assert len(result) == 3
        assert FAKE_ALIYUN_AK not in result[0]
        assert result[1] == "normal"
        assert FAKE_API_KEY not in result[2]

    def test_tuple_preserved(self) -> None:
        data = (FAKE_ALIYUN_AK, "clean")
        result = redact_dict(data)
        assert isinstance(result, tuple)
        assert FAKE_ALIYUN_AK not in result[0]
        assert result[1] == "clean"

    def test_non_dict_passthrough(self) -> None:
        assert redact_dict(42) == 42
        assert redact_dict(True) is True

    def test_no_mutation(self) -> None:
        """redact_dict 不修改原始输入。"""
        data = {"ak": FAKE_ALIYUN_AK}
        original_str = data["ak"]
        _ = redact_dict(data)
        assert data["ak"] == original_str  # unchanged

    def test_empty_structures(self) -> None:
        assert redact_dict({}) == {}
        assert redact_dict([]) == []


# ── CredRedactHook ──────────────────────────────────────────────────────────


class TestCredRedactHook:
    """PostToolUse hook:工具输出脱敏。"""

    def test_hook_redacts_tool_output(self) -> None:
        hook = CredRedactHook()
        input_data: dict[str, Any] = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "env"},
            "tool_response": {"stdout": f"AK={FAKE_ALIYUN_AK}"},
            "tool_use_id": "tool_123",
        }
        result = asyncio.run(hook(input_data, "tool_123", None))
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        updated = result["hookSpecificOutput"]["updatedToolOutput"]
        assert FAKE_ALIYUN_AK not in str(updated)
        assert "REDACTED" in str(updated)

    def test_hook_passthrough_clean_output(self) -> None:
        """工具输出无凭证 → 空字典放行。"""
        hook = CredRedactHook()
        input_data = {
            "tool_name": "Bash",
            "tool_response": {"stdout": "all clean here"},
        }
        result = asyncio.run(hook(input_data, "t1", None))
        assert result == {}

    def test_hook_malformed_input_passthrough(self) -> None:
        """结构非法的输入原样放行不炸。"""
        hook = CredRedactHook()
        # Non-mapping input.
        result = asyncio.run(hook("not a dict", "t1", None))  # type: ignore[arg-type]
        assert result == {}

        # Missing tool_response.
        result2 = asyncio.run(hook({"tool_name": "Bash"}, "t1", None))
        assert result2 == {}

    def test_hook_none_tool_response(self) -> None:
        """tool_response 为 None → 放行。"""
        hook = CredRedactHook()
        result = asyncio.run(hook({"tool_response": None}, "t1", None))
        assert result == {}

    def test_hook_redacts_string_response(self) -> None:
        """tool_response 是纯字符串 → 脱敏后返回。"""
        hook = CredRedactHook()
        input_data = {
            "tool_response": f"found {FAKE_API_KEY} in logs",
        }
        result = asyncio.run(hook(input_data, "t1", None))
        assert "hookSpecificOutput" in result
        updated = result["hookSpecificOutput"]["updatedToolOutput"]
        assert FAKE_API_KEY not in updated
        assert "REDACTED:api_key" in updated

    def test_hook_multiple_credential_types(self) -> None:
        """一次输出含多种凭证类型 → 全部脱敏。"""
        hook = CredRedactHook()
        input_data = {
            "tool_response": {
                "stdout": f"ak={FAKE_ALIYUN_AK} key={FAKE_AWS_AK} jwt {FAKE_JWT}",
            },
        }
        result = asyncio.run(hook(input_data, "t1", None))
        updated = str(result["hookSpecificOutput"]["updatedToolOutput"])
        assert FAKE_ALIYUN_AK not in updated
        assert FAKE_AWS_AK not in updated
        assert FAKE_JWT not in updated
        assert updated.count("REDACTED") >= 3


# ── pattern table structure ─────────────────────────────────────────────────


class TestPatternTable:
    """REDACT_PATTERNS 是代码常量且至少覆盖 6 类模式。"""

    def test_at_least_six_patterns(self) -> None:
        assert len(REDACT_PATTERNS) >= 6

    def test_each_has_name_and_regex(self) -> None:
        for p in REDACT_PATTERNS:
            assert isinstance(p.name, str) and p.name
            assert p.regex is not None

    def test_pattern_names_cover_required_types(self) -> None:
        names = {p.name for p in REDACT_PATTERNS}
        assert "aliyun_ak" in names
        assert "aws_ak" in names
        assert "api_key" in names
        assert "jwt" in names
        assert "pem_private_key" in names
        assert "password" in names
