"""Credential redaction — second-line security defense hook.

DESIGN §3.2: all text that is persisted or enters the agent context (logs,
tool output, reports, findings) must be scrubbed of credential-style strings
beforehand. AK/SK, API keys, tokens, PEM private keys, and inline password
pairs are matched against a hardcoded pattern table and replaced with
``<REDACTED:type:sha256[:8]>`` — auditable and traceable (the same credential
always hashes to the same placeholder), but never exposing the plaintext.

The pattern table (``REDACT_PATTERNS``) is a tuple of ``RedactPattern`` code
constants, each with a name, compiled regex, and optional example whitelist.
False-positive control:

- Tokens shorter than 16 chars are left alone (avoids mangling ordinary text).
- Known documentation example strings (e.g. ``AKIAIOSFODNN7EXAMPLE``) are
  whitelisted and never redacted.

``CredRedactHook`` matches the Claude Agent SDK ``PostToolUse`` hook contract
and scrubs tool output text. ``redact_dict`` recursively scrubs nested
dict/list/str structures for findings JSON and reports.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

__all__ = [
    "CredRedactHook",
    "REDACT_PATTERNS",
    "RedactPattern",
    "redact",
    "redact_dict",
]

# Minimum credential-token length to be considered real (not a false positive).
_MIN_TOKEN_LEN = 16

# Maximum number of consecutive same-type redactions before switching to a
# generic placeholder — prevents pathological regex blowup on adversarial input.
_PLACEHOLDER_TEMPLATE = "<REDACTED:{type}:{hash}>"


def _short_hash(token: str) -> str:
    """First 8 hex chars of sha256(token), for auditable yet non-reversible placeholders."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]


class RedactPattern:
    """A credential-detection pattern (code constant).

    Attributes
    ----------
    name : str
        Short type label placed in the redaction placeholder (e.g. ``aliyun_ak``).
    regex : re.Pattern[str]
        Compiled regex with a single capturing group selecting the credential
        token.
    examples : frozenset[str]
        Known documentation/placeholder strings that must NOT be redacted
        (whitelist).
    """

    __slots__ = ("name", "regex", "examples")

    def __init__(self, name: str, pattern: str, examples: frozenset[str] | None = None) -> None:
        self.name = name
        self.regex = re.compile(pattern)
        self.examples = examples or frozenset()


# --------------------------------------------------------------------------- #
# Pattern table — code constants, not model output.
# --------------------------------------------------------------------------- #

# AWS well-known documentation examples (never redact).
_AWS_EXAMPLES = frozenset({
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "ASIAIOSFODNN7EXAMPLE",
    "ASIAJEXAMPLE",
})

REDACT_PATTERNS: tuple[RedactPattern, ...] = (
    # --- Aliyun AccessKey ID (LTAI prefix) ---
    RedactPattern(
        name="aliyun_ak",
        pattern=r"(LTAI[0-9A-Za-z]{12,})",
    ),
    # --- AWS AccessKey ID (AKIA / ASIA prefix, 16 chars total) ---
    RedactPattern(
        name="aws_ak",
        pattern=r"\b((?:AKIA|ASIA)[0-9A-Z]{8,})\b",
        examples=_AWS_EXAMPLES,
    ),
    # --- AWS Secret Access Key (40-char base64 after known-key pattern) ---
    # Only matches when preceded by "secret" context to reduce false positives.
    RedactPattern(
        name="aws_sk",
        pattern=r"(?i)(?:secret[_\-\s]?(?:access[_\-\s]?)?key|aws_secret)[:\s=\"]+\s*([A-Za-z0-9/+=]{40})\b",
    ),
    # --- OpenAI / generic sk- API key ---
    RedactPattern(
        name="api_key",
        pattern=r"\b(sk-[A-Za-z0-9]{20,})\b",
        examples=frozenset({"sk-XXXXXXXXXXXXXXXXXXXX", "sk-1234567890abcdefghijklmnop"}),
    ),
    # --- JWT tokens (eyJ header prefix) ---
    RedactPattern(
        name="jwt",
        pattern=r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
    ),
    # --- Bearer tokens ---
    RedactPattern(
        name="bearer",
        pattern=r"(?i)(Bearer\s+)([A-Za-z0-9_\-\.=]{20,})\b",
    ),
    # --- PEM private key blocks ---
    RedactPattern(
        name="pem_private_key",
        pattern=r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
                r"[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)",
    ),
    # --- Inline password= / secret: key-value pairs ---
    RedactPattern(
        name="password",
        pattern=r"(?i)((?:password|passwd|secret|token|api[_\-\s]?key)"
                r"[:\s=]+)([^\s\"',;]{8,})",
    ),
)


def _replace_match(pattern: RedactPattern, match: re.Match[str]) -> str:
    """Build the replacement string for a single pattern match.

    Pattern group conventions:
    - ``bearer``: group 1 = prefix (``Bearer ``), group 2 = token.
    - ``password``: group 1 = key prefix (``secret: ``), group 2 = token.
    - ``pem_private_key``: group 0 = entire PEM block.
    - all others: group 1 = the credential token.
    """
    if pattern.name in ("bearer", "password"):
        prefix = match.group(1)
        token = match.group(2)
        return prefix + _make_placeholder(pattern.name, token)
    elif pattern.name == "pem_private_key":
        full_block = match.group(0)
        return _make_placeholder(pattern.name, full_block)
    else:
        token = match.group(1)
        return _make_placeholder(pattern.name, token, match, pattern)


def redact(text: str) -> str:
    """Redact credential-style strings from *text*.

    Each match is replaced with ``<REDACTED:type:sha256[:8]>``. The same
    credential string always produces the same hash, enabling correlation
    across logs without exposing the plaintext.

    False-positive control:
    - Tokens shorter than ``_MIN_TOKEN_LEN`` (16) are left as-is.
    - Whitelisted documentation examples are skipped.
    """
    if not isinstance(text, str):
        return text  # non-string input: pass through unchanged

    result = text
    for pattern in REDACT_PATTERNS:
        result = pattern.regex.sub(
            lambda m, p=pattern: _replace_match(p, m), result
        )

    return result


def _make_placeholder(
    ptype: str,
    token: str,
    match: re.Match[str] | None = None,
    pattern: RedactPattern | None = None,
) -> str:
    """Build a redaction placeholder, or return the original match if it's a false positive."""
    # Length check: too short to be a real credential.
    if len(token) < _MIN_TOKEN_LEN:
        # Return the full matched text if available, else the token itself.
        if match is not None:
            return match.group(0)
        return token

    # Whitelist check: documentation examples.
    if pattern is not None and token in pattern.examples:
        if match is not None:
            return match.group(0)
        return token

    return _PLACEHOLDER_TEMPLATE.format(type=ptype, hash=_short_hash(token))


def redact_dict(data: Any) -> Any:
    """Recursively redact credential strings in a dict/list/str structure.

    Returns a new structure with the same shape; the input is never mutated.
    """
    if isinstance(data, str):
        return redact(data)
    if isinstance(data, dict):
        return {k: redact_dict(v) for k, v in data.items()}
    if isinstance(data, list):
        return [redact_dict(item) for item in data]
    if isinstance(data, tuple):
        return tuple(redact_dict(item) for item in data)
    return data


# --------------------------------------------------------------------------- #
# PostToolUse hook
# --------------------------------------------------------------------------- #


class CredRedactHook:
    """PostToolUse hook: scrubs credential strings from tool output.

    Matches the Claude Agent SDK ``HookCallback`` contract:
    ``async (input_data, tool_use_id, context) -> dict[str, Any]``.

    The hook inspects ``tool_response`` in the input, runs ``redact`` on any
    string content, and returns an ``updatedToolOutput`` with the scrubbed
    text. If the input structure is malformed or contains no scrubable text,
    the hook returns an empty dict (pass-through) rather than raising.
    """

    async def __call__(
        self,
        input_data: Mapping[str, Any],
        tool_use_id: str | None = None,
        context: Any = None,
    ) -> dict[str, Any]:
        if not isinstance(input_data, Mapping):
            return {}

        tool_response = input_data.get("tool_response")
        if tool_response is None:
            return {}

        scrubbed = redact_dict(tool_response)
        if scrubbed == tool_response:
            # Nothing changed: pass through without wrapping.
            return {}

        return {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": scrubbed,
            }
        }
