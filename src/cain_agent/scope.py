"""Scope guard: YAML-loaded allow/deny lists plus a PreToolUse hook.

The scope is the security foundation of the platform: whether a target is
authorized is enforced by engineering here, not left to the agent's own
judgement. ``Scope`` loads ``in_scope`` / ``out_of_scope`` from YAML, validates
every entry, and answers authorization questions with a default-deny
(whitelist) posture. ``ScopeGuardHook`` plugs into the Claude Agent SDK
PreToolUse event and blocks any tool call whose target falls outside scope.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

__all__ = ["Scope", "ScopeConfigError", "ScopeGuardHook"]

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# --- validation regexes ------------------------------------------------------
_DOMAIN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?")
_WILDCARD_RE = re.compile(r"\*\.([A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?)")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_CIDR_TAIL_RE = re.compile(r"/\d{1,3}")
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>]+")
_HOST_HEADER_RE = re.compile(r"(?i)^\s*Host:\s*([^\s,;]+)")
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_IPV4_CIDR_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,3}")

# Tool names that execute an arbitrary shell command. The SDK uses "Bash"; the
# extra aliases cover other shells so extraction treats them uniformly.
_BASH_TOOL_NAMES = frozenset({"bash", "sh", "shell", "terminal", "execute_bash"})

# Programs whose positional arguments are inherently targets (hosts/URLs/nets),
# so every positional is captured rather than only host-looking ones.
_PERMISSIVE_PROGRAMS = frozenset({
    "curl", "wget", "nmap", "nc", "ncat", "netcat", "masscan", "nikto",
    "gobuster", "ffuf", "whatweb", "nuclei", "httpx", "dnsrecon", "dig",
})

# Flags that consume the following token as their value, so that token must not
# be mistaken for a target host. Focused on the pentest-relevant toolset.
_VALUE_FLAGS: dict[str, set[str]] = {
    "curl": {
        "-o", "--output", "-H", "--header", "-A", "--user-agent", "-e", "--referer",
        "-u", "--user", "-x", "--proxy", "-U", "--proxy-user", "--proxy-header",
        "-K", "--config", "--url", "-E", "--cert", "--key", "--pass",
        "-X", "--request", "--request-target",
        "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
        "--form-string", "-F", "--form", "-b", "--cookie", "-c", "--cookie-jar",
        "-C", "--continue-at", "-T", "--upload-file", "-D", "--dump-header",
        "-w", "--write-out", "--resolve", "--connect-to", "-r", "--range",
        "-z", "--time-cond", "--netrc-file", "--oauth2-bearer", "--output-dir",
        "--mail-from", "--mail-rcpt", "--mail-auth", "--egd-file", "--random-file",
        "--libcurl", "--retry", "--retry-delay", "--retry-max-time",
        "-m", "--max-time", "--connect-timeout", "--speed-time", "-y",
        "--speed-limit", "-Y", "--limit-rate", "--local-port", "--max-filesize",
        "--max-redirs", "--noproxy", "--socks4", "--socks4a", "--socks5",
        "--interface", "--dns-servers", "-P", "--ftp-port",
    },
    "wget": {
        "-O", "--output-document", "-o", "--output-file", "-a", "--append-output",
        "--header", "-P", "--directory-prefix", "-U", "--user-agent", "-T",
        "--timeout", "-w", "--wait", "--waitretry", "-l", "--level", "-t", "--tries",
        "-X", "--exclude-directories", "-I", "--include-directories", "-B", "--base",
        "--referer", "--user", "--password", "--http-user", "--http-password",
        "--proxy-user", "--proxy-password", "-e", "--execute", "--limit-rate",
        "--bind-address", "--certificate", "--ca-certificate", "--load-cookies",
        "--save-cookies", "-i", "--input-file", "-Q", "--quota", "--cut-dirs",
        "--exclude-domains", "--span-hosts",
    },
    "nmap": {
        "-oN", "-oX", "-oS", "-oG", "-oA", "-oM", "-iL", "-iR", "-p", "--port",
        "--script", "--script-args", "--script-args-file", "--datadir",
        "--servicedb", "--versiondb", "--data-length", "--excludefile",
        "--exclude", "--max-retries", "--host-timeout", "--scan-delay",
        "--max-scan-delay", "--min-hostgroup", "--max-hostgroup",
        "--min-parallelism", "--max-parallelism", "--min-rate", "--max-rate",
        "--ttl", "--spoof-mac", "--version-intensity", "--min-rtt-timeout",
        "--max-rtt-timeout", "--initial-rtt-timeout", "--max-os-tries",
        "--source-port", "-g", "--dns-servers", "-S", "--reason",
    },
}

# Tool-input fields that carry an explicit target for non-Bash tools.
_NON_BASH_TARGET_FIELDS = ("url", "host", "ip", "endpoint", "domain", "address")


class ScopeConfigError(ValueError):
    """Raised when ``scope.yaml`` is structurally invalid."""


def _is_ip_literal(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _looks_like_host(token: str) -> bool:
    """Heuristic: does this bare token plausibly name a host/IP target?"""
    if "://" in token:
        return True
    if token.startswith("["):  # bracketed IPv6 literal
        return True
    if _IPV4_CIDR_RE.fullmatch(token) or _IPV4_RE.fullmatch(token):
        return True
    # A dot covers domains and host:port; bare single labels (e.g. "localhost")
    # are intentionally treated as ambiguous and ignored for non-permissive tools.
    return "." in token


def _dedup(items: list[str]) -> list[str]:
    """Order-preserving, case-insensitive deduplication."""
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        key = it.casefold()
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


class Scope:
    """Authorized-target whitelist with deny-priority default-deny semantics.

    Entry forms accepted in ``in_scope`` / ``out_of_scope``:
      * bare domain  ``example.com``   -> matches itself and every subdomain.
      * wildcard     ``*.example.com`` -> matches subdomains only, never apex.
      * bare IP      ``10.1.2.3``      -> treated as a /32 (or /128) host.
      * CIDR         ``10.0.0.0/24``   -> a full network range.

    Matching precedence is deny-first: an out_of_scope hit always denies, even
    when a broader in_scope entry would otherwise allow it. With no matching
    in_scope entry the target is denied (whitelist model).
    """

    def __init__(self, in_scope: Sequence[str], out_of_scope: Sequence[str]) -> None:
        self.in_plain, self.in_wild, self.in_nets = self._bucket(in_scope, "in_scope")
        self.out_plain, self.out_wild, self.out_nets = self._bucket(out_of_scope, "out_of_scope")

    # -- construction / loading ------------------------------------------------
    @staticmethod
    def _bucket(
        entries: Sequence[str], name: str
    ) -> tuple[list[str], list[str], list[IpNetwork]]:
        plain: list[str] = []
        wild: list[str] = []
        nets: list[IpNetwork] = []
        for entry in entries:
            if "*" in entry:
                m = _WILDCARD_RE.fullmatch(entry)
                if not m:
                    raise ScopeConfigError(
                        f"{name} 通配条目格式非法: {entry!r}（仅支持 *.example.com 形式）"
                    )
                wild.append(m.group(1).lower())
                continue
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                net = None
            if net is not None:
                nets.append(net)
                continue
            if not _DOMAIN_RE.fullmatch(entry):
                raise ScopeConfigError(f"{name} 条目格式非法: {entry!r}")
            plain.append(entry.lower())
        return plain, wild, nets

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Scope:
        if not isinstance(data, Mapping):
            raise ScopeConfigError("scope 配置必须是包含 in_scope / out_of_scope 列表的映射")
        in_scope = data.get("in_scope", [])
        out_of_scope = data.get("out_of_scope", [])
        cls._validate_list(in_scope, "in_scope")
        cls._validate_list(out_of_scope, "out_of_scope")
        return cls(in_scope, out_of_scope)

    @classmethod
    def from_file(cls, path: str | Path) -> Scope:
        with Path(path).open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return cls.from_dict(data if data is not None else {})

    @staticmethod
    def _validate_list(value: object, name: str) -> None:
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            raise ScopeConfigError(f"{name} 必须是字符串列表")
        for item in value:
            if not isinstance(item, str):
                raise ScopeConfigError(f"{name} 条目必须是字符串: {item!r}")
            if not item:
                raise ScopeConfigError(f"{name} 条目不能为空字符串")
            if item != item.strip():
                raise ScopeConfigError(f"{name} 条目不能包含首尾空白: {item!r}")
            if re.search(r"\s", item):
                raise ScopeConfigError(f"{name} 条目不能包含空白字符: {item!r}")

    # -- authorization ---------------------------------------------------------
    def is_allowed(self, target: str) -> bool:
        """True iff ``target`` is in scope and not explicitly out of scope."""
        host = self._normalize_host(target)
        net = self._parse_net(host)
        if net is not None:
            # Deny-priority: any overlap with an out_of_scope network blocks it.
            if any(net.overlaps(blocked) for blocked in self.out_nets):
                return False
            # Allow only when fully contained in an in_scope network.
            return any(self._subnet_of(net, allowed) for allowed in self.in_nets)
        # domain target
        if any(self._domain_matches(host, base) for base in self.out_plain):
            return False
        if any(self._wildcard_matches(host, base) for base in self.out_wild):
            return False
        if any(self._domain_matches(host, base) for base in self.in_plain):
            return True
        return any(self._wildcard_matches(host, base) for base in self.in_wild)

    @staticmethod
    def _parse_net(host: str) -> IpNetwork | None:
        if not host:
            return None
        try:
            return ipaddress.ip_network(host, strict=False)
        except ValueError:
            return None

    @staticmethod
    def _subnet_of(a: IpNetwork, b: IpNetwork) -> bool:
        # subnet_of() is overloaded per address family; narrow explicitly so a
        # cross-family pair falls through to the default-deny False below.
        if isinstance(a, ipaddress.IPv4Network) and isinstance(b, ipaddress.IPv4Network):
            return a.subnet_of(b)
        if isinstance(a, ipaddress.IPv6Network) and isinstance(b, ipaddress.IPv6Network):
            return a.subnet_of(b)
        return False  # mismatched address families

    @staticmethod
    def _domain_matches(host: str, base: str) -> bool:
        return host == base or host.endswith("." + base)

    @staticmethod
    def _wildcard_matches(host: str, base: str) -> bool:
        # strict subdomain only; the apex never matches a *.wildcard entry
        return host.endswith("." + base)

    # -- normalization ---------------------------------------------------------
    @classmethod
    def _normalize_host(cls, raw: str) -> str:
        s = raw.strip()
        s = _SCHEME_RE.sub("", s, count=1)  # strip scheme like https://
        s = s.lstrip("/")
        if "@" in s:  # strip userinfo user:pass@
            s = s.rsplit("@", 1)[1]
        # Split authority from path/query/fragment while preserving a CIDR slash.
        cut = len(s)
        for ch in ("/", "?", "#"):
            idx = s.find(ch)
            if idx != -1 and idx < cut:
                cut = idx
        authority = s[:cut]
        tail = s[cut:]
        if tail.startswith("/") and _is_ip_literal(authority):
            m = _CIDR_TAIL_RE.match(tail)
            if m is not None:
                authority += m.group(0)
        authority = cls._strip_port(authority)
        return authority.lower().rstrip(".")

    @staticmethod
    def _strip_port(authority: str) -> str:
        if authority.startswith("["):  # [ipv6] or [ipv6]:port
            rb = authority.find("]")
            if rb != -1:
                return authority[1:rb]
            return authority
        # A single ':' with a numeric right side is host:port; multiple ':' is a
        # bare IPv6 literal and is left untouched.
        if authority.count(":") == 1:
            left, right = authority.split(":", 1)
            if right.isdigit():
                return left
        return authority

    # -- target extraction -----------------------------------------------------
    def extract_targets(self, tool_name: str, tool_input: Mapping[str, Any]) -> list[str]:
        """Return the distinct target strings referenced by a tool call."""
        if self._is_bash_tool(tool_name):
            command = tool_input.get("command")
            return self._extract_from_command(command) if isinstance(command, str) else []
        targets: list[str] = []
        for field in _NON_BASH_TARGET_FIELDS:
            value = tool_input.get(field)
            if isinstance(value, str) and value:
                targets.append(value)
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                targets.extend(v for v in value if isinstance(v, str) and v)
        return targets

    @staticmethod
    def _is_bash_tool(tool_name: str) -> bool:
        return tool_name.lower() in _BASH_TOOL_NAMES

    @classmethod
    def _extract_from_command(cls, command: str) -> list[str]:
        targets: list[str] = list(_URL_RE.findall(command))
        for sub in re.split(r"&&|\|\||\||;|&", command):
            sub = sub.strip()
            if not sub:
                continue
            try:
                tokens = shlex.split(sub)
            except ValueError:
                tokens = sub.split()
            if not tokens:
                continue
            program = Path(tokens[0]).name.lower()
            targets.extend(cls._extract_hosts_from_tokens(program, tokens[1:]))
        return _dedup(targets)

    @classmethod
    def _extract_hosts_from_tokens(cls, program: str, args: list[str]) -> list[str]:
        value_flags = _VALUE_FLAGS.get(program, set())
        permissive = program in _PERMISSIVE_PROGRAMS
        hosts: list[str] = []
        header_values: list[str] = []
        skip_next = False
        i = 0
        while i < len(args):
            tok = args[i]
            if skip_next:
                skip_next = False
                i += 1
                continue
            if tok.startswith("--") and "=" in tok:  # --flag=value: value attached
                i += 1
                continue
            if tok in value_flags:
                # curl/wget -H/--header may embed a Host: header -> capture it.
                if (
                    program in {"curl", "wget"}
                    and tok in {"-H", "--header", "--proxy-header"}
                    and i + 1 < len(args)
                ):
                    header_values.append(args[i + 1])
                skip_next = True
                i += 1
                continue
            if tok.startswith("-"):  # any other flag (boolean or attached)
                i += 1
                continue
            if permissive or _looks_like_host(tok):
                hosts.append(tok)
            i += 1
        for header in header_values:
            hm = _HOST_HEADER_RE.search(header)
            if hm:
                hosts.append(hm.group(1))
        return hosts


class ScopeGuardHook:
    """PreToolUse hook: blocks tool calls whose target is outside scope.

    Matches the Claude Agent SDK ``HookCallback`` contract
    ``async (input_data, tool_use_id, context) -> dict[str, Any]``. An allow is
    an empty dict (pass-through); a deny carries the SDK ``hookSpecificOutput``
    deny decision. A Bash command from which no target host can be extracted is
    denied outright rather than allowed by accident.
    """

    def __init__(self, scope: Scope) -> None:
        self.scope = scope

    async def __call__(
        self,
        input_data: Mapping[str, Any],
        tool_use_id: str | None,
        context: Any = None,
    ) -> dict[str, Any]:
        tool_name = str(input_data.get("tool_name", ""))
        raw_input = input_data.get("tool_input")
        tool_input: Mapping[str, Any] = raw_input if isinstance(raw_input, Mapping) else {}
        targets = self.scope.extract_targets(tool_name, tool_input)
        if not targets:
            if Scope._is_bash_tool(tool_name):
                return self._deny("无法从 Bash 命令中提取出有效的目标 host（默认拒绝）")
            return {}
        for target in targets:
            if not self.scope.is_allowed(target):
                return self._deny(f"目标不在授权范围内: {target}")
        return {}

    @staticmethod
    def _deny(reason: str) -> dict[str, Any]:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
