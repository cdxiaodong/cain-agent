"""ReadonlyGuard —— 只读守门员（工具调用前的安全检查）

职责：
- 检查工具是否在只读白名单
- 检查参数是否包含写操作（-delete, -rm, DROP, WRITE 等）
- 拦截危险操作并返回拒绝原因

只读原则（cain-agent 核心安全红线）：
- 所有工具只能读取目标系统信息
- 禁止修改/删除/写入操作
- 违反只读原则的工具调用被拒绝
"""

from __future__ import annotations

import re


class ReadonlyGuard:
    """只读守门员：工具调用前的安全检查。"""

    # 危险参数模式（写操作）
    WRITE_PATTERNS = [
        r"-delete", r"-rm\b", r"DROP\s+\w+", r"WRITE\s+\w+",
        r"--delete", r"--remove", r"\bDELETE\b", r"\bDROP\b",
        r"put-object", r"upload", r"write-file", r"create-file",
    ]

    # 允许的只读工具白名单（命令前缀）
    ALLOWED_READONLY_TOOLS = {
        "curl", "httpx", "nuclei", "nmap", "subfinder",
        "httpie", "dig", "whois", "nslookup", "assetfinder",
        "waybackurls", "naabu", "rustscan",
    }

    def __init__(self, allowed_tools: set[str] | None = None) -> None:
        self._compile_patterns()
        # allow external whitelist (e.g. from ToolRegistry), fall back to builtin set
        self.ALLOWED_READONLY_TOOLS = (
            allowed_tools
            if allowed_tools is not None
            else {
                "curl", "httpx", "nuclei", "nmap", "subfinder",
                "httpie", "dig", "whois", "nslookup", "assetfinder",
                "waybackurls", "naabu", "rustscan",
            }
        )

    def _compile_patterns(self) -> None:
        """预编译正则模式。"""
        self.compiled_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.WRITE_PATTERNS
        ]

    def check(self, tool_name: str, args: list[str]) -> bool:
        """检查工具+参数是否符合只读原则。返回 True 允许，False 拒绝。"""
        # 1. 检查工具是否在白名单
        if tool_name not in self.ALLOWED_READONLY_TOOLS:
            return False

        # 2. 检查参数是否包含写操作
        args_str = " ".join(args)
        for pattern in self.compiled_patterns:
            if pattern.search(args_str):
                return False

        # 3. 特殊检查：curl 不允许 POST/PUT/DELETE
        if tool_name == "curl":
            for arg in args:
                if arg.upper() in {"-X", "--request"}:
                    idx = args.index(arg)
                    if idx + 1 < len(args):
                        method = args[idx + 1].upper()
                        if method in {"POST", "PUT", "DELETE", "PATCH"}:
                            return False

        return True

    def check_command(self, command: str) -> tuple[bool, str]:
        """检查完整命令字符串。返回 (是否允许, 拒绝原因)。"""
        parts = command.strip().split()
        if not parts:
            return False, "空命令"

        tool = parts[0]
        args = parts[1:]

        if not self.check(tool, args):
            return False, f"工具 {tool} 或参数违反只读原则"

        return True, ""

    def violation_reason(self, tool_name: str, args: list[str]) -> str | None:
        """返回违反只读原则的具体原因（用于日志）。"""
        if tool_name not in self.ALLOWED_READONLY_TOOLS:
            return f"工具 {tool_name} 不在只读白名单"

        args_str = " ".join(args)
        for pattern in self.compiled_patterns:
            match = pattern.search(args_str)
            if match:
                return f"参数包含写操作: {match.group()}"

        return None
