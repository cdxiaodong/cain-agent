"""Tool —— 只读安全工具接口定义

只读原则：
- 所有工具只能读取目标系统信息，不能修改/删除
- 工具调用前需经过只读白名单校验
- 危险操作（如 --delete、DROP、rm）被拒绝

参考 T3MP3ST 工具链设计（36+ 工具），但严格限制为只读。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cain_agent.toolchain.executor import ToolResult


class ToolCategory(str, Enum):
    """工具分类（按 MITRE ATT&CK 阶段）。"""

    RECON = "recon"  # TA0043: 侦察
    SCAN = "scan"  # TA0007: 漏洞扫描
    EXPLOIT = "exploit"  # TA0001: 利用（只读验证）
    POST = "post"  # TA0008: 后渗透（只读信息收集）
    REPORT = "report"  # TA0011: 报告生成


@dataclass
class ToolSpec:
    """工具规范。"""

    name: str  # 工具名
    category: ToolCategory
    description: str
    binary: str  # 二进制路径或命令
    readonly: bool = True  # 是否只读工具
    dangerous_flags: list[str] = field(default_factory=list)  # 危险参数黑名单
    example: str = ""  # 示例用法


@dataclass
class ToolResult:
    """工具执行结果。"""

    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration: float = 0.0
    findings: list[dict] = field(default_factory=list)  # 结构化发现


class Tool(ABC):
    """工具接口（抽象基类）。"""

    @abstractmethod
    def spec(self) -> ToolSpec:
        """返回工具规范。"""

    @abstractmethod
    def execute(self, args: list[str], target: str) -> ToolResult:
        """执行工具（只读约束由守门员校验）。"""
