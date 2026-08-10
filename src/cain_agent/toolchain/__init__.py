"""Toolchain —— 只读工具链集成

只读原则：所有工具只能读取目标系统信息，禁止修改/删除/写入操作。

核心组件：
- ToolRegistry: 工具注册表（发现、注册、路由）
- ReadonlyGuard: 只读守门员（安全检查）
- ToolExecutor: 工具执行器（调用只读工具）
"""

from cain_agent.toolchain.executor import ToolExecutor
from cain_agent.toolchain.readonly_guard import ReadonlyGuard
from cain_agent.toolchain.registry import ToolRegistry
from cain_agent.toolchain.tool import Tool, ToolCategory, ToolResult, ToolSpec

__all__ = [
    "Tool",
    "ToolCategory",
    "ToolExecutor",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "ReadonlyGuard",
]
