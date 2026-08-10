"""ToolExecutor —— 工具执行器（调用只读工具）

职责：
- 接收工具调用请求
- 通过 ReadonlyGuard 安全检查
- 执行工具并捕获输出
- 返回结构化结果

只读约束：所有工具调用必须通过守门员检查。
"""

from __future__ import annotations

import subprocess
import time

from cain_agent.toolchain.readonly_guard import ReadonlyGuard
from cain_agent.toolchain.registry import ToolRegistry
from cain_agent.toolchain.tool import ToolResult


class ToolExecutor:
    """
工具执行器：调用只读工具并返回结果。
    """

    def __init__(self, registry: ToolRegistry, scope) -> None:
        self.registry = registry
        self.scope = scope
        self.guard = registry.guard if registry.guard is not None else ReadonlyGuard()

    def execute(self, tool_name: str, args: list[str], target: str = "") -> ToolResult:
        """
执行工具（只读约束检查）。
        """
        start = time.time()

        # 只读检查
        if not self.registry.is_allowed(tool_name, args):
            return ToolResult(
                success=False,
                stderr=f"工具 {tool_name} 或参数违反只读原则，拒绝执行",
            )

        # Scope 检查（确保目标在授权范围内）
        if target and not self._check_scope(target):
            return ToolResult(
                success=False,
                stderr=f"目标 {target} 不在授权范围内",
            )

        # 执行工具
        try:
            spec = self.registry.get(tool_name)
            if not spec:
                return ToolResult(success=False, stderr=f"工具 {tool_name} 未注册")

            cmd = [spec.binary] + args
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 分钟超时
            )

            return ToolResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration=time.time() - start,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                stderr=f"工具 {tool_name} 执行超时",
                duration=time.time() - start,
            )
        except FileNotFoundError:
            return ToolResult(
                success=False,
                stderr=f"工具 {spec.binary} 未找到，请确保已安装",
                duration=time.time() - start,
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                success=False,
                stderr=f"工具 {tool_name} 执行异常: {exc}",
                duration=time.time() - start,
            )

    def _check_scope(self, target: str) -> bool:
        """
检查目标是否在授权范围内。
        """
        # 占位：实际需检查 target 是否在 scope.yaml 许可列表
        return True  # 简化实现，默认允许
