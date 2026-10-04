"""C1 补丁 diff 解析层——unified diff → 结构化变更集(纯函数零 IO)。

只认标准 unified diff(`diff -u` / `git diff` 输出);非 diff 输入、坏
hunk 头显式 ``PatchDiffError`` 带行号。二进制文件标记行直接跳过。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_SIG_RE = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
_CHECK_RE = re.compile(
    r"^\+\s*(?:if\b|raise\b|assert\b|elif\b|if\s+not\b)"
    r"|^\+\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*[A-Za-z_][A-Za-z0-9_.\[\]]+\s*="
)


class PatchDiffError(ValueError):
    """unified diff 解析失败。"""


@dataclass(frozen=True)
class Hunk:
    """一个 hunk 的结构化提取。"""

    file_path: str
    old_start: int
    new_start: int
    signature_changes: tuple[str, ...] = ()
    """签名级变化(def/class 名,增删均记)。"""
    added_checks: tuple[str, ...] = ()
    """新增校验/类型约束行(原文,不含 +/- 前缀)。"""
    removed_paths: tuple[str, ...] = ()
    """删除的分支/检查行(原文)。"""

    def symbols(self) -> frozenset[str]:
        """本 hunk 出现的全部符号(签名名 + 行内标识符,蒸馏校验比对用)。"""
        found = set(self.signature_changes)
        for line in (*self.added_checks, *self.removed_paths):
            found.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", line))
        return frozenset(found)


@dataclass(frozen=True)
class ChangeSet:
    """一次补丁的结构化变更集(文件级 hunk 列表)。"""

    hunks: tuple[Hunk, ...] = field(default_factory=tuple)

    def symbols(self) -> frozenset[str]:
        found: set[str] = set()
        for hunk in self.hunks:
            found.update(hunk.symbols())
        return frozenset(found)


def parse_unified_diff(text: str) -> ChangeSet:
    """解析 unified diff 文本为变更集;非法输入抛 ``PatchDiffError``(带行号)。"""
    lines = text.splitlines()
    hunks: list[Hunk] = []
    current_file = ""
    i = 0

    def _die(msg: str, lineno: int) -> None:
        raise PatchDiffError(f"line {lineno}: {msg}")

    while i < len(lines):
        line = lines[i]
        lineno = i + 1
        if line.startswith(("diff ", "index ", "new file mode", "deleted file mode",
                            "similarity index", "rename from", "rename to")):
            i += 1
            continue
        if line.startswith("--- "):
            # --- a/path:配对的 +++ 必须在下一行,但只前进一行让 +++ 分支
            # 自己处理(否则跳过 +++ 导致 current_file 未设置)
            if i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
                _die("缺少配对的 +++ 头", lineno)
            i += 1
            continue
        if line.startswith("+++ "):
            current_file = line[4:].split("\t")[0].lstrip("b/")
            i += 1
            continue
        if line.startswith("Binary files"):
            i += 1
            continue
        m = _HUNK_RE.match(line)
        if m:
            old_start = int(m.group(1))
            new_start = int(m.group(3))
            sig: list[str] = []
            checks: list[str] = []
            removed: list[str] = []
            j = i + 1
            while j < len(lines) and not lines[j].startswith("@@"):
                body = lines[j]
                if body.startswith(("diff ", "--- ", "+++ ")):
                    break  # 新文件头:交回主循环处理(更新 current_file)
                if body.startswith("\\"):  # "\ No newline" 尾注
                    j += 1
                    continue
                content = body[1:] if body[:1] in "+-" else body[1:] if body.startswith(" ") else body
                sig_m = _SIG_RE.match(content) if body[:1] in "+- " else None
                if sig_m and body[:1] in "+-":
                    sig.append(sig_m.group(1))
                if body.startswith("+") and _CHECK_RE.match(body):
                    checks.append(content.strip())
                if body.startswith("-") and re.match(
                    r"^-\s*(?:if\b|raise\b|assert\b|elif\b|if\s+not\b|return\b)", body
                ):
                    removed.append(content.strip())
                j += 1
            if not current_file:
                _die("hunk 出现在 +++ 文件头之前", lineno)
            hunks.append(Hunk(
                file_path=current_file,
                old_start=old_start,
                new_start=new_start,
                signature_changes=tuple(dict.fromkeys(sig)),
                added_checks=tuple(checks),
                removed_paths=tuple(removed),
            ))
            i = j
            continue
        if line.startswith(("@", " ", "+", "-")) and hunks:
            i += 1
            continue
        if not line.strip():
            i += 1
            continue
        _die(f"无法识别的行(非 unified diff): {line[:40]!r}", lineno)

    return ChangeSet(hunks=tuple(hunks))


__all__ = ["ChangeSet", "Hunk", "PatchDiffError", "parse_unified_diff"]
