"""pi backend skill-prompt transport regression tests.

The bridge protocol must preserve stage-specific skill text byte-for-byte.  These
tests stop at the Python/Node boundary so they are deterministic and do not need
provider credentials.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from cain_agent.handlers import SkillLoader
from cain_agent.pi_executor import PiExecutor

BRIDGE = Path(__file__).resolve().parents[1] / "toolchain" / "pi" / "bridge.mjs"


class _Stdin:
    def __init__(self) -> None:
        self.raw = bytearray()

    def write(self, data: bytes) -> None:
        self.raw.extend(data)

    async def drain(self) -> None:
        return None


class _Stdout:
    def __init__(self) -> None:
        self._sent = False

    async def readline(self) -> bytes:
        if self._sent:
            return b""
        self._sent = True
        return b'{"type":"done","text":"ok","numTurns":1,"error":null}\n'


class _Process:
    def __init__(self) -> None:
        self.stdin = _Stdin()
        self.stdout = _Stdout()

    def kill(self) -> None:
        return None

    async def wait(self) -> int:
        return 0


def _write_skill(root: Path, name: str, phase: str, body: str) -> None:
    path = root / name / "SKILL.md"
    path.parent.mkdir(parents=True)
    path.write_text(
        "---\n"
        f"name: {name}\n"
        f"description: {phase} 阶段代表性技能\n"
        f"phase: {phase}\n"
        "severity_focus: info\n"
        "---\n\n"
        f"# {name}\n\n{body}\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("phase", "name", "marker"),
    [
        ("recon", "sqli-surface-recon", "识别可能承载 SQL 查询的参数面"),
        ("test", "file-upload-check", "验证无害文件的类型与执行边界"),
        ("report", "evidence-report", "按证据链汇总确认项与未决项"),
    ],
)
def test_pi_preserves_representative_stage_skill_prompt(
    tmp_path: Path, phase: str, name: str, marker: str
) -> None:
    _write_skill(tmp_path, name, phase, marker * 200)
    prompt = f"stage={phase}\n{SkillLoader(tmp_path).render(phase)}"
    process = _Process()
    executor = PiExecutor(bridge_path=BRIDGE)

    async def spawn() -> _Process:
        return process

    executor._spawn_bridge = spawn  # type: ignore[method-assign]
    result = asyncio.run(executor.run(prompt))

    wire = bytes(process.stdin.raw)
    request: dict[str, Any] = json.loads(wire.decode("utf-8"))
    assert result.text == "ok"
    assert request["prompt"] == prompt
    assert marker in request["prompt"]
    assert request["prompt"].rstrip().endswith(marker * 200)

    # JSON framing adds only a small constant envelope; skill text is neither
    # duplicated nor Unicode-escaped into an unexpectedly large payload.
    assert len(wire) <= len(prompt.encode("utf-8")) + 512


def test_real_sqli_skill_is_not_truncated_at_pi_boundary() -> None:
    skills_root = Path(__file__).resolve().parents[1] / "skills"
    prompt = SkillLoader(skills_root).render("test")
    sqli = (skills_root / "web" / "sqli" / "SKILL.md").read_text(encoding="utf-8")
    process = _Process()
    executor = PiExecutor(bridge_path=BRIDGE)

    async def spawn() -> _Process:
        return process

    executor._spawn_bridge = spawn  # type: ignore[method-assign]
    asyncio.run(executor.run(prompt))
    request = json.loads(bytes(process.stdin.raw).decode("utf-8"))

    assert sqli in prompt
    assert request["prompt"] == prompt
    assert sqli[-256:] in request["prompt"]
