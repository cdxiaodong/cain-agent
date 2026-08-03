"""CLI 单元测试。

进程内调用 ``cain_agent.cli.main``，通过 ``monkeypatch`` 修改 ``sys.argv``，
用 ``capsys`` 捕获标准输出，不起子进程。覆盖两类入口：

1. ``--version`` 打印版本号；
2. 无任何参数时打印帮助。
"""

from __future__ import annotations

import sys

import pytest

from cain_agent import __version__
from cain_agent.cli import main


def test_cli_version_prints_version(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--version`` 输出包含程序名与当前版本号。"""
    monkeypatch.setattr(sys, "argv", ["cain-agent", "--version"])

    main()

    out = capsys.readouterr().out
    assert "cain-agent" in out
    assert __version__ in out


def test_cli_version_is_exact_line(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--version`` 输出形如 ``cain-agent <version>``，避免被帮助文本污染。"""
    monkeypatch.setattr(sys, "argv", ["cain-agent", "--version"])

    main()

    out = capsys.readouterr().out
    assert out.strip() == f"cain-agent {__version__}"


def test_cli_no_args_prints_help(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """无参数时打印帮助：含 usage 行、程序名与 ``--version`` 选项说明。"""
    monkeypatch.setattr(sys, "argv", ["cain-agent"])

    main()

    out = capsys.readouterr().out
    assert "usage:" in out
    assert "cain-agent" in out
    assert "--version" in out
