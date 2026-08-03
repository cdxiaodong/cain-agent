"""Smoke tests: package imports, version format, CLI runs."""

from __future__ import annotations

import re

from cain_agent import __version__
from cain_agent.cli import main


def test_version_format() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)


def test_cli_version(capsys) -> None:  # type: ignore[no-untyped-def]
    import sys

    sys.argv = ["cain-agent", "--version"]
    main()
    out = capsys.readouterr().out
    assert __version__ in out
