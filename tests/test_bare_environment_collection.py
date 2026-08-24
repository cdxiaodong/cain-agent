"""Regression test for collection without optional cloud SDKs."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_pytest_collection_does_not_import_cloud_sdks(tmp_path: Path) -> None:
    """Hide optional SDKs and ensure the complete suite still collects."""
    sitecustomize = tmp_path / "sitecustomize.py"
    sitecustomize.write_text(
        "\n".join(
            [
                "import sys",
                "",
                "class _BlockedDistributionFinder:",
                "    def find_spec(self, fullname, path=None, target=None):",
                "        if fullname.split('.')[0] in {'boto3', 'kubernetes'}:",
                "            raise ModuleNotFoundError(f'blocked for test: {fullname}')",
                "        return None",
                "",
                "sys.meta_path.insert(0, _BlockedDistributionFinder())",
            ]
        ),
        encoding="utf-8",
    )

    source_root = Path(__file__).resolve().parents[1] / "src"
    python_path = os.pathsep.join([str(tmp_path), str(source_root), os.environ.get("PYTHONPATH", "")])
    env = {**os.environ, "PYTHONPATH": python_path.rstrip(os.pathsep)}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        timeout=120,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "ModuleNotFoundError" not in output
