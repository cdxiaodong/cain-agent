"""Cain CLI entry point.

Phase 0 stub: only `version` is implemented. The orchestrator pipeline
(recon → test → framework → report) lands in Phase 1 per DESIGN.md.
"""

from __future__ import annotations

import argparse

from cain_agent import __version__


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cain-agent",
        description="Cain — Real-world AI Penetration Testing Engineer (authorized use only)",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    args = parser.parse_args()

    if args.version:
        print(f"cain-agent {__version__}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
