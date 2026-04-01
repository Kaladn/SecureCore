"""SecureCore CLI command center.

Operator surface for watching and controlling the organism.
CLI first. Metrics first. No browser dependency.

Usage:
    python -m securecore.cli.main status
    python -m securecore.cli.main tail ingress
    python -m securecore.cli.main tail evidence --cell abc123
    python -m securecore.cli.main cells
    python -m securecore.cli.main cells --cell abc123
    python -m securecore.cli.main reaper
    python -m securecore.cli.main reaper --pause
    python -m securecore.cli.main reaper --resume
    python -m securecore.cli.main forge --substrate ingress
    python -m securecore.cli.main forge --verify ingress
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Direct-launch bootstrap
if __name__ == "__main__" and (__package__ is None or __package__ == ""):
    repo_root = str(Path(__file__).resolve().parent.parent.parent)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securecore",
        description="SecureCore CLI command center",
    )
    sub = parser.add_subparsers(dest="command", help="command to run")

    # status
    sub.add_parser("status", help="organism health overview")

    # tail
    tail_p = sub.add_parser("tail", help="tail a substrate or log stream")
    tail_p.add_argument("target", help="substrate name or log stream name")
    tail_p.add_argument("-n", type=int, default=20, help="number of records")
    tail_p.add_argument("--cell", type=str, default="", help="filter by cell_id")
    tail_p.add_argument("--follow", "-f", action="store_true", help="follow (poll for new records)")

    # cells
    cells_p = sub.add_parser("cells", help="mirror cell inspection")
    cells_p.add_argument("--cell", type=str, default="", help="full report for one cell")
    cells_p.add_argument("--locked", action="store_true", help="show only locked cells")
    cells_p.add_argument("--evidence", action="store_true", help="include evidence timeline")

    # reaper
    reaper_p = sub.add_parser("reaper", help="reaper status and control")
    reaper_p.add_argument("--pause", action="store_true", help="pause the reaper")
    reaper_p.add_argument("--resume", action="store_true", help="resume the reaper")
    reaper_p.add_argument("--shun", type=str, default="", help="manually shun an IP")
    reaper_p.add_argument("--unshun", type=str, default="", help="remove IP from shun list")

    # forge
    forge_p = sub.add_parser("forge", help="forge inspection")
    forge_p.add_argument("--substrate", type=str, default="", help="forge store for a substrate")
    forge_p.add_argument("--verify", type=str, default="", help="verify forge chain for a substrate")
    forge_p.add_argument("--tail", type=int, default=0, help="tail forge records")

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "status":
        from securecore.cli.commands.status import run
        run()
    elif args.command == "tail":
        from securecore.cli.commands.tail import run
        run(args.target, args.n, args.cell, args.follow)
    elif args.command == "cells":
        from securecore.cli.commands.cells import run
        run(args.cell, args.locked, args.evidence)
    elif args.command == "reaper":
        from securecore.cli.commands.reaper import run
        run(args.pause, args.resume, args.shun, args.unshun)
    elif args.command == "forge":
        from securecore.cli.commands.forge import run
        run(args.substrate, args.verify, args.tail)


if __name__ == "__main__":
    main()
