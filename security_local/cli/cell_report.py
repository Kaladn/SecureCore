"""CLI tool for dumping mirror cell forensic evidence.

Usage:
    python cli/cell_report.py                    # list all cells
    python cli/cell_report.py --locked           # list locked cells only
    python cli/cell_report.py --cell <cell_id>   # full report for one cell
    python cli/cell_report.py --verify <cell_id> # verify chain integrity
    python cli/cell_report.py --dashboard        # threat dashboard summary
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from core.honeypot.cell_store import (
    get_all_persisted_cells,
    get_cell_full_report,
    get_threat_dashboard,
)
from core.honeypot.forensics import verify_chain_integrity
from core.models import MirrorCellRecord


def main() -> None:
    parser = argparse.ArgumentParser(description="Mirror Cell Forensic Reporter")
    parser.add_argument("--locked", action="store_true", help="Show only locked cells")
    parser.add_argument("--cell", type=str, help="Full report for a specific cell ID")
    parser.add_argument("--verify", type=str, help="Verify chain integrity for a cell ID")
    parser.add_argument("--dashboard", action="store_true", help="Threat dashboard summary")
    args = parser.parse_args()

    with app.app_context():
        if args.dashboard:
            data = get_threat_dashboard()
            print(json.dumps(data, indent=2))

        elif args.verify:
            result = verify_chain_integrity(args.verify)
            print(json.dumps(result, indent=2))
            if not result.get("intact"):
                print("\n!! CHAIN INTEGRITY VIOLATION DETECTED !!")
                sys.exit(1)

        elif args.cell:
            report = get_cell_full_report(args.cell)
            if "error" in report:
                print(f"Error: {report['error']}")
                sys.exit(1)
            print(json.dumps(report, indent=2))

        else:
            cells = get_all_persisted_cells()
            if args.locked:
                cells = [c for c in cells if c.get("locked")]

            if not cells:
                print("No mirror cells found.")
                return

            print(f"\n{'='*80}")
            print(f" MIRROR CELL REGISTRY — {len(cells)} cell(s)")
            print(f"{'='*80}\n")

            for c in cells:
                lock_indicator = " [LOCKED]" if c.get("locked") else ""
                level = c.get("escalation_level", 0)
                level_name = c.get("escalation_name", "UNKNOWN")
                print(
                    f"  {c['cell_id']}  "
                    f"IP={c['source_ip']}  "
                    f"Level={level}({level_name}){lock_indicator}  "
                    f"Interactions={c['total_interactions']}  "
                    f"Status={c['status']}"
                )
                print(f"    First: {c['first_seen']}  Last: {c['last_seen']}")
                print()


if __name__ == "__main__":
    main()
