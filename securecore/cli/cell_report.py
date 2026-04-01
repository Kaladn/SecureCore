"""CLI tool for dumping mirror cell forensic evidence.

Usage:
    python -m securecore.cli.cell_report                   # list all cells
    python -m securecore.cli.cell_report --cell <id>       # full evidence bundle
    python -m securecore.cli.cell_report --verify <name>   # verify substrate chain
    python -m securecore.cli.cell_report --dashboard       # substrate + agent stats
    python -m securecore.cli.cell_report --audit           # full chain audit
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from securecore.app import app


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureCore Forensic Reporter")
    parser.add_argument("--cell", type=str, help="Evidence bundle for a cell ID")
    parser.add_argument("--verify", type=str, help="Verify substrate chain by name")
    parser.add_argument("--dashboard", action="store_true", help="Substrate + agent stats")
    parser.add_argument("--audit", action="store_true", help="Full chain integrity audit")
    parser.add_argument("--tail", type=str, help="Tail a substrate (name)")
    parser.add_argument("-n", type=int, default=20, help="Number of records for tail")
    args = parser.parse_args()

    with app.app_context():
        substrates = app.substrates
        agents = app.agents

        if args.dashboard:
            print(f"\n{'='*70}")
            print(f" SECURECORE DASHBOARD")
            print(f"{'='*70}\n")
            print("SUBSTRATES:")
            for name, sub in substrates.items():
                print(f"  {name:20s}  records={sub.count():>6d}  file={sub.jsonl_path}")
            print("\nAGENTS:")
            for name, agent in agents.items():
                s = agent.stats
                print(f"  {name:20s}  running={s['running']}  consumed={s['consumed']:>6d}  emitted={s['emitted']:>4d}")
            print()

        elif args.verify:
            sub = substrates.get(args.verify)
            if not sub:
                print(f"Unknown substrate: {args.verify}")
                print(f"Available: {', '.join(substrates.keys())}")
                sys.exit(1)
            result = sub.verify_chain()
            print(json.dumps(result, indent=2))
            if not result.get("intact"):
                print("\n!! CHAIN INTEGRITY VIOLATION !!")
                sys.exit(1)

        elif args.cell:
            evidence_sub = substrates.get("evidence")
            if not evidence_sub:
                print("Evidence substrate not available")
                sys.exit(1)
            bundle = evidence_sub.export_evidence_bundle(args.cell)
            print(json.dumps(bundle, indent=2))

        elif args.audit:
            print(f"\n{'='*70}")
            print(f" FULL CHAIN AUDIT")
            print(f"{'='*70}\n")
            all_intact = True
            for name, sub in substrates.items():
                result = sub.verify_chain()
                status = "INTACT" if result.get("intact") else "BROKEN"
                if not result.get("intact"):
                    all_intact = False
                print(f"  {name:20s}  {status}  records={result.get('total_records', 0)}")
            print(f"\n  Overall: {'ALL CHAINS INTACT' if all_intact else '!! VIOLATIONS DETECTED !!'}")

        elif args.tail:
            sub = substrates.get(args.tail)
            if not sub:
                print(f"Unknown substrate: {args.tail}")
                sys.exit(1)
            records = list(sub.stream())[-args.n:]
            for r in records:
                print(json.dumps(r.to_dict(), indent=2))

        else:
            # List cells from mirror substrate
            mirror_sub = substrates.get("mirror")
            if not mirror_sub:
                print("Mirror substrate not available")
                return

            cells_seen = {}
            for record in mirror_sub.stream():
                if record.record_type == "cell_created":
                    cells_seen[record.cell_id] = {
                        "cell_id": record.cell_id,
                        "source_ip": record.payload.get("source_ip", ""),
                        "first_seen": record.timestamp,
                        "fingerprint": record.payload.get("attacker_fingerprint", "")[:16],
                    }

            if not cells_seen:
                print("No mirror cells found.")
                return

            print(f"\n{'='*70}")
            print(f" MIRROR CELLS - {len(cells_seen)} cell(s)")
            print(f"{'='*70}\n")
            for c in cells_seen.values():
                print(f"  {c['cell_id']}  IP={c['source_ip']}  fingerprint={c['fingerprint']}  first={c['first_seen']}")


if __name__ == "__main__":
    main()
