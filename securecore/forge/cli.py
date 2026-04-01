"""CLI for inspecting a Forge substrate store."""

from __future__ import annotations

import argparse
import json

from securecore.forge.pulse_writer import ForgePulseWriter
from securecore.forge.reader import ForgeReader
from securecore.forge.writer import ForgeWriter


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureCore Forge CLI")
    parser.add_argument("--dir", required=True, help="Forge substrate directory")
    parser.add_argument("--stats", action="store_true", help="Show forge stats")
    parser.add_argument("--verify", action="store_true", help="Verify forge chain")
    parser.add_argument("--tail", type=int, help="Tail forge records")
    parser.add_argument("--pulse-stats", action="store_true", help="Show empty/default pulse writer state")
    args = parser.parse_args()

    if args.stats:
        writer = ForgeWriter(args.dir)
        print(json.dumps(writer.stats(), indent=2))
        return

    if args.pulse_stats:
        pulse = ForgePulseWriter(ForgeWriter(args.dir))
        print(json.dumps(pulse.stats(), indent=2))
        return

    reader = ForgeReader(args.dir)

    if args.verify:
        print(json.dumps(reader.verify(), indent=2))
        return

    if args.tail is not None:
        for record in reader.tail(args.tail):
            print(json.dumps(record.to_dict(), indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()
