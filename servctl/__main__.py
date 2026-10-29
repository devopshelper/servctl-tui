from __future__ import annotations

import argparse

from . import __version__


def main() -> None:
    parser = argparse.ArgumentParser(prog="servctl", description=__doc__ or
                                     "TUI control plane for Linux servers")
    parser.add_argument("--dry-run", action="store_true",
                        help="start in dry-run mode (print commands, change nothing)")
    parser.add_argument("--version", action="version", version=f"servctl {__version__}")
    args = parser.parse_args()

    from .ui import ServctlApp
    ServctlApp(dry_run=args.dry_run).run()


if __name__ == "__main__":
    main()
