from __future__ import annotations

import argparse

from . import __version__


def main() -> None:
    parser = argparse.ArgumentParser(prog="servctl", description="TUI control plane for Linux servers")
    parser.add_argument("--dry-run", action="store_true",
                        help="start in dry-run mode (print commands, change nothing)")
    parser.add_argument("--config", help="config file (default /etc/servctl/config.yml as root, "
                                         "~/.config/servctl/config.yml otherwise)")
    parser.add_argument("--modules", help="comma-separated module ids to show, overriding the config")
    parser.add_argument("--list-modules", action="store_true", help="print module ids and exit")
    parser.add_argument("--version", action="version", version=f"servctl {__version__}")
    args = parser.parse_args()

    from .config import Config
    from .registry import BUILTIN
    cfg = Config(args.config)

    if args.list_modules:
        enabled = cfg.get("modules.enabled")
        for m in BUILTIN:
            on = m.required or (m.default if enabled is None else m.id in enabled)
            print(f"{'*' if on else ' '} {m.id:<10} {m.category:<9} {m.description}")
        return

    pinned = [x.strip() for x in args.modules.split(",") if x.strip()] if args.modules else None
    if pinned:
        unknown = [p for p in pinned if p not in {m.id for m in BUILTIN}]
        if unknown:  # may be plugin modules, which load later
            print(f"note: {', '.join(unknown)} are not built-in modules; ignored unless a plugin provides them")

    from .ui import ServctlApp
    ServctlApp(dry_run=args.dry_run, cfg=cfg, pinned=pinned).run()


if __name__ == "__main__":
    main()
