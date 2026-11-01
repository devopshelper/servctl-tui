from __future__ import annotations

import argparse
import os

from . import __version__


def apply_color_mode(mode: str) -> None:
    """Pick the colour depth before Textual creates its console.

    PuTTY and many SSH clients send TERM=xterm, which makes Rich fall back to
    16 colours even though the terminal can do far more.
    """
    if mode == "truecolor":
        os.environ["COLORTERM"] = "truecolor"
    elif mode == "256":
        os.environ.pop("COLORTERM", None)
        os.environ["TERM"] = "xterm-256color"
    elif mode == "16":
        os.environ.pop("COLORTERM", None)
        os.environ["TERM"] = "xterm"
    elif os.environ.get("TERM") in ("xterm", "putty", "vt100", "vt220", "screen", "linux") and not os.environ.get("COLORTERM"):
        os.environ["TERM"] = "xterm-256color"


def main() -> None:
    parser = argparse.ArgumentParser(prog="servctl", description="TUI control plane for Linux servers")
    parser.add_argument("--dry-run", action="store_true",
                        help="start in dry-run mode (print commands, change nothing)")
    parser.add_argument("--config", help="config file (default /etc/servctl/config.yml as root, "
                                         "~/.config/servctl/config.yml otherwise)")
    parser.add_argument("--modules", help="comma-separated module ids to show, overriding the config")
    parser.add_argument("--list-modules", action="store_true", help="print module ids and exit")
    parser.add_argument("--version", action="version", version=f"servctl {__version__}")
    parser.add_argument("--theme", help="override UI theme (e.g. putty, textual-dark, monokai, nord)")
    parser.add_argument("--colors", choices=["auto", "16", "256", "truecolor"],
                        help="terminal color mode (default: auto)")
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

    apply_color_mode(args.colors or cfg.get("ui.colors") or "auto")
    if args.theme:
        cfg.set("ui.theme", args.theme)
    pinned = [x.strip() for x in args.modules.split(",") if x.strip()] if args.modules else None
    if pinned:
        unknown = [p for p in pinned if p not in {m.id for m in BUILTIN}]
        if unknown:  # may be plugin modules, which load later
            print(f"note: {', '.join(unknown)} are not built-in modules; ignored unless a plugin provides them")

    from .ui import ServctlApp
    ServctlApp(dry_run=args.dry_run, cfg=cfg, pinned=pinned).run()


if __name__ == "__main__":
    main()
