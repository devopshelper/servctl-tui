"""YAML configuration: which modules are enabled, UI preferences, per-module defaults.

Lookup order: --config / $SERVCTL_CONFIG, then /etc/servctl/config.yml when
running as root, otherwise ~/.config/servctl/config.yml.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from .core import is_root

SYSTEM_PATH = Path("/etc/servctl/config.yml")
USER_PATH = Path(os.path.expanduser("~/.config/servctl/config.yml"))

DEFAULTS: Dict[str, Any] = {
    "modules": {
        # null = every module that is on by default
        "enabled": None,
    },
    "ui": {
        "theme": "tokyo-night",
        "colors": "auto",        # auto | 16 | 256 | truecolor
        "animations": True,
        "splash": True,
        "dry_run": False,
        "show_log": False,
    },
    "plugins": {
        "dir": "/etc/servctl/plugins",
        # Only plugin files listed here (by file name, without .py) are loaded.
        "trusted": [],
    },
    "speedtest": {
        "url": "https://speed.cloudflare.com",
        "download_mb": 100,
        "upload_mb": 25,
        "streams": 4,
    },
    "disk": {
        "dir": "/var/tmp",
        "size": "1G",
        "runtime": 10,
    },
    "iperf": {
        "port": 5201,
        "timeout_min": 15,
    },
    "dns": {
        # Extra resolvers for the benchmark, as "Label=IP" or just "IP".
        "extra_resolvers": [],
        "dkim_selectors": [],
    },
}


def _merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def default_path() -> Path:
    env = os.environ.get("SERVCTL_CONFIG")
    if env:
        return Path(env)
    return SYSTEM_PATH if is_root() else USER_PATH


class Config:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else default_path()
        self.exists = self.path.exists()
        self.error = ""
        raw: Dict[str, Any] = {}
        if self.exists:
            try:
                raw = yaml.safe_load(self.path.read_text()) or {}
                if not isinstance(raw, dict):
                    raise ValueError("top level must be a mapping")
            except (OSError, ValueError, yaml.YAMLError) as exc:
                self.error = f"{self.path}: {exc} (using defaults)"
                raw = {}
        self.data = _merge(DEFAULTS, raw)

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted: str, value: Any) -> None:
        node = self.data
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".yml.tmp")
        tmp.write_text("# servctl configuration - edit here or in the Settings screen\n" +
                       yaml.safe_dump(self.data, sort_keys=False, default_flow_style=False))
        os.replace(tmp, self.path)
        self.exists = True
