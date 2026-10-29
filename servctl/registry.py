"""Module registry and trusted plugin loader.

A module is one entry in the sidebar. Built-in modules get their pane class
from servctl.ui; plugins provide their own. A plugin is a Python file in the
plugins directory that defines ``MODULES = [Module(...)]`` and is listed under
``plugins.trusted`` in the config. Plugins use the same Pane base class and
plan engine as the built-ins.
"""
from __future__ import annotations

import importlib.util
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple

CATEGORIES = ("System", "Logs", "Services", "Network", "DNS", "Storage", "Plugins")


@dataclass
class Module:
    id: str
    title: str
    category: str
    description: str
    default: bool = True
    pane: Any = None          # Pane subclass; filled in by the UI for built-ins
    required: bool = False    # cannot be disabled


BUILTIN: List[Module] = [
    Module("overview", "Overview", "System", "Host summary: OS, disks, memory, key services.",
           required=True),
    Module("cleanup", "Cleanup", "System",
           "Prune containers/images/networks/volumes, package cache, old kernels, rotated logs."),
    Module("logrotate", "Logrotate", "Logs", "Edit retention of /etc/logrotate.d rules and global defaults."),
    Module("journald", "Journald", "Logs", "Journal size/age limits and one-off vacuum."),
    Module("siem", "SIEM forwarding", "Logs", "rsyslog forwarding to a remote SIEM (UDP/TCP/TLS)."),
    Module("syncthing", "Syncthing", "Services", "Install Syncthing as a per-user service (EPEL or upstream)."),
    Module("speedtest", "Speedtest", "Network", "Internet bandwidth/latency (Cloudflare or Ookla CLI)."),
    Module("iperf", "iperf3", "Network", "Temporary iperf3 listener with auto-closing firewall port, or client test."),
    Module("dnsbench", "DNS benchmark", "DNS",
           "Rank public resolvers for this network; checks DNSSEC and Spamhaus access."),
    Module("unbound", "Unbound resolver", "DNS",
           "Local recursive resolver from root hints (needed for Spamhaus lookups)."),
    Module("maildns", "Mail DNS", "DNS", "MX/SPF/DKIM/DMARC/MTA-STS/DANE/PTR and blocklist checks."),
    Module("disk", "Disk benchmark", "Storage", "Sequential and random read/write throughput and IOPS (fio)."),
    Module("settings", "Settings", "System", "Choose which modules are shown.", required=True),
]


def _safe_plugin_file(path: Path) -> Tuple[bool, str]:
    """Refuse plugins others could have tampered with (they run as root)."""
    try:
        st = path.stat()
    except OSError as exc:
        return False, str(exc)
    if os.geteuid() == 0 and st.st_uid != 0:
        return False, "not owned by root"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False, "group/world writable"
    return True, ""


def load_plugins(directory: str, trusted: Sequence[str]) -> Tuple[List[Module], List[str]]:
    modules: List[Module] = []
    messages: List[str] = []
    d = Path(directory)
    if not d.is_dir():
        return modules, messages
    for path in sorted(d.glob("*.py")):
        name = path.stem
        if name not in trusted:
            messages.append(f"plugin {path} skipped: not in plugins.trusted")
            continue
        ok, why = _safe_plugin_file(path)
        if not ok:
            messages.append(f"plugin {path} refused: {why}")
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"servctl_plugin_{name}", path)
            assert spec and spec.loader
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            found = list(getattr(mod, "MODULES", []))
        except Exception as exc:  # a broken plugin must not take the app down
            messages.append(f"plugin {path} failed to load: {exc!r}")
            continue
        for m in found:
            if isinstance(m, Module) and m.pane is not None:
                if m.category not in CATEGORIES:
                    m.category = "Plugins"
                modules.append(m)
        messages.append(f"plugin {path}: loaded {len(found)} module(s)")
    return modules, messages


def resolve_enabled(modules: Sequence[Module], enabled: Optional[Sequence[str]]) -> List[Module]:
    """Modules to show, in registry order. ``enabled=None`` means defaults."""
    wanted = None if enabled is None else set(enabled)
    out = []
    for m in modules:
        if m.required or (m.default if wanted is None else m.id in wanted):
            out.append(m)
    return out
