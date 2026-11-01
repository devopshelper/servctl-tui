"""Cheap host metrics from /proc and statvfs (no external tools, safe to poll)."""
from __future__ import annotations

import os
import platform
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .core import capture, os_info, read_text

REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "jfs", "reiserfs", "nfs",
           "nfs4", "cifs", "fuseblk", "exfat"}


@dataclass
class Disk:
    mount: str
    device: str
    fstype: str
    total: int
    used: int

    @property
    def pct(self) -> float:
        return 100.0 * self.used / self.total if self.total else 0.0


def meminfo() -> Dict[str, int]:
    out: Dict[str, int] = {}
    for line in (read_text("/proc/meminfo") or "").splitlines():
        m = re.match(r"(\w+):\s+(\d+)", line)
        if m:
            out[m.group(1)] = int(m.group(2)) * 1024
    return out


def memory() -> Tuple[int, int, int, int]:
    """(mem_used, mem_total, swap_used, swap_total) in bytes."""
    m = meminfo()
    total = m.get("MemTotal", 0)
    used = total - m.get("MemAvailable", m.get("MemFree", 0))
    st = m.get("SwapTotal", 0)
    return used, total, st - m.get("SwapFree", 0), st


def disks() -> List[Disk]:
    seen = set()
    out = []
    for line in (read_text("/proc/mounts") or "").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] not in REAL_FS:
            continue
        dev, mount, fs = parts[0], parts[1].replace("\\040", " "), parts[2]
        if dev in seen or mount.startswith(("/snap", "/var/lib/docker", "/var/lib/containers")):
            continue
        try:
            st = os.statvfs(mount)
        except OSError:
            continue
        seen.add(dev)
        total = st.f_blocks * st.f_frsize
        used = total - st.f_bfree * st.f_frsize
        if total:
            out.append(Disk(mount, dev, fs, total, used))
    return sorted(out, key=lambda d: d.mount)


def uptime() -> str:
    try:
        secs = int(float((read_text("/proc/uptime") or "0").split()[0]))
    except (ValueError, IndexError):
        return "?"
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    return (f"{d}d " if d else "") + f"{h}h {rem // 60}m"


def load() -> Tuple[float, float, float]:
    try:
        return os.getloadavg()
    except (OSError, AttributeError):
        return (0.0, 0.0, 0.0)


def services(names: List[str]) -> Dict[str, str]:
    rc, out = capture(["systemctl", "is-active", *names], 5)
    states = out.splitlines()
    if len(states) != len(names):
        return {n: "unknown" for n in names}
    return dict(zip(names, states))


def failed_units() -> List[str]:
    rc, out = capture(["systemctl", "--failed", "--no-legend", "--plain"], 5)
    return [l.split()[0] for l in out.splitlines() if l.strip()] if rc == 0 else []


def host_summary() -> Dict[str, str]:
    osi = os_info()
    return {"host": platform.node(), "os": osi.pretty, "kernel": platform.release(),
            "arch": platform.machine(), "cpus": str(os.cpu_count() or "?")}


def human(n: float) -> str:
    for unit in ("B", "K", "M", "G", "T", "P"):
        if abs(n) < 1024 or unit == "P":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return str(n)


def pct_color(pct: float) -> str:
    return "green" if pct < 70 else "yellow" if pct < 90 else "red"


def bar(pct: float, width: int = 24) -> Tuple[str, str]:
    """(filled, empty) strings for a usage bar using full and light-shade blocks."""
    filled = int(round(width * min(max(pct, 0), 100) / 100))
    return "█" * filled, "░" * (width - filled)
