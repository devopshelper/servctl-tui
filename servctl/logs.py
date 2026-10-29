"""logrotate and journald retention plans."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from .core import Step, read_text

LOGROTATE_DIR = "/etc/logrotate.d"
LOGROTATE_CONF = "/etc/logrotate.conf"
JOURNALD_DROPIN = "/etc/systemd/journald.conf.d/60-servctl.conf"

FREQUENCIES = ("daily", "weekly", "monthly", "yearly")
# Boolean directives and their negations.
FLAGS = {
    "compress": "nocompress",
    "delaycompress": "nodelaycompress",
    "copytruncate": "nocopytruncate",
    "missingok": "nomissingok",
    "notifempty": "ifempty",
    "dateext": "nodateext",
}
_VALUED = ("rotate", "maxsize", "size", "maxage", "minsize")
MANAGED = set(FREQUENCIES) | {"hourly"} | set(FLAGS) | set(FLAGS.values()) | set(_VALUED)
_SCRIPT_START = {"postrotate", "prerotate", "firstaction", "lastaction", "preremove"}
_SIZE_RE = re.compile(r"^\d+[kMG]?$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")


@dataclass
class RotateSettings:
    frequency: str = "daily"
    rotate: int = 7
    maxsize: str = ""          # rotate early when the file grows past this (e.g. 100M)
    maxage: int = 0            # delete rotated files older than N days (0 = off)
    compress: bool = True
    delaycompress: bool = True
    copytruncate: bool = False
    missingok: bool = True
    notifempty: bool = True
    dateext: bool = True

    def validate(self) -> None:
        if self.frequency not in FREQUENCIES:
            raise ValueError(f"frequency must be one of {', '.join(FREQUENCIES)}")
        if self.rotate < 0:
            raise ValueError("rotate count must be >= 0")
        if self.maxsize and not _SIZE_RE.match(self.maxsize):
            raise ValueError("size must look like 500k, 100M or 1G")
        if self.maxage < 0:
            raise ValueError("maxage must be >= 0")

    def directives(self) -> List[str]:
        out = [self.frequency, f"rotate {self.rotate}"]
        if self.maxsize:
            out.append(f"maxsize {self.maxsize}")
        if self.maxage:
            out.append(f"maxage {self.maxage}")
        for flag, neg in FLAGS.items():
            on = getattr(self, flag)
            # Only write negations that matter; positive flags always written.
            if on:
                out.append(flag)
            elif flag in ("compress", "copytruncate", "dateext"):
                out.append(neg)
        return out


def _first_token(line: str) -> str:
    s = line.strip()
    return s.split()[0] if s and not s.startswith("#") else ""


def patch_block_settings(text: str, s: RotateSettings) -> str:
    """Replace managed directives inside every { } block, keeping everything else."""
    out: List[str] = []
    depth = 0
    in_script = False
    for line in text.splitlines():
        stripped = line.strip()
        tok = _first_token(line)
        if in_script:
            out.append(line)
            if tok == "endscript":
                in_script = False
            continue
        if depth == 1 and tok in _SCRIPT_START:
            in_script = True
            out.append(line)
            continue
        if depth == 1 and tok in MANAGED:
            continue
        if stripped.startswith("}"):
            depth = max(0, depth - 1)
            out.append(line)
            continue
        out.append(line)
        if stripped.endswith("{") and not stripped.startswith("#"):
            depth += 1
            if depth == 1:
                out.extend("    " + d for d in s.directives())
    return "\n".join(out) + "\n"


def patch_global_settings(text: str, s: RotateSettings) -> str:
    """Replace top-level (depth 0) defaults in logrotate.conf.

    New directives are placed where the old ones were, and always before the
    first ``include`` so they apply to files in /etc/logrotate.d.
    """
    lines = text.splitlines()
    keep: List[str] = []
    insert_at: Optional[int] = None
    depth = 0
    in_script = False
    for line in lines:
        stripped = line.strip()
        tok = _first_token(line)
        if in_script:
            in_script = tok != "endscript"
            keep.append(line)
            continue
        if tok in _SCRIPT_START:
            in_script = True
        if depth == 0 and tok in MANAGED:
            if insert_at is None:
                insert_at = len(keep)
            continue
        if depth == 0 and tok == "include" and insert_at is None:
            insert_at = len(keep)
        if stripped.startswith("}"):
            depth = max(0, depth - 1)
        elif stripped.endswith("{") and not stripped.startswith("#"):
            depth += 1
        keep.append(line)
    if insert_at is None:
        insert_at = 0
        while insert_at < len(keep) and keep[insert_at].strip().startswith("#"):
            insert_at += 1
    # Per-file behaviour flags stay in the individual rules.
    per_file = {"missingok", "notifempty", "delaycompress", "copytruncate", "nocopytruncate"}
    global_dirs = [d for d in s.directives() if d.split()[0] not in per_file]
    keep[insert_at:insert_at] = global_dirs
    return "\n".join(keep) + "\n"


def parse_settings(text: str, block: bool = True) -> RotateSettings:
    """Best-effort read of managed directives (first block, or top level)."""
    s = RotateSettings(frequency="weekly", rotate=4, maxsize="", maxage=0, compress=False,
                       delaycompress=False, copytruncate=False, missingok=False,
                       notifempty=False, dateext=False)
    depth = 0
    seen_block = False
    in_script = False
    for line in text.splitlines():
        stripped = line.strip()
        tok = _first_token(line)
        if in_script:
            in_script = tok != "endscript"
            continue
        if tok in _SCRIPT_START:
            in_script = True
            continue
        if stripped.startswith("}"):
            depth -= 1
            if block and seen_block:
                break
            continue
        if stripped.endswith("{") and not stripped.startswith("#"):
            depth += 1
            seen_block = True
            continue
        if (depth == 1) != block or not tok:
            continue
        parts = stripped.split()
        if tok in FREQUENCIES:
            s.frequency = tok
        elif tok == "rotate" and len(parts) > 1 and parts[1].isdigit():
            s.rotate = int(parts[1])
        elif tok in ("maxsize", "size") and len(parts) > 1:
            s.maxsize = parts[1]
        elif tok == "maxage" and len(parts) > 1 and parts[1].isdigit():
            s.maxage = int(parts[1])
        elif tok in FLAGS:
            setattr(s, tok, True)
        elif tok in FLAGS.values():
            setattr(s, next(k for k, v in FLAGS.items() if v == tok), False)
    return s


def parse_paths(text: str) -> List[str]:
    """Paths of the first block. They may share the '{' line or sit on lines above it."""
    pending: List[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        head = s[:-1] if s.endswith("{") else s
        pending += [t for t in head.split() if t.startswith(("/", '"', "'"))]
        if s.endswith("{"):
            return pending
        if s.startswith("}"):
            pending = []
    return []


def render_new_rule(paths: List[str], s: RotateSettings) -> str:
    body = "\n".join("    " + d for d in s.directives())
    return f"# Managed by servctl\n{' '.join(paths)} {{\n{body}\n}}\n"


def logrotate_rule_plan(name: str, paths: List[str], s: RotateSettings,
                        existing: Optional[str] = None) -> List[Step]:
    s.validate()
    if not _NAME_RE.match(name):
        raise ValueError("Rule name may only contain letters, digits, '.', '_', '-', '@'")
    path = f"{LOGROTATE_DIR}/{name}"
    if existing is None:
        existing = read_text(path)
    if existing is not None and parse_paths(existing):
        content = patch_block_settings(existing, s)
        title = f"Update retention in {path} (paths and scripts kept)"
    else:
        if not paths:
            raise ValueError("Enter at least one log path, e.g. /var/log/myapp/*.log")
        bad = [p for p in paths if not p.startswith("/")]
        if bad:
            raise ValueError(f"Log paths must be absolute: {', '.join(bad)}")
        content = render_new_rule(paths, s)
        title = f"Create {path}"
    return [
        Step.write(title, path, content),
        # Debug mode parses the config and simulates, changing nothing.
        Step.cmd("Validate with logrotate --debug", "logrotate", "-d", LOGROTATE_CONF),
    ]


def logrotate_global_plan(s: RotateSettings, current: Optional[str] = None) -> List[Step]:
    s.validate()
    if current is None:
        current = read_text(LOGROTATE_CONF)
    if current is None:
        raise ValueError(f"{LOGROTATE_CONF} not found - is logrotate installed?")
    return [
        Step.write(f"Update global defaults in {LOGROTATE_CONF}", LOGROTATE_CONF,
                   patch_global_settings(current, s)),
        Step.cmd("Validate with logrotate --debug", "logrotate", "-d", LOGROTATE_CONF),
    ]


def logrotate_force_plan(name: str) -> List[Step]:
    return [Step.cmd(f"Force rotation of {name}", "logrotate", "-f", f"{LOGROTATE_DIR}/{name}")]


# --------------------------------------------------------------------------- #
# journald
# --------------------------------------------------------------------------- #

_J_SIZE_RE = re.compile(r"^\d+(\.\d+)?[KMGT]?$")
_J_TIME_RE = re.compile(r"^\d+\s*(s|sec|m|min|h|hour|d|day|days|w|week|weeks|month|months|y|year|years)?$")

JOURNALD_FIELDS = {
    # key: (label, kind)
    "SystemMaxUse": ("Max total disk use", "size"),
    "SystemKeepFree": ("Always keep free", "size"),
    "SystemMaxFileSize": ("Max size per file", "size"),
    "MaxRetentionSec": ("Max age of entries", "time"),
    "MaxFileSec": ("Rotate files every", "time"),
}


def _check(kind: str, key: str, value: str) -> None:
    rx = _J_SIZE_RE if kind == "size" else _J_TIME_RE
    if not rx.match(value):
        ex = "500M, 2G" if kind == "size" else "2weeks, 1month, 30d"
        raise ValueError(f"{key}: '{value}' is not valid (examples: {ex})")


def journald_plan(values: Dict[str, str], persistent: bool) -> List[Step]:
    lines = ["# Managed by servctl", "[Journal]"]
    if persistent:
        lines.append("Storage=persistent")
    for key, (_, kind) in JOURNALD_FIELDS.items():
        v = values.get(key, "").strip()
        if v:
            _check(kind, key, v)
            lines.append(f"{key}={v}")
    if len(lines) == 2:
        raise ValueError("Set at least one limit")
    return [
        Step.write("Write journald drop-in", JOURNALD_DROPIN, "\n".join(lines) + "\n"),
        Step.cmd("Restart journald", "systemctl", "restart", "systemd-journald"),
        Step.cmd("Show disk usage", "journalctl", "--disk-usage"),
    ]


def journald_remove_plan() -> List[Step]:
    return [
        Step.delete("Remove servctl journald drop-in", JOURNALD_DROPIN),
        Step.cmd("Restart journald", "systemctl", "restart", "systemd-journald"),
    ]


def read_journald_dropin() -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in (read_text(JOURNALD_DROPIN) or "").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def vacuum_plan(size: str, time: str, files: str) -> List[Step]:
    args = []
    if size:
        _check("size", "size", size)
        args.append(f"--vacuum-size={size}")
    if time:
        _check("time", "time", time)
        args.append(f"--vacuum-time={time}")
    if files:
        if not files.isdigit() or int(files) < 1:
            raise ValueError("files must be a positive number")
        args.append(f"--vacuum-files={files}")
    if not args:
        raise ValueError("Set a size, an age or a file count to vacuum")
    return [
        # Vacuum only touches archived files; rotate first so the active one counts.
        Step.cmd("Archive active journal files", "journalctl", "--rotate"),
        Step.cmd("Vacuum journal", "journalctl", *args),
        Step.cmd("Show disk usage", "journalctl", "--disk-usage"),
    ]
