"""Routine cleanup plans: container engine prune + host housekeeping."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from .core import Step, which

_UNTIL_RE = re.compile(r"^\d+(h|m|s)$")


def container_engine() -> Optional[str]:
    for name in ("docker", "podman"):
        if which(name):
            return name
    return None


@dataclass
class ContainerOpts:
    containers: bool = True
    images: bool = True
    all_images: bool = False      # also unused tagged images, not just dangling
    networks: bool = True
    volumes: bool = False         # data loss risk -> off by default
    all_volumes: bool = False     # docker >= 23 only prunes anonymous volumes without --all
    build_cache: bool = True
    until: str = ""               # only prune objects older than e.g. "24h"


def container_plan(engine: str, o: ContainerOpts) -> List[Step]:
    if o.until and not _UNTIL_RE.match(o.until):
        raise ValueError("'Older than' must look like 24h, 90m or 3600s")
    f = ["--filter", f"until={o.until}"] if o.until else []
    steps: List[Step] = []
    if o.containers:
        steps.append(Step.cmd("Remove stopped containers", engine, "container", "prune", "-f", *f))
    if o.images:
        extra = ["-a"] if o.all_images else []
        what = "unused images" if o.all_images else "dangling images"
        steps.append(Step.cmd(f"Remove {what}", engine, "image", "prune", "-f", *extra, *f))
    if o.networks:
        steps.append(Step.cmd("Remove unused networks", engine, "network", "prune", "-f", *f))
    if o.volumes:
        # Volume prune does not support the "until" filter.
        extra = ["--all"] if (o.all_volumes and engine == "docker") else []
        steps.append(Step.cmd("Remove unused volumes", engine, "volume", "prune", "-f", *extra))
    if o.build_cache and engine == "docker":
        extra = ["-a"] if o.all_images else []
        steps.append(Step.cmd("Remove build cache", engine, "builder", "prune", "-f", *extra, *f))
    return steps


@dataclass
class SystemOpts:
    pkg_cache: bool = True
    autoremove: bool = False
    old_kernels: bool = False
    keep_kernels: int = 2
    rotated_logs: bool = True
    log_days: int = 30
    coredumps: bool = True
    core_days: int = 7
    tmpfiles: bool = True


def system_plan(pkg: str, o: SystemOpts) -> List[Step]:
    if o.keep_kernels < 1:
        raise ValueError("Keep at least 1 kernel")
    if o.log_days < 1 or o.core_days < 0:
        raise ValueError("Day values must be positive")
    steps: List[Step] = []
    if o.pkg_cache and pkg:
        argv = ["apt-get", "clean"] if pkg == "apt-get" else [pkg, "clean", "all"]
        steps.append(Step.cmd("Clean package manager cache", *argv))
    if o.autoremove and pkg:
        steps.append(Step.cmd("Remove orphaned dependencies", pkg, "autoremove", "-y"))
    if o.old_kernels and pkg in ("dnf", "yum"):
        # dnf exits non-zero when there is nothing to remove.
        steps.append(Step.cmd(f"Remove old kernels (keep {o.keep_kernels})", pkg, "remove", "-y",
                              "--oldinstallonly", "--setopt", f"installonly_limit={o.keep_kernels}",
                              "kernel", allow_fail=True))
    if o.rotated_logs:
        steps.append(Step.cmd(
            f"Delete rotated logs in /var/log older than {o.log_days} days",
            "find", "/var/log", "-xdev", "-type", "f", "-regextype", "posix-extended",
            "-regex", r".*(\.(gz|xz|bz2|zst|old)|\.[0-9]+|-[0-9]{8}(\.(gz|xz|bz2|zst))?)$",
            "-mtime", f"+{o.log_days}", "-print", "-delete"))
    if o.coredumps:
        steps.append(Step.sh(
            f"Delete core dumps older than {o.core_days} days",
            "for d in /var/lib/systemd/coredump /var/crash /var/spool/abrt; do\n"
            f"  [ -d \"$d\" ] && find \"$d\" -mindepth 1 -mtime +{o.core_days} -print -delete\n"
            "done; true"))
    if o.tmpfiles and which("systemd-tmpfiles"):
        steps.append(Step.cmd("Clean temp dirs per tmpfiles.d policy", "systemd-tmpfiles", "--clean"))
    return steps
