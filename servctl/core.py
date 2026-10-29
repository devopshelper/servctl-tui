"""Plan/step engine shared by every screen.

Every action in servctl is expressed as a list of Steps. A Step either runs a
command (argv, never a shell string unless explicitly wrapped in bash -c),
writes a file, or removes a file. Plans are shown to the user before they run,
can be executed in dry-run mode, and file changes are backed up and rolled back
automatically if a later step in the same plan fails.
"""
from __future__ import annotations

import datetime
import os
import pwd
import shlex
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

BACKUP_ROOT = Path(os.environ.get("SERVCTL_BACKUP_DIR", "/var/backups/servctl"))

# emit(message, style) -- style is a Rich style string or "".
Emitter = Callable[[str, str], None]


@dataclass
class Step:
    title: str
    argv: Optional[List[str]] = None
    path: Optional[str] = None
    content: Optional[str] = None
    remove: bool = False
    mode: int = 0o644
    allow_fail: bool = False
    # Optional text shown instead of argv (used to hide secrets).
    display: Optional[str] = None

    @classmethod
    def cmd(cls, title: str, *argv: str, allow_fail: bool = False,
            display: Optional[str] = None) -> "Step":
        return cls(title=title, argv=list(argv), allow_fail=allow_fail, display=display)

    @classmethod
    def sh(cls, title: str, script: str, allow_fail: bool = False) -> "Step":
        script = script.strip("\n")
        return cls(title=title, argv=["bash", "-euo", "pipefail", "-c", script],
                   allow_fail=allow_fail, display=script)

    @classmethod
    def write(cls, title: str, path: str, content: str, mode: int = 0o644) -> "Step":
        return cls(title=title, path=path, content=content, mode=mode)

    @classmethod
    def delete(cls, title: str, path: str) -> "Step":
        return cls(title=title, path=path, remove=True)

    def describe(self) -> str:
        if self.argv is not None:
            body = self.display if self.display is not None else shlex.join(self.argv)
            return "\n".join("$ " + line if i == 0 else "  " + line
                             for i, line in enumerate(body.splitlines() or [""]))
        if self.remove:
            return f"remove {self.path} (backed up first)"
        lines = (self.content or "").rstrip("\n").splitlines()
        return f"write {self.path} (mode {self.mode:o}):\n" + "\n".join("  │ " + l for l in lines)


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #

def _backup(path: Path, stamp: str) -> Optional[Path]:
    if not path.exists():
        return None
    dest = BACKUP_ROOT / stamp / path.relative_to("/")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dest)
    return dest


def _atomic_write(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".servctl-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    # Keep SELinux labels correct for files written under /etc.
    if shutil.which("restorecon"):
        subprocess.run(["restorecon", str(path)], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)


def _run_cmd(argv: List[str], emit: Emitter) -> int:
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, text=True, bufsize=1,
                                env={**os.environ, "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"})
    except FileNotFoundError:
        emit(f"  command not found: {argv[0]}", "red")
        return 127
    assert proc.stdout is not None
    for line in proc.stdout:
        emit("  " + line.rstrip("\n"), "dim")
    return proc.wait()


def run_plan(steps: List[Step], emit: Emitter, dry_run: bool = False) -> bool:
    """Run steps in order. Returns True on success.

    On a failing step (without allow_fail) all file writes/removals made by
    this plan are restored from their backups, newest first.
    """
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    undo: List[Tuple[Path, Optional[Path]]] = []
    total = len(steps)

    for i, step in enumerate(steps, 1):
        emit(f"[{i}/{total}] {step.title}", "bold cyan")
        if dry_run:
            for line in step.describe().splitlines():
                emit("  (dry-run) " + line, "yellow")
            continue

        ok = True
        if step.argv is not None:
            emit("  " + step.describe().splitlines()[0], "")
            rc = _run_cmd(step.argv, emit)
            ok = rc == 0
            if not ok:
                emit(f"  exit code {rc}", "yellow" if step.allow_fail else "red")
        else:
            path = Path(step.path or "")
            try:
                backup = _backup(path, stamp)
                undo.append((path, backup))
                if backup:
                    emit(f"  backup -> {backup}", "dim")
                if step.remove:
                    if path.exists():
                        path.unlink()
                    emit(f"  removed {path}", "")
                else:
                    _atomic_write(path, step.content or "", step.mode)
                    emit(f"  wrote {path}", "")
            except OSError as exc:
                emit(f"  {exc}", "red")
                ok = False

        if not ok and not step.allow_fail:
            emit("Step failed, aborting plan.", "bold red")
            _rollback(undo, emit)
            return False

    emit("Dry-run finished, nothing was changed." if dry_run else "Done.", "bold green")
    return True


def _rollback(undo: List[Tuple[Path, Optional[Path]]], emit: Emitter) -> None:
    for path, backup in reversed(undo):
        try:
            if backup is None:
                if path.exists():
                    path.unlink()
                    emit(f"  rollback: removed new file {path}", "yellow")
            else:
                shutil.copy2(backup, path)
                emit(f"  rollback: restored {path}", "yellow")
        except OSError as exc:
            emit(f"  rollback of {path} failed: {exc}", "red")


# --------------------------------------------------------------------------- #
# Read-only helpers used to populate the UI
# --------------------------------------------------------------------------- #

def capture(argv: List[str], timeout: int = 20) -> Tuple[int, str]:
    try:
        res = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, text=True, timeout=timeout,
                             env={**os.environ, "LC_ALL": "C"})
        return res.returncode, res.stdout.rstrip()
    except FileNotFoundError:
        return 127, f"{argv[0]}: not installed"
    except subprocess.TimeoutExpired:
        return 124, f"{shlex.join(argv)}: timed out"


def read_text(path: str) -> Optional[str]:
    try:
        return Path(path).read_text()
    except OSError:
        return None


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def is_root() -> bool:
    return os.geteuid() == 0


def user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def default_user() -> str:
    return os.environ.get("SUDO_USER") or ("" if is_root() else pwd.getpwuid(os.getuid()).pw_name)


@dataclass
class OSInfo:
    id: str = "unknown"
    id_like: List[str] = field(default_factory=list)
    version_id: str = ""
    pretty: str = "Unknown Linux"

    @property
    def rhel_like(self) -> bool:
        return self.id in ("rhel", "centos", "rocky", "almalinux", "ol", "fedora") or \
            any(x in ("rhel", "fedora", "centos") for x in self.id_like)

    @property
    def major(self) -> str:
        return self.version_id.split(".")[0]

    @property
    def pkg(self) -> str:
        if which("dnf"):
            return "dnf"
        if which("yum"):
            return "yum"
        if which("apt-get"):
            return "apt-get"
        return ""


def os_info(path: str = "/etc/os-release") -> OSInfo:
    data: Dict[str, str] = {}
    for line in (read_text(path) or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip('"')
    return OSInfo(id=data.get("ID", "unknown"), id_like=data.get("ID_LIKE", "").split(),
                  version_id=data.get("VERSION_ID", ""),
                  pretty=data.get("PRETTY_NAME", "Unknown Linux"))


def selinux_enforcing() -> bool:
    return (read_text("/sys/fs/selinux/enforce") or "0").strip() == "1"


def firewalld_running() -> bool:
    return bool(which("firewall-cmd")) and capture(["firewall-cmd", "--state"], 5)[0] == 0


def tcp_check(host: str, port: int, timeout: float = 4.0) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"TCP connection to {host}:{port} succeeded"
    except OSError as exc:
        return False, f"TCP connection to {host}:{port} failed: {exc}"
