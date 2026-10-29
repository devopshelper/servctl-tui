"""Install and enable Syncthing as a per-user system service (RHEL 9 focused)."""
from __future__ import annotations

import pwd
import re
from dataclasses import dataclass
from typing import List

from .core import OSInfo, Step, firewalld_running

SYNC_PORTS = ("22000/tcp", "22000/udp", "21027/udp")

# Fallback unit if the release tarball does not ship one.
_FALLBACK_UNIT = """[Unit]
Description=Syncthing - Open Source Continuous File Synchronization for %I
Documentation=man:syncthing(1)
After=network.target

[Service]
User=%i
ExecStart=/usr/local/bin/syncthing serve --no-browser
Restart=on-failure
RestartSec=5
SuccessExitStatus=3 4
RestartForceExitStatus=3 4
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""

_UPSTREAM_SCRIPT = r"""
case "$(uname -m)" in
  x86_64) a=amd64 ;; aarch64) a=arm64 ;; armv7l) a=arm ;;
  *) echo "unsupported architecture $(uname -m)"; exit 1 ;;
esac
tag=$(curl -fsSL https://api.github.com/repos/syncthing/syncthing/releases/latest \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
[ -n "$tag" ] || { echo "could not determine latest release"; exit 1; }
echo "latest release: $tag"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
name="syncthing-linux-$a-$tag"
base="https://github.com/syncthing/syncthing/releases/download/$tag"
curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz"
curl -fsSL -o "$tmp/sha256sum.txt.asc" "$base/sha256sum.txt.asc"
(cd "$tmp" && grep " $name.tar.gz\$" sha256sum.txt.asc | sha256sum -c -)
tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
install -m 0755 "$tmp/$name/syncthing" /usr/local/bin/syncthing
unit="$tmp/$name/etc/linux-systemd/system/syncthing@.service"
if [ -f "$unit" ]; then
  sed 's#/usr/bin/syncthing#/usr/local/bin/syncthing#g' "$unit" > /etc/systemd/system/syncthing@.service
else
  cat > /etc/systemd/system/syncthing@.service <<'EOF'
__FALLBACK_UNIT__EOF
fi
command -v restorecon >/dev/null && restorecon -v /usr/local/bin/syncthing /etc/systemd/system/syncthing@.service
/usr/local/bin/syncthing --version
""".replace("__FALLBACK_UNIT__", _FALLBACK_UNIT)


@dataclass
class SyncthingOpts:
    user: str
    method: str = "epel"           # "epel" or "upstream"
    open_firewall: bool = True
    gui_remote: bool = False       # listen on 0.0.0.0 instead of 127.0.0.1
    gui_port: int = 8384
    gui_user: str = ""
    gui_password: str = ""


def install_plan(o: SyncthingOpts, osi: OSInfo) -> List[Step]:
    if not re.match(r"^[a-z_][a-z0-9_.-]*\$?$", o.user or ""):
        raise ValueError("Enter the Linux user Syncthing should run as")
    try:
        home = pwd.getpwnam(o.user).pw_dir
    except KeyError:
        raise ValueError(f"User '{o.user}' does not exist (create it with: useradd -m {o.user})")
    if o.user == "root":
        raise ValueError("Running Syncthing as root is not recommended; pick a normal user")
    if not 1 <= o.gui_port <= 65535:
        raise ValueError("GUI port must be 1-65535")
    if bool(o.gui_user) != bool(o.gui_password):
        raise ValueError("Set both GUI user and GUI password, or neither")
    if o.gui_remote and not o.gui_password:
        raise ValueError("Exposing the GUI on the network requires a GUI user and password")

    unit = f"syncthing@{o.user}.service"
    steps: List[Step] = []

    if o.method == "epel":
        if not osi.rhel_like:
            raise ValueError("The EPEL method is for RHEL/Rocky/Alma; use 'upstream binary' here")
        major = osi.major or "9"
        if osi.id == "rhel":
            steps.append(Step.cmd("Enable EPEL repository", "dnf", "install", "-y",
                                  f"https://dl.fedoraproject.org/pub/epel/epel-release-latest-{major}.noarch.rpm"))
        elif osi.id != "fedora":
            steps.append(Step.cmd("Enable EPEL repository", "dnf", "install", "-y", "epel-release"))
        steps.append(Step.cmd("Install syncthing package", "dnf", "install", "-y", "syncthing"))
        binary = "/usr/bin/syncthing"
    elif o.method == "upstream":
        steps.append(Step.sh("Download latest Syncthing release from GitHub (checksum verified)",
                             _UPSTREAM_SCRIPT))
        binary = "/usr/local/bin/syncthing"
    else:
        raise ValueError(f"unknown install method {o.method}")

    addr = f"{'0.0.0.0' if o.gui_remote else '127.0.0.1'}:{o.gui_port}"
    steps.append(Step.write(
        f"Set GUI listen address to {addr}",
        f"/etc/systemd/system/{unit}.d/servctl.conf",
        f"# Managed by servctl\n[Service]\nEnvironment=STGUIADDRESS={addr}\n"))
    steps.append(Step.cmd("Reload systemd", "systemctl", "daemon-reload"))

    if o.gui_user:
        steps.append(Step.cmd("Stop Syncthing if running", "systemctl", "stop", unit, allow_fail=True))
        argv = ["runuser", "-u", o.user, "--", "env", f"HOME={home}", binary, "generate",
                f"--gui-user={o.gui_user}", f"--gui-password={o.gui_password}"]
        shown = " ".join(argv[:-1]) + " --gui-password=********"
        steps.append(Step.cmd("Set GUI credentials", *argv, display=shown))

    steps.append(Step.cmd(f"Enable and start {unit}", "systemctl", "enable", "--now", unit))

    if o.open_firewall and firewalld_running():
        for p in SYNC_PORTS:
            steps.append(Step.cmd(f"Open {p}", "firewall-cmd", "--permanent", f"--add-port={p}"))
        if o.gui_remote:
            steps.append(Step.cmd(f"Open GUI port {o.gui_port}/tcp", "firewall-cmd", "--permanent",
                                  f"--add-port={o.gui_port}/tcp"))
        steps.append(Step.cmd("Reload firewalld", "firewall-cmd", "--reload"))

    steps.append(Step.cmd("Show service status", "systemctl", "--no-pager", "status", unit,
                          allow_fail=True))
    return steps


def disable_plan(user: str) -> List[Step]:
    if not user:
        raise ValueError("Enter the user whose Syncthing service should be stopped")
    return [Step.cmd("Stop and disable Syncthing", "systemctl", "disable", "--now",
                     f"syncthing@{user}.service")]
