#!/usr/bin/env bash
# Installs servctl into /opt/servctl (isolated venv) and links /usr/local/bin/servctl.
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo ./install.sh"; exit 1; }
command -v python3 >/dev/null || { command -v dnf >/dev/null && dnf install -y python3 || apt-get install -y python3; }
python3 -m venv --help >/dev/null 2>&1 || apt-get install -y python3-venv
python3 -m venv /opt/servctl
/opt/servctl/bin/pip install --quiet --upgrade pip
/opt/servctl/bin/pip install --quiet .
ln -sf /opt/servctl/bin/servctl /usr/local/bin/servctl
echo "installed: run 'sudo servctl' (or 'servctl --dry-run' to look around safely)"
