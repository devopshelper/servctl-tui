#!/usr/bin/env bash
# servctl installer for Debian, Ubuntu, RHEL, Rocky, AlmaLinux, Fedora, and CentOS
#
# Quick 1-line installation:
#   curl -fsSL https://raw.githubusercontent.com/devopshelper/servctl-tui/master/install.sh | sudo bash
#
# Local repository installation:
#   sudo ./install.sh
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Error: Please run as root (e.g. sudo bash ...)"; exit 1; }

echo "==> Preparing system environment..."

# Detect package manager
PKG=""
if command -v apt-get >/dev/null 2>&1; then
    PKG="apt-get"
elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG="yum"
fi

# Ensure Python 3, venv, and core tools are present
if [ "$PKG" = "apt-get" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-venv python3-pip git curl >/dev/null
elif [ "$PKG" = "dnf" ] || [ "$PKG" = "yum" ]; then
    "$PKG" install -y -q python3 git curl >/dev/null
fi

command -v python3 >/dev/null 2>&1 || { echo "Error: Python 3 could not be installed."; exit 1; }

echo "==> Setting up isolated virtual environment in /opt/servctl..."
mkdir -p /opt/servctl
python3 -m venv /opt/servctl

echo "==> Installing servctl and dependencies..."
/opt/servctl/bin/pip install --quiet --upgrade pip

# Check if running locally inside cloned repository
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
    /opt/servctl/bin/pip install --quiet "$SCRIPT_DIR"
else
    # Piped via curl / standalone execution: install from GitHub
    /opt/servctl/bin/pip install --quiet "git+https://github.com/devopshelper/servctl-tui.git"
fi

ln -sf /opt/servctl/bin/servctl /usr/local/bin/servctl

echo ""
echo "============================================================"
echo "  servctl successfully installed!"
echo "  Command: servctl"
echo "  Run:     sudo servctl"
echo "  Test:    servctl --dry-run (safe simulation, no root)"
echo "============================================================"
