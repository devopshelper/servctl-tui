<div align="center">

```text
 ████ █████ ████  █   █  ████ █████ █    
█     █     █   █ █   █ █       █   █    
 ███  ████  ████  █   █ █       █   █    
    █ █     █  █   █ █  █       █   █    
████  █████ █   █   █    ████   █   █████
```

# servctl

### Transactional, Plan-First Terminal UI for Linux Server Administration

[![Python Version](https://img.shields.io/badge/python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Textual UI](https://img.shields.io/badge/TUI-Textual_8.0+-00ADD8?style=for-the-badge&logo=gnubash&logoColor=white)](https://textual.textualize.io/)
[![Platform](https://img.shields.io/badge/Platform-RHEL_9_%7C_Rocky_%7C_Alma_%7C_Ubuntu_%7C_Debian-E95420?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/devopshelper/servctl-tui)
[![Safety Engine](https://img.shields.io/badge/Safety-Dry--Run_%26_Auto--Rollback-2ea44f?style=for-the-badge&logo=shield&logoColor=white)](#-the-safety-engine)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

<p align="center">
  <b>servctl</b> is an ergonomic, menu-driven TUI control plane designed for sysadmins and DevOps engineers.
  <br />
  Every modification is turned into an explicit, transparent <b>plan</b> with instant diff previews, pre-execution backups, dry-run simulation, and automatic rollback if anything fails.
</p>

---

[Features](#-features-at-a-glance) • [Safety Engine](#-the-safety-engine) • [Installation](#-installation) • [Keybindings](#-keyboard-navigation) • [Configuration](#-configuration) • [Plugins](#-extensibility--plugins)

---

</div>

## 🌟 Features at a Glance

* 🛡️ **Transactional Plan Engine**: See exact shell commands and unified file diffs before anything touches your system.
* ⏪ **Time Machine & Backup Explorer**: Automatic timestamped backups in `/var/backups/servctl/` with 1-click rollback plans.
* 🧪 **True Dry-Run Mode**: Press <kbd>F2</kbd> anytime to simulate changes without root privileges.
* 📋 **SSH-Native Clipboard (OSC 52)**: One-click copy for generated MariaDB passwords and iperf3 commands directly to your client clipboard over remote SSH.
* 🔥 **Dual Firewall Manager**: Seamless support for **firewalld** (runtime + permanent + auto-closing timers) and **nftables** (atomic batch transactions, port-range narrowing, SSH lockout guard).
* 🗄️ **MariaDB Orchestration**: Install, secure, configure database users with stdin-fed passwords (never in `ps`), privilege presets, and pre-drop gzipped dumps.
* 🧹 **Smart Cleanup Presets**: 1-click presets (*Safe Clean*, *Deep Clean*, *Containers Only*) for Docker/Podman and host housekeeping.
* 🔒 **Mail & Recursive DNS Auditing**: Local root-hints **Unbound** resolver (for Spamhaus DNSBL access) + full MX, SPF (10-lookup limit), DMARC, DKIM, MTA-STS, and DANE verification.
* 🖥️ **Terminal & Font Resilience**: Built strictly with classic CP437/WGL4 glyphs (`┌─┐`, `░▒▓█`) for zero-tofu rendering across PuTTY, Windows consoles, and low-color links.

---

## 🛡️ The Safety Engine

```
  [ Action Triggered ]
          │
          ▼
  ┌───────────────────┐
  │  Plan Generation  │  ──► Explicit Steps (argv commands, atomic writes, deletions)
  └───────────────────┘
          │
          ▼
  ┌───────────────────┐
  │  Review Dialog    │  ──► Colored Unified Diff (diff -u) + exact $ commands
  └───────────────────┘
          │
    User Confirms
          │
          ▼
  ┌───────────────────┐
  │ Snapshot Backups  │  ──► Saved to /var/backups/servctl/<timestamp>/
  └───────────────────┘
          │
          ▼
  ┌───────────────────┐
  │ Step-by-Step Exec │
  └───────────────────┘
     │             │
  Success        Failure
     │             │
     ▼             ▼
  [ Done ]     ┌────────────────────────────────────────────────────────┐
               │ Automated Reverse Rollback: restored to previous state │
               └────────────────────────────────────────────────────────┘
```

---

## 📦 Modules

Modules can be enabled or disabled in **Settings** (persisted to `/etc/servctl/config.yml`). Overview and Settings are always active.

| Category | Module | Highlights |
|---|---|---|
| **System** | **Overview** | Real-time CPU, load, memory, statvfs disk bars, degraded systemd unit health monitor. |
| **System** | **Cleanup** | 1-click presets (*Safe*, *Deep*, *Containers*); Docker/Podman prune (containers, images, build cache with age filters); dnf/apt cache, orphans, old kernels, rotated logs, core dumps. |
| **Logs** | **Logrotate** | In-place retention editor for `/etc/logrotate.d` and global defaults; validated via `logrotate -d`. |
| **Logs** | **Journald** | Persistent drop-ins for `SystemMaxUse` and `MaxRetentionSec`; manual vacuum by size, age, or file count. |
| **Logs** | **SIEM Forwarding** | High-throughput rsyslog shipper (UDP/TCP/TLS, RFC 5424/3164, disk-buffered queues, imfile for `audit.log`, SELinux port labelling, validated with `rsyslogd -N1`). |
| **Services** | **MariaDB** | RHEL 9 AppStream installer & hardening; local socket unix_socket auth; MariaDB 11.4+ SSL client compatibility; user creation with stdin-fed passwords; privilege presets (`all`, `rw_ddl`, `rw`, `ro`); guarded drop with automatic gzipped dump. |
| **Services** | **Syncthing** | EPEL or upstream installation (checksum verified), systemd `syncthing@user` service, firewall ports, remote GUI credentials. |
| **Network** | **Firewall** | **firewalld or nftables**. Open/close by port (`443`, `8000-8100`) or service name (`http`, `https`, `wireguard`, `cockpit`); auto-closing timeout; atomic set/range narrowing; listening socket reachability audit; SSH lockout prevention. |
| **Network** | **Speedtest** | Zero-dependency built-in Cloudflare multi-stream test (down/up, latency, jitter) or official Ookla CLI. |
| **Network** | **iperf3** | Temporary listener with **self-expiring** firewalld rule and time limit; 1-click copy for client command. |
| **DNS** | **DNS Benchmark** | Benchmarks public, system, and local resolvers by latency, reliability, DNSSEC, and Spamhaus answer compatibility. |
| **DNS** | **Unbound** | Dedicated local recursive resolver from IANA root hints (no forwarders) for direct Spamhaus DNSBL access with monthly refresh timer. |
| **DNS** | **Mail DNS** | Deep email security audit: MX, PTR + FCrDNS, Spamhaus/SpamCop, SPF (RFC 7208 10-lookup limit evaluation), DMARC, DKIM selectors, MTA-STS, TLS-RPT, BIMI, and DANE TLSA. |
| **Storage** | **Disk Benchmark** | CrystalDiskMark-style fio benchmarks (SEQ1M Q8, RND4K Q32/Q1 read/write) with MB/s, IOPS, and p99 latency; dd fallback. |
| **Settings**| **Backup Explorer**| **Time Machine**: Browse historical pre-change snapshots, inspect file diffs, and generate instant rollback plans. |

---

## 🚀 Installation

### Quick Install (Root / Server)

```bash
# Clone or unpack
git clone https://github.com/devopshelper/servctl-tui.git /opt/servctl-src
cd /opt/servctl-src

# Install into isolated venv at /opt/servctl (links /usr/local/bin/servctl)
sudo ./install.sh

# Run
sudo servctl
```

### Safe Exploration Mode (Non-Root)

You can launch `servctl` on any machine without root privileges to test screens and diagnostics:

```bash
servctl --dry-run
```

### Requirements

* **Python**: ≥ 3.9 (RHEL 9 system python, Debian 11+, Ubuntu 20.04+ supported out of the box).
* **Dependencies**: `textual`, `dnspython`, `PyYAML` (installed automatically into the venv by `install.sh`).
* Optional utilities (`fio`, `iperf3`, `unbound`, `rsyslog`) can be installed on-demand from inside their respective panes.

---

## ⌨️ Keyboard Navigation

Designed for pure keyboard flow without touching the mouse:

| Key | Action |
|:---|:---|
| <kbd>Tab</kbd> / <kbd>Shift+Tab</kbd> | Switch to next / previous module (from anywhere) |
| <kbd>↑</kbd> / <kbd>↓</kbd> or <kbd>j</kbd> / <kbd>k</kbd> | Move in the sidebar menu or between fields |
| <kbd>Enter</kbd> or <kbd>→</kbd> | Jump from menu into module screen |
| <kbd>Esc</kbd> | Return focus to the sidebar menu |
| <kbd>←</kbd> / <kbd>→</kbd> | Move between buttons and switches (in text inputs: move cursor) |
| <kbd>Space</kbd> | Toggle switch / open dropdown |
| <kbd>Ctrl+P</kbd> | **Command Palette**: fuzzy search modules, direct actions, and change theme |
| <kbd>F1</kbd> | Complete Key Reference dialog |
| <kbd>F2</kbd> | Toggle **DRY-RUN** / **LIVE** execution mode |
| <kbd>F3</kbd> / <kbd>F4</kbd> | Toggle activity log panel / clear log |
| <kbd>F5</kbd> | Refresh current screen data |
| <kbd>Ctrl+Q</kbd> | Quit `servctl` |

---

## 🎨 Appearance & Themes

* **Themes**: Live theme previews via **Settings** or <kbd>Ctrl+P</kbd> → *Change theme*. Default: `tokyo-night`.
* **Animations**: Shimmering gradient wordmark, smooth slide-ins, top-bar activity comet, and count-up benchmarks. Can be toggled off for high-latency SSH connections (`ui.animations: false`).
* **Terminal Glyph Policy**: Only CP437/WGL4 characters are drawn (`┌─┐`, `░▒▓█`, ASCII). Renders cleanly in PuTTY, minimal serial consoles, and Windows Terminal without missing-character boxes.
* **Colors**: Automatically upgrades plain `TERM=xterm` (16 colors) to 256 colors (`xterm-256color`) or truecolor.

---

## ⚙️ Configuration

Configuration is stored in `/etc/servctl/config.yml` (root) or `~/.config/servctl/config.yml` (non-root):

```yaml
modules:
  enabled: [overview, cleanup, firewall, mariadb, journald, unbound, maildns, dnsbench, settings]
ui:
  theme: tokyo-night
  colors: auto          # auto | 16 | 256 | truecolor
  animations: true
  splash: true
  dry_run: false
  show_log: false
speedtest:
  url: https://speed.cloudflare.com
  download_mb: 100
  upload_mb: 25
  streams: 4
disk:
  dir: /var/tmp
  size: 1G
  runtime: 10
iperf:
  port: 5201
  timeout_min: 15
dns:
  extra_resolvers: ["Gateway=192.168.1.1"]
  dkim_selectors: [mail2024, google, default]
plugins:
  dir: /etc/servctl/plugins
  trusted: [who]
```

CLI overrides:
```bash
servctl --list-modules
servctl --modules firewall,cleanup    # Temporarily restrict UI to specified panes
servctl --dry-run                     # Force simulation mode
```

---

## 🧩 Extensibility & Plugins

A plugin is an isolated Python file placed in `plugins.dir` defining `MODULES = [Module(...)]` with a custom `Pane` subclass:
* Integrates directly into the plan/confirm/dry-run/rollback engine.
* Plugins only load when listed in `plugins.trusted`.
* Enforces strict file security: refused if not root-owned or if group/world-writable.
* See [`examples/plugins/who.py`](examples/plugins/who.py) for a working template.

---

## 🛠️ Development & Testing

```bash
# Run unit tests
python3 -m unittest -v tests.test_plans tests.test_v2 tests.test_v4

# Build release distribution zip
./release.sh
```

---

<div align="center">
  <sub>Built with ❤️ for Linux System Administrators and DevOps Engineers.</sub>
</div>
