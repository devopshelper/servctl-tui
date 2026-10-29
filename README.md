# servctl

A terminal UI control plane for routine Linux server administration, aimed at
RHEL 9 (Rocky/Alma too) and also usable on Debian/Ubuntu.

Every change is turned into a **plan** of exact commands and file writes. You see
the plan before anything runs, you can run it as a **dry-run**, and changed files
are backed up to `/var/backups/servctl/<timestamp>/`. If any step fails, the files
that plan touched are restored automatically. Diagnostics (benchmarks, lookups)
are read-only and run straight away.

## Modules

Pick the ones you want in **Settings** (saved to the config file). Overview and
Settings are always on.

| Group | Module | What it does |
|---|---|---|
| System | Cleanup | docker/podman prune (containers, images, networks, volumes, build cache, "older than" filter); dnf/apt cache, orphans, old kernels, old rotated logs, core dumps, tmpfiles |
| Logs | Logrotate | edit retention of any `/etc/logrotate.d` rule in place (paths and `postrotate` scripts kept) or create one; global defaults in `/etc/logrotate.conf`; validated with `logrotate -d` |
| Logs | Journald | `SystemMaxUse`, `MaxRetentionSec`, … as a drop-in; one-off vacuum by size/age/files |
| Logs | SIEM forwarding | rsyslog to a SIEM over UDP/TCP/TLS, RFC 5424/3164, disk-buffered queue, extra files (e.g. `audit.log`) via imfile, SELinux port labelling, validated with `rsyslogd -N1` |
| Services | MariaDB | install `mariadb-server` (RHEL 9 AppStream), secure it, bind local or LAN (+ firewall port); create databases; create users (generated passwords, sent over stdin - never in `ps`); grant/revoke per database with presets (all, app read/write+DDL, read/write, read-only); list databases with users who can access them, users with their databases, all grants; drop user/database (database: typed confirmation + gzipped dump first) |
| Services | Syncthing | install from EPEL or upstream release (checksum verified), `syncthing@user` service, GUI address/credentials, firewalld ports |
| Network | Firewall | **firewalld or nftables**. Open/close by port (`443`, `80,443`, `8000-8100`), TCP/UDP/both, optional source IP/network, zone, permanent or auto-close after N minutes (firewalld). Closing finds whatever opens the port - port entry, service (`ssh` = 22), rich rule, nft rule or set - and narrows sets/ranges instead of deleting them. Lists every rule, plus listening sockets with open/blocked/localhost-only status. Refuses to close your SSH port unless you tick the override |
| Network | Speedtest | built-in Cloudflare test (latency, jitter, multi-stream down/up) or the Ookla CLI; one-click Ookla install |
| Network | iperf3 | temporary listener with a **self-expiring** firewalld rule and time limit, shows the client command; or run a client test |
| DNS | DNS benchmark | ranks public, system and local resolvers by cached/uncached latency and reliability; flags DNSSEC validation and **whether Spamhaus answers through each resolver**; apply the winner as system DNS |
| DNS | Unbound resolver | local **recursive** resolver from IANA root hints (no forwarders) with DNSSEC, monthly root-hints refresh timer, optional LAN service; becomes the system resolver only after it answers |
| DNS | Mail DNS | MX, PTR + forward-confirmation, Spamhaus/SpamCop listing, SPF (incl. 10-lookup limit), DMARC, DKIM (common + your selectors), MTA-STS policy, TLS-RPT, BIMI, DANE; plus a quick record lookup |
| Storage | Disk benchmark | CrystalDiskMark-style fio tests (SEQ1M Q8, RND4K Q32/Q1, read/write) with MB/s, IOPS, avg and p99 latency; dd fallback |

### Firewall notes

- **firewalld** (RHEL default): changes are applied to runtime *and* permanent
  config, so no reload is needed and nothing is lost on reboot. "Auto-close after"
  uses firewalld's own `--timeout` (runtime only).
- **nftables** (when firewalld is not running): opening inserts an `accept` rule
  into the input chain whose policy is `drop`; closing deletes or narrows the
  accept rule (`{ 22, 80, 443 }` → `{ 22, 443 }`, `8000-8100` → `8000-8049` +
  `8051-8100`, applied as one atomic nft transaction). With no filtering chain,
  closing adds a drop rule to a small `inet servctl` table. "Keep after reboot"
  saves the ruleset to `/etc/sysconfig/nftables.conf` (RHEL) or
  `/etc/nftables.conf` (validated first, previous file backed up).
- While firewalld is running its nftables tables are shown read-only.

### Why Unbound for Spamhaus

Spamhaus refuses DNSBL queries that come through large public resolvers
(8.8.8.8, 1.1.1.1, …) and answers `127.255.255.254` instead. A local Unbound
that recurses from the root servers queries Spamhaus directly from your IP. The
DNS benchmark and Unbound self-test both show whether Spamhaus works.

## Install

```bash
unzip servctl-*.zip && cd servctl-*/
sudo ./install.sh          # venv in /opt/servctl, command: servctl
sudo servctl               # or: servctl --dry-run (safe look-around, no root needed)
```

Needs Python ≥ 3.9 (RHEL 9's system python works). `install.sh` pulls `textual`,
`dnspython` and `PyYAML` into the venv. Tools such as fio, iperf3, unbound or the
Ookla CLI are installed from inside the app when you need them.

## Keys

| Key | Action |
|---|---|
| ↑/↓ in sidebar | switch module |
| Enter | jump into the module's first field |
| Esc | back to the menu |
| Tab / Shift+Tab | move between fields |
| Ctrl+P | command palette (jump to any module, change theme) |
| F2 | toggle dry-run / live |
| F3 | show/hide the log panel |
| F4 | clear log |
| F5 | refresh the current screen |
| Ctrl+Q | quit |

## Appearance

- Themes: pick one in **Settings** (live preview) or Ctrl+P > *Change theme*.
  Default is `tokyo-night`.
- Animations: shimmering gradient wordmark, a short splash, a bouncing activity
  indicator in the top bar while anything runs, slide-in when opening a module,
  and count-up speed test results. Turn them off in Settings (`ui.animations`)
  for slow SSH links.
- Only classic terminal characters are drawn (ASCII, `┌─┐│`, `░▒▓█`), so it
  renders in PuTTY, Windows consoles and minimal fonts without `□` boxes.

### Colours look washed out or basic?

PuTTY and some SSH clients send `TERM=xterm`, which limits apps to 16 colours.
servctl upgrades plain `xterm` to 256 colours automatically (`ui.colors: auto`).
You can force a mode in Settings or the config (`16`, `256`, `truecolor`). In
PuTTY, setting *Connection > Data > Terminal-type string* to `xterm-256color`
fixes it for every app.

## Configuration

`/etc/servctl/config.yml` when run as root, else `~/.config/servctl/config.yml`
(override with `--config` or `$SERVCTL_CONFIG`). Created by the Settings screen.

```yaml
modules:
  enabled: [overview, cleanup, journald, unbound, maildns, dnsbench, settings]
ui:
  theme: tokyo-night
  colors: auto          # auto | 16 | 256 | truecolor
  animations: true
  splash: true
  dry_run: false
  show_log: false
speedtest: {url: https://speed.cloudflare.com, download_mb: 100, upload_mb: 25, streams: 4}
disk: {dir: /var/tmp, size: 1G, runtime: 10}
iperf: {port: 5201, timeout_min: 15}
dns:
  extra_resolvers: ["Office=10.0.0.53"]
  dkim_selectors: [mail2024]
plugins:
  dir: /etc/servctl/plugins
  trusted: [who]
```

Command-line overrides:

```bash
servctl --list-modules
servctl --modules unbound,maildns     # show only these, ignoring the config
```

## Plugins

A plugin is a Python file in `plugins.dir` defining `MODULES = [Module(...)]`
with a `Pane` subclass. It gets the same plan/confirm/dry-run/rollback engine as
the built-ins. Plugins load only when listed in `plugins.trusted`, and are refused
if not owned by root or group/world writable. See `examples/plugins/who.py`.

## Development

```bash
python3 -m unittest -v tests.test_plans tests.test_v2 tests.test_v4
# real-tool checks run when available: rsyslogd, logrotate, unbound, fio, nft (root), local MariaDB;
# firewalld flows use tests/fakes/firewall-cmd
./release.sh                                            # builds dist/servctl-<version>.zip
```
