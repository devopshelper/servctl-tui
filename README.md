# servctl

A terminal UI control plane for routine Linux server administration, aimed at
RHEL 9 (Rocky/Alma too) and also usable on Debian/Ubuntu.

Every action is turned into a **plan** of exact commands and file writes. You see
the plan before anything runs, you can run it as a **dry-run**, and changed files
are backed up to `/var/backups/servctl/<timestamp>/`. If any step fails, the files
that plan changed are restored automatically.

## Install

```bash
unzip servctl-*.zip && cd servctl-*/
sudo ./install.sh          # venv in /opt/servctl, command: servctl
sudo servctl               # or: servctl --dry-run (safe look-around, no root needed)
```

Needs Python ≥ 3.9 (RHEL 9's system python works) and the `textual` package (installed by `install.sh`).

## Keys

| Key | Action |
|---|---|
| F2 | toggle dry-run / live |
| F3 | show/hide the log panel |
| F4 | clear log |
| F5 | refresh the current tab |
| Ctrl+P | command palette |
| Ctrl+Q | quit |

## Development

```bash
python3 -m unittest -v tests.test_plans   # unit tests (validates configs with rsyslogd/logrotate if installed)
./release.sh                              # builds dist/servctl-<version>.zip
```
