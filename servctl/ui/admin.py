"""Panes for the original admin modules: overview, cleanup, logs, Syncthing, SIEM."""
from __future__ import annotations

import os
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Grid, Horizontal
from textual.widgets import Button, Checkbox, Input, Rule, Select, Static

from .. import cleanup, logs, siem, syncthing, sysinfo
from ..core import (capture, default_user, is_root, os_info, read_text, selinux_enforcing,
                    tcp_check, which)
from .base import Pane, cmd_block, row, section


SERVICES = ["sshd", "firewalld", "rsyslog", "systemd-journald", "chronyd", "unbound", "docker",
            "podman", "NetworkManager", "systemd-resolved"]


def _card(title: str, cid: str) -> Static:
    w = Static("loading...", id=cid, classes="card")
    w.border_title = title
    return w


class OverviewPane(Pane):
    """Dashboard of cards that refreshes itself every few seconds while visible."""

    def compose(self) -> ComposeResult:
        with Grid(id="ov-grid"):
            yield _card("Host", "ov-host")
            yield _card("Services", "ov-svc")
            yield _card("Load & memory", "ov-mem")
            yield _card("Disks", "ov-disks")
        yield Static("F5 refresh  ·  Ctrl+P command palette  ·  Esc back to the menu  ·  F2 dry-run",
                     classes="hint")

    def on_mount(self) -> None:
        self.set_interval(5, self._auto)

    def _auto(self) -> None:
        if self.display and self.app.screen is self.screen:
            self.refresh_info()

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        h = sysinfo.host_summary()
        se = capture(["getenforce"])[1] if which("getenforce") else "n/a"
        host = Text()
        for k, v in (("host", h["host"]), ("os", h["os"]), ("kernel", f"{h['kernel']} ({h['arch']})"),
                     ("uptime", sysinfo.uptime()), ("selinux", se),
                     ("user", "root" if is_root() else "non-root (dry-run only)")):
            host.append(f"{k:<8}", style="dim")
            host.append(f"{v}\n")
        self.ui(self.query_one("#ov-host", Static).update, host)

        l1, l5, l15 = sysinfo.load()
        cpus = os.cpu_count() or 1
        used, total, sused, stotal = sysinfo.memory()
        mem = Text()
        lp = 100 * l1 / cpus
        mem.append(f"{'load':<6}", style="dim")
        mem.append(f"{l1:.2f} {l5:.2f} {l15:.2f}", style=sysinfo.pct_color(lp))
        mem.append(f"  ({cpus} CPUs)\n", style="dim")
        self._bar(mem, "cpu", lp, f"1-min load vs {cpus} CPUs")
        self._bar(mem, "mem", 100 * used / total if total else 0,
                  f"{sysinfo.human(used)} / {sysinfo.human(total)}")
        if stotal:
            self._bar(mem, "swap", 100 * sused / stotal, f"{sysinfo.human(sused)} / {sysinfo.human(stotal)}")
        self.ui(self.query_one("#ov-mem", Static).update, mem)

        dk = Text()
        for d in sysinfo.disks()[:8]:
            mount = d.mount if len(d.mount) <= 18 else "~" + d.mount[-17:]
            self._bar(dk, mount, d.pct, f"{sysinfo.human(d.used)} / {sysinfo.human(d.total)}  {d.fstype}",
                      width=30, label_w=19)
        self.ui(self.query_one("#ov-disks", Static).update, dk if dk.plain else Text("no disks found"))

        states = sysinfo.services(SERVICES)
        failed = sysinfo.failed_units()
        sv = Text()
        shown = [(n, st) for n, st in states.items() if st not in ("inactive", "unknown")] or list(states.items())
        for name, st in shown:
            mark, style = {"active": ("[ up ]", "green"), "failed": ("[FAIL]", "bold red"),
                           "activating": ("[ .. ]", "yellow")}.get(st, ("[ -- ]", "dim"))
            sv.append(mark + " ", style=style)
            sv.append(f"{name}\n")
        sv.append(f"\n{len(failed)} failed unit(s)", style="bold red" if failed else "green")
        if failed:
            sv.append(": " + ", ".join(failed[:5]), style="red")
        self.ui(self.query_one("#ov-svc", Static).update, sv)

    @staticmethod
    def _bar(t: Text, label: str, pct: float, detail: str, width: int = 30, label_w: int = 6) -> None:
        full, empty = sysinfo.bar(pct, width)
        t.append(f"{label:<{label_w}}", style="dim")
        t.append(full, style=sysinfo.pct_color(pct))
        t.append(empty, style="dim")
        t.append(f" {pct:>3.0f}%  ", style="bold " + sysinfo.pct_color(pct))
        t.append(detail + "\n", style="dim")


class CleanupPane(Pane):
    def compose(self) -> ComposeResult:
        engine = cleanup.container_engine()
        yield from section(f"Containers ({engine or 'docker/podman not found'})",
                           "Prunes only what is not used by any container. Volumes hold data: "
                           "off by default.")
        yield Static("loading...", id="cl-df", classes="info")
        with Grid(classes="checks"):
            yield Checkbox("Stopped containers", True, id="cl-containers")
            yield Checkbox("Dangling images", True, id="cl-images")
            yield Checkbox("ALL unused images", False, id="cl-allimages")
            yield Checkbox("Unused networks", True, id="cl-networks")
            yield Checkbox("Unused volumes", False, id="cl-volumes")
            yield Checkbox("...incl. named volumes", False, id="cl-allvolumes")
            yield Checkbox("Build cache", True, id="cl-build")
        yield row("Only older than", Input(placeholder="e.g. 24h (blank = everything)",
                                           id="cl-until"))
        with Horizontal(classes="buttons"):
            yield Button("Run container cleanup", id="cl-run-containers", variant="warning",
                         disabled=engine is None)

        yield Rule()
        yield from section("Host housekeeping")
        yield Static("loading...", id="cl-du", classes="info")
        with Grid(classes="checks"):
            yield Checkbox("Package cache", True, id="cl-pkg")
            yield Checkbox("Orphaned packages", False, id="cl-autoremove")
            yield Checkbox("Old kernels", False, id="cl-kernels")
            yield Checkbox("Old rotated logs", True, id="cl-logs")
            yield Checkbox("Old core dumps", True, id="cl-cores")
            yield Checkbox("tmpfiles --clean", True, id="cl-tmp")
        yield row("Kernels to keep", Input("2", id="cl-keep", type="integer"))
        yield row("Rotated logs older than", Input("30", id="cl-logdays", type="integer"))
        yield row("Core dumps older than", Input("7", id="cl-coredays", type="integer"))
        with Horizontal(classes="buttons"):
            yield Button("Run host cleanup", id="cl-run-system", variant="warning")

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        engine = cleanup.container_engine()
        self.set_info("cl-df", cmd_block([engine, "system", "df"]) if engine else
                      "No container engine installed.")
        dirs = [d for d in ("/var/cache/dnf", "/var/cache/apt", "/var/log",
                            "/var/lib/systemd/coredump", "/var/crash", "/tmp", "/var/tmp")
                if os.path.isdir(d)]
        self.set_info("cl-du", cmd_block(["du", "-sh", "--one-file-system", *dirs], "usage"))

    @on(Button.Pressed, "#cl-run-containers")
    def _containers(self) -> None:
        engine = cleanup.container_engine()
        if not engine:
            return
        self.submit("Container cleanup", lambda: cleanup.container_plan(engine, cleanup.ContainerOpts(
            containers=self.chk("cl-containers"), images=self.chk("cl-images") or self.chk("cl-allimages"),
            all_images=self.chk("cl-allimages"), networks=self.chk("cl-networks"),
            volumes=self.chk("cl-volumes") or self.chk("cl-allvolumes"),
            all_volumes=self.chk("cl-allvolumes"), build_cache=self.chk("cl-build"),
            until=self.val("cl-until"))))

    @on(Button.Pressed, "#cl-run-system")
    def _system(self) -> None:
        self.submit("Host housekeeping", lambda: cleanup.system_plan(os_info().pkg, cleanup.SystemOpts(
            pkg_cache=self.chk("cl-pkg"), autoremove=self.chk("cl-autoremove"),
            old_kernels=self.chk("cl-kernels"), keep_kernels=self.num("cl-keep", "Kernels to keep"),
            rotated_logs=self.chk("cl-logs"), log_days=self.num("cl-logdays", "Log age"),
            coredumps=self.chk("cl-cores"), core_days=self.num("cl-coredays", "Core dump age"),
            tmpfiles=self.chk("cl-tmp"))))


NEW = "__new__"


class LogrotatePane(Pane):
    def compose(self) -> ComposeResult:
        yield from section("Per-application rule (/etc/logrotate.d)",
                           "Pick an existing file to change its retention (paths and "
                           "postrotate scripts are kept), or create a new rule.")
        yield row("Rule file", Select([("+ new rule", NEW)], value=NEW, allow_blank=False,
                                      id="lr-file"))
        yield row("Name", Input(placeholder="myapp", id="lr-name"))
        yield row("Log paths", Input(placeholder="/var/log/myapp/*.log /opt/app/logs/*.log",
                                     id="lr-paths"))
        yield row("Rotate", Select([(f, f) for f in logs.FREQUENCIES], value="daily",
                                   allow_blank=False, id="lr-freq"))
        yield row("Keep N rotations", Input("7", id="lr-rotate", type="integer"))
        yield row("Also rotate if bigger", Input(placeholder="e.g. 100M (blank = off)",
                                                 id="lr-maxsize"))
        yield row("Max age (days)", Input(placeholder="blank = off", id="lr-maxage",
                                                    type="integer"))
        with Grid(classes="checks"):
            yield Checkbox("compress", True, id="lr-compress")
            yield Checkbox("delaycompress", True, id="lr-delaycompress")
            yield Checkbox("copytruncate", False, id="lr-copytruncate")
            yield Checkbox("missingok", True, id="lr-missingok")
            yield Checkbox("notifempty", True, id="lr-notifempty")
            yield Checkbox("dateext", True, id="lr-dateext")
        with Horizontal(classes="buttons"):
            yield Button("Apply rule", id="lr-apply", variant="primary")
            yield Button("Force rotate now", id="lr-force")
        yield Static("", id="lr-preview", classes="info")

        yield Rule()
        yield from section("Global defaults (/etc/logrotate.conf)",
                           "Used by every rule that does not set its own value.")
        yield row("Rotate", Select([(f, f) for f in logs.FREQUENCIES], value="weekly",
                                   allow_blank=False, id="lg-freq"))
        yield row("Keep N rotations", Input("4", id="lg-rotate", type="integer"))
        yield row("Also rotate if bigger", Input(placeholder="blank = off", id="lg-maxsize"))
        with Grid(classes="checks"):
            yield Checkbox("compress", False, id="lg-compress")
            yield Checkbox("dateext", True, id="lg-dateext")
        with Horizontal(classes="buttons"):
            yield Button("Apply global defaults", id="lg-apply", variant="primary")

    def refresh_info(self) -> None:
        sel = self.query_one("#lr-file", Select)
        current = sel.value
        try:
            files = sorted(p.name for p in Path(logs.LOGROTATE_DIR).iterdir() if p.is_file())
        except OSError:
            files = []
        sel.set_options([("+ new rule", NEW)] + [(f, f) for f in files])
        sel.value = current if current in files else NEW
        self._load_rule()
        conf = read_text(logs.LOGROTATE_CONF)
        if conf is not None:
            g = logs.parse_settings(conf, block=False)
            self.query_one("#lg-freq", Select).value = g.frequency
            self.set_val("lg-rotate", g.rotate)
            self.set_val("lg-maxsize", g.maxsize)
            self.query_one("#lg-compress", Checkbox).value = g.compress
            self.query_one("#lg-dateext", Checkbox).value = g.dateext

    @on(Select.Changed, "#lr-file")
    def _load_rule(self) -> None:
        name = self.sel("lr-file")
        preview = self.query_one("#lr-preview", Static)
        name_in, paths_in = self.query_one("#lr-name", Input), self.query_one("#lr-paths", Input)
        if name == NEW or not isinstance(name, str):
            name_in.disabled = paths_in.disabled = False
            name_in.value = paths_in.value = ""
            preview.update(Text("New file will be created as /etc/logrotate.d/<name>."))
            return
        text = read_text(f"{logs.LOGROTATE_DIR}/{name}") or ""
        s = logs.parse_settings(text)
        name_in.value, paths_in.value = name, " ".join(logs.parse_paths(text))
        name_in.disabled = paths_in.disabled = True
        self.query_one("#lr-freq", Select).value = s.frequency
        self.set_val("lr-rotate", s.rotate)
        self.set_val("lr-maxsize", s.maxsize)
        self.set_val("lr-maxage", s.maxage)
        for flag in logs.FLAGS:
            self.query_one(f"#lr-{flag}", Checkbox).value = getattr(s, flag)
        preview.update(Text(f"── current {logs.LOGROTATE_DIR}/{name} ──\n{text.rstrip()}"))

    def _settings(self, p: str, full: bool = True) -> logs.RotateSettings:
        maxage = self.val(f"{p}-maxage") if full else ""
        s = logs.RotateSettings(
            frequency=self.sel(f"{p}-freq"), rotate=self.num(f"{p}-rotate", "Keep N rotations"),
            maxsize=self.val(f"{p}-maxsize"), maxage=int(maxage) if maxage else 0,
            compress=self.chk(f"{p}-compress"), dateext=self.chk(f"{p}-dateext"))
        if full:
            for flag in ("delaycompress", "copytruncate", "missingok", "notifempty"):
                setattr(s, flag, self.chk(f"{p}-{flag}"))
        return s

    @on(Button.Pressed, "#lr-apply")
    def _apply(self) -> None:
        name = self.val("lr-name")
        self.submit(f"logrotate rule: {name or '?'}", lambda: logs.logrotate_rule_plan(
            name, self.val("lr-paths").split(), self._settings("lr")))

    @on(Button.Pressed, "#lr-force")
    def _force(self) -> None:
        name = self.sel("lr-file")
        if name == NEW:
            self.app.notify("Pick an existing rule file first", severity="warning")
            return
        self.submit(f"Force rotation: {name}", lambda: logs.logrotate_force_plan(name))

    @on(Button.Pressed, "#lg-apply")
    def _apply_global(self) -> None:
        self.submit("logrotate global defaults",
                    lambda: logs.logrotate_global_plan(self._settings("lg", full=False)))


class JournaldPane(Pane):
    def compose(self) -> ComposeResult:
        yield from section("Current journal", "")
        yield Static("loading...", id="jd-info", classes="info")
        yield from section("Persistent limits",
                           f"Written to {logs.JOURNALD_DROPIN}; journald is restarted. "
                           "Blank fields are left at the system default.")
        examples = {"size": "e.g. 2G", "time": "e.g. 1month, 2weeks, 30d"}
        for key, (label, kind) in logs.JOURNALD_FIELDS.items():
            yield row(label, Input(placeholder=f"{key}  ({examples[kind]})", id=f"jd-{key}"))
        yield Checkbox("Keep journal on disk across reboots (Storage=persistent)", False,
                       id="jd-persistent")
        with Horizontal(classes="buttons"):
            yield Button("Apply limits", id="jd-apply", variant="primary")
            yield Button("Remove servctl limits", id="jd-remove")

        yield Rule()
        yield from section("Vacuum now", "One-off cleanup. Fill one or more.")
        yield row("Shrink to size", Input(placeholder="e.g. 500M", id="jv-size"))
        yield row("Drop entries older than", Input(placeholder="e.g. 2weeks", id="jv-time"))
        yield row("Keep at most N files", Input(placeholder="e.g. 10", id="jv-files",
                                                type="integer"))
        with Horizontal(classes="buttons"):
            yield Button("Vacuum now", id="jv-run", variant="warning")

    def on_mount(self) -> None:
        current = logs.read_journald_dropin()
        for key in logs.JOURNALD_FIELDS:
            self.set_val(f"jd-{key}", current.get(key, ""))
        self.query_one("#jd-persistent", Checkbox).value = current.get("Storage") == "persistent"

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        rc, cfg = capture(["systemd-analyze", "cat-config", "systemd/journald.conf"])
        effective = "\n".join(l for l in cfg.splitlines()
                              if l.strip() and not l.lstrip().startswith("#")) if rc == 0 else cfg
        self.set_info("jd-info", cmd_block(["journalctl", "--disk-usage"], "usage") +
                      "\n── effective settings ──\n" + (effective or "(all defaults)"))

    @on(Button.Pressed, "#jd-apply")
    def _apply(self) -> None:
        self.submit("journald limits", lambda: logs.journald_plan(
            {k: self.val(f"jd-{k}") for k in logs.JOURNALD_FIELDS}, self.chk("jd-persistent")))

    @on(Button.Pressed, "#jd-remove")
    def _remove(self) -> None:
        self.submit("Remove journald limits", logs.journald_remove_plan)

    @on(Button.Pressed, "#jv-run")
    def _vacuum(self) -> None:
        self.submit("Vacuum journal", lambda: logs.vacuum_plan(
            self.val("jv-size"), self.val("jv-time"), self.val("jv-files")))


class SyncthingPane(Pane):
    def compose(self) -> ComposeResult:
        osi = os_info()
        yield from section("Syncthing",
                           "Runs as syncthing@<user>.service. By default the web GUI only "
                           "listens on localhost - reach it with an SSH tunnel: "
                           "ssh -L 8384:localhost:8384 <server>")
        yield Static("loading...", id="st-info", classes="info")
        yield row("Run as user", Input(default_user(), id="st-user"))
        yield row("Install method", Select(
            [("EPEL package (dnf)", "epel"), ("Upstream binary from GitHub", "upstream")],
            value="epel" if osi.rhel_like else "upstream", allow_blank=False, id="st-method"))
        yield row("GUI port", Input("8384", id="st-port", type="integer"))
        yield row("GUI user", Input(placeholder="optional (required for remote GUI)", id="st-guiuser"))
        yield row("GUI password", Input(password=True, id="st-guipass"))
        with Grid(classes="checks"):
            yield Checkbox("Open firewalld ports", True, id="st-firewall")
            yield Checkbox("GUI on all interfaces", False, id="st-remote")
        with Horizontal(classes="buttons"):
            yield Button("Install / configure", id="st-install", variant="primary")
            yield Button("Refresh status", id="st-status")
            yield Button("Stop & disable", id="st-disable")

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        user = self.app.call_from_thread(lambda: self.val("st-user"))
        parts = []
        binary = which("syncthing") or ("/usr/local/bin/syncthing"
                                         if os.path.exists("/usr/local/bin/syncthing") else None)
        parts.append(capture([binary, "--version"])[1] if binary else "syncthing: not installed")
        if user:
            parts.append(cmd_block(["systemctl", "--no-pager", "status", "-n", "5",
                                     f"syncthing@{user}.service"], f"syncthing@{user}"))
        if which("firewall-cmd"):
            parts.append(cmd_block(["firewall-cmd", "--list-ports"], "firewalld open ports"))
        self.set_info("st-info", "\n".join(parts))

    @on(Button.Pressed, "#st-install")
    def _install(self) -> None:
        self.submit("Install Syncthing", lambda: syncthing.install_plan(syncthing.SyncthingOpts(
            user=self.val("st-user"), method=self.sel("st-method"),
            open_firewall=self.chk("st-firewall"), gui_remote=self.chk("st-remote"),
            gui_port=self.num("st-port", "GUI port"), gui_user=self.val("st-guiuser"),
            gui_password=self.query_one("#st-guipass", Input).value), os_info()))

    @on(Button.Pressed, "#st-status")
    def _status(self) -> None:
        self.refresh_info()

    @on(Button.Pressed, "#st-disable")
    def _disable(self) -> None:
        self.submit("Disable Syncthing", lambda: syncthing.disable_plan(self.val("st-user")))


class SiemPane(Pane):
    def compose(self) -> ComposeResult:
        yield from section("Forward logs to a SIEM with rsyslog",
                           f"Config goes to {siem.CONF_PATH}. Logs are buffered on disk while "
                           "the SIEM is unreachable and keep being written locally.")
        yield Static("loading...", id="sm-info", classes="info")
        yield row("SIEM host", Input(placeholder="siem.example.com or 10.0.0.5", id="sm-host"))
        yield row("Protocol", Select([("TCP", "tcp"), ("TLS (TCP + certificates)", "tls"),
                                      ("UDP (may lose messages)", "udp")],
                                     value="tcp", allow_blank=False, id="sm-proto"))
        yield row("Port", Input("514", id="sm-port", type="integer"))
        yield row("Format", Select([("RFC 5424 (structured)", "rfc5424"),
                                    ("RFC 3164 (BSD legacy)", "rfc3164")],
                                   value="rfc5424", allow_blank=False, id="sm-fmt"))
        yield row("TCP framing", Select([("LF-delimited (traditional)", "traditional"),
                                         ("octet-counted", "octet-counted")],
                                        value="traditional", allow_blank=False, id="sm-framing"))
        yield row("What to send", Input("*.info", id="sm-selector"))
        yield row("Also send files", Input(placeholder="/var/log/audit/audit.log (space separated)",
                                           id="sm-files"))
        yield row("Disk buffer max", Input("1g", id="sm-queue"))
        yield from section("TLS only")
        yield row("CA certificate", Input("/etc/pki/tls/certs/ca-bundle.crt", id="sm-ca"))
        yield row("Verify server", Select([("cert + hostname", "x509/name"),
                                           ("cert only", "x509/certvalid"),
                                           ("no verification", "anon")],
                                          value="x509/name", allow_blank=False, id="sm-auth"))
        yield row("Expected cert name", Input(placeholder="defaults to SIEM host", id="sm-peer"))
        with Horizontal(classes="buttons"):
            yield Button("Test connection", id="sm-test")
            yield Button("Apply", id="sm-apply", variant="primary")
            yield Button("Send test message", id="sm-msg")
            yield Button("Remove forwarding", id="sm-remove")

    def on_mount(self) -> None:
        text = read_text(siem.CONF_PATH)
        if text:
            c = siem.parse_config(text)
            for key, wid in (("host", "sm-host"), ("port", "sm-port"), ("selector", "sm-selector"),
                             ("queue_size", "sm-queue"), ("ca_file", "sm-ca"),
                             ("permitted_peer", "sm-peer")):
                if c.get(key):
                    self.set_val(wid, c[key])
            self.set_val("sm-files", " ".join(c["files"]))
            for key, wid in (("protocol", "sm-proto"), ("fmt", "sm-fmt"),
                             ("framing", "sm-framing"), ("auth_mode", "sm-auth")):
                if c.get(key):
                    self.query_one(f"#{wid}", Select).value = c[key]

    @on(Select.Changed, "#sm-proto")
    def _proto(self, event: Select.Changed) -> None:
        port = self.query_one("#sm-port", Input)
        if event.value == "tls" and port.value in ("514", ""):
            port.value = "6514"
        elif event.value != "tls" and port.value == "6514":
            port.value = "514"

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        rc, active = capture(["systemctl", "is-active", "rsyslog"], 5)
        text = read_text(siem.CONF_PATH)
        lines = [f"rsyslog: {active}   SELinux enforcing: {selinux_enforcing()}"]
        if os.path.isdir("/var/lib/rsyslog"):
            lines.append(cmd_block(["du", "-sh", "/var/lib/rsyslog"], "disk buffer"))
        lines.append(f"── {siem.CONF_PATH} ──\n" + (text.rstrip() if text else "(not configured)"))
        self.set_info("sm-info", "\n".join(lines))

    def _opts(self) -> siem.SiemOpts:
        return siem.SiemOpts(
            host=self.val("sm-host"), port=self.num("sm-port", "Port"),
            protocol=self.sel("sm-proto"), fmt=self.sel("sm-fmt"),
            framing=self.sel("sm-framing"), selector=self.val("sm-selector"),
            files=self.val("sm-files").split(), queue_size=self.val("sm-queue"),
            ca_file=self.val("sm-ca"), auth_mode=self.sel("sm-auth"),
            permitted_peer=self.val("sm-peer"))

    @on(Button.Pressed, "#sm-test")
    def _test(self) -> None:
        try:
            o = self._opts()
            o.validate()
        except ValueError as exc:
            self.app.notify(str(exc), severity="error")
            return
        if o.protocol == "udp":
            self.app.notify("UDP is connectionless - use 'Send test message' and check the SIEM.")
            return
        self._tcp_test(o.host, o.port)

    @work(thread=True)
    def _tcp_test(self, host: str, port: int) -> None:
        ok, msg = tcp_check(host, port)
        self.app.call_from_thread(self.app.notify, msg, severity="information" if ok else "error")
        self.app.call_from_thread(self.app.log_line, msg, "green" if ok else "red")

    @on(Button.Pressed, "#sm-apply")
    def _apply(self) -> None:
        self.submit("SIEM forwarding", lambda: siem.apply_plan(self._opts(), os_info().pkg))

    @on(Button.Pressed, "#sm-msg")
    def _msg(self) -> None:
        self.submit("Send test message", siem.test_message_plan)

    @on(Button.Pressed, "#sm-remove")
    def _remove(self) -> None:
        self.submit("Remove SIEM forwarding", siem.remove_plan)


