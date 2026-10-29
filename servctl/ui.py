"""Textual front-end."""
from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Callable, Dict, List, Optional

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (Button, Checkbox, Footer, Header, Input, Label, RichLog, Rule,
                             Select, Static, TabbedContent, TabPane)

from . import __version__, cleanup, logs, siem, syncthing
from .core import (Step, capture, default_user, is_root, os_info, read_text, run_plan,
                   selinux_enforcing, tcp_check, which)

CSS = """
Screen { layout: vertical; }
TabbedContent { height: 1fr; }
#log { height: 12; border: round $accent; }  /* hidden until an action runs; F3 toggles */
#log.hidden { display: none; }
.pane { padding: 0 1; }
.section { text-style: bold; color: $accent; margin: 1 0 0 0; }
.hint { color: $text-muted; margin: 0 0 1 0; }
.row { height: auto; }
.row > .lbl { width: 24; padding: 1 1 0 0; }
.row > Input, .row > Select { width: 1fr; max-width: 60; }
.checks { layout: grid; grid-size: 3; grid-rows: 3; height: auto; grid-gutter: 0 1; }
.buttons { height: auto; margin: 1 0; }
.buttons Button { margin: 0 1 0 0; }
.info { border: round $primary-darken-2; padding: 0 1; height: auto; max-height: 20;
        overflow-y: auto; }
.warn { color: $warning; text-style: bold; }

ConfirmScreen { align: center middle; }
#dialog { width: 90%; max-width: 120; height: 85%; border: thick $warning;
          background: $surface; padding: 1 2; }
#dialog-title { text-style: bold; }
#dialog-plan { height: 1fr; border: round $primary-darken-2; margin: 1 0; }
#dialog-buttons { height: auto; align-horizontal: right; }
#dialog-buttons Button { margin-left: 2; }
"""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def row(label: str, widget) -> Horizontal:
    return Horizontal(Label(label, classes="lbl"), widget, classes="row")


def section(title: str, hint: str = "") -> List[Static]:
    out = [Static(title, classes="section")]
    if hint:
        out.append(Static(hint, classes="hint"))
    return out


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, steps: List[Step], dry_run: bool) -> None:
        super().__init__()
        self.plan_title = title
        self.steps = steps
        self.dry_run = dry_run

    def compose(self) -> ComposeResult:
        body = "\n\n".join(f"{i}. {s.title}{'  (failure tolerated)' if s.allow_fail else ''}\n"
                           f"{s.describe()}" for i, s in enumerate(self.steps, 1))
        mode = ("DRY-RUN: commands are only printed, nothing is changed." if self.dry_run else
                "LIVE: these commands will run as " + ("root." if is_root() else "a non-root user!"))
        with Vertical(id="dialog"):
            yield Label(self.plan_title, id="dialog-title")
            yield Label(mode, classes="hint" if self.dry_run else "warn")
            with VerticalScroll(id="dialog-plan"):
                yield Static(Text(body))
            with Horizontal(id="dialog-buttons"):
                yield Button("Cancel", id="no")
                yield Button("Dry-run" if self.dry_run else "Run", id="yes",
                             variant="primary" if self.dry_run else "error")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    @on(Button.Pressed)
    def _pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_cancel(self) -> None:
        self.dismiss(False)


class Pane(VerticalScroll):
    """Base for each tab: value helpers, plan submission, async info refresh."""

    DEFAULT_CLASSES = "pane"

    def val(self, wid: str) -> str:
        return self.query_one(f"#{wid}", Input).value.strip()

    def num(self, wid: str, what: str) -> int:
        v = self.val(wid)
        if not v.lstrip("-").isdigit():
            raise ValueError(f"{what} must be a whole number")
        return int(v)

    def chk(self, wid: str) -> bool:
        return self.query_one(f"#{wid}", Checkbox).value

    def sel(self, wid: str):
        return self.query_one(f"#{wid}", Select).value

    def set_val(self, wid: str, value) -> None:
        self.query_one(f"#{wid}", Input).value = "" if value in (None, 0) else str(value)

    def submit(self, title: str, build: Callable[[], List[Step]],
               on_done: Optional[Callable[[], None]] = None) -> None:
        try:
            steps = build()
        except ValueError as exc:
            self.app.notify(str(exc), title="Invalid input", severity="error")
            return
        self.app.execute(title, steps, on_done or self.refresh_info)

    def set_info(self, wid: str, text: str) -> None:
        self.app.call_from_thread(self.query_one(f"#{wid}", Static).update, Text(text))

    def on_mount(self) -> None:
        self.refresh_info()

    def refresh_info(self) -> None:  # overridden
        pass


def _cmd_block(argv: List[str], title: Optional[str] = None) -> str:
    rc, out = capture(argv)
    return f"── {title or ' '.join(argv)} ──\n{out}"


# --------------------------------------------------------------------------- #
# Tabs
# --------------------------------------------------------------------------- #

class OverviewPane(Pane):
    def compose(self) -> ComposeResult:
        yield from section("Host overview", "F5 refreshes the current tab.")
        yield Static("loading…", id="ov-info", classes="info")

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        osi = os_info()
        lines = [
            f"Host     : {platform.node()}",
            f"OS       : {osi.pretty}   kernel {platform.release()}",
            f"Uptime   : {capture(['uptime', '-p'])[1]}",
            f"Running as {'root' if is_root() else 'NON-ROOT (changes need sudo)'}"
            f"   SELinux: {capture(['getenforce'])[1] if which('getenforce') else 'n/a'}",
            "",
        ]
        svc = ["docker", "podman", "rsyslog", "systemd-journald", "firewalld"]
        states = []
        for s in svc:
            rc, out = capture(["systemctl", "is-active", s], 5)
            states.append(f"{s}={out.splitlines()[-1] if out else '?'}")
        lines.append("Services : " + "  ".join(states))
        rc, out = capture(["systemctl", "list-units", "syncthing@*", "--no-legend", "--plain"], 5)
        lines.append("Syncthing: " + (", ".join(l.split()[0] + "=" + l.split()[2]
                                               for l in out.splitlines() if l.strip()) or "none"))
        lines.append("")
        lines.append(_cmd_block(["df", "-h", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay",
                                 "-x", "squashfs"], "disk"))
        lines.append(_cmd_block(["free", "-h"], "memory"))
        lines.append(_cmd_block(["journalctl", "--disk-usage"], "journal"))
        self.set_info("ov-info", "\n".join(lines))


class CleanupPane(Pane):
    def compose(self) -> ComposeResult:
        engine = cleanup.container_engine()
        yield from section(f"Containers ({engine or 'docker/podman not found'})",
                           "Prunes only what is not used by any container. Volumes hold data: "
                           "off by default.")
        yield Static("loading…", id="cl-df", classes="info")
        with Grid(classes="checks"):
            yield Checkbox("Stopped containers", True, id="cl-containers")
            yield Checkbox("Dangling images", True, id="cl-images")
            yield Checkbox("ALL unused images", False, id="cl-allimages")
            yield Checkbox("Unused networks", True, id="cl-networks")
            yield Checkbox("Unused volumes", False, id="cl-volumes")
            yield Checkbox("…incl. named volumes", False, id="cl-allvolumes")
            yield Checkbox("Build cache", True, id="cl-build")
        yield row("Only older than", Input(placeholder="e.g. 24h (blank = everything)",
                                           id="cl-until"))
        with Horizontal(classes="buttons"):
            yield Button("Run container cleanup", id="cl-run-containers", variant="warning",
                         disabled=engine is None)

        yield Rule()
        yield from section("Host housekeeping")
        yield Static("loading…", id="cl-du", classes="info")
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
        self.set_info("cl-df", _cmd_block([engine, "system", "df"]) if engine else
                      "No container engine installed.")
        dirs = [d for d in ("/var/cache/dnf", "/var/cache/apt", "/var/log",
                            "/var/lib/systemd/coredump", "/var/crash", "/tmp", "/var/tmp")
                if os.path.isdir(d)]
        self.set_info("cl-du", _cmd_block(["du", "-sh", "--one-file-system", *dirs], "usage"))

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
        yield row("Rule file", Select([("➕ new rule", NEW)], value=NEW, allow_blank=False,
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
        sel.set_options([("➕ new rule", NEW)] + [(f, f) for f in files])
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
        yield Static("loading…", id="jd-info", classes="info")
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
        self.set_info("jd-info", _cmd_block(["journalctl", "--disk-usage"], "usage") +
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
        yield Static("loading…", id="st-info", classes="info")
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
            parts.append(_cmd_block(["systemctl", "--no-pager", "status", "-n", "5",
                                     f"syncthing@{user}.service"], f"syncthing@{user}"))
        if which("firewall-cmd"):
            parts.append(_cmd_block(["firewall-cmd", "--list-ports"], "firewalld open ports"))
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
        yield Static("loading…", id="sm-info", classes="info")
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
            lines.append(_cmd_block(["du", "-sh", "/var/lib/rsyslog"], "disk buffer"))
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


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #

class ServctlApp(App):
    CSS = CSS
    TITLE = "servctl"
    BINDINGS = [
        Binding("f2", "toggle_dry_run", "Dry-run"),
        Binding("f3", "toggle_log", "Log"),
        Binding("f4", "clear_log", "Clear log"),
        Binding("f5", "refresh", "Refresh"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__()
        self.dry_run = dry_run
        self.busy = False

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="tab-overview"):
            tabs: Dict[str, type] = {
                "Overview": OverviewPane, "Cleanup": CleanupPane, "Logrotate": LogrotatePane,
                "Journald": JournaldPane, "Syncthing": SyncthingPane, "SIEM": SiemPane,
            }
            for title, cls in tabs.items():
                with TabPane(title, id=f"tab-{title.lower()}"):
                    yield cls()
        yield RichLog(id="log", wrap=True, markup=False, highlight=False, max_lines=5000,
                      classes="hidden")
        yield Footer()

    def on_mount(self) -> None:
        self._update_subtitle()
        self.log_line(f"servctl {__version__} - every action shows its exact commands before "
                      "running. File changes are backed up to /var/backups/servctl.", "bold")
        if not is_root() and not self.dry_run:
            self.dry_run = True
            self._update_subtitle()
            self.log_line("Not running as root: dry-run mode enabled (F2 to toggle).", "yellow")
            self.notify("Not running as root: dry-run mode enabled (F2 to toggle).",
                        severity="warning", timeout=8)

    def _update_subtitle(self) -> None:
        self.sub_title = ("DRY-RUN" if self.dry_run else "LIVE") + (" · root" if is_root() else " · non-root")

    def log_line(self, text: str, style: str = "") -> None:
        self.query_one("#log", RichLog).write(Text(text, style=style))

    def execute(self, title: str, steps: List[Step], on_done: Optional[Callable[[], None]]) -> None:
        if not steps:
            self.notify("Nothing selected.", severity="warning")
            return
        if self.busy:
            self.notify("Another action is still running.", severity="warning")
            return

        def confirmed(ok: Optional[bool]) -> None:
            if ok:
                self.busy = True
                self.query_one("#log").remove_class("hidden")
                self._run(title, steps, self.dry_run, on_done)

        self.push_screen(ConfirmScreen(title, steps, self.dry_run), confirmed)

    @work(thread=True)
    def _run(self, title: str, steps: List[Step], dry_run: bool,
             on_done: Optional[Callable[[], None]]) -> None:
        emit = lambda msg, style="": self.call_from_thread(self.log_line, msg, style)
        emit(f"▶ {title}{' (dry-run)' if dry_run else ''}", "bold magenta")
        try:
            ok = run_plan(steps, emit, dry_run=dry_run)
        except Exception as exc:  # never let a worker crash the UI
            emit(f"Unexpected error: {exc!r}", "bold red")
            ok = False
        self.busy = False
        self.call_from_thread(self.notify, f"{title}: {'finished' if ok else 'FAILED - see log'}",
                              severity="information" if ok else "error")
        if on_done:
            self.call_from_thread(on_done)

    def action_toggle_dry_run(self) -> None:
        self.dry_run = not self.dry_run
        self._update_subtitle()
        self.notify("Dry-run ON" if self.dry_run else "LIVE mode: actions will change the system",
                    severity="information" if self.dry_run else "warning")

    def action_toggle_log(self) -> None:
        self.query_one("#log").toggle_class("hidden")

    def action_clear_log(self) -> None:
        self.query_one("#log", RichLog).clear()

    def action_refresh(self) -> None:
        active = self.query_one(TabbedContent).active_pane
        if active is not None:
            for pane in active.query(Pane):
                pane.refresh_info()
