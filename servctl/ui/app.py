"""The application shell: top bar, sidebar of enabled modules, content area, log, palette."""
from __future__ import annotations

import itertools
import platform
import time
from functools import partial
from typing import Any, Callable, Dict, Iterable, List, Optional

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import ContentSwitcher, Footer, OptionList, RichLog, Static
from textual.widgets.option_list import Option

from .. import __version__
from ..config import Config
from ..core import Step, is_root, os_info, run_plan
from ..registry import BUILTIN, CATEGORIES, Module, load_plugins, resolve_enabled
from .admin import (CleanupPane, JournaldPane, LogrotatePane, OverviewPane, SiemPane,
                    SyncthingPane)
from .base import CSS, ConfirmScreen, Pane, PaneHeader
from .firewall import FirewallPane
from .mariadb import MariaDbPane
from .fx import Activity, Brand, Splash, slide_in
from .net import DiskPane, DnsBenchPane, IperfPane, MailDnsPane, SpeedtestPane, UnboundPane
from .settings import SettingsPane

PANES: Dict[str, type] = {
    "overview": OverviewPane, "cleanup": CleanupPane, "logrotate": LogrotatePane,
    "journald": JournaldPane, "siem": SiemPane, "syncthing": SyncthingPane,
    "speedtest": SpeedtestPane, "iperf": IperfPane, "dnsbench": DnsBenchPane,
    "unbound": UnboundPane, "maildns": MailDnsPane, "disk": DiskPane, "settings": SettingsPane,
    "firewall": FirewallPane, "mariadb": MariaDbPane,
}

DEFAULT_THEME = "tokyo-night"


class ServctlApp(App):
    CSS = CSS
    TITLE = "servctl"
    BINDINGS = [
        Binding("escape", "focus_sidebar", "Menu"),
        Binding("f2", "toggle_dry_run", "Dry-run"),
        Binding("f3", "toggle_log", "Log"),
        Binding("f4", "clear_log", "Clear log", show=False),
        Binding("f5", "refresh", "Refresh"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self, dry_run: bool = False, cfg: Optional[Config] = None,
                 pinned: Optional[List[str]] = None) -> None:
        super().__init__()
        self.cfg = cfg or Config()
        self.dry_run = dry_run or bool(self.cfg.get("ui.dry_run"))
        self.animations = bool(self.cfg.get("ui.animations", True))
        self.pinned = pinned
        self.busy = False
        self.running: Dict[int, str] = {}
        self._ids = itertools.count()
        builtin = []
        for m in BUILTIN:
            m.pane = PANES[m.id]
            builtin.append(m)
        plugins, self.plugin_messages = load_plugins(self.cfg.get("plugins.dir"),
                                                     self.cfg.get("plugins.trusted") or [])
        self.all_modules: List[Module] = builtin + plugins

    # ------------------------------------------------------------------ layout

    def enabled_modules(self) -> List[Module]:
        wanted = self.pinned if self.pinned is not None else self.cfg.get("modules.enabled")
        return resolve_enabled(self.all_modules, wanted)

    def compose(self) -> ComposeResult:
        with Horizontal(id="topbar"):
            yield Brand(" servctl ", id="brand")
            yield Static(Text(f"{platform.node()}  ·  {os_info().pretty}"), id="hostinfo")
            yield Activity(id="activity")
            yield Static(id="mode")
            yield Static(id="clock")
        with Horizontal(id="body"):
            yield OptionList(id="sidebar")
            yield ContentSwitcher(id="content")
        log = RichLog(id="log", wrap=True, markup=False, highlight=False, max_lines=5000,
                      classes="" if self.cfg.get("ui.show_log") else "hidden")
        log.border_title = "Activity log  (F3 hide · F4 clear)"
        yield log
        yield Footer()

    def on_mount(self) -> None:
        theme = self.cfg.get("ui.theme") or DEFAULT_THEME
        self.theme = theme if theme in self.available_themes else DEFAULT_THEME
        self.theme_changed_signal.subscribe(self, self._theme_changed)
        self._update_mode()
        self._tick_clock()
        self.set_interval(15, self._tick_clock)
        self._build_sidebar()
        self.log_line(f"servctl {__version__} - every change shows its exact commands before running. "
                      "Changed files are backed up to /var/backups/servctl.", "bold")
        if self.cfg.error:
            self.log_line(self.cfg.error, "red")
            self.notify(self.cfg.error, severity="error", timeout=10)
        for msg in self.plugin_messages:
            self.log_line(msg, "dim")
        if not is_root() and not self.dry_run:
            self.dry_run = True
            self._update_mode()
            self.notify("Not running as root: dry-run mode enabled (F2 to toggle).",
                        severity="warning", timeout=8)
        if not self.cfg.exists:
            self.goto("settings")
            self.notify("First run: choose the modules you want, then Save.", timeout=10)
        else:
            self.goto(self.enabled_modules()[0].id)
        self.query_one("#sidebar").focus()
        if self.animations and self.cfg.get("ui.splash", True):
            self.push_screen(Splash(__version__))

    def _tick_clock(self) -> None:
        self.query_one("#clock", Static).update(time.strftime("%H:%M"))

    def _theme_changed(self, theme) -> None:
        # Persist themes picked from the command palette too.
        if self.cfg.exists and self.cfg.get("ui.theme") != theme.name:
            self.cfg.set("ui.theme", theme.name)
            try:
                self.cfg.save()
            except OSError:
                pass

    def _build_sidebar(self) -> None:
        sidebar = self.query_one("#sidebar", OptionList)
        sidebar.clear_options()
        mods = self.enabled_modules()
        options: List[Option] = []
        for cat in CATEGORIES:
            in_cat = [m for m in mods if m.category == cat and m.id != "settings"]
            if not in_cat:
                continue
            if options:
                options.append(Option(" ", disabled=True))
            options.append(Option(Text(f" {cat.upper()}", style="bold dim"), disabled=True))
            options += [Option(f"   {m.title}", id=m.id) for m in in_cat]
        options.append(Option(" ", disabled=True))
        options.append(Option(Text(" " + "─" * 24, style="dim"), disabled=True))
        options.append(Option("   Settings", id="settings"))
        sidebar.add_options(options)

    def _module(self, mid: str) -> Optional[Module]:
        return next((m for m in self.all_modules if m.id == mid), None)

    def goto(self, mid: str) -> None:
        sidebar = self.query_one("#sidebar", OptionList)
        try:
            sidebar.highlighted = sidebar.get_option_index(mid)
        except Exception:
            pass
        self.call_later(self.show, mid)

    @on(OptionList.OptionHighlighted, "#sidebar")
    async def _highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option.id:
            await self.show(event.option.id)

    @on(OptionList.OptionSelected, "#sidebar")
    async def _selected(self, event: OptionList.OptionSelected) -> None:
        # Enter on a menu entry jumps into that module's first field.
        if event.option.id:
            pane = await self.show(event.option.id)
            if pane is not None:
                target = next(iter(pane.query("Input, Select, Checkbox, Button, DataTable")), None)
                (target or pane).focus()

    async def show(self, mid: str) -> Optional[Pane]:
        """Switch the content area to a module, building it on first use.

        Runs in the app's message loop (not a cancellable worker), so a pane is
        always either fully switched to or still hidden - never left stacked
        under another one.
        """
        module = self._module(mid)
        if module is None:
            return None
        switcher = self.query_one("#content", ContentSwitcher)
        wid = f"mod-{mid}".replace(".", "_")
        found = switcher.query(f"#{wid}")
        if found:
            pane = found.first()
        else:
            pane = module.pane(id=wid)
            pane.display = False
            await switcher.mount(pane)
            await pane.mount(PaneHeader(module.title, module.description), before=0)
        if switcher.current != wid:
            switcher.current = wid
            slide_in(pane)
        return pane

    def save_settings(self, enabled: List[str], prefs: Dict[str, Any]) -> None:
        self.cfg.set("modules.enabled", enabled)
        for key, value in prefs.items():
            self.cfg.set(f"ui.{key}", value)
        try:
            self.cfg.save()
        except OSError as exc:
            self.notify(f"Could not save {self.cfg.path}: {exc}", severity="error")
            return
        self.animations = bool(prefs.get("animations", self.animations))
        if prefs.get("theme") and prefs["theme"] in self.available_themes:
            self.theme = prefs["theme"]
        if self.pinned is None:
            keep = {f"mod-{m.id}".replace(".", "_") for m in self.enabled_modules()}
            for child in list(self.query_one("#content", ContentSwitcher).children):
                if child.id not in keep:
                    child.remove()
            self._build_sidebar()
            self.goto("settings")
        self.notify(f"Saved {self.cfg.path}")

    def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
        yield from super().get_system_commands(screen)
        for m in self.enabled_modules():
            yield SystemCommand(f"Open: {m.title}", m.description, partial(self.goto, m.id))
        yield SystemCommand("Toggle dry-run", "Switch between dry-run and live mode",
                            self.action_toggle_dry_run)

    # ------------------------------------------------------------------ running things

    def _update_mode(self) -> None:
        badge = self.query_one("#mode", Static)
        badge.update("DRY-RUN" if self.dry_run else "LIVE")
        badge.set_class(self.dry_run, "dry")
        badge.set_class(not self.dry_run, "live")
        self.sub_title = ("DRY-RUN" if self.dry_run else "LIVE") + (" · root" if is_root() else " · non-root")

    def _set_running(self, key: int, title: Optional[str]) -> None:
        if title is None:
            self.running.pop(key, None)
        else:
            self.running[key] = title
        self.query_one("#brand", Brand).busy = bool(self.running)

    def log_line(self, text: str, style: str = "") -> None:
        self.query_one("#log", RichLog).write(Text(text, style=style))

    def execute(self, title: str, steps: List[Step], on_done: Optional[Callable[[], None]]) -> None:
        if not steps:
            self.notify("Nothing selected.", severity="warning")
            return
        if self.busy:
            self.notify("Another change is still running.", severity="warning")
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
        key = next(self._ids)
        self.call_from_thread(self._set_running, key, title)
        emit = lambda msg, style="": self.call_from_thread(self.log_line, msg, style)
        emit(f"► {title}{' (dry-run)' if dry_run else ''}", "bold magenta")
        try:
            ok = run_plan(steps, emit, dry_run=dry_run)
        except Exception as exc:  # never let a worker crash the UI
            emit(f"Unexpected error: {exc!r}", "bold red")
            ok = False
        self.busy = False
        self.call_from_thread(self._set_running, key, None)
        self.call_from_thread(self.notify, f"{title}: {'finished' if ok else 'FAILED - see log'}",
                              severity="information" if ok else "error")
        if on_done:
            self.call_from_thread(on_done)

    def start_task(self, title: str, fn: Callable[[Callable[[str, str], None]], Any],
                   on_done: Optional[Callable[[Any], None]] = None) -> None:
        self._task_worker(title, fn, on_done)

    @work(thread=True)
    def _task_worker(self, title: str, fn: Callable, on_done: Optional[Callable[[Any], None]]) -> None:
        key = next(self._ids)
        self.call_from_thread(self._set_running, key, title)
        emit = lambda msg, style="": self.call_from_thread(self.log_line, msg, style)
        emit(f"► {title}", "bold blue")
        result = None
        try:
            result = fn(emit)
            self.call_from_thread(self.notify, f"{title}: done")
        except Exception as exc:
            emit(f"{title} failed: {exc}", "bold red")
            self.call_from_thread(self.notify, f"{title} failed: {exc}", severity="error", timeout=8)
        self.call_from_thread(self._set_running, key, None)
        if on_done:
            self.call_from_thread(on_done, result)

    # ------------------------------------------------------------------ actions

    def action_focus_sidebar(self) -> None:
        self.query_one("#sidebar").focus()

    def action_toggle_dry_run(self) -> None:
        self.dry_run = not self.dry_run
        self._update_mode()
        self.notify("Dry-run ON" if self.dry_run else "LIVE mode: actions will change the system",
                    severity="information" if self.dry_run else "warning")

    def action_toggle_log(self) -> None:
        self.query_one("#log").toggle_class("hidden")

    def action_clear_log(self) -> None:
        self.query_one("#log", RichLog).clear()

    def action_refresh(self) -> None:
        switcher = self.query_one("#content", ContentSwitcher)
        if switcher.current:
            pane = switcher.query_one(f"#{switcher.current}")
            if isinstance(pane, Pane):
                pane.refresh_info()
