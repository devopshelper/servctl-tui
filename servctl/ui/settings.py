"""Settings: pick which modules appear in the sidebar, UI preferences, plugin status."""
from __future__ import annotations

import re

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Checkbox, Select, Static

from ..registry import CATEGORIES
from .base import Pane, row, section


def _cid(module_id: str) -> str:
    return "set-" + re.sub(r"[^A-Za-z0-9_-]", "_", module_id)


class SettingsPane(Pane):
    def compose(self) -> ComposeResult:
        app = self.app
        enabled = {m.id for m in app.enabled_modules()}
        hint = f"Saved to {app.cfg.path}."
        if app.pinned is not None:
            hint += "  Started with --modules, so the sidebar ignores these until you restart without it."
        yield from section("Modules", hint)
        for cat in CATEGORIES:
            mods = [m for m in app.all_modules if m.category == cat]
            if not mods:
                continue
            yield Static(cat, classes="section")
            for m in mods:
                yield Checkbox(f"{m.title}  ·  {m.description}", m.id in enabled or m.required,
                               id=_cid(m.id), disabled=m.required)
        yield from section("Appearance & behaviour")
        themes = sorted(t for t in app.available_themes if not t.endswith("-light") and t != "textual-ansi")
        yield row("Theme", Select([(t, t) for t in themes], value=app.theme if app.theme in themes else themes[0],
                                  allow_blank=False, id="set-theme"))
        yield row("Colours", Select([("auto (upgrade plain xterm to 256)", "auto"), ("16 colours", "16"),
                                     ("256 colours", "256"), ("truecolor (24-bit)", "truecolor")],
                                    value=app.cfg.get("ui.colors") or "auto", allow_blank=False,
                                    id="set-colors"))
        yield Static("Colour changes apply on the next start. Themes apply immediately "
                     "(also: Ctrl+P > Change theme).", classes="hint")
        yield Checkbox("Animations (shimmer, spinner, fades)", bool(app.cfg.get("ui.animations", True)),
                       id="set-pref-anim")
        yield Checkbox("Splash screen at start", bool(app.cfg.get("ui.splash", True)), id="set-pref-splash")
        yield Checkbox("Start in dry-run mode", bool(app.cfg.get("ui.dry_run")), id="set-pref-dry")
        yield Checkbox("Show the log panel at start", bool(app.cfg.get("ui.show_log")), id="set-pref-log")
        with Horizontal(classes="buttons"):
            yield Button("Save", id="set-save", variant="primary")
            yield Button("Select all", id="set-all")
            yield Button("Defaults", id="set-defaults")
        yield from section("Plugins",
                           f"Python files in {app.cfg.get('plugins.dir')} that are listed under "
                           "plugins.trusted in the config file. They must be root-owned and not "
                           "group/world writable.")
        yield Static(Text("\n".join(app.plugin_messages) or "No plugins found."), classes="info")

    def _set_all(self, value_for) -> None:
        for m in self.app.all_modules:
            if not m.required:
                self.query_one(f"#{_cid(m.id)}", Checkbox).value = value_for(m)

    @on(Button.Pressed, "#set-all")
    def _all(self) -> None:
        self._set_all(lambda m: True)

    @on(Button.Pressed, "#set-defaults")
    def _defaults(self) -> None:
        self._set_all(lambda m: m.default)

    @on(Button.Pressed, "#set-save")
    def _save(self) -> None:
        enabled = [m.id for m in self.app.all_modules
                   if m.required or self.query_one(f"#{_cid(m.id)}", Checkbox).value]
        self.app.save_settings(enabled, {
            "theme": self.sel("set-theme"), "colors": self.sel("set-colors"),
            "animations": self.chk("set-pref-anim"), "splash": self.chk("set-pref-splash"),
            "dry_run": self.chk("set-pref-dry"), "show_log": self.chk("set-pref-log")})

    @on(Select.Changed, "#set-theme")
    def _preview_theme(self, event: Select.Changed) -> None:
        if isinstance(event.value, str):
            self.app.theme = event.value
