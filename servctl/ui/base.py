"""Shared UI building blocks: theme CSS, Pane base class, confirmation dialog.

Glyph policy: only characters from the classic terminal sets (CP437/WGL4) are
used - box lines like ┌─┐, shades ░▒▓█ and ASCII - so the UI renders on
PuTTY, Windows consoles and minimal fonts without "tofu" boxes. Textual's
default widget borders use eighth-block glyphs (▊▔▎), so every widget runs in
compact mode and all borders are 'solid'.
"""
from __future__ import annotations

import threading
from typing import Any, Callable, List, Optional

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.color import Color
from textual.content import Content
from textual.scrollbar import ScrollBarRender
from textual.style import Style as VisualStyle
from textual.widgets import Button, Checkbox, DataTable, Input, Label, RichLog, Select, Static

from ..core import Step, capture, is_root

# Whole-cell scrollbars: the smooth ones use ▁▂▃ / ▉▊▋ partial blocks.
ScrollBarRender.VERTICAL_BARS = [" "] * 8
ScrollBarRender.HORIZONTAL_BARS = [" "] * 8

def _switch(self) -> Content:
    """Checkboxes drawn as a toggle switch:  off ▐█ ▌ grey   on ▐ █▌ green.

    Only █ ▐ ▌ and spaces are used - classic terminal characters every font
    has (Textual's default ▐X▌ uses the same half blocks).
    """
    v = self.app.get_css_variables()
    on = bool(self.value)
    bg = Color.parse(v["background"])
    track = Color.parse(v["success"]) if on else Color.parse(v.get("panel-lighten-2", v["panel"]))
    knob = Color.parse(v.get("foreground", "#e6e6e6"))
    if not on:
        knob = knob.blend(track, 0.35)
    if self.disabled:
        track, knob = track.blend(bg, 0.55), knob.blend(bg, 0.55)
    # (bg is only used for the disabled look)
    outside = self.background_colors[1]
    cap = VisualStyle(foreground=track, background=outside)   # ▐ ▌ round the track ends
    pad = VisualStyle(background=track)
    nub = VisualStyle(foreground=knob, background=track)
    inner = [(" ", pad), ("█", nub)] if on else [("█", nub), (" ", pad)]
    return Content.assemble(("▐", cap), *inner, ("▌", cap))


Checkbox._button = property(_switch)

# Dropdowns open with Enter/Space only, so Up/Down stay free for moving between fields.
Select.BINDINGS = [Binding("enter,space", "show_overlay", "Show menu", show=False)]
Select._merged_bindings = Select._merge_bindings()


class NavTable(DataTable):
    """DataTable whose Up/Down leave the table at its first/last row."""

    def action_cursor_up(self) -> None:
        if self.row_count == 0 or self.cursor_row <= 0:
            self.screen.focus_previous()
        else:
            super().action_cursor_up()

    def action_cursor_down(self) -> None:
        if self.row_count == 0 or self.cursor_row >= self.row_count - 1:
            self.screen.focus_next()
        else:
            super().action_cursor_down()

CSS = """
Screen { layout: vertical; background: $background; }

/* ---------- top bar ---------- */
#topbar { dock: top; height: 1; background: $panel; }
#brand { width: auto; padding: 0 1; text-style: bold; }
#hostinfo { width: 1fr; color: $text-muted; padding: 0 1; }
#activity { width: auto; padding: 0 1; color: $accent; }
#mode { width: auto; padding: 0 1; text-style: bold; }
#mode.dry { background: $warning; color: $background; }
#mode.live { background: $error; color: $text; }
#clock { width: auto; padding: 0 1; color: $text-muted; }

/* ---------- layout ---------- */
#body { height: 1fr; }
#sidebar { width: 28; height: 100%; max-height: 100%; border: none; border-right: solid $primary 40%; background: $panel;
           padding: 1 0; }
#sidebar:focus { border-right: solid $accent; }
#sidebar > .option-list--option-highlighted { background: $primary 50%; text-style: bold; }
#sidebar:focus > .option-list--option-highlighted { background: $accent; color: $background; }
#sidebar > .option-list--option-hover { background: $primary 20%; }
#content { width: 1fr; }
#content > * { height: 1fr; }
#log { height: 12; border: solid $accent 50%; background: transparent; }
#log.hidden { display: none; }

/* ---------- panes ---------- */
.pane { padding: 0 2; }
PaneHeader { height: auto; margin: 1 0 0 0; padding: 0 0 0 0; border-bottom: solid $accent 60%; }
PaneHeader .ph-title { text-style: bold; color: $accent; }
PaneHeader .ph-desc { color: $text-muted; }
.section { text-style: bold; color: $text; margin: 1 0 0 0; border-bottom: solid $primary 30%; }
.hint { color: $text-muted; margin: 0 0 1 0; }
.row { height: auto; margin: 0 0 1 0; }
.row > .lbl { width: 26; color: $text-muted; }
.row > Input, .row > Select { width: 1fr; max-width: 64; }
.checks { layout: grid; grid-size: 3; grid-rows: 1; height: auto; grid-gutter: 1 2; margin: 0 0 1 0; }
.buttons { height: auto; margin: 1 0; }
.buttons Button { margin: 0 2 0 0; }
.info { border: solid $primary 40%; border-title-color: $accent; padding: 0 1; height: auto;
        max-height: 20; overflow-y: auto; margin: 1 0 0 0; }
.warn { color: $warning; text-style: bold; }
.out { height: 16; border: solid $primary 40%; border-title-color: $accent; background: transparent; }
.big { text-style: bold; padding: 1 2; border: solid $success; border-title-color: $success;
       height: auto; margin: 1 0 0 0; }
DataTable.results { height: auto; max-height: 20; margin: 1 0; border: solid $primary 40%; background: transparent;
                    border-title-color: $accent; }

/* ---------- overview dashboard ---------- */
#ov-grid { layout: grid; grid-size: 2; grid-columns: 1fr 1fr; grid-gutter: 1 2; height: auto; margin: 1 0; }
.card { border: solid $primary 50%; border-title-color: $accent; border-title-style: bold;
        padding: 0 1; height: auto; min-height: 8; }
#ov-mem, #ov-disks { column-span: 2; }

/* ---------- compact widgets: give them a visible field background ---------- */
Input.-textual-compact { background: $boost; }
Input.-textual-compact:focus { background: $primary 25%; }
Select.-textual-compact > SelectCurrent { background: $boost; }
Select.-textual-compact:focus > SelectCurrent { background: $primary 25%; }
SelectOverlay { border: solid $accent; }
Checkbox.-textual-compact { background: transparent; }
.pane > Checkbox { margin: 0 0 1 0; }
.checks.two { grid-size: 2; }
Checkbox.-textual-compact:focus { background: $primary 25%; }
Button.-textual-compact { min-width: 10; padding: 0 2; background: $panel-lighten-2; color: auto 90%;
                          text-style: bold; }
Button.-textual-compact:hover { background: $panel-lighten-3; }
Button.-textual-compact.-primary { background: $primary; color: auto 90%; }
Button.-textual-compact.-success { background: $success; color: auto 90%; }
Button.-textual-compact.-warning { background: $warning; color: auto 90%; }
Button.-textual-compact.-error { background: $error; color: auto 90%; }
Button.-textual-compact:focus { background: $accent; color: auto 90%; text-style: bold underline; }
Button.-textual-compact:disabled { background: $panel; color: $text-disabled; text-style: none; }

/* ---------- Textual built-ins that default to block-glyph borders ---------- */
Toast { border-left: solid $success; }
Toast.-information { border-left: solid $success; }
Toast.-warning { border-left: solid $warning; }
Toast.-error { border-left: solid $error; }
FooterKey.-command-palette { border-left: solid $foreground 20%; }
CommandPalette #--input { border: solid $accent; }
CommandList { border: none; border-bottom: solid $primary 40%; }
CommandList:focus { border: none; border-bottom: solid $primary 40%; }

/* ---------- confirm dialog ---------- */
ConfirmScreen { align: center middle; background: $background 60%; }
#dialog { width: 90%; max-width: 120; height: 85%; border: double $warning;
          border-title-color: $warning; border-title-style: bold; background: $surface; padding: 1 2; }
#dialog.dry { border: double $primary; border-title-color: $primary; }
#dialog-plan { height: 1fr; border: solid $primary 40%; margin: 1 0; padding: 0 1; }
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


class PaneHeader(Vertical):
    """Title + description shown at the top of every module."""

    def __init__(self, title: str, description: str) -> None:
        super().__init__()
        self._title, self._desc = title, description

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="ph-title")
        yield Static(self._desc, classes="ph-desc")


def make_compact(root) -> None:
    for w in root.query("Input, Select, Button, Checkbox"):
        w.compact = True


HELP = [
    ("Tab / Shift+Tab", "next / previous menu (works everywhere)"),
    ("Up / Down", "move through the menu, or between fields inside a screen"),
    ("Enter or Right", "from the menu: jump into the screen"),
    ("Esc", "back to the menu"),
    ("Left / Right", "between buttons and checkboxes (in text fields: move the cursor)"),
    ("Enter", "text field: go to the next field  ·  button: press  ·  dropdown: open"),
    ("Space", "toggle a checkbox, open a dropdown"),
    ("Up / Down in a table", "move between rows; leaves the table at the first/last row"),
    ("PageUp / PageDown", "scroll the screen"),
    ("Ctrl+P", "command palette: jump to any module, change theme"),
    ("F2", "dry-run on/off"),
    ("F3 / F4", "show/hide the activity log / clear it"),
    ("F5", "refresh the current screen"),
    ("Ctrl+Q", "quit"),
]


class HelpScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape,f1,q,enter", "close", "Close")]
    DEFAULT_CSS = """
    HelpScreen { align: center middle; background: $background 60%; }
    #help { width: 84; height: auto; max-height: 90%; border: double $accent; background: $surface;
            padding: 1 2; border-title-color: $accent; border-title-style: bold; }
    """

    def compose(self) -> ComposeResult:
        body = Text()
        for key, what in HELP:
            body.append(f"{key:<22}", style="bold")
            body.append(what + "\n")
        body.append("\nEsc / F1 to close", style="dim")
        box = Static(body, id="help")
        box.border_title = " Keys "
        yield box

    def action_close(self) -> None:
        self.dismiss(None)


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, steps: List[Step], dry_run: bool) -> None:
        super().__init__()
        self.plan_title = title
        self.steps = steps
        self.dry_run = dry_run

    def compose(self) -> ComposeResult:
        body = Text()
        for i, s in enumerate(self.steps, 1):
            body.append(f"{i:>2}. ", style="bold")
            body.append(s.title, style="bold")
            if s.allow_fail:
                body.append("  (failure tolerated)", style="dim")
            body.append("\n")
            for line in s.describe().splitlines():
                style = "green" if line.lstrip().startswith("$") else "dim" if "│" in line else ""
                body.append("    " + line + "\n", style=style)
            body.append("\n")
        mode = ("DRY-RUN - commands are only printed, nothing is changed." if self.dry_run else
                "LIVE - these commands will run as " + ("root." if is_root() else "a NON-ROOT user!"))
        dialog = Vertical(id="dialog", classes="dry" if self.dry_run else "")
        dialog.border_title = f" Review plan: {self.plan_title} "
        with dialog:
            yield Label(mode, classes="hint" if self.dry_run else "warn")
            with VerticalScroll(id="dialog-plan"):
                yield Static(body)
            with Horizontal(id="dialog-buttons"):
                yield Button("Cancel  [Esc]", id="no", compact=True)
                yield Button("Dry-run" if self.dry_run else "Run it", id="yes", compact=True,
                             variant="primary" if self.dry_run else "error")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    @on(Button.Pressed)
    def _pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_cancel(self) -> None:
        self.dismiss(False)


class Pane(VerticalScroll):
    """Base for each module: value helpers, plan submission, async info refresh.

    Keyboard model inside a module: Up/Down (and Left/Right on buttons and
    checkboxes) move between fields, Enter in a text field moves to the next
    one. Tab is reserved for switching modules (bound on the app).
    """

    DEFAULT_CLASSES = "pane"
    can_focus = False
    BINDINGS = [
        Binding("down", "next_field", "Next field", show=False),
        Binding("up", "prev_field", "Previous field", show=False),
        Binding("right", "next_field", "Next field", show=False),
        Binding("left", "prev_field", "Previous field", show=False),
    ]

    def action_next_field(self) -> None:
        if self.first_field() is None:      # nothing to edit here: arrows scroll instead
            self.scroll_down()
        else:
            self.screen.focus_next()

    def action_prev_field(self) -> None:
        if self.first_field() is None:
            self.scroll_up()
        else:
            self.screen.focus_previous()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.screen.focus_next()

    def first_field(self):
        return next((w for w in self.query("Input, Select, Checkbox, Button, DataTable")
                     if w.focusable), None)

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

    def task(self, title: str, fn: Callable[[Callable[[str, str], None]], Any],
             on_done: Optional[Callable[[Any], None]] = None) -> None:
        """Run a read-only diagnostic in a thread (no confirmation, ignores dry-run)."""
        self.app.start_task(title, fn, on_done)

    def ui(self, fn: Callable, *args: Any) -> None:
        """Call fn on the UI thread, from either a worker or the UI thread itself."""
        if threading.get_ident() == self.app._thread_id:
            fn(*args)
        else:
            self.app.call_from_thread(fn, *args)

    def set_info(self, wid: str, text: str) -> None:
        self.ui(self.query_one(f"#{wid}", Static).update, Text(text))

    def on_mount(self) -> None:
        make_compact(self)
        for w in self.query(".info"):
            w.border_title = w.border_title or "Status"
        for w in self.query(RichLog).filter(".out"):
            w.border_title = w.border_title or "Output"
            w.can_focus = False
        for w in self.query(DataTable).filter(".results"):
            w.border_title = w.border_title or "Results"
        self.refresh_info()

    def refresh_info(self) -> None:  # overridden
        pass


def cmd_block(argv: List[str], title: Optional[str] = None) -> str:
    rc, out = capture(argv)
    return f"── {title or ' '.join(argv)} ──\n{out}"
