"""Shared UI building blocks: CSS, Pane base class, confirmation dialog."""
from __future__ import annotations

import threading
from typing import Any, Callable, List, Optional

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select, Static

from ..core import Step, capture, is_root

CSS = """
Screen { layout: vertical; }
#body { height: 1fr; }
#sidebar { width: 26; border-right: tall $primary-darken-2; }
#content { width: 1fr; }
#content > * { height: 1fr; }
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
.out { height: 16; border: round $primary-darken-2; }
.big { text-style: bold; padding: 1 2; border: round $success; height: auto; }
DataTable.results { height: auto; max-height: 20; margin: 1 0; }

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
        self.refresh_info()

    def refresh_info(self) -> None:  # overridden
        pass


def cmd_block(argv: List[str], title: Optional[str] = None) -> str:
    rc, out = capture(argv)
    return f"── {title or ' '.join(argv)} ──\n{out}"


