"""Animations: shimmering gradient wordmark, splash screen, activity comet.

Everything is drawn with CP437-safe glyphs (█ ▓ ▒ ░ and ASCII) and colours
taken from the active theme, so it follows theme changes. All effects can be
turned off with ``ui.animations: false`` (useful over slow SSH links).
"""
from __future__ import annotations

import math
import time
from typing import List, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.color import Color
from textual.css.scalar import ScalarOffset
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

LOGO = [
    " ████ █████ ████  █   █  ████ █████ █    ",
    "█     █     █   █ █   █ █       █   █    ",
    " ███  ████  ████  █   █ █       █   █    ",
    "    █ █     █  █   █ █  █       █   █    ",
    "████  █████ █   █   █    ████   █   █████",
]


def theme_colors(app) -> List[Color]:
    """Gradient stops from the active theme: primary -> accent -> secondary."""
    t = app.current_theme
    stops = [t.primary, t.accent or t.primary, t.secondary or t.primary]
    return [Color.parse(c) for c in stops]


def gradient_at(stops: List[Color], x: float) -> Color:
    x = min(max(x, 0.0), 1.0) * (len(stops) - 1)
    i = min(int(x), len(stops) - 2)
    return stops[i].blend(stops[i + 1], x - i)


def shimmer_text(text: str, stops: List[Color], phase: Optional[float], width: Optional[int] = None,
                 bold: bool = True) -> Text:
    """Gradient across the text; a bright band sits at ``phase`` (0..1), or none."""
    out = Text()
    n = max(1, (width or len(text)) - 1)
    for i, ch in enumerate(text):
        x = (i % (width or len(text) or 1)) / n
        c = gradient_at(stops, x)
        if phase is not None:
            d = abs(x - phase) * 8
            if d < 1:
                c = c.blend(Color(255, 255, 255), 0.65 * (1 - d))
        out.append(ch, style=f"{'bold ' if bold else ''}{c.hex}")
    return out


class Brand(Static):
    """Wordmark in the top bar. Shimmers on start and while work is running."""

    def __init__(self, label: str, **kw) -> None:
        super().__init__(**kw)
        self.label = label
        self._t0 = time.monotonic()
        self.busy = False

    def on_mount(self) -> None:
        self._tick()
        if self.app.animations:
            self.set_interval(1 / 15, self._tick)

    def _tick(self) -> None:
        stops = theme_colors(self.app)
        phase = None
        if self.app.animations:
            t = time.monotonic() - self._t0
            if t < 2.0 or self.busy:
                phase = (t * 0.7) % 1.4 - 0.2
        self.update(shimmer_text(self.label, stops, phase))


class Activity(Static):
    """Comet that bounces while tasks/plans run, plus the current task name."""

    TRACK = 10
    TAIL = "█▓▒░"

    def on_mount(self) -> None:
        self._t0 = time.monotonic()
        self.set_interval(1 / 12, self._tick)

    def _tick(self) -> None:
        running = list(self.app.running.values())
        if not running:
            self.update("")
            self.display = False
            return
        self.display = True
        label = running[-1] + (f" +{len(running) - 1}" if len(running) > 1 else "")
        if not self.app.animations:
            self.update(Text(f"[ busy ] {label}", style="bold"))
            return
        t = time.monotonic() - self._t0
        # Ping-pong position along the track.
        span = self.TRACK - 1
        pos = span * (0.5 - 0.5 * math.cos(t * 2.4))
        forward = math.sin(t * 2.4) >= 0
        stops = theme_colors(self.app)
        cells = [" "] * self.TRACK
        for k, ch in enumerate(self.TAIL):
            idx = round(pos - k if forward else pos + k)
            if 0 <= idx < self.TRACK and cells[idx] == " ":
                cells[idx] = ch
        bar = Text("[", style="dim")
        bar.append_text(shimmer_text("".join(cells), stops, None, bold=False))
        bar.append("] ", style="dim")
        bar.append_text(shimmer_text(label, stops, (t * 0.5) % 1.4 - 0.2))
        self.update(bar)


class Splash(ModalScreen[None]):
    """Short animated logo on start. Any key or click skips it."""

    DEFAULT_CSS = """
    Splash { align: center middle; background: $background; }
    #splash { width: auto; height: auto; padding: 1 4; border: double $accent; background: $surface; }
    #splash-logo { width: auto; }
    #splash-sub { width: 100%; text-align: center; color: $text-muted; margin-top: 1; }
    """

    def __init__(self, version: str, duration: float = 1.6) -> None:
        super().__init__()
        self.version = version
        self.duration = duration
        self._t0 = time.monotonic()

    def compose(self) -> ComposeResult:
        with Vertical(id="splash"):
            yield Static(id="splash-logo")
            yield Static(f"server control plane  ·  v{self.version}\npress any key", id="splash-sub")

    def on_mount(self) -> None:
        self._draw()
        self.set_interval(1 / 20, self._draw)
        self.set_timer(self.duration, self._close)

    def _draw(self) -> None:
        t = (time.monotonic() - self._t0) / self.duration
        stops = theme_colors(self.app)
        width = max(len(l) for l in LOGO)
        out = Text()
        # Reveal left to right, then a bright sweep passes over the logo.
        reveal = min(1.0, t * 2.2)
        for line in LOGO:
            shown = line[: int(len(line) * reveal)]
            out.append_text(shimmer_text(shown, stops, t * 1.6 - 0.3, width=width))
            out.append("\n")
        self.query_one("#splash-logo", Static).update(out)

    def _close(self) -> None:
        if self.is_attached:
            self.dismiss(None)

    def on_key(self) -> None:
        self._close()

    def on_click(self) -> None:
        self._close()


def slide_in(widget, duration: float = 0.18) -> None:
    """Short slide from the right when a module opens.

    Deliberately not an opacity fade: Textual caches label renders made while
    a parent is semi-transparent, which left button labels dim afterwards.
    """
    if not widget.app.animations:
        return
    widget.styles.offset = (6, 0)
    widget.styles.animate("offset", value=ScalarOffset.from_offset((0, 0)), duration=duration,
                          easing="out_cubic")


def count_up(widget: Static, render, duration: float = 0.7) -> None:
    """Call render(progress 0..1) repeatedly so numbers roll up to their final value."""
    if not widget.app.animations:
        widget.update(render(1.0))
        return
    t0 = time.monotonic()

    def step() -> None:
        p = min(1.0, (time.monotonic() - t0) / duration)
        widget.update(render(1 - (1 - p) ** 3))
        if p >= 1.0:
            timer.stop()

    timer = widget.set_interval(1 / 30, step)
    step()
