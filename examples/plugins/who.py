"""Example servctl plugin: who is logged in, and recent logins.

Install:
    sudo install -m 0644 -o root who.py /etc/servctl/plugins/who.py
then add it to /etc/servctl/config.yml:
    plugins:
      trusted: [who]
and enable "Logged-in users" in Settings.
"""
from textual import on, work
from textual.app import ComposeResult
from textual.widgets import Button, Static

from servctl.core import Step
from servctl.registry import Module
from servctl.ui.base import Pane, cmd_block, section


class WhoPane(Pane):
    def compose(self) -> ComposeResult:
        yield from section("Logged-in users", "Read-only example of a plugin pane.")
        yield Static("loading…", id="who-info", classes="info")
        yield Button("Lock idle sessions (example plan)", id="who-lock")

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        self.set_info("who-info", cmd_block(["who", "-a"], "who") + "\n" +
                      cmd_block(["last", "-n", "10"], "last 10 logins"))

    @on(Button.Pressed, "#who-lock")
    def _lock(self) -> None:
        # Plugins get the same confirm/dry-run/rollback engine as built-ins.
        self.submit("Lock all sessions", lambda: [Step.cmd("Lock sessions", "loginctl", "lock-sessions")])


MODULES = [Module("who", "Logged-in users", "System", "who/last output (example plugin)", pane=WhoPane)]
