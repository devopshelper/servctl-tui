"""Firewall pane: open/close ports and list rules for firewalld or nftables."""
from __future__ import annotations

from typing import List, Optional

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Grid, Horizontal
from textual.widgets import Button, Checkbox, DataTable, Input, Select, Static

from .. import firewall as fw
from .base import NavTable, Pane, row, section

VERDICT_STYLE = {"accept": "bold green", "drop": "bold red", "reject": "bold red"}
REACH_STYLE = {"open": "green", "restricted": "yellow", "BLOCKED": "bold red", "localhost only": "dim",
               "open (no filter)": "green", "open (no firewall)": "green"}


class FirewallPane(Pane):
    entries: List[fw.Entry] = []
    listeners: List[fw.Listener] = []
    active: str = "none"

    def compose(self) -> ComposeResult:
        yield Static("loading...", id="fw-info", classes="info")
        yield row("Firewall", Select([("Auto (firewalld if running, else nftables)", "auto"),
                                      ("firewalld", "firewalld"), ("nftables", "nftables")],
                                     value="auto", allow_blank=False, id="fw-backend"))
        yield from section("Open or close ports")
        yield row("Port(s)", Input(placeholder="443   or  80,443   or  8000-8100", id="fw-ports"))
        yield row("Protocol", Select([("TCP", "tcp"), ("UDP", "udp"), ("TCP + UDP", "both")],
                                     value="tcp", allow_blank=False, id="fw-proto"))
        yield row("Zone (firewalld)", Select([("public", "public")], value="public", allow_blank=False,
                                             id="fw-zone"))
        yield row("Only from (optional)", Input(placeholder="IP or network, e.g. 203.0.113.7 or 10.0.0.0/8",
                                                id="fw-source"))
        yield row("Auto-close after (min)", Input(placeholder="blank = keep open (firewalld only)",
                                                  id="fw-timeout", type="integer"))
        with Grid(classes="checks two"):
            yield Checkbox("Keep after reboot", True, id="fw-perm")
            yield Checkbox("Allow changing my SSH port", False, id="fw-ssh")
        with Horizontal(classes="buttons"):
            yield Button("Open port", id="fw-open", variant="success")
            yield Button("Close port", id="fw-close", variant="error")
            yield Button("Refresh", id="fw-refresh")
        yield from section("Rules", "Everything that currently allows or blocks a port. Select a row to remove it.")
        t = NavTable(id="fw-rules", classes="results", cursor_type="row")
        t.add_columns("action", "ports", "proto", "via", "zone / chain", "source", "saved")
        yield t
        with Horizontal(classes="buttons"):
            yield Button("Remove selected rule", id="fw-del", variant="error")
        yield from section("Listening on this host", "What is actually listening, and whether the firewall "
                                                    "lets it through. Select a row to open it.")
        t2 = NavTable(id="fw-listen", classes="results", cursor_type="row")
        t2.add_columns("port", "proto", "process", "bound to", "firewall")
        yield t2
        with Horizontal(classes="buttons"):
            yield Button("Open selected port", id="fw-open-listen", variant="success")

    def on_mount(self) -> None:
        self.query_one("#fw-rules", DataTable).border_title = "Rules"
        self.query_one("#fw-listen", DataTable).border_title = "Listening ports"

    # ------------------------------------------------------------------ data

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        choice = self.app.call_from_thread(lambda: self.sel("fw-backend"))
        active = fw.backend(choice)
        rs = fw.nft_ruleset() if active == "nftables" else None
        zones, default = [], ""
        if active == "firewalld":
            f = fw.Firewalld()
            entries, summary = f.entries(), f.summary()
            zones, default = f.zones() or ["public"], f.default_zone()
        elif active == "nftables":
            entries = fw.nft_entries(rs)
            summary = fw.nft_summary(rs) + "\n" + fw.nft_config_note()
            if fw.firewalld_running():
                summary += "\nfirewalld is running and owns nftables: rules are shown read-only here."
        else:
            entries, summary = [], "No firewall tools found (firewall-cmd or nft)."
        listeners = fw.listening()
        reach = [fw.reachability(l, entries, active, rs) for l in listeners]
        ssh = ", ".join(map(str, sorted(fw.ssh_ports())))
        summary += f"\nSSH port(s): {ssh}  (protected from closing unless you allow it)"
        self.ui(self._fill, active, entries, listeners, reach, zones, default, summary)

    def _fill(self, active, entries, listeners, reach, zones, default, summary) -> None:
        self.active, self.entries, self.listeners = active, entries, listeners
        self.query_one("#fw-info", Static).update(Text(summary))
        if zones:
            zsel = self.query_one("#fw-zone", Select)
            current = zsel.value if zsel.value in zones else default
            zsel.set_options([(z + ("  (default)" if z == default else ""), z) for z in zones])
            zsel.value = current
        self.query_one("#fw-zone", Select).disabled = active != "firewalld"
        self.query_one("#fw-timeout", Input).disabled = active != "firewalld"
        rules = self.query_one("#fw-rules", DataTable)
        rules.clear()
        for i, e in enumerate(entries):
            via = {"port": "port", "service": e.detail, "rich": "rich rule",
                   "rule": "rule" + ("" if e.editable else " (complex)")}[e.kind]
            saved = {True: "yes", False: "NO (runtime)", None: "-"}[e.persistent]
            rules.add_row(Text(e.verdict.upper(), style=VERDICT_STYLE.get(e.verdict, "")), e.ports_text,
                          "+".join(e.protos) or "any", via, e.where, e.source or "any", saved, key=str(i))
        lt = self.query_one("#fw-listen", DataTable)
        lt.clear()
        for i, (l, r) in enumerate(zip(listeners, reach)):
            lt.add_row(str(l.port), l.proto, l.process or "?", ", ".join(l.addresses[:3]),
                       Text(r, style=REACH_STYLE.get(r, "")), key=str(i))

    @on(Select.Changed, "#fw-backend")
    @on(Button.Pressed, "#fw-refresh")
    def _reload(self) -> None:
        self.refresh_info()

    # ------------------------------------------------------------------ actions

    def _editable(self) -> bool:
        if self.active == "none":
            self.app.notify("No firewall backend available", severity="error")
            return False
        if self.active == "nftables" and fw.firewalld_running():
            self.app.notify("firewalld is running and owns nftables - switch Firewall to firewalld",
                            severity="warning")
            return False
        return True

    def _form(self):
        ranges = fw.parse_ports(self.val("fw-ports"))
        protos = fw.protos_for(self.sel("fw-proto"))
        t = self.val("fw-timeout")
        timeout = int(t) if t else 0
        return ranges, protos, timeout

    @on(Button.Pressed, "#fw-open")
    def _open(self) -> None:
        if not self._editable():
            return

        def build():
            ranges, protos, timeout = self._form()
            if self.active == "firewalld":
                return fw.fw_open_plan(ranges, protos, str(self.sel("fw-zone")), self.val("fw-source"),
                                       self.chk("fw-perm"), timeout)
            return fw.nft_open_plan(ranges, protos, self.val("fw-source"), fw.nft_ruleset(), self.chk("fw-perm"))
        self.submit(f"Open {self.val('fw-ports')}/{self.sel('fw-proto')}", build)

    @on(Button.Pressed, "#fw-close")
    def _close(self) -> None:
        if not self._editable():
            return

        def build():
            ranges, protos, _ = self._form()
            if self.active == "firewalld":
                return fw.fw_close_plan(ranges, protos, self.entries, allow_ssh=self.chk("fw-ssh"))
            return fw.nft_close_plan(ranges, protos, fw.nft_ruleset(), self.chk("fw-perm"),
                                     allow_ssh=self.chk("fw-ssh"))
        self.submit(f"Close {self.val('fw-ports')}/{self.sel('fw-proto')}", build)

    def _selected(self, table_id: str, items: list) -> Optional[object]:
        t = self.query_one(f"#{table_id}", DataTable)
        if t.row_count == 0:
            self.app.notify("Nothing to select", severity="warning")
            return None
        key = t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
        return items[int(key)]

    @on(Button.Pressed, "#fw-del")
    def _delete(self) -> None:
        e = self._selected("fw-rules", self.entries)
        if e is None or not self._editable():
            return
        if self.active == "firewalld":
            self.submit(f"Remove {e.detail or e.ports_text} from zone {e.where}",
                        lambda: fw.fw_close_entry_plan(e, self.chk("fw-ssh")))
        else:
            if not e.editable and e.verdict == "accept":
                self.app.notify("Complex rule: removing it may affect more than this port - review the plan",
                                severity="warning")
            self.submit(f"Remove nftables rule {e.ref['handle']}",
                        lambda: fw.nft_delete_entry_plan(e, self.chk("fw-perm"), self.chk("fw-ssh")))

    @on(Button.Pressed, "#fw-open-listen")
    def _open_listener(self) -> None:
        l = self._selected("fw-listen", self.listeners)
        if l is None:
            return
        if l.local_only:
            self.app.notify(f"{l.process or 'This service'} only listens on localhost - opening the firewall "
                            "will not make it reachable. Change its bind address first.", severity="warning")
            return
        self.query_one("#fw-ports", Input).value = str(l.port)
        self.query_one("#fw-proto", Select).value = l.proto
        self._open()
