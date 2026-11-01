"""MariaDB pane: install, databases, users, privileges."""
from __future__ import annotations

import re
from typing import List

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Grid, Horizontal
from textual.widgets import Button, Checkbox, DataTable, Input, Select, Static

from .. import mariadb as m
from ..core import os_info
from ..sysinfo import human
from .base import NavTable, Pane, copy_to_clipboard, row, section


def _names(text: str) -> List[str]:
    return [x for x in re.split(r"[,\s]+", text.strip()) if x]


class MariaDbPane(Pane):
    dbs: list = []
    accounts: list = []
    grant_rows: list = []

    def compose(self) -> ComposeResult:
        yield Static("loading...", id="my-info", classes="info")

        yield from section("Install", "Installs mariadb-server from the OS repositories (AppStream on RHEL 9), "
                                      "starts it at boot and removes anonymous users, remote root and the test DB.")
        with Grid(classes="checks"):
            yield Checkbox("Listen on all interfaces", False, id="my-listen")
            yield Checkbox("Open 3306 in the firewall", False, id="my-fw")
        yield row("Allow from (optional)", Input(placeholder="client network, e.g. 10.0.0.0/24", id="my-fwsrc"))
        with Horizontal(classes="buttons"):
            yield Button("Install / configure", id="my-install", variant="primary")
            yield Button("Refresh", id="my-refresh")

        yield from section("Databases")
        yield row("Database name(s)", Input(placeholder="shop  blog  (space or comma separated)", id="my-dbname"))
        yield row("Character set", Select([(k, k) for k in m.CHARSETS], value="utf8mb4", allow_blank=False,
                                          id="my-charset"))
        with Horizontal(classes="buttons"):
            yield Button("Create database(s)", id="my-dbcreate", variant="success")
        t = NavTable(id="my-dbs", classes="results", cursor_type="row")
        t.add_columns("database", "charset", "tables", "size", "users with access")
        yield t
        yield row("Type name to drop", Input(placeholder="safety check: the selected database's name",
                                             id="my-dropconfirm"))
        with Horizontal(classes="buttons"):
            yield Button("Drop selected database (backup first)", id="my-dbdrop", variant="error")

        yield from section("Users", "Host: 'localhost' (same server), '%' (anywhere) or a pattern such as 10.0.0.%")
        yield row("User name", Input(placeholder="app", id="my-user"))
        yield row("Host", Input("localhost", id="my-host"))
        yield row("Password", Input(password=True, placeholder="min. 10 characters", id="my-pass"))
        yield Static("", id="my-genout", classes="hint")
        yield Checkbox("Reset the password if the user already exists", False, id="my-reset")
        with Horizontal(classes="buttons"):
            yield Button("Generate password", id="my-gen")
            yield Button("Copy password", id="my-copypw", compact=True)
            yield Button("Create user", id="my-usercreate", variant="success")
            yield Button("Drop selected user", id="my-userdrop", variant="error")
        t = NavTable(id="my-users", classes="results", cursor_type="row")
        t.add_columns("user", "host", "auth", "databases")
        yield t

        yield from section("Privileges", "Select a user above (or type it), list the databases, pick a level.")
        yield row("Databases", Input(placeholder="shop blog", id="my-grantdbs"))
        yield row("Level", Select([(label, key) for key, (label, _) in m.PRIV_PRESETS.items()],
                                  value="rw_ddl", allow_blank=False, id="my-level"))
        with Grid(classes="checks"):
            yield Checkbox("Create missing databases", True, id="my-createmissing")
            yield Checkbox("WITH GRANT OPTION", False, id="my-grantopt")
        with Horizontal(classes="buttons"):
            yield Button("Grant", id="my-grant", variant="success")
            yield Button("Revoke", id="my-revoke", variant="error")
        t = NavTable(id="my-grants", classes="results", cursor_type="row")
        t.add_columns("user", "host", "database", "privileges", "grant option")
        yield t

    def on_mount(self) -> None:
        for wid, title in (("my-dbs", "Databases"), ("my-users", "Users"), ("my-grants", "Privileges")):
            self.query_one(f"#{wid}", DataTable).border_title = title

    # ------------------------------------------------------------------ data

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        st = m.status()
        dbs = m.databases()
        accounts = m.users()
        grants = [g for g in m.grants(accounts) if not g.privileges.startswith("PROXY")]
        self.ui(self._fill, st, dbs, accounts, grants)

    def _fill(self, st, dbs, accounts, grants) -> None:
        self.dbs, self.accounts, self.grant_rows = dbs, accounts, grants
        if "version" in st:
            text = (f"MariaDB {st['version']}   service: {st['service'].splitlines()[0]}\n"
                    f"listening on {st['bind'] or '*'}:{st['port']}   data: {st['datadir']}   "
                    f"socket: {st['socket']}")
        elif st.get("installed") == "yes":
            text = f"MariaDB is installed but not reachable: {st.get('error', '')}\nservice: {st['service']}"
        else:
            text = "MariaDB is not installed yet - use Install / configure below."
        self.query_one("#my-info", Static).update(Text(text))

        access = {}
        for g in grants:
            access.setdefault(g.db, set()).add(f"{g.user}@{g.host}")
        t = self.query_one("#my-dbs", DataTable)
        t.clear()
        for name, cs, tables, size in dbs:
            sysdb = name in m.SYSTEM_DBS
            t.add_row(Text(name, style="" if sysdb else "bold"), cs, str(tables), human(size),
                      ", ".join(sorted(access.get(name, []))) or ("(system)" if sysdb else "-"), key=name)

        per_user = {}
        for g in grants:
            if g.target != "*.*":
                per_user.setdefault((g.user, g.host), []).append(g.db)
        t = self.query_one("#my-users", DataTable)
        t.clear()
        for user, host, plugin in accounts:
            system = user in ("root", "mysql", "mariadb.sys")
            t.add_row(Text(user or "(anonymous)", style="" if system else "bold"), host, plugin,
                      ", ".join(per_user.get((user, host), [])) or ("all (admin)" if system else "-"),
                      key=f"{user}\t{host}")

        t = self.query_one("#my-grants", DataTable)
        t.clear()
        for i, g in enumerate(grants):
            target = "ALL databases" if g.target == "*.*" else g.db
            privs = g.privileges if len(g.privileges) < 70 else g.privileges[:67] + "..."
            t.add_row(g.user, g.host, target, privs, "yes" if g.grant_option else "", key=str(i))

    # ------------------------------------------------------------------ helpers

    @on(DataTable.RowHighlighted, "#my-users")
    def _pick_user(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key and event.row_key.value:
            user, host = event.row_key.value.split("\t")
            self.query_one("#my-user", Input).value = user
            self.query_one("#my-host", Input).value = host

    @on(DataTable.RowHighlighted, "#my-dbs")
    def _pick_db(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key and event.row_key.value and event.row_key.value not in m.SYSTEM_DBS:
            self.query_one("#my-grantdbs", Input).value = event.row_key.value

    def _current_db(self) -> str:
        t = self.query_one("#my-dbs", DataTable)
        if t.row_count == 0:
            return ""
        return t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value or ""

    # ------------------------------------------------------------------ actions

    @on(Button.Pressed, "#my-refresh")
    def _refresh(self) -> None:
        self.refresh_info()

    @on(Button.Pressed, "#my-install")
    def _install(self) -> None:
        self.submit("Install MariaDB", lambda: m.install_plan(
            os_info().pkg, self.chk("my-listen"), self.chk("my-fw"), self.val("my-fwsrc")))

    @on(Button.Pressed, "#my-dbcreate")
    def _create_db(self) -> None:
        self.submit("Create databases", lambda: m.create_db_plan(_names(self.val("my-dbname")),
                                                                 str(self.sel("my-charset"))))

    @on(Button.Pressed, "#my-dbdrop")
    def _drop_db(self) -> None:
        db = self._current_db()
        self.submit(f"Drop database {db}", lambda: m.drop_db_plan(db, self.val("my-dropconfirm")))

    @on(Button.Pressed, "#my-gen")
    def _generate(self) -> None:
        pw = m.generate_password()
        self.query_one("#my-pass", Input).value = pw
        self.query_one("#my-genout", Static).update(Text(f"Generated password: {pw}   (copied to clipboard!)", style="bold green"))
        copy_to_clipboard(self.app, pw, "MariaDB password")

    @on(Button.Pressed, "#my-copypw")
    def _copypw(self) -> None:
        pw = self.query_one("#my-pass", Input).value
        if pw:
            copy_to_clipboard(self.app, pw, "MariaDB password")
        else:
            self.app.notify("No password to copy", severity="warning")

    @on(Button.Pressed, "#my-usercreate")
    def _create_user(self) -> None:
        user, host = self.val("my-user"), self.val("my-host") or "localhost"
        self.submit(f"Create user {user}@{host}", lambda: m.create_user_plan(
            user, host, self.query_one("#my-pass", Input).value, self.chk("my-reset")))

    @on(Button.Pressed, "#my-userdrop")
    def _drop_user(self) -> None:
        user, host = self.val("my-user"), self.val("my-host")
        self.submit(f"Drop user {user}@{host}", lambda: m.drop_user_plan(user, host))

    @on(Button.Pressed, "#my-grant")
    def _grant(self) -> None:
        user, host = self.val("my-user"), self.val("my-host") or "localhost"
        self.submit(f"Grant to {user}@{host}", lambda: m.grant_plan(
            user, host, _names(self.val("my-grantdbs")), str(self.sel("my-level")),
            self.chk("my-createmissing"), self.chk("my-grantopt")))

    @on(Button.Pressed, "#my-revoke")
    def _revoke(self) -> None:
        user, host = self.val("my-user"), self.val("my-host") or "localhost"
        self.submit(f"Revoke from {user}@{host}", lambda: m.revoke_plan(user, host, _names(self.val("my-grantdbs"))))
