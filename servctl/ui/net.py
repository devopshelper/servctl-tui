"""Panes for network, DNS and storage diagnostics."""
from __future__ import annotations

import time
from typing import List, Optional

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Grid, Horizontal
from textual.widgets import Button, Checkbox, DataTable, Input, RichLog, Rule, Select, Static

from .. import bench, dnsutil, maildns, unbound
from ..core import Step, capture, os_info, which
from .base import NavTable, Pane, cmd_block, row, section
from .fx import count_up


def _fmt_ms(v: Optional[float]) -> str:
    return "-" if v is None else f"{v:.1f}"


# --------------------------------------------------------------------------- #
# Speedtest
# --------------------------------------------------------------------------- #

class SpeedtestPane(Pane):
    def compose(self) -> ComposeResult:
        cfg = self.app.cfg
        yield from section("Internet speed test",
                           "Built-in test uses Cloudflare's speed endpoints (no install needed). "
                           "The Ookla CLI is used when installed and selected.")
        yield Static("No test run yet.", id="sp-result", classes="big")
        yield row("Engine", Select([("Built-in (Cloudflare)", "cf"), ("Ookla / speedtest-cli", "ookla")],
                                   value="cf", allow_blank=False, id="sp-engine"))
        yield row("Download size (MB)", Input(str(cfg.get("speedtest.download_mb")), id="sp-down",
                                              type="integer"))
        yield row("Upload size (MB)", Input(str(cfg.get("speedtest.upload_mb")), id="sp-up",
                                            type="integer"))
        yield row("Parallel streams", Input(str(cfg.get("speedtest.streams")), id="sp-streams",
                                            type="integer"))
        with Horizontal(classes="buttons"):
            yield Button("Run speed test", id="sp-run", variant="primary")
            yield Button("Install Ookla CLI", id="sp-install")
        yield from section("History (this session)")
        t = NavTable(id="sp-hist", classes="results", cursor_type="row")
        t.add_columns("time", "engine", "ping ms", "jitter", "down Mbit/s", "up Mbit/s", "server")
        yield t

    @on(Button.Pressed, "#sp-run")
    def _run(self) -> None:
        engine = self.sel("sp-engine")
        try:
            down, up = self.num("sp-down", "Download size"), self.num("sp-up", "Upload size")
            streams = self.num("sp-streams", "Streams")
            if not (1 <= streams <= 16 and 1 <= down <= 1000 and 1 <= up <= 1000):
                raise ValueError("Use 1-16 streams and 1-1000 MB")
        except ValueError as exc:
            self.app.notify(str(exc), severity="error")
            return
        if engine == "ookla" and not bench.ookla_flavour():
            self.app.notify("No speedtest CLI installed - use 'Install Ookla CLI' or the built-in engine",
                            severity="warning")
            return
        self.query_one("#sp-result", Static).update("Running...")
        url = self.app.cfg.get("speedtest.url")
        fn = (lambda emit: bench.cloudflare_speedtest(url, down, up, streams, emit)) if engine == "cf" \
            else bench.ookla_speedtest
        self.task("Speed test", fn, self._show)

    def _show(self, r: Optional[bench.SpeedResult]) -> None:
        if r is None:
            self.query_one("#sp-result", Static).update("Test failed - see log (F3).")
            return
        def render(p: float) -> Text:
            t = Text()
            t.append("  DOWN ", style="bold reverse green")
            t.append(f" {r.down_mbps * p:>9,.1f} Mbit/s    ", style="bold green")
            t.append("  UP ", style="bold reverse cyan")
            t.append(f" {r.up_mbps * p:>9,.1f} Mbit/s    ", style="bold cyan")
            t.append("  PING ", style="bold reverse yellow")
            t.append(f" {r.ping_ms * p:>6.1f} ms  (jitter {r.jitter_ms * p:.1f})\n\n", style="bold yellow")
            t.append(f"{r.engine}  ·  {r.server}  ·  public IP {r.ip or '?'}  {r.extra}", style="dim")
            return t
        count_up(self.query_one("#sp-result", Static), render)
        self.query_one("#sp-hist", DataTable).add_row(
            time.strftime("%H:%M:%S"), r.engine, f"{r.ping_ms:.1f}", f"{r.jitter_ms:.1f}",
            f"{r.down_mbps:.1f}", f"{r.up_mbps:.1f}", r.server)

    @on(Button.Pressed, "#sp-install")
    def _install(self) -> None:
        self.submit("Install Ookla speedtest CLI", lambda: bench.ookla_install_plan(os_info().pkg))


# --------------------------------------------------------------------------- #
# Disk benchmark
# --------------------------------------------------------------------------- #

class DiskPane(Pane):
    def compose(self) -> ComposeResult:
        cfg = self.app.cfg
        yield from section("Disk benchmark",
                           "CrystalDiskMark-style fio tests with O_DIRECT (bypasses page cache). "
                           "A temporary file is written in the target directory and removed after.")
        yield Static("loading...", id="dk-info", classes="info")
        yield row("Target directory", Input(cfg.get("disk.dir"), id="dk-dir"))
        yield row("Test file size", Input(cfg.get("disk.size"), id="dk-size"))
        yield row("Seconds per test", Input(str(cfg.get("disk.runtime")), id="dk-runtime", type="integer"))
        with Grid(classes="checks"):
            for i, t in enumerate(bench.DISK_TESTS):
                yield Checkbox(t.label, i < 4, id=f"dk-t{i}")
        with Horizontal(classes="buttons"):
            yield Button("Run benchmark", id="dk-run", variant="primary")
            yield Button("Install fio", id="dk-install")
        t = NavTable(id="dk-table", classes="results", cursor_type="row")
        t.add_columns("test", "MB/s", "IOPS", "avg latency µs", "p99 latency µs")
        yield t

    def on_mount(self) -> None:
        self.query_one("#dk-install", Button).display = not which("fio")

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        d = self.app.call_from_thread(lambda: self.val("dk-dir")) or "/"
        src = capture(["findmnt", "-n", "-o", "SOURCE,FSTYPE,OPTIONS", "-T", d])[1]
        self.set_info("dk-info", f"{d} is on: {src}\n" + cmd_block(["df", "-h", d], "free space") +
                      ("" if which("fio") else "\nfio not installed: only a sequential dd test will run."))

    @on(Input.Submitted, "#dk-dir")
    def _dir(self) -> None:
        self.refresh_info()

    @on(Button.Pressed, "#dk-run")
    def _run(self) -> None:
        d, size = self.val("dk-dir"), self.val("dk-size")
        try:
            runtime = self.num("dk-runtime", "Seconds per test")
            if not 3 <= runtime <= 300:
                raise ValueError("Seconds per test must be 3-300")
            bench.check_target(d, size)
        except ValueError as exc:
            self.app.notify(str(exc), severity="error")
            return
        tests = [t for i, t in enumerate(bench.DISK_TESTS) if self.chk(f"dk-t{i}")]
        table = self.query_one("#dk-table", DataTable)
        table.clear()

        def add(r: bench.DiskResult) -> None:
            if r.error:
                table.add_row(r.label, Text(r.error, style="red"), "", "", "")
            else:
                table.add_row(r.label, f"{r.mbps:,.1f}", f"{r.iops:,.0f}" if r.iops else "-",
                              f"{r.lat_us:,.0f}" if r.lat_us else "-", f"{r.p99_us:,.0f}" if r.p99_us else "-")

        progress = lambda r: self.ui(add, r)
        if which("fio"):
            if not tests:
                self.app.notify("Pick at least one test", severity="warning")
                return
            fn = lambda emit: bench.run_fio(tests, d, size, runtime, emit, progress)
        else:
            fn = lambda emit: bench.run_dd(d, size, emit, progress)
        self.task(f"Disk benchmark in {d}", fn)

    @on(Button.Pressed, "#dk-install")
    def _install(self) -> None:
        pkg = os_info().pkg
        self.submit("Install fio", lambda: [Step.cmd("Install fio", pkg, "install", "-y", "fio")],
                    on_done=self.on_mount)


# --------------------------------------------------------------------------- #
# iperf3
# --------------------------------------------------------------------------- #

class IperfPane(Pane):
    listener: Optional[bench.IperfListener] = None

    def compose(self) -> ComposeResult:
        port = str(self.app.cfg.get("iperf.port"))
        yield from section("Temporary iperf3 listener",
                           "Starts 'iperf3 -s'. The firewalld port is opened as a runtime rule that "
                           "expires by itself; the listener stops at the time limit too.")
        yield Static("", id="ip-status", classes="info")
        yield row("Port", Input(port, id="ip-port", type="integer"))
        yield row("Bind address", Input(placeholder="blank = all addresses", id="ip-bind"))
        yield row("Stop after (minutes)", Input(str(self.app.cfg.get("iperf.timeout_min")), id="ip-minutes",
                                                type="integer"))
        with Grid(classes="checks"):
            yield Checkbox("Open firewalld port", True, id="ip-fw")
            yield Checkbox("Also UDP", False, id="ip-udp")
        with Horizontal(classes="buttons"):
            yield Button("Start listener", id="ip-start", variant="primary")
            yield Button("Stop listener", id="ip-stop", disabled=True)
            yield Button("Install iperf3", id="ip-install")
        yield Rule()
        yield from section("Run a test against another server")
        yield row("Server", Input(placeholder="host or IP running iperf3 -s", id="ic-host"))
        yield row("Port", Input(port, id="ic-port", type="integer"))
        yield row("Seconds", Input("10", id="ic-secs", type="integer"))
        yield row("Parallel streams", Input("4", id="ic-streams", type="integer"))
        yield row("UDP bitrate", Input("1G", id="ic-rate"))
        with Grid(classes="checks"):
            yield Checkbox("Reverse (download)", False, id="ic-rev")
            yield Checkbox("UDP", False, id="ic-udp")
        with Horizontal(classes="buttons"):
            yield Button("Run test", id="ic-run", variant="primary")
        yield RichLog(id="ip-out", classes="out", wrap=True)

    def on_mount(self) -> None:
        self.query_one("#ip-install", Button).display = not which("iperf3")
        self._status()

    def _status(self) -> None:
        l = self.listener
        if l and l.running:
            left = max(0, int(l.deadline - time.time()))
            ips = bench.local_ips() or ["<this-server>"]
            text = (f"LISTENING on port {l.port}, stops in {left // 60}m{left % 60:02d}s\n"
                    "From the other machine run:\n" +
                    "\n".join(f"  iperf3 -c {ip} -p {l.port}        (upload to here)\n"
                              f"  iperf3 -c {ip} -p {l.port} -R     (download from here)" for ip in ips[:3]))
        else:
            text = "Listener not running."
        self.query_one("#ip-status", Static).update(Text(text))
        self.query_one("#ip-start", Button).disabled = bool(l and l.running)
        self.query_one("#ip-stop", Button).disabled = not (l and l.running)

    def _out(self, msg: str, style: str = "") -> None:
        self.query_one("#ip-out", RichLog).write(Text(msg, style=style))

    @on(Button.Pressed, "#ip-start")
    def _start(self) -> None:
        if not which("iperf3"):
            self.app.notify("iperf3 is not installed", severity="error")
            return
        try:
            port = self.num("ip-port", "Port")
            minutes = self.num("ip-minutes", "Minutes")
            if not (1 <= port <= 65535 and 1 <= minutes <= 240):
                raise ValueError("Port 1-65535, minutes 1-240")
        except ValueError as exc:
            self.app.notify(str(exc), severity="error")
            return
        if self.app.dry_run:
            self._out(f"(dry-run) would run: iperf3 -s -p {port}; firewall-cmd --add-port={port}/tcp "
                      f"--timeout={minutes}m", "yellow")
            return
        self.listener = bench.IperfListener(port, minutes, self.val("ip-bind"), self.chk("ip-udp"),
                                            self.chk("ip-fw"), lambda m, s="": self.ui(self._out, m, s),
                                            on_exit=lambda: self.ui(self._status))
        self.query_one("#ip-start", Button).disabled = True
        self._start_listener()
        if getattr(self, "_tick", None) is None:
            self._tick = self.set_interval(1, self._status, name="ip-tick")

    @work(thread=True)
    def _start_listener(self) -> None:
        try:
            self.listener.start()     # runs firewall-cmd, keep it off the UI thread
        except Exception as exc:
            self.ui(self._out, f"could not start listener: {exc}", "red")
        self.ui(self._status)

    @on(Button.Pressed, "#ip-stop")
    def _stop(self) -> None:
        if self.listener:
            self.listener.stop()

    def on_unmount(self) -> None:
        if self.listener:
            self.listener.stop("servctl closing")

    @on(Button.Pressed, "#ip-install")
    def _install(self) -> None:
        pkg = os_info().pkg
        self.submit("Install iperf3", lambda: [Step.cmd("Install iperf3", pkg, "install", "-y", "iperf3")],
                    on_done=self.on_mount)

    @on(Button.Pressed, "#ic-run")
    def _client(self) -> None:
        try:
            o = bench.IperfClientOpts(host=self.val("ic-host"), port=self.num("ic-port", "Port"),
                                      seconds=self.num("ic-secs", "Seconds"),
                                      streams=self.num("ic-streams", "Streams"),
                                      reverse=self.chk("ic-rev"), udp=self.chk("ic-udp"),
                                      bitrate=self.val("ic-rate") or "1G")
        except ValueError as exc:
            self.app.notify(str(exc), severity="error")
            return
        out = lambda m, s="": self.ui(self._out, m, s)

        def run(emit):
            res = bench.iperf_client(o, out)
            out(res, "bold green")
            return res
        self.task(f"iperf3 test to {o.host}", run)


# --------------------------------------------------------------------------- #
# DNS benchmark
# --------------------------------------------------------------------------- #

class DnsBenchPane(Pane):
    def compose(self) -> ComposeResult:
        yield from section("Find the best DNS resolver for this network",
                           "Measures cached and uncached (full recursion) lookup time, reliability, "
                           "DNSSEC validation, and whether Spamhaus answers through that resolver.")
        yield Static("loading...", id="db-info", classes="info")
        with Grid(classes="checks"):
            yield Checkbox("Public resolvers", True, id="db-public")
            yield Checkbox("Current system resolvers", True, id="db-system")
            yield Checkbox("Local 127.0.0.1 (Unbound)", True, id="db-local")
        extra = " ".join(self.app.cfg.get("dns.extra_resolvers") or [])
        yield row("Extra resolvers", Input(extra, placeholder="Label=IP or IP, space separated", id="db-extra"))
        yield row("Rounds", Input("2", id="db-rounds", type="integer"))
        with Horizontal(classes="buttons"):
            yield Button("Run benchmark", id="db-run", variant="primary")
            yield Button("Use selected as system DNS", id="db-use")
            yield Button("Restore system DNS", id="db-restore")
        t = NavTable(id="db-table", classes="results", cursor_type="row")
        t.add_columns("#", "resolver", "address", "cached ms", "uncached ms", "reliable",
                      "DNSSEC", "Spamhaus")
        yield t

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        self.set_info("db-info", dnsutil.current_dns_summary())

    def _targets(self) -> List[tuple]:
        targets = []
        if self.chk("db-public"):
            targets += dnsutil.PUBLIC_RESOLVERS
        if self.chk("db-system"):
            targets += [("System", ns) for ns in dnsutil.system_nameservers()]
        if self.chk("db-local"):
            targets.append(("Local", "127.0.0.1"))
        targets += dnsutil.parse_resolver_list(self.val("db-extra").split())
        seen, out = set(), []
        for label, ip in targets:
            if ip not in seen:
                seen.add(ip)
                out.append((label, ip))
        return out

    @on(Button.Pressed, "#db-run")
    def _run(self) -> None:
        targets = self._targets()
        if not targets:
            self.app.notify("Nothing selected", severity="warning")
            return
        try:
            rounds = self.num("db-rounds", "Rounds")
            if not 1 <= rounds <= 10:
                raise ValueError("Rounds must be 1-10")
        except ValueError as exc:
            self.app.notify(str(exc), severity="error")
            return
        table = self.query_one("#db-table", DataTable)
        table.clear()

        def fill(results: Optional[List[dnsutil.BenchResult]]) -> None:
            if not results:
                return
            table.clear()
            for i, r in enumerate(results, 1):
                spam_style = "green" if r.spamhaus == "OK" else "red"
                table.add_row(str(i), r.label, r.server, _fmt_ms(r.cached_ms), _fmt_ms(r.uncached_ms),
                              f"{r.reliability:.0f}%",
                              {True: "validates", False: "no", None: "?"}[r.dnssec],
                              Text(r.spamhaus, style=spam_style), key=r.server)

        def run(emit):
            emit(f"testing {len(targets)} resolvers × {len(dnsutil.POPULAR)} domains × {rounds} rounds", "")
            return dnsutil.benchmark(targets, rounds, lambda r: emit(
                f"  {r.label:<18} {r.server:<16} cached {_fmt_ms(r.cached_ms):>6} ms  "
                f"uncached {_fmt_ms(r.uncached_ms):>6} ms  spamhaus: {r.spamhaus}", ""))
        self.task("DNS benchmark", run, fill)

    @on(Button.Pressed, "#db-use")
    def _use(self) -> None:
        table = self.query_one("#db-table", DataTable)
        if table.row_count == 0:
            self.app.notify("Run the benchmark and select a row first", severity="warning")
            return
        server = str(table.get_row_at(table.cursor_row)[2])
        self.submit(f"Use {server} as system DNS", lambda: dnsutil.system_dns_plan([server]))

    @on(Button.Pressed, "#db-restore")
    def _restore(self) -> None:
        self.submit("Restore system DNS", dnsutil.restore_dns_plan)


# --------------------------------------------------------------------------- #
# Unbound
# --------------------------------------------------------------------------- #

class UnboundPane(Pane):
    def compose(self) -> ComposeResult:
        yield from section("Unbound: local recursive resolver",
                           "Resolves from the root servers itself (no forwarders), validates "
                           "DNSSEC, and keeps root hints fresh with a monthly timer. Spamhaus and "
                           "other DNS blocklists answer it, unlike big public resolvers.")
        yield Static("loading...", id="ub-info", classes="info")
        yield row("Port", Input("53", id="ub-port", type="integer"))
        yield row("Cache size (MB)", Input("128", id="ub-cache", type="integer"))
        yield row("Threads", Input("0", id="ub-threads", type="integer"))
        yield row("LAN networks allowed", Input(placeholder="e.g. 192.168.1.0/24 10.0.0.0/8", id="ub-cidrs"))
        with Grid(classes="checks"):
            yield Checkbox("IPv6", True, id="ub-ipv6")
            yield Checkbox("DNSSEC validation", True, id="ub-dnssec")
            yield Checkbox("Use as system DNS", True, id="ub-system")
            yield Checkbox("Serve the LAN", False, id="ub-lan")
            yield Checkbox("Open firewalld (LAN)", True, id="ub-fw")
        with Horizontal(classes="buttons"):
            yield Button("Install / configure", id="ub-apply", variant="primary")
            yield Button("Self-test", id="ub-test")
            yield Button("Flush cache", id="ub-flush")
            yield Button("Restore system DNS", id="ub-restore")
        yield RichLog(id="ub-out", classes="out", wrap=True)

    @work(thread=True, exclusive=True)
    def refresh_info(self) -> None:
        active = capture(["systemctl", "is-active", "unbound"], 5)[1].strip()
        ver = capture(["unbound", "-V"], 5)[1].splitlines()[0] if which("unbound") else "not installed"
        lines = [f"unbound: {active}   {ver}", dnsutil.current_dns_summary()]
        rc, socks = capture(["ss", "-H", "-lnup", "sport = :53"], 5)
        rc2, socks_t = capture(["ss", "-H", "-lntp", "sport = :53"], 5)
        listeners = (socks + "\n" + socks_t).strip()
        lines.append("port 53 listeners:\n" + (listeners or "  (none)"))
        if active == "active" and which("unbound-control"):
            rc, stats = capture(["unbound-control", "stats_noreset"], 5)
            keep = [l for l in stats.splitlines() if l.startswith(
                ("total.num.queries=", "total.num.cachehits=", "total.recursion.time.avg=", "time.up="))]
            if keep:
                lines.append("stats: " + "  ".join(keep))
        self.set_info("ub-info", "\n".join(lines))

    def _opts(self) -> unbound.UnboundOpts:
        return unbound.UnboundOpts(
            port=self.num("ub-port", "Port"), ipv6=self.chk("ub-ipv6"), lan=self.chk("ub-lan"),
            lan_cidrs=self.val("ub-cidrs").split(), threads=self.num("ub-threads", "Threads"),
            cache_mb=self.num("ub-cache", "Cache size"), dnssec=self.chk("ub-dnssec"),
            set_system_dns=self.chk("ub-system"), open_firewall=self.chk("ub-fw"))

    @on(Button.Pressed, "#ub-apply")
    def _apply(self) -> None:
        self.submit("Install / configure Unbound", lambda: unbound.install_plan(self._opts(), os_info().pkg))

    @on(Button.Pressed, "#ub-test")
    def _test(self) -> None:
        port = self.val("ub-port") or "53"
        out = self.query_one("#ub-out", RichLog)

        def show(results):
            for ok, msg in results or []:
                out.write(Text(("[ OK ] " if ok else "[FAIL] ") + msg, style="green" if ok else "red"))
        self.task("Unbound self-test", lambda emit: unbound.self_test(int(port)), show)

    @on(Button.Pressed, "#ub-flush")
    def _flush(self) -> None:
        self.submit("Flush Unbound cache", unbound.flush_plan)

    @on(Button.Pressed, "#ub-restore")
    def _restore(self) -> None:
        self.submit("Restore system DNS", dnsutil.restore_dns_plan)


# --------------------------------------------------------------------------- #
# Mail DNS
# --------------------------------------------------------------------------- #

# Plain ASCII tags render in every terminal font (no tofu boxes).
_STYLE = {maildns.OK: ("[ OK ]", "green"), maildns.WARN: ("[WARN]", "yellow"),
          maildns.FAIL: ("[FAIL]", "red"), maildns.INFO: ("[INFO]", "cyan")}


class MailDnsPane(Pane):
    def compose(self) -> ComposeResult:
        yield from section("Mail DNS checks",
                           "Full report for a domain (MX, PTR, blocklists, SPF, DMARC, DKIM, MTA-STS, "
                           "TLS-RPT, BIMI, DANE) or an IP address (PTR + blocklists).")
        yield row("Domain or IP", Input(placeholder="example.com or 203.0.113.10", id="md-target"))
        yield row("Resolver", Select([("System resolver", "system"), ("Local Unbound 127.0.0.1", "127.0.0.1"),
                                      ("Custom (below)", "custom")], value="system", allow_blank=False,
                                     id="md-resolver"))
        yield row("Custom resolver", Input(placeholder="e.g. 9.9.9.9", id="md-custom"))
        sels = " ".join(self.app.cfg.get("dns.dkim_selectors") or [])
        yield row("DKIM selectors", Input(sels, placeholder="your selectors, space separated", id="md-sel"))
        with Horizontal(classes="buttons"):
            yield Button("Full mail report", id="md-run", variant="primary")
        yield from section("Quick lookup")
        yield row("Record type", Select([(t, t) for t in ("MX", "TXT", "A", "AAAA", "PTR", "CNAME", "NS",
                                                          "SOA", "TLSA", "CAA", "SRV")],
                                        value="TXT", allow_blank=False, id="md-type"))
        with Horizontal(classes="buttons"):
            yield Button("Lookup", id="md-lookup")
            yield Button("Clear", id="md-clear")
        yield RichLog(id="md-out", classes="out", wrap=True)

    def _server(self) -> Optional[str]:
        choice = self.sel("md-resolver")
        if choice == "system":
            return None
        if choice == "custom":
            v = self.val("md-custom")
            if not v:
                raise ValueError("Enter a custom resolver IP")
            return v
        return choice

    def _write(self, text: str, style: str = "") -> None:
        self.query_one("#md-out", RichLog).write(Text(text, style=style))

    @on(Input.Submitted, "#md-target")
    @on(Button.Pressed, "#md-run")
    def _run(self) -> None:
        target = self.val("md-target")
        if not target:
            self.app.notify("Enter a domain or IP", severity="warning")
            return
        try:
            server = self._server()
        except ValueError as exc:
            self.app.notify(str(exc), severity="error")
            return
        self._write(f"── {target} via {server or 'system resolver'} ──", "bold")
        last = {"section": ""}

        def emit_finding(f: maildns.Finding) -> None:
            icon, style = _STYLE[f.status]
            head = f.section if f.section != last["section"] else ""
            last["section"] = f.section
            self.ui(self._write, f"{head:<8} {icon} {f.text}", style)

        selectors = self.val("md-sel").split()
        self.task(f"Mail DNS report for {target}",
                  lambda emit: maildns.Checker(server, emit_finding).run(target, selectors))

    @on(Button.Pressed, "#md-lookup")
    def _lookup(self) -> None:
        name, rtype = self.val("md-target"), self.sel("md-type")
        if not name:
            self.app.notify("Enter a name", severity="warning")
            return
        try:
            server = self._server()
        except ValueError as exc:
            self.app.notify(str(exc), severity="error")
            return

        def show(a):
            if a is None:
                return
            flags = " (DNSSEC validated)" if a.ad else ""
            self._write(f"{rtype} {name} → {a.rcode} in {a.ms:.1f} ms{flags}", "bold")
            for r in a.records or ([a.error] if a.error else ["(no records)"]):
                self._write("   " + r, "red" if a.error else "")
        self.task(f"Lookup {rtype} {name}", lambda emit: maildns.lookup(name, rtype, server), show)

    @on(Button.Pressed, "#md-clear")
    def _clear(self) -> None:
        self.query_one("#md-out", RichLog).clear()
