"""Speedtest, disk benchmark and iperf3 helpers."""
from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import statistics
import subprocess
import threading
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .core import Step, capture, firewalld_running, which

Emit = Callable[[str, str], None]

# --------------------------------------------------------------------------- #
# Speedtest
# --------------------------------------------------------------------------- #


def _connection(base: str, timeout: float = 15) -> Tuple[http.client.HTTPConnection, str]:
    u = urllib.parse.urlsplit(base)
    host, port = u.hostname or "", u.port
    https = u.scheme == "https"
    proxy = os.environ.get("https_proxy" if https else "http_proxy") or \
        os.environ.get("HTTPS_PROXY" if https else "HTTP_PROXY")
    cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
    if proxy and host not in (os.environ.get("no_proxy") or "").split(","):
        p = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
        conn = cls(p.hostname, p.port or 8080, timeout=timeout)
        conn.set_tunnel(host, port or (443 if https else 80))
    else:
        conn = cls(host, port, timeout=timeout)
    return conn, u.path.rstrip("/")


@dataclass
class SpeedResult:
    engine: str
    ping_ms: float = 0.0
    jitter_ms: float = 0.0
    down_mbps: float = 0.0
    up_mbps: float = 0.0
    server: str = ""
    ip: str = ""
    extra: str = ""


def _trace(base: str) -> Dict[str, str]:
    conn, prefix = _connection(base)
    try:
        conn.request("GET", prefix + "/cdn-cgi/trace")
        body = conn.getresponse().read().decode("utf-8", "replace")
    finally:
        conn.close()
    return dict(l.split("=", 1) for l in body.splitlines() if "=" in l)


def _latency(base: str, n: int = 12) -> Tuple[float, float]:
    conn, prefix = _connection(base)
    samples = []
    try:
        conn.request("GET", prefix + "/__down?bytes=0")   # opens TCP+TLS, not counted
        conn.getresponse().read()
        for _ in range(n):
            t0 = time.perf_counter()
            conn.request("GET", prefix + "/__down?bytes=0")
            conn.getresponse().read()
            samples.append((time.perf_counter() - t0) * 1000)
    finally:
        conn.close()
    jitter = statistics.mean(abs(a - b) for a, b in zip(samples, samples[1:])) if len(samples) > 1 else 0
    return statistics.median(samples), jitter


def _down_stream(base: str, nbytes: int) -> int:
    conn, prefix = _connection(base, timeout=60)
    got = 0
    try:
        conn.request("GET", f"{prefix}/__down?bytes={nbytes}")
        r = conn.getresponse()
        while True:
            chunk = r.read(256 * 1024)
            if not chunk:
                break
            got += len(chunk)
    finally:
        conn.close()
    return got


def _up_stream(base: str, nbytes: int) -> int:
    conn, prefix = _connection(base, timeout=60)
    try:
        conn.request("POST", f"{prefix}/__up", body=b"0" * nbytes,
                     headers={"Content-Type": "application/octet-stream"})
        conn.getresponse().read()
    finally:
        conn.close()
    return nbytes


def _parallel(fn: Callable[[str, int], int], base: str, total: int, streams: int) -> float:
    per = max(1, total // streams)
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=streams) as pool:
        moved = sum(pool.map(lambda _: fn(base, per), range(streams)))
    secs = time.perf_counter() - t0
    return moved * 8 / secs / 1e6


def cloudflare_speedtest(base: str, down_mb: int, up_mb: int, streams: int, emit: Emit) -> SpeedResult:
    res = SpeedResult("Cloudflare")
    try:
        t = _trace(base)
        res.server = f"{t.get('colo', '?')} ({t.get('loc', '?')})"
        res.ip = t.get("ip", "")
        emit(f"edge {res.server}, your IP {res.ip}", "")
    except Exception as exc:
        emit(f"trace failed: {exc}", "yellow")
    res.ping_ms, res.jitter_ms = _latency(base)
    emit(f"latency {res.ping_ms:.1f} ms, jitter {res.jitter_ms:.1f} ms", "")
    # Short warm-up so TCP slow start does not drag the real figure down.
    _parallel(_down_stream, base, 2_000_000, streams)
    res.down_mbps = _parallel(_down_stream, base, down_mb * 1_000_000, streams)
    emit(f"download {res.down_mbps:.1f} Mbit/s ({streams} streams, {down_mb} MB)", "")
    res.up_mbps = _parallel(_up_stream, base, up_mb * 1_000_000, streams)
    emit(f"upload {res.up_mbps:.1f} Mbit/s ({streams} streams, {up_mb} MB)", "")
    return res


def ookla_flavour() -> Optional[str]:
    """'ookla' for the official CLI, 'sivel' for python speedtest-cli, None if absent."""
    if which("speedtest"):
        out = capture(["speedtest", "--version"], 10)[1]
        if "Ookla" in out:
            return "ookla"
        return "sivel"
    if which("speedtest-cli"):
        return "sivel"
    return None


def ookla_speedtest(emit: Emit) -> SpeedResult:
    flavour = ookla_flavour()
    if flavour == "ookla":
        argv = ["speedtest", "--accept-license", "--accept-gdpr", "-f", "json"]
    elif flavour == "sivel":
        argv = [which("speedtest-cli") or "speedtest", "--json", "--secure"]
    else:
        raise RuntimeError("no speedtest CLI installed")
    emit("$ " + " ".join(argv), "dim")
    rc, out = capture(argv, timeout=180)
    line = next((l for l in out.splitlines() if l.startswith("{")), "")
    if rc != 0 or not line:
        raise RuntimeError(out[-500:])
    d = json.loads(line)
    if flavour == "ookla":
        return SpeedResult("Ookla", ping_ms=d["ping"]["latency"], jitter_ms=d["ping"].get("jitter", 0),
                           down_mbps=d["download"]["bandwidth"] * 8 / 1e6,
                           up_mbps=d["upload"]["bandwidth"] * 8 / 1e6,
                           server=f"{d['server']['name']} ({d['server']['location']})",
                           ip=d.get("interface", {}).get("externalIp", ""),
                           extra=d.get("result", {}).get("url", ""))
    return SpeedResult("speedtest-cli", ping_ms=d["ping"], down_mbps=d["download"] / 1e6,
                       up_mbps=d["upload"] / 1e6,
                       server=f"{d['server']['sponsor']} ({d['server']['name']})",
                       ip=d.get("client", {}).get("ip", ""))


def ookla_install_plan(pkg: str) -> List[Step]:
    if pkg in ("dnf", "yum"):
        script = ("curl -fsSL https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh"
                  " | bash")
    elif pkg == "apt-get":
        script = ("curl -fsSL https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh"
                  " | bash")
    else:
        raise ValueError("Unsupported package manager")
    return [Step.sh("Add Ookla's official package repository", script),
            Step.cmd("Install the Ookla speedtest CLI", pkg, "install", "-y", "speedtest")]


# --------------------------------------------------------------------------- #
# Disk benchmark
# --------------------------------------------------------------------------- #


@dataclass
class DiskTest:
    label: str
    rw: str
    bs: str
    iodepth: int
    jobs: int = 1


# CrystalDiskMark-style defaults, so numbers are comparable with what people post.
DISK_TESTS = [
    DiskTest("SEQ1M Q8T1 read", "read", "1M", 8),
    DiskTest("SEQ1M Q8T1 write", "write", "1M", 8),
    DiskTest("RND4K Q32T1 read", "randread", "4k", 32),
    DiskTest("RND4K Q32T1 write", "randwrite", "4k", 32),
    DiskTest("RND4K Q1T1 read", "randread", "4k", 1),
    DiskTest("RND4K Q1T1 write", "randwrite", "4k", 1),
]


@dataclass
class DiskResult:
    label: str
    mbps: float = 0.0
    iops: float = 0.0
    lat_us: float = 0.0
    p99_us: float = 0.0
    error: str = ""


_SIZE_RE = re.compile(r"^(\d+)([KMG])$", re.I)


def size_bytes(s: str) -> int:
    m = _SIZE_RE.match(s.strip())
    if not m:
        raise ValueError("Size must look like 512M or 2G")
    return int(m.group(1)) * {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}[m.group(2).upper()]


def check_target(directory: str, size: str) -> None:
    if not os.path.isdir(directory):
        raise ValueError(f"{directory} is not a directory")
    need = size_bytes(size)
    free = shutil.disk_usage(directory).free
    if free < need * 1.2:
        raise ValueError(f"Not enough free space in {directory}: need {need >> 20} MiB + 20%")


def fio_argv(t: DiskTest, directory: str, size: str, runtime: int, filename: str,
             direct: bool = True) -> List[str]:
    return ["fio", "--name=servctl", f"--directory={directory}", f"--filename={filename}",
            f"--size={size}", f"--rw={t.rw}", f"--bs={t.bs}", f"--iodepth={t.iodepth}",
            f"--numjobs={t.jobs}", f"--direct={1 if direct else 0}", "--ioengine=libaio",
            f"--runtime={runtime}", "--time_based", "--ramp_time=1", "--group_reporting",
            "--randrepeat=0", "--norandommap", "--output-format=json"]


def parse_fio(label: str, out: str, rw: str) -> DiskResult:
    start = out.find("{")
    data = json.loads(out[start:])
    job = data["jobs"][0]["read" if "read" in rw else "write"]
    lat = job.get("clat_ns", {})
    p99 = lat.get("percentile", {}).get("99.000000", 0)
    return DiskResult(label, mbps=job["bw_bytes"] / 1e6, iops=job["iops"],
                      lat_us=lat.get("mean", 0) / 1000, p99_us=p99 / 1000)


def run_fio(tests: List[DiskTest], directory: str, size: str, runtime: int,
            emit: Emit, progress: Callable[[DiskResult], None]) -> List[DiskResult]:
    check_target(directory, size)
    filename = f".servctl-fio-{uuid.uuid4().hex[:8]}.tmp"
    path = os.path.join(directory, filename)
    results = []
    direct = True
    try:
        for t in tests:
            emit(f"{t.label}: running {runtime}s...", "")
            argv = fio_argv(t, directory, size, runtime, filename, direct)
            rc, out = capture(argv, timeout=runtime * 3 + 600)
            if rc != 0 and direct and ("direct" in out.lower() or "Invalid argument" in out):
                emit("O_DIRECT not supported here (tmpfs?), retrying buffered - results include page cache",
                     "yellow")
                direct = False
                rc, out = capture(fio_argv(t, directory, size, runtime, filename, direct),
                                  timeout=runtime * 3 + 600)
            if rc != 0:
                r = DiskResult(t.label, error=out.strip().splitlines()[-1] if out.strip() else f"exit {rc}")
            else:
                try:
                    r = parse_fio(t.label, out, t.rw)
                except (ValueError, KeyError, IndexError) as exc:
                    r = DiskResult(t.label, error=f"could not parse fio output: {exc}")
            results.append(r)
            progress(r)
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return results


def run_dd(directory: str, size: str, emit: Emit,
           progress: Callable[[DiskResult], None]) -> List[DiskResult]:
    """Sequential-only fallback when fio is not installed."""
    check_target(directory, size)
    mib = size_bytes(size) >> 20
    path = os.path.join(directory, f".servctl-dd-{uuid.uuid4().hex[:8]}.tmp")
    results = []
    try:
        for label, argv in (
            ("SEQ1M write (dd)", ["dd", "if=/dev/zero", f"of={path}", "bs=1M", f"count={mib}",
                                  "oflag=direct", "conv=fdatasync"]),
            ("SEQ1M read (dd)", ["dd", f"if={path}", "of=/dev/null", "bs=1M", "iflag=direct"]),
        ):
            emit(f"{label}...", "")
            rc, out = capture(argv, timeout=1800)
            m = re.search(r"copied,\s*([\d.]+)\s*s", out)
            if rc == 0 and m:
                r = DiskResult(label, mbps=size_bytes(size) / float(m.group(1)) / 1e6)
            else:
                r = DiskResult(label, error=out.strip().splitlines()[-1] if out.strip() else f"exit {rc}")
            results.append(r)
            progress(r)
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return results


# --------------------------------------------------------------------------- #
# iperf3
# --------------------------------------------------------------------------- #


def local_ips() -> List[str]:
    rc, out = capture(["hostname", "-I"], 5)
    return [ip for ip in out.split() if not ip.startswith(("127.", "::1", "fe80"))] if rc == 0 else []


class IperfListener:
    """A temporary iperf3 server with an auto-expiring firewalld rule."""

    def __init__(self, port: int, minutes: int, bind: str, udp: bool, open_firewall: bool,
                 emit: Emit, on_exit: Callable[[], None]) -> None:
        self.port, self.minutes, self.bind, self.udp = port, minutes, bind, udp
        self.open_firewall = open_firewall and firewalld_running()
        self.emit, self.on_exit = emit, on_exit
        self.proc: Optional[subprocess.Popen] = None
        self.deadline = 0.0
        self._timer: Optional[threading.Timer] = None

    def _fw(self, action: str) -> None:
        protos = ["tcp", "udp"] if self.udp else ["tcp"]
        for p in protos:
            argv = ["firewall-cmd", f"--{action}-port={self.port}/{p}"]
            if action == "add":
                argv.append(f"--timeout={self.minutes}m")   # runtime only, removes itself
            rc, out = capture(argv, 15)
            self.emit(f"$ {' '.join(argv)} -> {out.strip()}", "dim" if rc == 0 else "yellow")

    def start(self) -> None:
        if not which("iperf3"):
            raise RuntimeError("iperf3 is not installed")
        argv = ["iperf3", "-s", "-p", str(self.port)]
        if self.bind:
            argv += ["-B", self.bind]
        if "--forceflush" in capture(["iperf3", "--help"], 5)[1]:
            argv.append("--forceflush")
        if self.open_firewall:
            self._fw("add")
        self.emit("$ " + " ".join(argv), "dim")
        self.proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, text=True, bufsize=1)
        self.deadline = time.time() + self.minutes * 60
        self._timer = threading.Timer(self.minutes * 60, self.stop, kwargs={"reason": "time limit reached"})
        self._timer.daemon = True
        self._timer.start()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            line = line.rstrip()
            if line:
                self.emit(line, "")
        rc = self.proc.wait()
        self.emit(f"iperf3 listener exited ({rc})", "yellow" if rc else "")
        if self._timer:
            self._timer.cancel()
        if self.open_firewall:
            self._fw("remove")
        self.on_exit()

    def stop(self, reason: str = "stopped") -> None:
        if self.proc and self.proc.poll() is None:
            self.emit(f"stopping iperf3 listener: {reason}", "yellow")
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


@dataclass
class IperfClientOpts:
    host: str
    port: int = 5201
    seconds: int = 10
    streams: int = 4
    reverse: bool = False
    udp: bool = False
    bitrate: str = "1G"


def iperf_client(o: IperfClientOpts, emit: Emit) -> str:
    if not re.match(r"^[A-Za-z0-9.:\-\[\]]+$", o.host or ""):
        raise ValueError("Enter the iperf3 server host or IP")
    argv = ["iperf3", "-c", o.host, "-p", str(o.port), "-t", str(o.seconds), "-P", str(o.streams), "-J"]
    if o.reverse:
        argv.append("-R")
    if o.udp:
        argv += ["-u", "-b", o.bitrate]
    emit("$ " + " ".join(argv), "dim")
    rc, out = capture(argv, timeout=o.seconds + 60)
    try:
        d = json.loads(out[out.find("{"):])
    except ValueError:
        raise RuntimeError(out[-400:])
    if d.get("error"):
        raise RuntimeError(d["error"])
    end = d["end"]
    direction = "server -> this host" if o.reverse else "this host -> server"
    if o.udp:
        s = end["sum"]
        return (f"UDP {direction}: {s['bits_per_second'] / 1e6:.1f} Mbit/s, jitter {s['jitter_ms']:.2f} ms, "
                f"loss {s['lost_percent']:.2f}%")
    sent, recv = end["sum_sent"], end["sum_received"]
    return (f"TCP {direction}: {recv['bits_per_second'] / 1e6:.1f} Mbit/s received, "
            f"{sent['bits_per_second'] / 1e6:.1f} Mbit/s sent, {sent.get('retransmits', 0)} retransmits")
