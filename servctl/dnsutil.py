"""DNS queries, resolver benchmark, Spamhaus reachability, system resolver plans.

Can also be run as ``python -m servctl.dnsutil SERVER NAME`` to wait until a
resolver answers (used by the Unbound plan before switching system DNS).
"""
from __future__ import annotations

import random
import statistics
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename

from .core import Step, capture, read_text, which

PUBLIC_RESOLVERS: List[Tuple[str, str]] = [
    ("Cloudflare", "1.1.1.1"),
    ("Cloudflare", "1.0.0.1"),
    ("Google", "8.8.8.8"),
    ("Google", "8.8.4.4"),
    ("Quad9", "9.9.9.9"),
    ("Quad9 unfiltered", "9.9.9.10"),
    ("OpenDNS", "208.67.222.222"),
    ("AdGuard", "94.140.14.14"),
    ("Control D", "76.76.2.0"),
    ("CleanBrowsing", "185.228.168.9"),
    ("Lumen/Level3", "4.2.2.1"),
    ("Comodo", "8.26.56.26"),
]

POPULAR = ["google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
           "microsoft.com", "apple.com", "cloudflare.com", "github.com", "netflix.com",
           "instagram.com", "linkedin.com", "reddit.com", "office.com", "zoom.us"]

SPAMHAUS_TEST = "2.0.0.127.zen.spamhaus.org"   # permanent test point, always listed
SPAMHAUS_ERRORS = {
    "127.255.255.252": "typo in query",
    "127.255.255.254": "blocked: public/open resolver",
    "127.255.255.255": "blocked: excessive queries",
}
ZEN_CODES = {
    "127.0.0.2": "SBL (spam source)", "127.0.0.3": "CSS (snowshoe spam)",
    "127.0.0.4": "XBL (exploited/botnet)", "127.0.0.5": "XBL", "127.0.0.6": "XBL",
    "127.0.0.7": "XBL", "127.0.0.9": "DROP (hijacked netblock)",
    "127.0.0.10": "PBL (ISP: end-user range, should not send mail directly)",
    "127.0.0.11": "PBL (Spamhaus: end-user range)",
}


@dataclass
class Answer:
    rcode: str
    records: List[str] = field(default_factory=list)
    ms: float = 0.0
    error: str = ""
    ad: bool = False

    @property
    def ok(self) -> bool:
        return not self.error and self.rcode in ("NOERROR", "NXDOMAIN")


def parse_server(spec: str) -> Tuple[str, int]:
    spec = spec.strip()
    if spec.startswith("["):                  # [v6]:port
        host, _, port = spec[1:].partition("]")
        return host, int(port.lstrip(":") or 53)
    if spec.count(":") == 1:                  # v4:port or name:port
        host, port = spec.split(":")
        return host, int(port)
    return spec, 53


def system_nameservers() -> List[str]:
    try:
        return list(dns.resolver.Resolver().nameservers)
    except Exception:
        return []


def query(name: str, rtype: str = "A", server: Optional[str] = None, timeout: float = 2.0,
          dnssec: bool = False) -> Answer:
    if not server:
        ns = system_nameservers()
        if not ns:
            return Answer("ERROR", error="no system nameserver configured")
        server = ns[0]
    host, port = parse_server(server)
    q = dns.message.make_query(name, rtype, want_dnssec=dnssec)
    q.flags |= dns.flags.AD           # ask the resolver to report validation status
    t0 = time.perf_counter()
    try:
        r = dns.query.udp(q, host, port=port, timeout=timeout)
        if r.flags & dns.flags.TC:
            r = dns.query.tcp(q, host, port=port, timeout=timeout)
    except dns.exception.Timeout:
        return Answer("TIMEOUT", ms=(time.perf_counter() - t0) * 1000, error="timeout")
    except (OSError, dns.exception.DNSException) as exc:
        return Answer("ERROR", ms=(time.perf_counter() - t0) * 1000, error=str(exc) or type(exc).__name__)
    ms = (time.perf_counter() - t0) * 1000
    want = dns.rdatatype.from_text(rtype)
    recs = [rd.to_text() for rrset in r.answer if rrset.rdtype == want for rd in rrset]
    return Answer(dns.rcode.to_text(r.rcode()), recs, ms, ad=bool(r.flags & dns.flags.AD))


def spamhaus_status(server: Optional[str]) -> str:
    a = query(SPAMHAUS_TEST, "A", server, timeout=3)
    if a.error:
        return a.error
    for rec in a.records:
        if rec in SPAMHAUS_ERRORS:
            return SPAMHAUS_ERRORS[rec]
    if any(r.startswith("127.0.0.") for r in a.records):
        return "OK"
    return f"no answer ({a.rcode})"


def dnssec_validates(server: Optional[str]) -> Optional[bool]:
    """A validating resolver must SERVFAIL on a deliberately broken signature."""
    bad = query("dnssec-failed.org", "A", server, timeout=3)
    good = query("isc.org", "A", server, timeout=3)
    if bad.error or good.error:
        return None
    return bad.rcode == "SERVFAIL" and good.rcode == "NOERROR"


def _rand_label(n: int = 12) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


@dataclass
class BenchResult:
    label: str
    server: str
    cached_ms: Optional[float] = None
    uncached_ms: Optional[float] = None
    reliability: float = 0.0
    dnssec: Optional[bool] = None
    spamhaus: str = ""

    @property
    def score(self) -> float:
        """Lower is better. Uncached lookups weigh more; failures cost a lot."""
        if self.cached_ms is None or self.uncached_ms is None:
            return float("inf")
        return 0.4 * self.cached_ms + 0.6 * self.uncached_ms + (100 - self.reliability) * 20


def bench_resolver(label: str, server: str, rounds: int = 2) -> BenchResult:
    res = BenchResult(label, server)
    cached: List[float] = []
    uncached: List[float] = []
    sent = ok = 0
    domains = POPULAR[:]
    for d in domains:                       # warm-up: puts answers in the resolver cache
        query(d, "A", server, timeout=2)
    for _ in range(rounds):
        for d in domains:
            a = query(d, "A", server, timeout=2)
            sent += 1
            if a.ok:
                ok += 1
                cached.append(a.ms)
            # Random names cannot be cached, so this measures full recursion.
            b = query(f"{_rand_label()}.{d}", "A", server, timeout=3)
            sent += 1
            if b.ok:
                ok += 1
                uncached.append(b.ms)
    res.reliability = 100.0 * ok / sent if sent else 0.0
    if cached:
        res.cached_ms = statistics.median(cached)
    if uncached:
        res.uncached_ms = statistics.median(uncached)
    res.dnssec = dnssec_validates(server)
    res.spamhaus = spamhaus_status(server)
    return res


def benchmark(targets: List[Tuple[str, str]], rounds: int,
              progress: Callable[[BenchResult], None]) -> List[BenchResult]:
    results: List[BenchResult] = []
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(targets)))) as pool:
        futures = [pool.submit(bench_resolver, lbl, srv, rounds) for lbl, srv in targets]
        for f in futures:
            r = f.result()
            results.append(r)
            progress(r)
    return sorted(results, key=lambda r: r.score)


def parse_resolver_list(items: List[str]) -> List[Tuple[str, str]]:
    out = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        label, _, ip = item.rpartition("=")
        out.append((label or "Custom", ip))
    return out


# --------------------------------------------------------------------------- #
# Pointing the system at a resolver
# --------------------------------------------------------------------------- #

RESOLVED_DROPIN = "/etc/systemd/resolved.conf.d/60-servctl.conf"
NM_DROPIN = "/etc/NetworkManager/conf.d/90-servctl-dns.conf"


def dns_backend() -> str:
    if capture(["systemctl", "is-active", "systemd-resolved"], 5)[1].strip() == "active":
        return "resolved"
    if which("nmcli") and capture(["systemctl", "is-active", "NetworkManager"], 5)[1].strip() == "active":
        return "networkmanager"
    return "resolv.conf"


def system_dns_plan(servers: List[str], backend: Optional[str] = None) -> List[Step]:
    if not servers:
        raise ValueError("No resolver selected")
    for s in servers:
        host, port = parse_server(s)
        if port != 53:
            raise ValueError("System resolvers must listen on port 53")
    backend = backend or dns_backend()
    plain = [parse_server(s)[0] for s in servers]
    if backend == "resolved":
        return [
            Step.write("Point systemd-resolved at the resolver", RESOLVED_DROPIN,
                       "# Managed by servctl\n[Resolve]\nDNS=" + " ".join(plain) +
                       "\nDomains=~.\n"),
            Step.cmd("Restart systemd-resolved", "systemctl", "restart", "systemd-resolved"),
            Step.cmd("Show resolver status", "resolvectl", "dns", allow_fail=True),
        ]
    resolv = "# Managed by servctl\n" + "".join(f"nameserver {s}\n" for s in plain) + \
             "options edns0 trust-ad\n"
    if backend == "networkmanager":
        # Global DNS overrides the per-connection servers without bouncing any link.
        return [
            Step.write("Set NetworkManager global DNS", NM_DROPIN,
                       "# Managed by servctl\n[global-dns-domain-*]\nservers=" +
                       ",".join(plain) + "\n"),
            Step.cmd("Reload NetworkManager", "systemctl", "reload", "NetworkManager"),
            Step.cmd("Show /etc/resolv.conf", "cat", "/etc/resolv.conf"),
        ]
    return [Step.write("Write /etc/resolv.conf", "/etc/resolv.conf", resolv)]


def restore_dns_plan(backend: Optional[str] = None) -> List[Step]:
    backend = backend or dns_backend()
    if backend == "resolved":
        return [Step.delete("Remove servctl resolved drop-in", RESOLVED_DROPIN),
                Step.cmd("Restart systemd-resolved", "systemctl", "restart", "systemd-resolved")]
    if backend == "networkmanager":
        return [Step.delete("Remove servctl NetworkManager DNS drop-in", NM_DROPIN),
                Step.cmd("Reload NetworkManager", "systemctl", "reload", "NetworkManager"),
                Step.cmd("Show /etc/resolv.conf", "cat", "/etc/resolv.conf")]
    raise ValueError("/etc/resolv.conf is not managed by a service here; restore it from "
                     "/var/backups/servctl or edit it by hand")


def current_dns_summary() -> str:
    backend = dns_backend()
    lines = [f"DNS managed by: {backend}"]
    if backend == "resolved":
        lines.append(capture(["resolvectl", "dns"], 5)[1])
    resolv = read_text("/etc/resolv.conf") or ""
    lines.append("/etc/resolv.conf: " + ", ".join(
        l.split()[1] for l in resolv.splitlines() if l.startswith("nameserver") and len(l.split()) > 1))
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    """Wait (up to ~10s) for SERVER to resolve NAME. Exit 0 on success."""
    if len(argv) != 2:
        print("usage: python -m servctl.dnsutil SERVER NAME")
        return 2
    server, name = argv
    for _ in range(10):
        a = query(name, "A", server)
        if a.rcode == "NOERROR" and a.records:
            print(f"{server} resolved {name} -> {', '.join(a.records)} in {a.ms:.1f} ms")
            return 0
        time.sleep(1)
    print(f"{server} did not resolve {name}: {a.error or a.rcode}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
