"""Mail-related DNS checks for a domain (or an IP address)."""
from __future__ import annotations

import ipaddress
import re
import ssl
import urllib.request
from dataclasses import dataclass
from typing import Callable, List, Optional, Set

import dns.reversename

from .dnsutil import ZEN_CODES, SPAMHAUS_ERRORS, Answer, query

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"

COMMON_DKIM_SELECTORS = [
    "default", "dkim", "mail", "selector1", "selector2", "google", "k1", "k2", "k3",
    "s1", "s2", "smtp", "mx", "email", "key1", "dkim1", "mandrill", "mxvault", "zoho",
    "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3", "sig1", "everlytickey1",
    "mailjet", "sendgrid", "pm", "scph0124", "amazonses",
]
DNSBLS = [("zen.spamhaus.org", "Spamhaus ZEN"), ("bl.spamcop.net", "SpamCop")]


@dataclass
class Finding:
    section: str
    status: str
    text: str


Emit = Callable[[Finding], None]


class Checker:
    def __init__(self, server: Optional[str], emit: Emit) -> None:
        self.server = server
        self.emit = emit

    def q(self, name: str, rtype: str) -> Answer:
        return query(name, rtype, self.server, timeout=4)

    def txt(self, name: str, prefix: str) -> List[str]:
        recs = [_txt(r) for r in self.q(name, "TXT").records]
        return [r for r in recs if r.lower().startswith(prefix.lower())]

    def say(self, section: str, status: str, text: str) -> None:
        self.emit(Finding(section, status, text))

    # ------------------------------------------------------------------ #

    def run(self, target: str, selectors: List[str]) -> None:
        target = target.strip().rstrip(".").lower()
        try:
            ipaddress.ip_address(target)
        except ValueError:
            self.domain_report(target, selectors)
        else:
            self.ip_report("IP", target)

    def domain_report(self, domain: str, selectors: List[str]) -> None:
        if not re.match(r"^[a-z0-9.-]+\.[a-z0-9-]+$", domain):
            self.say("input", FAIL, f"'{domain}' is not a domain name or IP address")
            return
        soa = query(domain, "SOA", self.server, timeout=4, dnssec=True)
        if soa.error:
            self.say("DNS", FAIL, f"resolver {self.server or 'system'} failed: {soa.error}")
            return
        if soa.rcode == "NXDOMAIN":
            self.say("DNS", FAIL, f"{domain} does not exist (NXDOMAIN)")
            return
        self.say("DNSSEC", OK if soa.ad else INFO,
                 "zone is signed and validated (AD flag)" if soa.ad else
                 "not validated (unsigned zone, or the resolver does not validate)")
        mx_hosts = self.mx(domain)
        self.spf(domain)
        self.dmarc(domain)
        self.dkim(domain, selectors)
        self.mta_sts(domain)
        tls = self.txt(f"_smtp._tls.{domain}", "v=TLSRPTv1")
        self.say("TLS-RPT", OK if tls else INFO, tls[0] if tls else "no _smtp._tls record (optional)")
        bimi = self.txt(f"default._bimi.{domain}", "v=BIMI1")
        self.say("BIMI", OK if bimi else INFO, bimi[0] if bimi else "no default._bimi record (optional)")
        for host in mx_hosts:
            self.dane(host)

    def mx(self, domain: str) -> List[str]:
        a = self.q(domain, "MX")
        if not a.records:
            self.say("MX", FAIL, "no MX record: senders fall back to the A record, if any")
            return []
        recs = sorted((int(r.split()[0]), r.split()[1].rstrip(".")) for r in a.records)
        if recs == [(0, "")] or recs == [(0, ".")] or (len(recs) == 1 and recs[0][1] in ("", ".")):
            self.say("MX", INFO, "null MX (RFC 7505): this domain does not receive mail")
            return []
        hosts = []
        for pref, host in recs:
            self.say("MX", OK, f"{pref:>3} {host}")
            hosts.append(host)
            ips = self.q(host, "A").records + self.q(host, "AAAA").records
            if not ips:
                self.say("MX", FAIL, f"    {host} has no A/AAAA record")
            for ip in ips:
                self.ip_report("MX", ip, indent="    ")
        return hosts

    def ip_report(self, section: str, ip: str, indent: str = "") -> None:
        rev = dns.reversename.from_address(ip).to_text()
        ptr = [p.rstrip(".") for p in self.q(rev, "PTR").records]
        if not ptr:
            self.say(section, WARN, f"{indent}{ip}: no PTR (reverse DNS) - many receivers reject this")
        else:
            fwd: Set[str] = set()
            for p in ptr:
                fwd.update(self.q(p, "AAAA" if ":" in ip else "A").records)
            match = ip in fwd or str(ipaddress.ip_address(ip)) in fwd
            self.say(section, OK if match else WARN,
                     f"{indent}{ip}: PTR {', '.join(ptr)} "
                     f"{'(forward-confirmed)' if match else '(PTR name does not resolve back to this IP)'}")
        for zone, name in DNSBLS:
            self.dnsbl(section, ip, zone, name, indent)

    def dnsbl(self, section: str, ip: str, zone: str, name: str, indent: str) -> None:
        rev = dns.reversename.from_address(ip).to_text()
        base = rev.replace(".in-addr.arpa.", "").replace(".ip6.arpa.", "")
        a = self.q(f"{base}.{zone}", "A")
        if a.error:
            self.say(section, WARN, f"{indent}{ip}: {name} lookup failed ({a.error})")
        elif not a.records:
            self.say(section, OK, f"{indent}{ip}: not listed on {name}")
        elif any(r in SPAMHAUS_ERRORS for r in a.records):
            err = next(SPAMHAUS_ERRORS[r] for r in a.records if r in SPAMHAUS_ERRORS)
            self.say(section, WARN, f"{indent}{ip}: {name} refused the query ({err}) - "
                                    "use a recursive resolver such as local Unbound")
        else:
            why = ", ".join(ZEN_CODES.get(r, r) for r in a.records) if zone.startswith("zen") \
                else ", ".join(a.records)
            self.say(section, FAIL, f"{indent}{ip}: LISTED on {name}: {why}")

    def spf(self, domain: str) -> None:
        recs = self.txt(domain, "v=spf1")
        if not recs:
            self.say("SPF", FAIL, "no SPF record")
            return
        if len(recs) > 1:
            self.say("SPF", FAIL, f"{len(recs)} SPF records - must be exactly one (permerror)")
        rec = recs[0]
        self.say("SPF", INFO, rec)
        m = re.search(r"([~?+-]?)all\b", rec)
        qual = m.group(1) if m else None
        policy = {"-": (OK, "-all: hard fail for others"), "~": (OK, "~all: soft fail for others"),
                  "?": (WARN, "?all: neutral, gives no protection"),
                  "+": (FAIL, "+all: anyone may send as this domain!"),
                  "": (FAIL, "all: anyone may send as this domain!")}
        if qual is None:
            self.say("SPF", WARN, "no 'all' mechanism at the end" + (" (uses redirect=)" if "redirect=" in rec else ""))
        else:
            st, txt = policy[qual]
            self.say("SPF", st, txt)
        count = self._spf_lookups(domain, set(), 0)
        self.say("SPF", OK if count <= 10 else FAIL,
                 f"{count} DNS-querying mechanisms (limit is 10)")

    def _spf_lookups(self, domain: str, seen: Set[str], depth: int) -> int:
        if domain in seen or depth > 10:
            return 0
        seen.add(domain)
        recs = self.txt(domain, "v=spf1")
        if not recs:
            return 0
        total = 0
        for term in recs[0].split()[1:]:
            t = term.lstrip("+-~?").lower()
            if t.startswith(("include:", "redirect=")):
                total += 1
                total += self._spf_lookups(re.split(r"[:=]", t, maxsplit=1)[1], seen, depth + 1)
            elif t in ("a", "mx", "ptr") or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
                total += 1
        return total

    def dmarc(self, domain: str) -> None:
        recs = self.txt(f"_dmarc.{domain}", "v=DMARC1")
        if not recs:
            self.say("DMARC", FAIL, "no _dmarc record")
            return
        rec = recs[0]
        self.say("DMARC", INFO, rec)
        tags = dict((k.strip().lower(), v.strip()) for k, _, v in
                    (p.partition("=") for p in rec.split(";")) if k.strip())
        p = tags.get("p", "").lower()
        self.say("DMARC", {"reject": OK, "quarantine": OK, "none": WARN}.get(p, FAIL),
                 f"policy p={p or 'MISSING'}" + (" (monitoring only)" if p == "none" else ""))
        if tags.get("pct", "100") != "100":
            self.say("DMARC", WARN, f"pct={tags['pct']}: policy applies to only part of the mail")
        self.say("DMARC", OK if "rua" in tags else WARN,
                 f"aggregate reports to {tags['rua']}" if "rua" in tags else "no rua= (you get no reports)")

    def dkim(self, domain: str, selectors: List[str]) -> None:
        found = 0
        for sel in dict.fromkeys(selectors + COMMON_DKIM_SELECTORS):
            name = f"{sel}._domainkey.{domain}"
            a = self.q(name, "TXT")
            recs = [_txt(r) for r in a.records]
            rec = next((r for r in recs if "p=" in r), None)
            if rec is None:
                continue
            found += 1
            key = re.search(r"p=([A-Za-z0-9+/=]*)", rec)
            k = re.search(r"k=(\w+)", rec)
            ktype = k.group(1) if k else "rsa"
            if key and not key.group(1):
                self.say("DKIM", INFO, f"{sel}: revoked (empty p=)")
            elif key:
                bits = len(key.group(1)) * 6 // 8 * 8
                approx = "~2048-bit" if bits > 2000 else "~1024-bit" if bits > 1000 else f"{bits} bits of key data"
                st = WARN if ktype == "rsa" and bits < 1200 else OK
                self.say("DKIM", st, f"{sel}: {ktype} key, {approx if ktype == 'rsa' else 'ok'}")
        if not found:
            self.say("DKIM", WARN, "no key found on common selectors - selectors cannot be listed, "
                                   "add yours in the 'DKIM selectors' field")

    def mta_sts(self, domain: str) -> None:
        recs = self.txt(f"_mta-sts.{domain}", "v=STSv1")
        if not recs:
            self.say("MTA-STS", INFO, "no _mta-sts record (optional)")
            return
        self.say("MTA-STS", OK, recs[0])
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            with urllib.request.urlopen(url, timeout=6, context=ssl.create_default_context()) as r:
                body = r.read(4096).decode("utf-8", "replace")
            mode = re.search(r"mode:\s*(\w+)", body)
            m = mode.group(1) if mode else "?"
            self.say("MTA-STS", OK if m == "enforce" else WARN, f"policy mode: {m}")
        except Exception as exc:
            self.say("MTA-STS", FAIL, f"policy file not reachable at {url}: {exc}")

    def dane(self, mx_host: str) -> None:
        a = query(f"_25._tcp.{mx_host}", "TLSA", self.server, timeout=4, dnssec=True)
        if a.records:
            self.say("DANE", OK if a.ad else WARN,
                     f"{mx_host}: {len(a.records)} TLSA record(s)" +
                     ("" if a.ad else " but not DNSSEC-validated by this resolver"))


def _txt(rdata_text: str) -> str:
    """dnspython renders TXT as quoted chunks: "abc" "def" -> abcdef."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', rdata_text)
    return "".join(parts) if parts else rdata_text


def lookup(name: str, rtype: str, server: Optional[str]) -> Answer:
    name = name.strip()
    if rtype == "PTR":
        try:
            name = dns.reversename.from_address(name).to_text()
        except Exception:
            pass
    return query(name, rtype, server, timeout=4, dnssec=True)
