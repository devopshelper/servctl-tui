"""Unbound as a local recursive resolver (root hints, no forwarders).

Recursion matters for DNS blocklists such as Spamhaus, which refuse queries
that arrive through big public resolvers (answering 127.255.255.254).
"""
from __future__ import annotations

import ipaddress
import os
import sys
from dataclasses import dataclass, field
from typing import List

from . import dnsutil
from .core import Step, firewalld_running

CONF = "/etc/unbound/unbound.conf"
STATE_DIR = "/var/lib/unbound"
HINTS = f"{STATE_DIR}/root.hints"
ROOT_KEY = f"{STATE_DIR}/root.key"
HINTS_URL = "https://www.internic.net/domain/named.root"
TIMER = "servctl-roothints"

_FETCH_HINTS = f"""
install -d -m 0755 {STATE_DIR}
tmp=$(mktemp)
curl -fsSL --retry 3 -o "$tmp" {HINTS_URL}
grep -q 'A.ROOT-SERVERS.NET' "$tmp" || {{ echo "downloaded root hints look wrong"; rm -f "$tmp"; exit 1; }}
install -m 0644 "$tmp" {HINTS}
rm -f "$tmp"
id unbound >/dev/null 2>&1 && chown -R unbound:unbound {STATE_DIR}
command -v restorecon >/dev/null && restorecon -R {STATE_DIR} || true
"""


@dataclass
class UnboundOpts:
    port: int = 53
    ipv6: bool = True
    lan: bool = False                 # also listen on all interfaces for these networks
    lan_cidrs: List[str] = field(default_factory=list)
    threads: int = 0                  # 0 = auto
    cache_mb: int = 128
    dnssec: bool = True
    set_system_dns: bool = True
    open_firewall: bool = True

    def validate(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError("Port must be 1-65535")
        if self.set_system_dns and self.port != 53:
            raise ValueError("To be the system resolver Unbound must listen on port 53")
        if self.lan and not self.lan_cidrs:
            raise ValueError("Listing on the LAN needs at least one allowed network, e.g. 192.168.1.0/24")
        for c in self.lan_cidrs:
            try:
                ipaddress.ip_network(c, strict=False)
            except ValueError:
                raise ValueError(f"'{c}' is not a network (example: 192.168.1.0/24)")
        if not 16 <= self.cache_mb <= 8192:
            raise ValueError("Cache size must be 16-8192 MB")


def render_config(o: UnboundOpts) -> str:
    o.validate()
    threads = o.threads or max(1, min(4, os.cpu_count() or 1))
    yn = lambda b: "yes" if b else "no"
    lines = [
        "# Managed by servctl - full recursion from the root servers, no forwarders.",
        "server:",
        "    verbosity: 1",
        f"    num-threads: {threads}",
        "    interface: 127.0.0.1",
    ]
    if o.ipv6:
        lines.append("    interface: ::1")
    if o.lan:
        lines.append("    interface: 0.0.0.0")
        if o.ipv6:
            lines.append("    interface: ::0")
    lines += [
        f"    port: {o.port}",
        "    do-ip4: yes",
        f"    do-ip6: {yn(o.ipv6)}",
        "    do-udp: yes",
        "    do-tcp: yes",
        "    access-control: 0.0.0.0/0 refuse",
        "    access-control: ::0/0 refuse",
        "    access-control: 127.0.0.0/8 allow",
        "    access-control: ::1/128 allow",
    ]
    lines += [f"    access-control: {ipaddress.ip_network(c, strict=False)} allow" for c in o.lan_cidrs]
    lines += [
        '    username: "unbound"',
        '    directory: "/etc/unbound"',
        '    chroot: ""',
        # Explicit so RHEL (ipsecmod) and Debian (subnetcache) builds behave the same.
        f'    module-config: "{"validator iterator" if o.dnssec else "iterator"}"',
        f'    root-hints: "{HINTS}"',
    ]
    if o.dnssec:
        lines.append(f'    auto-trust-anchor-file: "{ROOT_KEY}"')
    lines += [
        "    hide-identity: yes",
        "    hide-version: yes",
        "    harden-glue: yes",
        f"    harden-dnssec-stripped: {yn(o.dnssec)}",
        "    qname-minimisation: yes",
        "    aggressive-nsec: yes",
        "    prefetch: yes",
        "    prefetch-key: yes",
        "    serve-expired: yes",
        "    serve-expired-ttl: 86400",
        f"    msg-cache-size: {max(8, o.cache_mb // 2)}m",
        f"    rrset-cache-size: {o.cache_mb}m",
        "    so-reuseport: yes",
        "    edns-buffer-size: 1232",
        "    use-syslog: yes",
        "",
        "remote-control:",
        "    control-enable: yes",
        "    control-interface: /run/unbound.ctl",
        "",
    ]
    return "\n".join(lines)


HINTS_SCRIPT = "/usr/local/libexec/servctl-roothints"


def _timer_units() -> List[Step]:
    script = "#!/bin/bash\n# Managed by servctl\nset -euo pipefail\n" + _FETCH_HINTS.lstrip("\n")
    service = f"""# Managed by servctl
[Unit]
Description=Refresh root hints for Unbound
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={HINTS_SCRIPT}
ExecStartPost=/bin/systemctl try-reload-or-restart unbound.service
"""
    timer = """# Managed by servctl
[Unit]
Description=Monthly root hints refresh for Unbound

[Timer]
OnCalendar=monthly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
"""
    return [
        Step.write("Install root hints refresh script", HINTS_SCRIPT, script, mode=0o755),
        Step.write("Install root hints refresh service", f"/etc/systemd/system/{TIMER}.service", service),
        Step.write("Install monthly timer", f"/etc/systemd/system/{TIMER}.timer", timer),
    ]


def install_plan(o: UnboundOpts, pkg: str) -> List[Step]:
    content = render_config(o)
    steps: List[Step] = []
    if pkg:
        steps.append(Step.cmd("Install unbound", pkg, "install", "-y", "unbound"))
    steps.append(Step.sh("Download root hints from IANA", _FETCH_HINTS))
    if o.dnssec:
        # Exit code 1 means "anchor was updated", which is fine.
        steps.append(Step.sh("Create/refresh DNSSEC root trust anchor",
                             f"unbound-anchor -a {ROOT_KEY} || true\n"
                             f"id unbound >/dev/null 2>&1 && chown unbound:unbound {ROOT_KEY} || true"))
    steps += [
        Step.write(f"Write {CONF}", CONF, content),
        Step.cmd("Validate configuration", "unbound-checkconf", CONF),
        *_timer_units(),
        Step.cmd("Reload systemd", "systemctl", "daemon-reload"),
        Step.cmd("Enable root hints timer", "systemctl", "enable", "--now", f"{TIMER}.timer"),
        Step.cmd("Enable unbound at boot", "systemctl", "enable", "unbound"),
        Step.cmd("Restart unbound", "systemctl", "restart", "unbound"),
        Step.cmd("Wait until unbound answers", sys.executable, "-m", "servctl.dnsutil",
                 f"127.0.0.1:{o.port}", "example.com"),
    ]
    if o.lan and o.open_firewall and firewalld_running():
        steps += [Step.cmd("Allow DNS in firewalld", "firewall-cmd", "--permanent", "--add-service=dns"),
                  Step.cmd("Reload firewalld", "firewall-cmd", "--reload")]
    if o.set_system_dns:
        steps += dnsutil.system_dns_plan(["127.0.0.1"])
    return steps


def flush_plan() -> List[Step]:
    return [Step.cmd("Flush the whole cache", "unbound-control", "flush_zone", "."),
            Step.cmd("Flush infrastructure cache", "unbound-control", "flush_infra", "all")]


def self_test(port: int = 53) -> List[tuple]:
    """(ok, message) checks against the local resolver."""
    server = f"127.0.0.1:{port}"
    out = []
    a = dnsutil.query("example.com", "A", server)
    out.append((a.rcode == "NOERROR" and bool(a.records),
                f"example.com -> {', '.join(a.records) or a.error or a.rcode} ({a.ms:.0f} ms)"))
    b = dnsutil.query("example.com", "A", server)
    out.append((b.rcode == "NOERROR", f"cached repeat: {b.ms:.1f} ms"))
    v = dnsutil.dnssec_validates(server)
    out.append((v is True, "DNSSEC validation: " +
                {True: "working (dnssec-failed.org is rejected)",
                 False: "NOT validating", None: "could not test"}[v]))
    s = dnsutil.spamhaus_status(server)
    out.append((s == "OK", f"Spamhaus ZEN test point: {s}"))
    return out
