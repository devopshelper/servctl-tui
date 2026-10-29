"""rsyslog forwarding to a remote SIEM."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

from .core import Step, selinux_enforcing, which

CONF_PATH = "/etc/rsyslog.d/90-servctl-siem.conf"
RULESET = "servctl_siem"

FORMATS = {
    "rfc5424": "RSYSLOG_SyslogProtocol23Format",
    "rfc3164": "RSYSLOG_TraditionalForwardFormat",
}
_HOST_RE = re.compile(r"^[A-Za-z0-9.:\-\[\]]+$")
_SELECTOR_RE = re.compile(r"^[a-z0-9*,;.!=\s]+$")
_SIZE_RE = re.compile(r"^\d+[kmg]$", re.I)
# Ports SELinux already allows rsyslog to connect to over TCP.
_SELINUX_OK_TCP = {601, 6514, 20514}


@dataclass
class SiemOpts:
    host: str
    port: int = 514
    protocol: str = "tcp"          # udp | tcp | tls
    fmt: str = "rfc5424"
    framing: str = "traditional"   # traditional (LF) | octet-counted
    selector: str = "*.info"
    files: List[str] = field(default_factory=list)   # extra text logs, e.g. audit.log
    queue_size: str = "1g"
    ca_file: str = "/etc/pki/tls/certs/ca-bundle.crt"
    auth_mode: str = "x509/name"   # x509/name | x509/certvalid | anon
    permitted_peer: str = ""

    def validate(self) -> None:
        if not self.host or not _HOST_RE.match(self.host):
            raise ValueError("Enter a valid SIEM hostname or IP")
        if not 1 <= self.port <= 65535:
            raise ValueError("Port must be 1-65535")
        if self.protocol not in ("udp", "tcp", "tls"):
            raise ValueError("Protocol must be udp, tcp or tls")
        if self.fmt not in FORMATS:
            raise ValueError("Unknown format")
        if not self.selector or not _SELECTOR_RE.match(self.selector):
            raise ValueError("Selector must look like *.info or auth,authpriv.*;*.warn")
        if not _SIZE_RE.match(self.queue_size):
            raise ValueError("Queue size must look like 512m or 2g")
        for f in self.files:
            if not f.startswith("/") or '"' in f:
                raise ValueError(f"Bad file path: {f}")
        if self.protocol == "tls" and not self.ca_file.startswith("/"):
            raise ValueError("TLS needs the CA file that signed the SIEM's certificate")


def render_config(o: SiemOpts) -> str:
    o.validate()
    params = [
        'type="omfwd"',
        f'target="{o.host}"',
        f'port="{o.port}"',
        f'protocol="{"udp" if o.protocol == "udp" else "tcp"}"',
        f'template="{FORMATS[o.fmt]}"',
    ]
    if o.protocol != "udp":
        params.append(f'TCP_Framing="{o.framing}"')
    if o.protocol == "tls":
        params += ['StreamDriver="gtls"', 'StreamDriverMode="1"',
                   f'StreamDriverAuthMode="{o.auth_mode}"']
        if o.auth_mode == "x509/name":
            params.append(f'StreamDriverPermittedPeers="{o.permitted_peer or o.host}"')
    # Disk-assisted queue: keeps logs while the SIEM is unreachable and
    # survives rsyslog restarts. Retries forever instead of dropping.
    params += [
        'queue.type="LinkedList"',
        f'queue.filename="{RULESET}"',
        f'queue.maxDiskSpace="{o.queue_size}"',
        'queue.saveOnShutdown="on"',
        'queue.size="100000"',
        'action.resumeRetryCount="-1"',
        'action.resumeInterval="10"',
    ]
    action = "action(\n        " + "\n        ".join(params) + "\n    )"

    out = ["# Managed by servctl - changes here are overwritten from the TUI", ""]
    if o.protocol == "tls":
        out += [f'global(DefaultNetstreamDriverCAFile="{o.ca_file}")', ""]
    out += [f'ruleset(name="{RULESET}") {{', f"    {action}", "}", ""]
    out += ["# Forward local syslog/journal messages (they are still logged locally too)",
            f'if prifilt("{o.selector}") then {{', f"    call {RULESET}", "}", ""]
    if o.files:
        out += ['# Extra text log files, sent only to the SIEM (not into /var/log/messages)',
                'module(load="imfile")']
        for f in o.files:
            tag = re.sub(r"[^A-Za-z0-9_-]", "_", f.rsplit("/", 1)[-1].split(".")[0]) or "file"
            out.append(f'input(type="imfile" File="{f}" Tag="{tag}:" Facility="local6" '
                       f'ruleset="{RULESET}")')
        out.append("")
    return "\n".join(out)


def apply_plan(o: SiemOpts, pkg: str = "dnf") -> List[Step]:
    content = render_config(o)
    steps: List[Step] = []
    if not which("rsyslogd"):
        steps.append(Step.cmd("Install rsyslog", pkg or "dnf", "install", "-y", "rsyslog"))
    if o.protocol == "tls":
        steps.append(Step.cmd("Install TLS driver for rsyslog", pkg or "dnf", "install", "-y",
                              "rsyslog-gnutls"))
    if o.protocol != "udp" and o.port not in _SELINUX_OK_TCP and selinux_enforcing():
        steps.append(Step.sh(
            f"Allow rsyslog to connect to tcp/{o.port} under SELinux",
            f"semanage port -a -t syslogd_port_t -p tcp {o.port} 2>/dev/null"
            f" || semanage port -m -t syslogd_port_t -p tcp {o.port}",
            allow_fail=True))
    steps += [
        Step.write(f"Write {CONF_PATH}", CONF_PATH, content),
        Step.cmd("Validate rsyslog configuration", "rsyslogd", "-N1"),
        Step.cmd("Enable rsyslog at boot", "systemctl", "enable", "rsyslog", allow_fail=True),
        Step.cmd("Restart rsyslog", "systemctl", "restart", "rsyslog"),
        Step.cmd("Send a test message", "logger", "-p", "user.notice", "-t", "servctl",
                 f"servctl SIEM forwarding test to {o.host}:{o.port}/{o.protocol}"),
    ]
    return steps


def remove_plan() -> List[Step]:
    return [
        Step.delete("Remove SIEM forwarding config", CONF_PATH),
        Step.cmd("Validate rsyslog configuration", "rsyslogd", "-N1"),
        Step.cmd("Restart rsyslog", "systemctl", "restart", "rsyslog"),
    ]


def test_message_plan() -> List[Step]:
    return [Step.cmd("Send a test message", "logger", "-p", "user.notice", "-t", "servctl",
                     "servctl SIEM forwarding test message")]


def parse_config(text: str) -> dict:
    """Read the values back out of a config written by render_config."""
    def get(key: str) -> str:
        m = re.search(rf'\b{key}="([^"]*)"', text)
        return m.group(1) if m else ""
    out = {
        "host": get("target"), "port": get("port"), "framing": get("TCP_Framing"),
        "queue_size": get("queue.maxDiskSpace"), "ca_file": get("DefaultNetstreamDriverCAFile"),
        "auth_mode": get("StreamDriverAuthMode"), "permitted_peer": get("StreamDriverPermittedPeers"),
        "files": re.findall(r'type="imfile" File="([^"]*)"', text),
    }
    out["protocol"] = "tls" if get("StreamDriver") == "gtls" else get("protocol")
    tmpl = get("template")
    out["fmt"] = next((k for k, v in FORMATS.items() if v == tmpl), "")
    m = re.search(r'prifilt\("([^"]*)"\)', text)
    out["selector"] = m.group(1) if m else ""
    return out
