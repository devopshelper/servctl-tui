"""Open, close and list ports in firewalld or plain nftables.

firewalld: ports, services and rich rules per zone, runtime and permanent.
nftables (used when firewalld is not running): rules in input base chains and
the chains they jump to. Opening inserts an accept rule into the chain whose
policy is drop; closing removes or narrows the accept rule, or - when nothing
filters input - adds a drop rule to our own ``inet servctl`` table.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .core import Step, capture, firewalld_running, which

Range = Tuple[int, int]
FW = "firewall-cmd"
SERVCTL_TABLE = ("inet", "servctl")
SERVCTL_CHAIN = "input"
NFT_CONF_CANDIDATES = ("/etc/sysconfig/nftables.conf", "/etc/nftables.conf")


# --------------------------------------------------------------------------- #
# Port parsing helpers
# --------------------------------------------------------------------------- #

COMMON_SERVICES: Dict[str, int] = {
    "ssh": 22, "ftp": 21, "telnet": 23, "smtp": 25, "dns": 53, "domain": 53,
    "http": 80, "pop3": 110, "ntp": 123, "imap": 143, "snmp": 161, "ldap": 389,
    "https": 443, "smtps": 465, "imaps": 993, "pop3s": 995, "mysql": 3306, "mariadb": 3306,
    "rdp": 3389, "postgres": 5432, "postgresql": 5432, "redis": 6379, "http-alt": 8080,
    "cockpit": 9090, "wireguard": 51820, "syncthing": 8384, "iperf": 5201, "iperf3": 5201,
}


def parse_ports(text: str) -> List[Range]:
    """'22', '80,443', 'http, https', '8000-8100 9000' -> [(22,22), (80,80), ...]."""
    out: List[Range] = []
    for tok in re.split(r"[,\s]+", text.strip()):
        tok = tok.strip()
        if not tok:
            continue
        tok_lower = tok.lower()
        if tok_lower in COMMON_SERVICES:
            p = COMMON_SERVICES[tok_lower]
            out.append((p, p))
            continue
        try:
            p = socket.getservbyname(tok_lower)
            out.append((p, p))
            continue
        except (OSError, socket.error):
            pass
        m = re.fullmatch(r"(\d+)(?:[-:](\d+))?", tok)
        if not m:
            raise ValueError(f"'{tok}' is not a port, range, or recognized service name (examples: 443, http, 8000-8100)")
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= a <= 65535 and 1 <= b <= 65535) or b < a:
            raise ValueError(f"'{tok}' is out of range (1-65535, low-high)")
        out.append((a, b))
    if not out:
        raise ValueError("Enter a port or service name, e.g. 443, http or 8000-8100")
    return out


def protos_for(choice: str) -> List[str]:
    return ["tcp", "udp"] if choice == "both" else [choice]


def fmt_range(r: Range) -> str:
    return str(r[0]) if r[0] == r[1] else f"{r[0]}-{r[1]}"


def overlaps(a: Range, b: Range) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


def subtract(r: Range, cut: Range) -> List[Range]:
    """Pieces of r left after removing cut."""
    out = []
    if cut[0] > r[0]:
        out.append((r[0], min(r[1], cut[0] - 1)))
    if cut[1] < r[1]:
        out.append((max(r[0], cut[1] + 1), r[1]))
    return [p for p in out if p[0] <= p[1]]


def validate_source(src: str) -> str:
    src = src.strip()
    if not src:
        return ""
    try:
        return str(ipaddress.ip_network(src, strict=False))
    except ValueError:
        raise ValueError(f"'{src}' is not an IP address or network (e.g. 203.0.113.7 or 10.0.0.0/8)")


def ssh_ports() -> Set[int]:
    """Ports that carry SSH right now (current session first, then sshd's listeners)."""
    ports: Set[int] = set()
    conn = os.environ.get("SSH_CONNECTION", "").split()
    if len(conn) == 4 and conn[3].isdigit():
        ports.add(int(conn[3]))
    for s in listening():
        if s.process in ("sshd", "sshd-session"):
            ports.add(s.port)
    return ports or {22}


def guard_ssh(ranges: Sequence[Range], protos: Sequence[str], allow: bool) -> None:
    if allow or "tcp" not in protos:
        return
    hit = sorted(p for p in ssh_ports() if any(a <= p <= b for a, b in ranges))
    if hit:
        raise ValueError(f"Port {', '.join(map(str, hit))}/tcp carries SSH - closing it can lock you out. "
                         "Tick 'Allow changing my SSH port' to do it anyway.")


# --------------------------------------------------------------------------- #
# What is listening
# --------------------------------------------------------------------------- #

@dataclass
class Listener:
    proto: str
    port: int
    addresses: List[str] = field(default_factory=list)
    process: str = ""

    @property
    def local_only(self) -> bool:
        def loop(a: str) -> bool:
            a = a.strip("[]").split("%")[0]
            try:
                return ipaddress.ip_address(a).is_loopback
            except ValueError:
                return False
        return bool(self.addresses) and all(loop(a) for a in self.addresses)


def parse_ss(text: str) -> List[Listener]:
    found: Dict[Tuple[str, int], Listener] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ("tcp", "udp"):
            continue
        local = parts[4]
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        proc = re.search(r'users:\(\("([^"]+)"', line)
        key = (parts[0], int(port))
        item = found.setdefault(key, Listener(parts[0], int(port)))
        if addr not in item.addresses:
            item.addresses.append(addr)
        if proc and not item.process:
            item.process = proc.group(1)
    return sorted(found.values(), key=lambda l: (l.port, l.proto))


def listening() -> List[Listener]:
    rc, out = capture(["ss", "-H", "-tulpn"], 5)
    return parse_ss(out) if rc == 0 else []


# --------------------------------------------------------------------------- #
# Common listing model
# --------------------------------------------------------------------------- #

@dataclass
class Entry:
    backend: str                 # firewalld | nftables
    kind: str                    # port | service | rich | rule
    ranges: List[Range]
    protos: List[str]            # tcp/udp; empty = any protocol
    verdict: str                 # accept | drop | reject
    where: str                   # zone, or "family table chain"
    source: str = ""
    detail: str = ""
    persistent: Optional[bool] = None
    editable: bool = True
    ref: Dict[str, object] = field(default_factory=dict)

    def covers(self, port: int, proto: str) -> bool:
        return (not self.protos or proto in self.protos) and any(a <= port <= b for a, b in self.ranges)

    @property
    def ports_text(self) -> str:
        return ",".join(fmt_range(r) for r in self.ranges) or "any"


# --------------------------------------------------------------------------- #
# firewalld
# --------------------------------------------------------------------------- #

def parse_list_all(text: str) -> Dict[str, object]:
    """Parse `firewall-cmd --list-all` / `--info-service` output."""
    data: Dict[str, object] = {}
    key = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("\t") or line.startswith("        "):
            if key:
                data.setdefault(key, [])
                data[key].append(line.strip())   # type: ignore[union-attr]
            continue
        m = re.match(r"\s+([a-z -]+):\s*(.*)$", line)
        if m:
            key = m.group(1)
            val = m.group(2).strip()
            data[key] = val.split() if key not in ("target",) else val
            if key == "rich rules":
                data[key] = [val] if val else []
        else:
            data["name"] = line.split()[0]
    return data


def parse_port_tokens(tokens: Sequence[str]) -> List[Tuple[Range, str]]:
    out = []
    for t in tokens:
        m = re.fullmatch(r"(\d+)(?:-(\d+))?/(\w+)", t)
        if m:
            out.append(((int(m.group(1)), int(m.group(2) or m.group(1))), m.group(3)))
    return out


_RICH_PORT = re.compile(r'port\s+port="([\d-]+)"\s+protocol="(\w+)"')
_RICH_SRC = re.compile(r'source\s+(NOT\s+)?address="([^"]+)"')
_RICH_SVC = re.compile(r'service\s+name="([^"]+)"')


def parse_rich(rule: str, service_ports) -> Optional[Tuple[List[Range], List[str], str, str]]:
    """(ranges, protos, source, verdict) of a rich rule, or None if it has no port/service."""
    verdict = "accept" if re.search(r"\baccept\b", rule) else \
        "reject" if re.search(r"\breject\b", rule) else "drop" if re.search(r"\bdrop\b", rule) else ""
    if not verdict:
        return None
    src = _RICH_SRC.search(rule)
    source = ("not " if src and src.group(1) else "") + src.group(2) if src else ""
    ranges, protos = [], []
    m = _RICH_PORT.search(rule)
    if m:
        a, _, b = m.group(1).partition("-")
        ranges.append((int(a), int(b or a)))
        protos.append(m.group(2))
    sm = _RICH_SVC.search(rule)
    if sm:
        for r, p in service_ports(sm.group(1)):
            ranges.append(r)
            protos.append(p)
    if not ranges:
        return None
    return ranges, sorted(set(protos)), source, verdict


class Firewalld:
    def __init__(self) -> None:
        self._svc: Dict[str, List[Tuple[Range, str]]] = {}

    def run(self, *args: str) -> str:
        rc, out = capture([FW, *args], 15)
        return out if rc == 0 else ""

    def default_zone(self) -> str:
        return self.run("--get-default-zone").strip() or "public"

    def zones(self) -> List[str]:
        return self.run("--get-zones").split()

    def active_zones(self) -> Dict[str, Dict[str, List[str]]]:
        out: Dict[str, Dict[str, List[str]]] = {}
        zone = None
        for line in self.run("--get-active-zones").splitlines():
            if not line.strip():
                continue
            if not line.startswith((" ", "\t")):
                zone = line.split()[0]
                out[zone] = {}
            elif zone:
                k, _, v = line.strip().partition(":")
                out[zone][k.strip()] = v.split()
        return out

    def service_ports(self, name: str) -> List[Tuple[Range, str]]:
        if name not in self._svc:
            info = parse_list_all(self.run(f"--info-service={name}"))
            self._svc[name] = parse_port_tokens(info.get("ports", []))   # type: ignore[arg-type]
        return self._svc[name]

    def zones_to_show(self) -> List[str]:
        zones = list(self.active_zones())
        d = self.default_zone()
        return zones if d in zones else [d] + zones

    def entries(self) -> List[Entry]:
        out: List[Entry] = []
        for zone in self.zones_to_show():
            rt = parse_list_all(self.run(f"--zone={zone}", "--list-all"))
            pm = parse_list_all(self.run("--permanent", f"--zone={zone}", "--list-all"))
            pm_ports = set(pm.get("ports", []))       # type: ignore[arg-type]
            pm_svcs = set(pm.get("services", []))     # type: ignore[arg-type]
            pm_rich = set(pm.get("rich rules", []))   # type: ignore[arg-type]
            for tok in rt.get("ports", []):           # type: ignore[union-attr]
                for r, p in parse_port_tokens([tok]):
                    out.append(Entry("firewalld", "port", [r], [p], "accept", zone, detail=tok,
                                     persistent=tok in pm_ports, ref={"zone": zone, "token": tok}))
            for svc in rt.get("services", []):        # type: ignore[union-attr]
                ports = self.service_ports(svc)
                out.append(Entry("firewalld", "service", [r for r, _ in ports],
                                 sorted({p for _, p in ports}), "accept", zone, detail=f"service {svc}",
                                 persistent=svc in pm_svcs, ref={"zone": zone, "service": svc}))
            for rule in rt.get("rich rules", []):     # type: ignore[union-attr]
                parsed = parse_rich(rule, self.service_ports)
                if parsed:
                    ranges, protos, source, verdict = parsed
                    out.append(Entry("firewalld", "rich", ranges, protos, verdict, zone, source=source,
                                     detail=rule, persistent=rule in pm_rich, ref={"zone": zone, "rule": rule}))
        return out

    def summary(self) -> str:
        active = self.active_zones()
        lines = [f"firewalld: running   default zone: {self.default_zone()}"]
        for z, d in active.items():
            bits = [f"{k}: {' '.join(v)}" for k, v in d.items() if v]
            lines.append(f"  zone {z}  " + ("  ".join(bits) or "(no interfaces/sources)"))
        return "\n".join(lines)


def _fw_both(zone: str, op: str, value: str, permanent: bool, timeout: int = 0,
             allow_fail: bool = False) -> List[Step]:
    """Runtime change (takes effect now) + permanent change (survives reload/reboot)."""
    rt = [FW, f"--zone={zone}", f"--{op}={value}"]
    if timeout:
        rt.append(f"--timeout={timeout}m")
    steps = [Step.cmd(f"{op.replace('-', ' ')} {value} in zone {zone} (now)", *rt, allow_fail=allow_fail)]
    if permanent and not timeout:
        steps.append(Step.cmd(f"{op.replace('-', ' ')} {value} in zone {zone} (permanent)",
                              FW, "--permanent", f"--zone={zone}", f"--{op}={value}", allow_fail=allow_fail))
    return steps


def rich_rule(r: Range, proto: str, source: str, verdict: str = "accept") -> str:
    fam = "ipv6" if ":" in source else "ipv4"
    return (f'rule family="{fam}" source address="{source}" port port="{fmt_range(r)}" '
            f'protocol="{proto}" {verdict}')


def fw_open_plan(ranges: List[Range], protos: List[str], zone: str, source: str,
                 permanent: bool, timeout_min: int) -> List[Step]:
    if not zone:
        raise ValueError("Pick a zone")
    if timeout_min < 0 or timeout_min > 24 * 60:
        raise ValueError("Auto-close must be 0-1440 minutes")
    source = validate_source(source)
    steps: List[Step] = []
    for r in ranges:
        for p in protos:
            if source:
                steps += _fw_both(zone, "add-rich-rule", rich_rule(r, p, source), permanent, timeout_min)
            else:
                steps += _fw_both(zone, "add-port", f"{fmt_range(r)}/{p}", permanent, timeout_min)
    return steps


def _remove_entry_steps(e: Entry, cut: Optional[Tuple[Range, str]] = None) -> List[Step]:
    zone = str(e.ref["zone"])
    perm = e.persistent is not False
    if e.kind == "port":
        token = str(e.ref["token"])
        steps = _fw_both(zone, "remove-port", token, perm, allow_fail=False)
        if cut is not None:
            # Closing part of a range: put the remaining pieces back.
            (r,), (p,) = e.ranges, e.protos
            for piece in subtract(r, cut[0]):
                steps += _fw_both(zone, "add-port", f"{fmt_range(piece)}/{p}", perm)
        return steps
    if e.kind == "service":
        return _fw_both(zone, "remove-service", str(e.ref["service"]), perm)
    return _fw_both(zone, "remove-rich-rule", str(e.ref["rule"]), perm)


def fw_close_plan(ranges: List[Range], protos: List[str], entries: List[Entry], zone: str = "",
                  allow_ssh: bool = False) -> List[Step]:
    """Close the given ports in `zone` (or every zone where they are open)."""
    guard_ssh(ranges, protos, allow_ssh)
    steps: List[Step] = []
    seen: Set[int] = set()
    for want in ranges:
        for p in protos:
            hits = [e for e in entries if e.verdict == "accept" and (not zone or e.ref.get("zone") == zone)
                    and (not e.protos or p in e.protos) and any(overlaps(want, r) for r in e.ranges)]
            if not hits:
                continue
            for e in hits:
                if id(e) in seen:
                    continue
                seen.add(id(e))
                inside = e.kind == "port" and not (want[0] <= e.ranges[0][0] and e.ranges[0][1] <= want[1])
                if e.kind == "service":
                    extra = [f"{fmt_range(r)}/{q}" for r, q in zip(e.ranges, e.protos * len(e.ranges))]
                    note = f"service '{e.ref['service']}' covers {', '.join(extra) or 'other ports'}"
                    steps.append(Step.cmd(f"NOTE: removing the whole {note}", "true",
                                          display="(information only - nothing runs)"))
                steps += _remove_entry_steps(e, (want, p) if inside else None)
    if not steps:
        where = f"zone {zone}" if zone else "any zone"
        raise ValueError(f"{', '.join(fmt_range(r) for r in ranges)}/{'+'.join(protos)} "
                         f"is not open in {where}")
    return steps


def fw_close_entry_plan(e: Entry, allow_ssh: bool = False) -> List[Step]:
    guard_ssh(e.ranges, e.protos or ["tcp"], allow_ssh)
    return _remove_entry_steps(e)


# --------------------------------------------------------------------------- #
# nftables
# --------------------------------------------------------------------------- #

def nft_ruleset() -> Dict[str, list]:
    rc, out = capture(["nft", "-j", "list", "ruleset"], 10)
    if rc != 0 or not out.strip():
        return {"nftables": []}
    try:
        return json.loads(out)
    except ValueError:
        return {"nftables": []}


def _items(rs: Dict[str, list], kind: str) -> List[dict]:
    return [o[kind] for o in rs.get("nftables", []) if kind in o]


def _port_value(v) -> List[Range]:
    if isinstance(v, int):
        return [(v, v)]
    if isinstance(v, str):
        if v.isdigit():
            return [(int(v), int(v))]
        try:
            n = socket.getservbyname(v)
            return [(n, n)]
        except OSError:
            return []
    if isinstance(v, dict):
        if "range" in v:
            a, b = v["range"]
            return [(_port_value(a)[0][0], _port_value(b)[0][1])]
        if "set" in v:
            out: List[Range] = []
            for x in v["set"]:
                out += _port_value(x)
            return out
    if isinstance(v, list):
        out = []
        for x in v:
            out += _port_value(x)
        return out
    return []


def _addr_value(v) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, dict) and "prefix" in v:
        return f"{v['prefix']['addr']}/{v['prefix']['len']}"
    if isinstance(v, dict) and "set" in v:
        return ",".join(_addr_value(x) for x in v["set"])
    return "?"


_HARMLESS = {"counter", "comment", "log", "limit"}


def parse_nft_rule(rule: dict) -> Optional[Entry]:
    ranges: List[Range] = []
    protos: List[str] = []
    l4: List[str] = []
    source = ""
    verdict = ""
    simple = True
    for ex in rule.get("expr", []):
        if "match" in ex:
            m = ex["match"]
            left, right, op = m.get("left", {}), m.get("right"), m.get("op", "==")
            payload = left.get("payload", {}) if isinstance(left, dict) else {}
            meta = left.get("meta", {}) if isinstance(left, dict) else {}
            if payload.get("field") == "dport" and payload.get("protocol") in ("tcp", "udp", "th", "sctp"):
                if op not in ("==", "in"):
                    simple = False
                ranges = _port_value(right)
                if isinstance(right, str) and right.startswith("@"):
                    simple = False
                if payload["protocol"] != "th":
                    protos = [payload["protocol"]]
            elif meta.get("key") == "l4proto":
                vals = right.get("set", []) if isinstance(right, dict) else [right]
                l4 = [str(x) for x in vals]
            elif payload.get("field") == "saddr" and payload.get("protocol") in ("ip", "ip6"):
                source = _addr_value(right) if op == "==" else f"not {_addr_value(right)}"
            else:
                simple = False
        elif any(k in ex for k in ("accept", "drop", "reject")):
            verdict = next(k for k in ("accept", "drop", "reject") if k in ex)
        elif not any(k in ex for k in _HARMLESS):
            simple = False
    if not ranges or not verdict:
        return None
    if not protos:
        protos = [p for p in l4 if p in ("tcp", "udp")]
    where = f"{rule['family']} {rule['table']} {rule['chain']}"
    return Entry("nftables", "rule", ranges, protos, verdict, where, source=source,
                 detail=rule.get("comment", ""), persistent=None, editable=simple,
                 ref={"family": rule["family"], "table": rule["table"], "chain": rule["chain"],
                      "handle": rule["handle"], "servctl": (rule["family"], rule["table"]) == SERVCTL_TABLE})


def input_chains(rs: Dict[str, list]) -> List[dict]:
    return [c for c in _items(rs, "chain") if c.get("hook") == "input" and c.get("type", "filter") == "filter"
            and c.get("family") in ("inet", "ip", "ip6")]


def _reachable_chains(rs: Dict[str, list]) -> Set[Tuple[str, str, str]]:
    """Input base chains plus every chain they jump/goto into."""
    todo = [(c["family"], c["table"], c["name"]) for c in input_chains(rs)]
    seen: Set[Tuple[str, str, str]] = set()
    rules = _items(rs, "rule")
    while todo:
        cur = todo.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for r in rules:
            if (r["family"], r["table"], r["chain"]) != cur:
                continue
            for ex in r.get("expr", []):
                for k in ("jump", "goto"):
                    if k in ex:
                        todo.append((cur[0], cur[1], ex[k]["target"]))
    return seen


def nft_entries(rs: Dict[str, list]) -> List[Entry]:
    chains = _reachable_chains(rs)
    out = []
    for r in _items(rs, "rule"):
        if (r["family"], r["table"], r["chain"]) in chains:
            e = parse_nft_rule(r)
            if e:
                out.append(e)
    return out


def drop_policy_chains(rs: Dict[str, list]) -> List[dict]:
    return [c for c in input_chains(rs) if c.get("policy") == "drop"]


def nft_summary(rs: Dict[str, list]) -> str:
    chains = input_chains(rs)
    if not chains:
        return "nftables: no input filter chain - every listening port is reachable"
    lines = ["nftables input chains:"]
    for c in chains:
        lines.append(f"  {c['family']} {c['table']} {c['name']}  priority {c.get('prio')}  "
                     f"policy {c.get('policy', 'accept')}")
    return "\n".join(lines)


def _nft_rule_text(family: str, table: str, chain: str) -> Dict[int, str]:
    """handle -> rule text as nft prints it (used to rewrite multi-port rules)."""
    rc, out = capture(["nft", "-a", "list", "chain", family, table, chain], 10)
    rules: Dict[int, str] = {}
    for line in out.splitlines():
        m = re.match(r"\s*(.+?)\s+# handle (\d+)\s*$", line)
        if m and not m.group(1).startswith(("type ", "chain ", "table ")):
            rules[int(m.group(2))] = m.group(1)
    return rules


def narrow_rule_texts(text: str, cut: Range) -> List[str]:
    """Rule texts that replace `text` once the ports in `cut` are removed ([] = nothing left).

    Single ports stay together in one set; ranges get a rule each, because nft
    1.0.x asserts on anonymous sets that mix several intervals.
    """
    m = re.search(r"dport\s+(\{[^}]*\}|\S+)", text)
    if not m:
        return []
    raw = m.group(1).strip("{} ")
    singles: List[str] = []
    ranges: List[str] = []
    for item in [x.strip() for x in raw.split(",") if x.strip()]:
        r = _port_value(item if "-" not in item else {"range": item.split("-")})
        if not r:
            singles.append(item)
            continue
        for piece in subtract(r[0], cut) if overlaps(r[0], cut) else [r[0]]:
            (singles if piece[0] == piece[1] else ranges).append(fmt_range(piece))
    groups = ([singles[0] if len(singles) == 1 else "{ " + ", ".join(singles) + " }"] if singles else []) + ranges
    return [text[:m.start(1)] + g + text[m.end(1):] for g in groups]


def _match(proto: str, r: Range, source: str) -> List[str]:
    """nft rule tokens for a port match, as separate argv items."""
    toks: List[str] = []
    if source:
        toks += ["ip6" if ":" in source else "ip", "saddr", source]
    toks += [proto, "dport", fmt_range(r)]
    return toks


def nft_persist_steps() -> List[Step]:
    conf = next((p for p in NFT_CONF_CANDIDATES if os.path.exists(p)), NFT_CONF_CANDIDATES[0])
    script = f"""
f={conf}
tmp=$(mktemp)
{{ echo '#!/usr/sbin/nft -f'; echo '# Saved by servctl'; echo 'flush ruleset'; nft list ruleset; }} > "$tmp"
nft -c -f "$tmp"
mkdir -p /var/backups/servctl/nftables
[ -f "$f" ] && cp -a "$f" "/var/backups/servctl/nftables/$(basename "$f").$(date +%Y%m%d-%H%M%S)"
install -m 0600 "$tmp" "$f"
rm -f "$tmp"
echo "saved to $f"
"""
    return [Step.sh(f"Save the ruleset to {conf} (loaded at boot)", script),
            Step.cmd("Load it at boot", "systemctl", "enable", "nftables", allow_fail=True)]


def nft_open_plan(ranges: List[Range], protos: List[str], source: str, rs: Dict[str, list],
                  persist: bool) -> List[Step]:
    source = validate_source(source)
    entries = nft_entries(rs)
    steps: List[Step] = []
    targets = drop_policy_chains(rs)
    for r in ranges:
        for p in protos:
            # 1) our own drop rules for this port go away
            for e in entries:
                if e.verdict in ("drop", "reject") and e.editable and e.ref.get("servctl") and e.covers(r[0], p):
                    steps.append(Step.cmd(f"Remove servctl block on {e.ports_text}/{p}", "nft", "delete", "rule",
                                          *SERVCTL_TABLE, str(e.ref["chain"]), "handle", str(e.ref["handle"])))
            others = [e for e in entries if e.verdict in ("drop", "reject") and not e.ref.get("servctl")
                      and e.covers(r[0], p) and not e.source]
            for e in others:
                if e.editable:
                    steps.append(Step.cmd(f"Remove {e.verdict} rule for {e.ports_text}/{p} in {e.where}",
                                          "nft", "delete", "rule", str(e.ref["family"]), str(e.ref["table"]),
                                          str(e.ref["chain"]), "handle", str(e.ref["handle"])))
                else:
                    raise ValueError(f"A complex {e.verdict} rule in {e.where} (handle {e.ref['handle']}) "
                                     "blocks this port - edit it by hand")
            # 2) allow through every chain whose policy is drop
            for c in targets:
                already = any(e.verdict == "accept" and e.where == f"{c['family']} {c['table']} {c['name']}"
                              and all(e.covers(x, p) for x in (r[0], r[1])) and (not e.source or e.source == source)
                              for e in entries)
                if not already:
                    steps.append(Step.cmd(
                        f"Allow {fmt_range(r)}/{p}{' from ' + source if source else ''} in "
                        f"{c['family']} {c['table']} {c['name']}",
                        "nft", "insert", "rule", c["family"], c["table"], c["name"],
                        *_match(p, r, source), "accept", "comment", '"servctl"'))
    if not steps:
        raise ValueError("Already reachable: no nftables rule or policy blocks this port")
    if persist:
        steps += nft_persist_steps()
    return steps


def nft_close_plan(ranges: List[Range], protos: List[str], rs: Dict[str, list], persist: bool,
                   allow_ssh: bool = False, rule_text=_nft_rule_text) -> List[Step]:
    guard_ssh(ranges, protos, allow_ssh)
    entries = nft_entries(rs)
    policy_drop = bool(drop_policy_chains(rs))
    steps: List[Step] = []
    texts: Dict[Tuple[str, str, str], Dict[int, str]] = {}
    need_block: List[Tuple[Range, str]] = []
    done: Set[int] = set()
    for want in ranges:
        for p in protos:
            accepts = [e for e in entries if e.verdict == "accept" and (not e.protos or p in e.protos)
                       and any(overlaps(want, r) for r in e.ranges)]
            for e in accepts:
                h = int(e.ref["handle"])  # type: ignore[arg-type]
                if h in done:
                    continue
                loc = (str(e.ref["family"]), str(e.ref["table"]), str(e.ref["chain"]))
                if not e.editable:
                    need_block.append((want, p))
                    continue
                done.add(h)
                fully = all(want[0] <= r[0] and r[1] <= want[1] for r in e.ranges)
                if fully and (len(e.protos) <= 1 or set(e.protos) <= set(protos)):
                    steps.append(Step.cmd(f"Delete accept rule {e.ports_text}/{'+'.join(e.protos) or 'any'} "
                                          f"in {e.where}", "nft", "delete", "rule", *loc, "handle", str(h)))
                    continue
                if loc not in texts:
                    texts[loc] = rule_text(*loc)
                old = texts[loc].get(h)
                if old and set(e.protos) <= set(protos) | {p}:
                    news = narrow_rule_texts(old, want)
                    # One nft transaction: new rules land where the old one was, then it goes.
                    batch = "".join(f"add rule {' '.join(loc)} position {h} {t}\n" for t in reversed(news))
                    batch += f"delete rule {' '.join(loc)} handle {h}\n"
                    steps.append(Step.sh(f"Narrow rule in {e.where}: '{old}' -> "
                                         f"{' + '.join(repr(t) for t in news) or 'removed'}",
                                         f"nft -f - <<'NFT'\n{batch}NFT"))
                else:
                    need_block.append((want, p))
            if not policy_drop and not accepts:
                need_block.append((want, p))
    if need_block:
        steps += [Step.cmd("Create table inet servctl (if missing)", "nft", "add", "table", *SERVCTL_TABLE),
                  Step.cmd("Create its input chain (if missing)", "nft", "add", "chain", *SERVCTL_TABLE,
                           SERVCTL_CHAIN, "{ type filter hook input priority filter - 5 ; policy accept ; }")]
        for r, p in dict.fromkeys(need_block):
            steps.append(Step.cmd(f"Block {fmt_range(r)}/{p}", "nft", "add", "rule", *SERVCTL_TABLE,
                                  SERVCTL_CHAIN, *_match(p, r, ""), "drop", "comment", '"servctl"'))
    if not steps:
        raise ValueError("Already closed: no accept rule covers this port and the input policy is drop")
    if persist:
        steps += nft_persist_steps()
    return steps


def nft_delete_entry_plan(e: Entry, persist: bool, allow_ssh: bool = False) -> List[Step]:
    if e.verdict == "accept":
        guard_ssh(e.ranges, e.protos or ["tcp"], allow_ssh)
    steps = [Step.cmd(f"Delete rule handle {e.ref['handle']} in {e.where}", "nft", "delete", "rule",
                      str(e.ref["family"]), str(e.ref["table"]), str(e.ref["chain"]), "handle",
                      str(e.ref["handle"]))]
    return steps + (nft_persist_steps() if persist else [])


# --------------------------------------------------------------------------- #
# Backend selection and reachability estimate
# --------------------------------------------------------------------------- #

def backend(choice: str = "auto") -> str:
    if choice in ("firewalld", "nftables"):
        return choice
    if firewalld_running():
        return "firewalld"
    return "nftables" if which("nft") else "none"


def reachability(l: Listener, entries: List[Entry], back: str, rs: Optional[Dict[str, list]] = None) -> str:
    if l.local_only:
        return "localhost only"
    accepts = [e for e in entries if e.verdict == "accept" and e.covers(l.port, l.proto)]
    blocks = [e for e in entries if e.verdict in ("drop", "reject") and e.covers(l.port, l.proto) and not e.source]
    if back == "nftables":
        if blocks:
            return "BLOCKED"
        if accepts:
            return "open" if any(not e.source for e in accepts) else "restricted"
        return "BLOCKED" if rs is not None and drop_policy_chains(rs) else "open (no filter)"
    if back == "firewalld":
        if any(not e.source for e in accepts):
            return "open"
        return "restricted" if accepts else "BLOCKED"
    return "open (no firewall)"


def nft_config_note() -> str:
    conf = next((p for p in NFT_CONF_CANDIDATES if os.path.exists(p)), None)
    return f"boot config: {conf}" if conf else "boot config: none yet"
