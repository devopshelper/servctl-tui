"""Firewall (firewalld + nftables) and MariaDB tests."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from servctl import firewall as fw
from servctl import mariadb as m
from servctl.core import run_plan

FAKES = str(Path(__file__).parent / "fakes")

LIST_ALL = """public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources:
  services: cockpit dhcpv6-client ssh
  ports: 8080/tcp 9000-9100/udp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
\tport=80:proto=tcp:toport=8080:toaddr=
  source-ports:
  icmp-blocks:
  rich rules:
\trule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept
\trule family="ipv4" source address="192.0.2.9" service name="ssh" reject
"""

NFT_JSON = {"nftables": [
    {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter",
               "hook": "input", "prio": 0, "policy": "drop"}},
    {"chain": {"family": "inet", "table": "filter", "name": "tcp_in", "handle": 2}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 3,
              "expr": [{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established"]}},
                       {"accept": None}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4,
              "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                  "right": {"set": [22, 80, {"range": [8000, 8100]}]}}}, {"accept": None}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 5,
              "expr": [{"jump": {"target": "tcp_in"}}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "tcp_in", "handle": 6,
              "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                  "right": {"prefix": {"addr": "10.0.0.0", "len": 8}}}},
                       {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}},
                                  "right": {"set": ["tcp", "udp"]}}},
                       {"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}},
                                  "right": 5353}},
                       {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 7,
              "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth1"}},
                       {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                  "right": 3306}}, {"accept": None}]}},
]}

SS = """tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=1,fd=4))
tcp   LISTEN 0 80 127.0.0.1:3306 0.0.0.0:* users:(("mariadbd",pid=2,fd=20))
udp   UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("avahi",pid=3,fd=12))
tcp   LISTEN 0 511 *:8443 *:* users:(("nginx",pid=4,fd=6))"""


class PortParsing(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(fw.parse_ports("22, 80 8000-8100"), [(22, 22), (80, 80), (8000, 8100)])
        for bad in ("", "0", "70000", "90-80", "http"):
            with self.assertRaises(ValueError):
                fw.parse_ports(bad)

    def test_subtract(self):
        self.assertEqual(fw.subtract((8000, 8100), (8050, 8050)), [(8000, 8049), (8051, 8100)])
        self.assertEqual(fw.subtract((8000, 8100), (7000, 9000)), [])
        self.assertEqual(fw.subtract((80, 80), (80, 80)), [])

    def test_source(self):
        self.assertEqual(fw.validate_source("10.1.2.3/8"), "10.0.0.0/8")
        with self.assertRaises(ValueError):
            fw.validate_source("10.0.0.0/33")

    def test_ssh_guard(self):
        with mock.patch.object(fw, "ssh_ports", return_value={2222}):
            with self.assertRaises(ValueError):
                fw.guard_ssh([(2000, 3000)], ["tcp"], False)
            fw.guard_ssh([(2000, 3000)], ["tcp"], True)
            fw.guard_ssh([(2000, 3000)], ["udp"], False)


class Listening(unittest.TestCase):
    def test_parse_ss(self):
        ls = {(l.proto, l.port): l for l in fw.parse_ss(SS)}
        self.assertEqual(ls[("tcp", 22)].addresses, ["0.0.0.0", "[::]"])
        self.assertEqual(ls[("tcp", 22)].process, "sshd")
        self.assertTrue(ls[("tcp", 3306)].local_only)
        self.assertFalse(ls[("tcp", 8443)].local_only)


class FirewalldParsing(unittest.TestCase):
    def test_list_all(self):
        d = fw.parse_list_all(LIST_ALL)
        self.assertEqual(d["services"], ["cockpit", "dhcpv6-client", "ssh"])
        self.assertEqual(d["ports"], ["8080/tcp", "9000-9100/udp"])
        self.assertEqual(len(d["rich rules"]), 2)

    def test_rich(self):
        svc = lambda name: [((22, 22), "tcp")] if name == "ssh" else []
        r1 = fw.parse_rich('rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept', svc)
        self.assertEqual(r1, ([(5432, 5432)], ["tcp"], "10.0.0.0/8", "accept"))
        r2 = fw.parse_rich('rule family="ipv4" source address="192.0.2.9" service name="ssh" reject', svc)
        self.assertEqual(r2, ([(22, 22)], ["tcp"], "192.0.2.9", "reject"))


class FirewalldFake(unittest.TestCase):
    """Runs the real plan engine against tests/fakes/firewall-cmd."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name, "fw.json")
        zone = {"ports": ["9000-9100/tcp"], "services": ["ssh", "cockpit"],
                "rich": ['rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept']}
        self.state.write_text(json.dumps({"default": "public", "zones": {"public": {"interfaces": ["eth0"]}},
                                          "runtime": {"public": zone}, "permanent": {"public": zone}}))
        self.env = mock.patch.dict(os.environ, {"FAKE_FW_STATE": str(self.state),
                                                "PATH": FAKES + os.pathsep + os.environ["PATH"]})
        self.env.start()
        self.ssh = mock.patch.object(fw, "ssh_ports", return_value={22})
        self.ssh.start()

    def tearDown(self):
        self.ssh.stop()
        self.env.stop()
        self.tmp.cleanup()

    def layer(self, which="permanent"):
        return json.loads(self.state.read_text())[which]["public"]

    def run_ok(self, steps):
        self.assertTrue(run_plan(steps, lambda m, s: None))

    def test_backend_and_entries(self):
        self.assertEqual(fw.backend(), "firewalld")
        kinds = sorted((e.kind, e.ports_text) for e in fw.Firewalld().entries())
        self.assertEqual(kinds, [("port", "9000-9100"), ("rich", "5432"), ("service", "22"), ("service", "9090")])

    def test_open_close_roundtrip(self):
        self.run_ok(fw.fw_open_plan([(443, 443)], ["tcp", "udp"], "public", "", True, 0))
        self.assertIn("443/udp", self.layer()["ports"])
        self.run_ok(fw.fw_close_plan([(443, 443)], ["udp"], fw.Firewalld().entries()))
        self.assertNotIn("443/udp", self.layer()["ports"])
        self.assertIn("443/tcp", self.layer()["ports"])

    def test_timeout_is_runtime_only(self):
        self.run_ok(fw.fw_open_plan([(6000, 6000)], ["tcp"], "public", "", True, 15))
        self.assertIn("6000/tcp", self.layer("runtime")["ports"])
        self.assertNotIn("6000/tcp", self.layer()["ports"])

    def test_split_range_and_service(self):
        self.run_ok(fw.fw_close_plan([(9090, 9090)], ["tcp"], fw.Firewalld().entries()))
        p = self.layer()
        self.assertEqual(sorted(p["ports"]), ["9000-9089/tcp", "9091-9100/tcp"])
        self.assertNotIn("cockpit", p["services"])

    def test_source_restricted(self):
        self.run_ok(fw.fw_open_plan([(3306, 3306)], ["tcp"], "public", "192.168.1.0/24", True, 0))
        self.assertTrue(any('source address="192.168.1.0/24"' in r for r in self.layer()["rich"]))
        self.run_ok(fw.fw_close_plan([(5432, 5432)], ["tcp"], fw.Firewalld().entries()))
        self.assertFalse(any("5432" in r for r in self.layer()["rich"]))

    def test_refusals(self):
        with self.assertRaises(ValueError):
            fw.fw_close_plan([(22, 22)], ["tcp"], fw.Firewalld().entries())
        with self.assertRaises(ValueError):
            fw.fw_close_plan([(7777, 7777)], ["tcp"], fw.Firewalld().entries())


class NftParsing(unittest.TestCase):
    def test_entries(self):
        es = {e.ref["handle"]: e for e in fw.nft_entries(NFT_JSON)}
        self.assertEqual(sorted(es), [4, 6, 7])           # ct-state rule has no port; jump followed
        self.assertEqual(es[4].ranges, [(22, 22), (80, 80), (8000, 8100)])
        self.assertTrue(es[4].editable)
        self.assertEqual((es[6].protos, es[6].source), (["tcp", "udp"], "10.0.0.0/8"))
        self.assertFalse(es[7].editable)                  # iifname makes it complex

    def test_reachability(self):
        es = fw.nft_entries(NFT_JSON)
        r = lambda port, proto="tcp": fw.reachability(fw.Listener(proto, port, ["0.0.0.0"]), es, "nftables", NFT_JSON)
        self.assertEqual(r(80), "open")
        self.assertEqual(r(5353, "udp"), "restricted")
        self.assertEqual(r(9999), "BLOCKED")

    def test_narrow(self):
        self.assertEqual(fw.narrow_rule_texts("tcp dport { 22, 80, 443 } accept", (80, 80)),
                         ["tcp dport { 22, 443 } accept"])
        self.assertEqual(fw.narrow_rule_texts("tcp dport 8000-8100 accept", (8050, 8050)),
                         ["tcp dport 8000-8049 accept", "tcp dport 8051-8100 accept"])
        self.assertEqual(fw.narrow_rule_texts("tcp dport 80 accept", (80, 80)), [])


def _nft_usable():
    if not shutil.which("nft") or os.geteuid() != 0:
        return False
    r = subprocess.run(["nft", "add", "table", "inet", "servctl_t"], capture_output=True)
    subprocess.run(["nft", "delete", "table", "inet", "servctl_t"], capture_output=True)
    return r.returncode == 0


@unittest.skipUnless(_nft_usable(), "needs root and a usable nft")
class NftLive(unittest.TestCase):
    """Uses its own table with policy accept on a priority that does not matter."""

    def setUp(self):
        subprocess.run(["nft", "-f", "-"], input="""
table inet servctl_test {
  chain input { type filter hook input priority 100; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport { 22, 80, 443 } accept
    tcp dport 8000-8100 accept
  }
}""", text=True, check=True)
        self.ssh = mock.patch.object(fw, "ssh_ports", return_value={22})
        self.ssh.start()

    def tearDown(self):
        self.ssh.stop()
        for t in ("servctl_test", "servctl"):
            subprocess.run(["nft", "delete", "table", "inet", t], capture_output=True)

    def chain(self):
        return subprocess.run(["nft", "list", "chain", "inet", "servctl_test", "input"],
                              capture_output=True, text=True).stdout

    def test_open_close(self):
        self.assertTrue(run_plan(fw.nft_open_plan([(9000, 9000)], ["tcp"], "", fw.nft_ruleset(), False),
                                 lambda m, s: None))
        self.assertIn("tcp dport 9000 accept", self.chain())
        self.assertTrue(run_plan(fw.nft_close_plan([(80, 80)], ["tcp"], fw.nft_ruleset(), False),
                                 lambda m, s: None))
        self.assertIn("tcp dport { 22, 443 } accept", self.chain())
        self.assertTrue(run_plan(fw.nft_close_plan([(8050, 8050)], ["tcp"], fw.nft_ruleset(), False),
                                 lambda m, s: None))
        c = self.chain()
        self.assertIn("tcp dport 8000-8049 accept", c)
        self.assertIn("tcp dport 8051-8100 accept", c)
        self.assertLess(c.index("8000-8049"), c.index("8051-8100"))


class MariaDbUnit(unittest.TestCase):
    def test_validation(self):
        for args in (("x'y", "localhost"), ("app", "local host"), ("", "localhost")):
            with self.assertRaises(ValueError):
                m.check_user(*args)
        with self.assertRaises(ValueError):
            m.check_dbs(["shop;drop"])
        with self.assertRaises(ValueError):
            m.check_password("short")
        with self.assertRaises(ValueError):
            m.check_password("has\\backslash-long")

    def test_password_masked_and_on_stdin(self):
        s = m.create_user_plan("app", "%", "it's-Secret-1234", True)[0]
        self.assertNotIn("Secret", s.describe())
        self.assertNotIn("Secret", " ".join(s.argv))
        self.assertIn("'it''s-Secret-1234'", s.stdin)
        self.assertIn("ALTER USER 'app'@'%'", s.stdin)

    def test_grant_sql(self):
        s = m.grant_plan("app", "10.0.0.%", ["crm", "wiki"], "ro", True)[0]
        self.assertIn("CREATE DATABASE IF NOT EXISTS `crm`", s.stdin)
        self.assertIn("GRANT SELECT, SHOW VIEW ON `wiki`.* TO 'app'@'10.0.0.%';", s.stdin)
        with self.assertRaises(ValueError):
            m.grant_plan("app", "localhost", ["mysql"], "all", False)

    def test_parse_grant(self):
        g = m.parse_grant("GRANT SELECT, INSERT ON `my\\_shop`.* TO `app`@`10.0.0.%` WITH GRANT OPTION")
        self.assertEqual((g.user, g.host, g.db, g.privileges, g.grant_option),
                         ("app", "10.0.0.%", "my_shop", "SELECT, INSERT", True))
        g = m.parse_grant("GRANT USAGE ON *.* TO `app`@`localhost` IDENTIFIED BY PASSWORD '*ABC'")
        self.assertEqual((g.target, g.grant_option), ("*.*", False))

    def test_drop_db_needs_confirmation(self):
        with self.assertRaises(ValueError):
            m.drop_db_plan("shop", "")
        self.assertEqual(len(m.drop_db_plan("shop", "shop")), 2)   # backup + drop


def _mariadb_up():
    return m.run_sql("SELECT 1;")[0]


@unittest.skipUnless(_mariadb_up(), "no local MariaDB reachable over the socket")
class MariaDbLive(unittest.TestCase):
    def tearDown(self):
        run_plan([m.sql_step("cleanup", "DROP USER IF EXISTS 'servctl_t'@'localhost';"
                                         "DROP DATABASE IF EXISTS servctl_t1;")], lambda *a: None)

    def test_full_cycle(self):
        steps = (m.create_db_plan(["servctl_t1"]) +
                 m.create_user_plan("servctl_t", "localhost", "A-long-pass-123", False) +
                 m.grant_plan("servctl_t", "localhost", ["servctl_t1"], "rw", False))
        self.assertTrue(run_plan(steps, lambda *a: None))
        self.assertIn("servctl_t1", [d[0] for d in m.databases()])
        gs = [g for g in m.grants(m.users()) if g.user == "servctl_t" and g.db == "servctl_t1"]
        self.assertEqual(gs[0].privileges, "SELECT, INSERT, UPDATE, DELETE")
        self.assertTrue(run_plan(m.revoke_plan("servctl_t", "localhost", ["servctl_t1"]), lambda *a: None))
        self.assertFalse([g for g in m.grants(m.users()) if g.user == "servctl_t" and g.db == "servctl_t1"])


if __name__ == "__main__":
    unittest.main()
