"""Tests for the v0.2 modules: config, registry/plugins, DNS, Unbound, mail checks, benchmarks."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from servctl import bench, config, dnsutil, maildns, registry, unbound
from servctl.dnsutil import Answer


class ConfigTests(unittest.TestCase):
    def test_defaults_merge_and_save(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "c.yml")
            p.write_text("modules:\n  enabled: [overview, disk]\nspeedtest:\n  streams: 8\n")
            c = config.Config(p)
            self.assertEqual(c.get("modules.enabled"), ["overview", "disk"])
            self.assertEqual(c.get("speedtest.streams"), 8)
            self.assertEqual(c.get("speedtest.upload_mb"), 25)       # default kept
            c.set("ui.dry_run", True)
            c.save()
            self.assertTrue(config.Config(p).get("ui.dry_run"))

    def test_broken_yaml_falls_back(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "c.yml")
            p.write_text("modules: [unclosed\n")
            c = config.Config(p)
            self.assertTrue(c.error)
            self.assertIsNone(c.get("modules.enabled"))


class RegistryTests(unittest.TestCase):
    def test_required_modules_always_enabled(self):
        ids = [m.id for m in registry.resolve_enabled(registry.BUILTIN, ["disk"])]
        self.assertEqual(ids, ["overview", "disk", "settings"])

    def test_defaults(self):
        ids = {m.id for m in registry.resolve_enabled(registry.BUILTIN, None)}
        self.assertTrue({"unbound", "maildns", "speedtest"} <= ids)

    def test_plugins_need_trust(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "hello.py").write_text(
                "from servctl.registry import Module\n"
                "class P: pass\n"
                "MODULES = [Module('hello', 'Hello', 'Weird', 'demo', pane=P)]\n")
            os.chmod(Path(d, "hello.py"), 0o644)
            mods, msgs = registry.load_plugins(d, [])
            self.assertEqual(mods, [])
            self.assertIn("not in plugins.trusted", msgs[0])
            mods, msgs = registry.load_plugins(d, ["hello"])
            self.assertEqual([m.id for m in mods], ["hello"])
            self.assertEqual(mods[0].category, "Plugins")
            os.chmod(Path(d, "hello.py"), 0o666)
            mods, msgs = registry.load_plugins(d, ["hello"])
            self.assertEqual(mods, [])
            self.assertIn("writable", msgs[0])


class DnsTests(unittest.TestCase):
    def test_parse_server(self):
        self.assertEqual(dnsutil.parse_server("1.1.1.1"), ("1.1.1.1", 53))
        self.assertEqual(dnsutil.parse_server("127.0.0.1:5353"), ("127.0.0.1", 5353))
        self.assertEqual(dnsutil.parse_server("[::1]:5353"), ("::1", 5353))
        self.assertEqual(dnsutil.parse_server("2606:4700::1111"), ("2606:4700::1111", 53))

    def test_spamhaus_codes(self):
        with mock.patch.object(dnsutil, "query", return_value=Answer("NOERROR", ["127.255.255.254"])):
            self.assertEqual(dnsutil.spamhaus_status("8.8.8.8"), "blocked: public/open resolver")
        with mock.patch.object(dnsutil, "query", return_value=Answer("NOERROR", ["127.0.0.2", "127.0.0.10"])):
            self.assertEqual(dnsutil.spamhaus_status("127.0.0.1"), "OK")

    def test_score_orders_failures_last(self):
        good = dnsutil.BenchResult("a", "1", 5, 30, 100)
        flaky = dnsutil.BenchResult("b", "2", 4, 25, 80)
        dead = dnsutil.BenchResult("c", "3", None, None, 0)
        self.assertEqual(sorted([dead, flaky, good], key=lambda r: r.score), [good, flaky, dead])

    def test_system_dns_backends(self):
        nm = dnsutil.system_dns_plan(["127.0.0.1"], backend="networkmanager")
        self.assertIn("[global-dns-domain-*]\nservers=127.0.0.1", nm[0].content)
        rs = dnsutil.system_dns_plan(["127.0.0.1", "9.9.9.9"], backend="resolved")
        self.assertIn("DNS=127.0.0.1 9.9.9.9", rs[0].content)
        with self.assertRaises(ValueError):
            dnsutil.system_dns_plan(["127.0.0.1:5353"], backend="resolved")


class UnboundTests(unittest.TestCase):
    def test_render(self):
        c = unbound.render_config(unbound.UnboundOpts(lan=True, lan_cidrs=["192.168.1.7/24"]))
        self.assertIn("access-control: 192.168.1.0/24 allow", c)
        self.assertIn("interface: 0.0.0.0", c)
        self.assertIn('root-hints: "/var/lib/unbound/root.hints"', c)
        self.assertNotIn("forward-zone", c)

    def test_validation(self):
        with self.assertRaises(ValueError):
            unbound.UnboundOpts(lan=True).validate()
        with self.assertRaises(ValueError):
            unbound.UnboundOpts(port=5353, set_system_dns=True).validate()

    def test_plan_switches_dns_only_after_check(self):
        with mock.patch.object(dnsutil, "dns_backend", return_value="networkmanager"), \
                mock.patch.object(unbound, "firewalld_running", return_value=False):
            steps = unbound.install_plan(unbound.UnboundOpts(), "dnf")
        titles = [s.title for s in steps]
        self.assertLess(titles.index("Wait until unbound answers"), titles.index("Set NetworkManager global DNS"))
        self.assertLess(titles.index("Validate configuration"), titles.index("Restart unbound"))
        script = next(s for s in steps if s.path == unbound.HINTS_SCRIPT).content
        r = subprocess.run(["bash", "-n", "-c", script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipUnless(shutil.which("unbound-checkconf"), "unbound not installed")
    def test_checkconf(self):
        with tempfile.TemporaryDirectory() as d:
            c = unbound.render_config(unbound.UnboundOpts(lan=True, lan_cidrs=["10.0.0.0/8"]))
            c = c.replace("/var/lib/unbound", d).replace('username: "unbound"', 'username: ""')
            Path(d, "root.hints").write_text(". 3600000 NS A.ROOT-SERVERS.NET.\n"
                                             "A.ROOT-SERVERS.NET. 3600000 A 198.41.0.4\n")
            # In the real plan unbound-anchor creates this before the check.
            Path(d, "root.key").write_text(". 172800 IN DS 20326 8 2 "
                                           "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n")
            Path(d, "u.conf").write_text(c)
            r = subprocess.run(["unbound-checkconf", f"{d}/u.conf"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class FakeDNS:
    """Minimal zone for mail checks."""

    def __init__(self, zone):
        self.zone = zone

    def __call__(self, name, rtype="A", server=None, timeout=2.0, dnssec=False):
        name = name.rstrip(".").lower()
        recs = self.zone.get((name, rtype))
        if recs is None:
            known = any(n == name for n, _ in self.zone)
            return Answer("NOERROR" if known else "NXDOMAIN", [])
        return Answer("NOERROR", list(recs))


ZONE = {
    ("example.org", "SOA"): ["ns1. host. 1 2 3 4 5"],
    ("example.org", "MX"): ["10 mx1.example.org."],
    ("mx1.example.org", "A"): ["192.0.2.25"],
    ("25.2.0.192.in-addr.arpa", "PTR"): ["mx1.example.org."],
    ("25.2.0.192.zen.spamhaus.org", "A"): ["127.0.0.4"],
    ("example.org", "TXT"): ['"v=spf1 include:_spf.example.net mx ~all"', '"google-site-verification=x"'],
    ("_spf.example.net", "TXT"): ['"v=spf1 ip4:198.51.100.0/24 include:_spf2.example.net -all"'],
    ("_spf2.example.net", "TXT"): ['"v=spf1 a mx -all"'],
    ("_dmarc.example.org", "TXT"): ['"v=DMARC1; p=none; pct=50"'],
    ("s1._domainkey.example.org", "TXT"): ['"v=DKIM1; k=rsa; p=' + "A" * 392 + '"'],
}


class MailTests(unittest.TestCase):
    def report(self, target="example.org"):
        found = []
        with mock.patch.object(maildns, "query", FakeDNS(ZONE)):
            maildns.Checker(None, found.append).run(target, [])
        return found

    def find(self, found, section, needle):
        return next(f for f in found if f.section == section and needle in f.text)

    def test_report(self):
        f = self.report()
        self.assertEqual(self.find(f, "MX", "PTR mx1").status, maildns.OK)
        self.assertEqual(self.find(f, "MX", "Spamhaus").status, maildns.FAIL)
        self.assertIn("XBL", self.find(f, "MX", "Spamhaus").text)
        self.assertEqual(self.find(f, "SPF", "soft fail").status, maildns.OK)
        self.assertEqual(self.find(f, "SPF", "DNS-querying").text, "5 DNS-querying mechanisms (limit is 10)")
        self.assertEqual(self.find(f, "DMARC", "policy").status, maildns.WARN)
        self.assertEqual(self.find(f, "DMARC", "only part").status, maildns.WARN)
        self.assertEqual(self.find(f, "DKIM", "s1:").status, maildns.OK)

    def test_null_mx(self):
        zone = dict(ZONE)
        zone[("example.org", "MX")] = ["0 ."]
        found = []
        with mock.patch.object(maildns, "query", FakeDNS(zone)):
            maildns.Checker(None, found.append).mx("example.org")
        self.assertIn("null MX", found[0].text)

    def test_nxdomain(self):
        f = self.report("nope.invalid")
        self.assertEqual(f[0].status, maildns.FAIL)

    def test_txt_join(self):
        self.assertEqual(maildns._txt('"v=spf1 " "-all"'), "v=spf1 -all")


class BenchTests(unittest.TestCase):
    def test_size(self):
        self.assertEqual(bench.size_bytes("1G"), 1 << 30)
        with self.assertRaises(ValueError):
            bench.size_bytes("1 gig")

    def test_parse_fio(self):
        out = ('fio: some warning\n{"jobs": [{"read": {"bw_bytes": 500000000, "iops": 476.8, '
               '"clat_ns": {"mean": 16000000, "percentile": {"99.000000": 30000000}}}, "write": {}}]}')
        r = bench.parse_fio("x", out, "read")
        self.assertAlmostEqual(r.mbps, 500.0)
        self.assertAlmostEqual(r.p99_us, 30000.0)

    @unittest.skipUnless(shutil.which("fio"), "fio not installed")
    def test_fio_runs(self):
        with tempfile.TemporaryDirectory(dir="/var/tmp") as d:
            res = bench.run_fio([bench.DISK_TESTS[2]], d, "16M", 2, lambda m, s: None, lambda r: None)
            self.assertFalse(res[0].error, res[0].error)
            self.assertGreater(res[0].iops, 0)
            self.assertEqual(os.listdir(d), [])     # temp file removed


if __name__ == "__main__":
    unittest.main()
