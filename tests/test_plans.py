"""Unit tests for plan builders. Config validation tests run the real tools when installed."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from servctl import cleanup, core, logs, siem, syncthing

RHEL9_LOGROTATE_CONF = """\
# see "man logrotate" for details

# global options do not affect preceding include directives

# rotate log files weekly
weekly

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
dateext

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may be also be configured here.
"""

NGINX_RULE = """\
/var/log/nginx/*.log {
    create 0640 nginx root
    daily
    rotate 10
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        # daily inside a script must survive
        /bin/kill -USR1 `cat /run/nginx.pid 2>/dev/null` 2>/dev/null || true
    endscript
}
"""


class CoreTests(unittest.TestCase):
    def test_write_backup_and_rollback(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "etc" / "app.conf"
            target.parent.mkdir()
            target.write_text("original\n")
            new_file = Path(d) / "etc" / "new.conf"
            with mock.patch.object(core, "BACKUP_ROOT", Path(d) / "bk"):
                ok = core.run_plan([
                    core.Step.write("w1", str(target), "changed\n"),
                    core.Step.write("w2", str(new_file), "x\n"),
                    core.Step.cmd("fail", "false"),
                ], lambda m, s: None)
            self.assertFalse(ok)
            self.assertEqual(target.read_text(), "original\n")
            self.assertFalse(new_file.exists())

    def test_allow_fail_continues(self):
        out = []
        ok = core.run_plan([core.Step.cmd("a", "false", allow_fail=True),
                            core.Step.cmd("b", "echo", "hi")], lambda m, s: out.append(m))
        self.assertTrue(ok)
        self.assertIn("  hi", out)

    def test_dry_run_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x"
            core.run_plan([core.Step.write("w", str(p), "x")], lambda m, s: None, dry_run=True)
            self.assertFalse(p.exists())

    def test_secret_hidden(self):
        s = core.Step.cmd("t", "tool", "--password=hunter2", display="tool --password=***")
        self.assertNotIn("hunter2", s.describe())


class CleanupTests(unittest.TestCase):
    def test_docker_plan(self):
        steps = cleanup.container_plan("docker", cleanup.ContainerOpts(
            all_images=True, volumes=True, all_volumes=True, until="24h"))
        argvs = [s.argv for s in steps]
        self.assertIn(["docker", "image", "prune", "-f", "-a", "--filter", "until=24h"], argvs)
        self.assertIn(["docker", "volume", "prune", "-f", "--all"], argvs)
        self.assertIn(["docker", "builder", "prune", "-f", "-a", "--filter", "until=24h"], argvs)

    def test_podman_has_no_builder_or_all_volumes(self):
        steps = cleanup.container_plan("podman", cleanup.ContainerOpts(volumes=True, all_volumes=True))
        argvs = [s.argv for s in steps]
        self.assertIn(["podman", "volume", "prune", "-f"], argvs)
        self.assertFalse(any("builder" in a for a in argvs))

    def test_bad_until(self):
        with self.assertRaises(ValueError):
            cleanup.container_plan("docker", cleanup.ContainerOpts(until="1 day"))

    def test_system_plan_dnf(self):
        steps = cleanup.system_plan("dnf", cleanup.SystemOpts(old_kernels=True, autoremove=True))
        argvs = [s.argv for s in steps]
        self.assertIn(["dnf", "clean", "all"], argvs)
        self.assertTrue(any("--oldinstallonly" in a for a in argvs))

    def test_rotated_log_regex(self):
        step = next(s for s in cleanup.system_plan("dnf", cleanup.SystemOpts())
                    if s.argv[0] == "find")
        with tempfile.TemporaryDirectory() as d:
            names = ["messages", "messages-20260101", "secure-20260101.gz", "app.log.1",
                     "app.log.2.gz", "boot.log", "x.log.old", "cron"]
            for n in names:
                Path(d, n).touch()
                os.utime(Path(d, n), (0, 0))
            argv = [a if a != "/var/log" else d for a in step.argv]
            argv = [a for a in argv if a != "-delete"]
            found = {Path(p).name for p in subprocess.run(argv, capture_output=True, text=True)
                     .stdout.split()}
        self.assertEqual(found, {"messages-20260101", "secure-20260101.gz", "app.log.1",
                                 "app.log.2.gz", "x.log.old"})


class LogrotateTests(unittest.TestCase):
    def test_patch_existing_keeps_scripts(self):
        s = logs.RotateSettings(frequency="weekly", rotate=3, maxsize="200M", maxage=30)
        out = logs.patch_block_settings(NGINX_RULE, s)
        self.assertIn("create 0640 nginx root", out)
        self.assertIn("sharedscripts", out)
        self.assertIn("# daily inside a script must survive", out)
        self.assertIn("    weekly", out)
        self.assertIn("    rotate 3", out)
        self.assertIn("    maxsize 200M", out)
        self.assertIn("    maxage 30", out)
        self.assertNotIn("rotate 10", out)
        self.assertEqual(out.count("compress\n"), 2)  # compress + delaycompress, once each
        parsed = logs.parse_settings(out)
        self.assertEqual((parsed.frequency, parsed.rotate, parsed.maxsize, parsed.maxage),
                         ("weekly", 3, "200M", 30))

    def test_parse_existing(self):
        s = logs.parse_settings(NGINX_RULE)
        self.assertEqual((s.frequency, s.rotate, s.compress, s.copytruncate), ("daily", 10, True, False))
        self.assertEqual(logs.parse_paths(NGINX_RULE), ["/var/log/nginx/*.log"])

    def test_debian_style_paths_on_own_lines(self):
        text = "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n\tweekly\n\tpostrotate\n" \
               "\t\t/usr/lib/rsyslog/rsyslog-rotate\n\tendscript\n}\n"
        self.assertEqual(logs.parse_paths(text), ["/var/log/syslog", "/var/log/mail.log"])
        out = logs.patch_block_settings(text, logs.RotateSettings(rotate=14))
        self.assertTrue(out.startswith("/var/log/syslog\n/var/log/mail.log\n{\n    daily\n    rotate 14"))
        self.assertIn("/usr/lib/rsyslog/rsyslog-rotate", out)

    def test_global_inserted_before_include(self):
        s = logs.RotateSettings(frequency="daily", rotate=14, compress=True, dateext=True)
        out = logs.patch_global_settings(RHEL9_LOGROTATE_CONF, s)
        lines = out.splitlines()
        inc = lines.index("include /etc/logrotate.d")
        self.assertLess(lines.index("daily"), inc)
        self.assertLess(lines.index("rotate 14"), inc)
        self.assertLess(lines.index("compress"), inc)
        self.assertNotIn("weekly", lines)
        self.assertIn("create", lines)
        self.assertNotIn("missingok", lines)
        g = logs.parse_settings(out, block=False)
        self.assertEqual((g.frequency, g.rotate, g.compress), ("daily", 14, True))

    def test_new_rule_requires_paths(self):
        with self.assertRaises(ValueError):
            logs.logrotate_rule_plan("myapp", [], logs.RotateSettings(), existing=None)

    @unittest.skipUnless(shutil.which("logrotate"), "logrotate not installed")
    def test_generated_files_parse(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.log").write_text("x\n")
            rule = logs.render_new_rule([f"{d}/*.log"], logs.RotateSettings(maxsize="10M", maxage=5))
            patched = logs.patch_block_settings(
                NGINX_RULE.replace("/var/log/nginx", d).replace("nginx root", "root root"),
                logs.RotateSettings())
            glob = logs.patch_global_settings(RHEL9_LOGROTATE_CONF.replace("include /etc/logrotate.d", ""),
                                              logs.RotateSettings(compress=True))
            for i, text in enumerate((glob + rule, patched)):
                conf = Path(d, f"t{i}.conf")
                conf.write_text(text)
                r = subprocess.run(["logrotate", "-d", "-s", f"{d}/state", str(conf)],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertNotIn("error", (r.stdout + r.stderr).lower())


class JournaldTests(unittest.TestCase):
    def test_dropin(self):
        steps = logs.journald_plan({"SystemMaxUse": "2G", "MaxRetentionSec": "1month"}, True)
        self.assertEqual(steps[0].content,
                         "# Managed by servctl\n[Journal]\nStorage=persistent\n"
                         "SystemMaxUse=2G\nMaxRetentionSec=1month\n")

    def test_bad_values(self):
        with self.assertRaises(ValueError):
            logs.journald_plan({"SystemMaxUse": "lots"}, False)
        with self.assertRaises(ValueError):
            logs.journald_plan({}, False)

    def test_vacuum_rotates_first(self):
        steps = logs.vacuum_plan("500M", "2weeks", "")
        self.assertEqual(steps[0].argv, ["journalctl", "--rotate"])
        self.assertEqual(steps[1].argv, ["journalctl", "--vacuum-size=500M", "--vacuum-time=2weeks"])


class SiemTests(unittest.TestCase):
    def _opts(self, **kw):
        base = dict(host="siem.example.com", port=6514, protocol="tls",
                    files=["/var/log/audit/audit.log"], framing="octet-counted")
        base.update(kw)
        return siem.SiemOpts(**base)

    def test_roundtrip(self):
        o = self._opts()
        c = siem.parse_config(siem.render_config(o))
        self.assertEqual((c["host"], c["port"], c["protocol"], c["fmt"], c["files"], c["selector"]),
                         ("siem.example.com", "6514", "tls", "rfc5424",
                          ["/var/log/audit/audit.log"], "*.info"))

    def test_udp_has_no_tcp_options(self):
        text = siem.render_config(self._opts(protocol="udp", port=514))
        self.assertNotIn("TCP_Framing", text)
        self.assertNotIn("StreamDriver", text)

    def test_rejects_injection(self):
        with self.assertRaises(ValueError):
            siem.render_config(self._opts(host='x" type="omfile'))
        with self.assertRaises(ValueError):
            siem.render_config(self._opts(files=['/tmp/a" x="']))

    @unittest.skipUnless(shutil.which("rsyslogd"), "rsyslogd not installed")
    def test_rsyslog_accepts_config(self):
        with tempfile.TemporaryDirectory() as d:
            ca = Path(d, "ca.pem")
            ca.write_text("")
            for o in (self._opts(ca_file=str(ca)), self._opts(protocol="udp", files=[]),
                      self._opts(protocol="tcp", fmt="rfc3164", selector="auth,authpriv.*;*.warn")):
                conf = Path(d, "rsyslog.conf")
                conf.write_text(f'global(workDirectory="{d}")\n' + siem.render_config(o))
                r = subprocess.run(["rsyslogd", "-N1", "-f", str(conf)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class SyncthingTests(unittest.TestCase):
    def test_rhel_epel_plan(self):
        osi = core.OSInfo(id="rhel", id_like=["fedora"], version_id="9.4")
        with mock.patch.object(syncthing, "firewalld_running", return_value=True):
            steps = syncthing.install_plan(syncthing.SyncthingOpts(
                user="nobody", gui_user="admin", gui_password="s3cret", gui_remote=True), osi)
        text = "\n".join(s.describe() for s in steps)
        self.assertIn("epel-release-latest-9.noarch.rpm", text)
        self.assertIn("STGUIADDRESS=0.0.0.0:8384", text)
        self.assertIn("--add-port=22000/tcp", text)
        self.assertIn("--add-port=8384/tcp", text)
        self.assertNotIn("s3cret", text)
        self.assertEqual(steps[-2].argv[0:2], ["firewall-cmd", "--reload"])

    def test_remote_gui_needs_password(self):
        with self.assertRaises(ValueError):
            syncthing.install_plan(syncthing.SyncthingOpts(user="nobody", gui_remote=True),
                                   core.OSInfo(id="rocky", version_id="9.4"))

    def test_upstream_script_is_valid_bash(self):
        steps = syncthing.install_plan(syncthing.SyncthingOpts(user="nobody", method="upstream",
                                                               open_firewall=False),
                                       core.OSInfo(id="ubuntu"))
        script = steps[0].argv[-1]
        r = subprocess.run(["bash", "-n", "-c", script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
