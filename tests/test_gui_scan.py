#!/usr/bin/env python3
"""回归：公网目标可直接使用；CLI/GUI 均不再有 scope 拦截。"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "gui"))

import server as G  # noqa: E402


class FakeJob(object):
    """替代真实 Job：只记录入队参数，不启动子进程。"""
    seen = []

    def __init__(self, targets, opts):
        self.id = "fake-%d" % len(FakeJob.seen)
        self.total = len(targets)
        FakeJob.seen.append({"targets": targets, "opts": opts})

    def run(self):
        pass


class ScanGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._work = G.WORKROOT
        self._job = G.Job
        G.WORKROOT = self.tmp.name
        FakeJob.seen = []
        G.Job = FakeJob

    def tearDown(self):
        G.Job = self._job
        G.WORKROOT = self._work
        G.JOBS.clear()
        self.tmp.cleanup()

    def _post(self, body):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), G.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request(
                "http://127.0.0.1:%d/api/scan" % srv.server_address[1],
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.status, json.loads(r.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read().decode("utf-8"))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_public_target_queues_without_extra_fields(self):
        code, data = self._post({"targets": ["http://93.184.216.34/"], "mode": "recon"})
        self.assertEqual(code, 200)
        self.assertIn("job_id", data)
        self.assertEqual(FakeJob.seen[-1]["targets"], ["http://93.184.216.34/"])

    def test_private_target_still_queues(self):
        code, _ = self._post({"targets": ["127.0.0.1:8090"], "mode": "recon"})
        self.assertEqual(code, 200)

    def test_legacy_scope_fields_ignored(self):
        code, data = self._post({
            "targets": ["http://93.184.216.34/"], "mode": "recon",
            "scope": "10.0.0.0/8", "authorized": False})
        self.assertEqual(code, 200)
        self.assertIn("job_id", data)


class JobGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._work = G.WORKROOT
        G.WORKROOT = self.tmp.name

    def tearDown(self):
        G.WORKROOT = self._work
        self.tmp.cleanup()

    def _run(self, target):
        job = G.Job([target], {"mode": "recon", "concurrency": 1})
        called = []

        def fake_exec(cmd, log_path, timeout):
            called.append(cmd)
            return 50, "stub"

        job._exec = fake_exec
        res = job._run_one(job.targets[0])
        return job, called, res

    def test_public_target_not_denied(self):
        job, called, res = self._run("http://93.184.216.34/")
        self.assertNotEqual(res["status"], "denied")
        self.assertFalse(job.targets[0].get("error"))
        self.assertNotIn("--i-have-authorization", called[0])
        self.assertNotIn("--scope-file", called[0])


class CliScopeRemovalTest(unittest.TestCase):
    def test_batch_accepts_public_ip(self):
        with tempfile.TemporaryDirectory() as d:
            lst = os.path.join(d, "targets.txt")
            with open(lst, "w", encoding="utf-8") as f:
                f.write("http://8.8.8.8/\n")
            p = subprocess.run(
                [sys.executable, os.path.join(ROOT, "attack", "php2shell.py"),
                 "batch", "-f", lst, "--dry-run"],
                capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("http://8.8.8.8/", p.stdout)
        self.assertNotIn("[scope]", p.stderr)

    def test_help_no_scope_flags(self):
        for script in ("php2shell.py", "p2s_ext.py", "recon.py"):
            p = subprocess.run(
                [sys.executable, os.path.join(ROOT, "attack", script), "--help"],
                capture_output=True, text=True, timeout=60)
            self.assertNotIn("--scope-file", p.stdout + p.stderr, script)
            self.assertNotIn("i-have-authorization", p.stdout + p.stderr, script)
            self.assertNotIn("allow-public", p.stdout + p.stderr, script)


class TimeoutVerdictTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._work = G.WORKROOT
        G.WORKROOT = self.tmp.name

    def tearDown(self):
        G.WORKROOT = self._work
        self.tmp.cleanup()

    def test_timeout_is_not_reported_as_filenotfound(self):
        job = G.Job(["http://127.0.0.1:9/"],
                    {"mode": "oneclick", "timeout": 5, "per_target_timeout": 900})
        job._exec = lambda cmd, log_path, timeout: (
            2, "[1/5] scan\n\n[TIMEOUT] 超过 900s，已终止")
        res = job._run_one(job.targets[0])
        self.assertEqual(res["verdict"], "TIMEOUT")
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["evidence"]["report_error"], "")
        self.assertNotIn("FileNotFoundError", res["summary"])
        self.assertIn("900", res["summary"])


class SynthVerdictTest(unittest.TestCase):
    def test_no_session_sink_gets_own_status(self):
        t = G.synth_cve("", 15, "http://x/", "recon",
                        {"verdict": "NO_SESSION_SINK", "php_version": "8.2.32"}, "")
        self.assertEqual(t["verdict"], "NO_SESSION_SINK")
        self.assertEqual(t["status"], "no_sink")

    def test_unknown_version_stays_unknown(self):
        t = G.synth_cve("", 15, "http://x/", "recon",
                        {"verdict": "UNKNOWN_VERSION"}, "")
        self.assertEqual(t["status"], "unknown")


class NormalizeTest(unittest.TestCase):
    def test_bare_ipv6_gets_bracketed(self):
        self.assertEqual(G.normalize_target("2606:4700:3030::6815:4be8"),
                         "http://[2606:4700:3030::6815:4be8]")
        self.assertEqual(G.normalize_target("http://2606:4700:3030::6815:4be8/x"),
                         "http://[2606:4700:3030::6815:4be8]/x")

    def test_normal_targets_unchanged(self):
        self.assertEqual(G.normalize_target("1.2.3.4:8080"), "http://1.2.3.4:8080")
        self.assertEqual(G.normalize_target("example.com"), "http://example.com")
        self.assertEqual(G.normalize_target("http://[::1]:8080/"),
                         "http://[::1]:8080/")


if __name__ == "__main__":
    unittest.main(verbosity=2)
