#!/usr/bin/env python3
"""Fast recon regression: --fast sends only 3 requests and is mutually exclusive with --deep."""
import contextlib
import io
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "attack"))
sys.path.insert(0, os.path.join(ROOT, "gui"))

import recon  # noqa: E402
import server as G  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    count = 0
    php = "8.4.26"

    def do_GET(self):
        type(self).count += 1
        body = ("<html>PHP Version %s</html>" % self.php).encode()
        self.send_response(200)
        self.send_header("X-Powered-By", "PHP/" + self.php)
        self.send_header("Set-Cookie", "PHPSESSID=abcdef1234567890abcdef; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


class FastReconTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = _serve()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _run(self, *args):
        _Handler.count = 0
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = recon.main(["-u", self.base, "--json"] + list(args))
        return rc, json.loads(buf.getvalue()), _Handler.count

    def test_fast_uses_two_requests(self):
        rc, report, count = self._run("--fast")
        self.assertEqual(rc, 10)
        self.assertEqual(count, 2)
        self.assertEqual(report["requests"], 2)
        self.assertTrue(report["fast"])
        self.assertFalse(report["deep"])
        self.assertEqual(report["php_version"], "8.4.26")

    def test_fast_skips_sinks_for_patched(self):
        _Handler.php = "8.4.27"
        try:
            rc, report, count = self._run("--fast")
        finally:
            _Handler.php = "8.4.26"
        self.assertEqual(rc, 30)
        self.assertEqual(count, 1)
        self.assertEqual(report["verdict"], "NOT_AFFECTED")

    def test_fast_ignores_deep(self):
        rc, report, _ = self._run("--fast", "--deep")
        self.assertEqual(rc, 10)
        self.assertTrue(report["fast"])
        self.assertFalse(report["deep"])
        self.assertEqual(report["deep_probes"], [])

    def test_full_recon_probes_more(self):
        rc, report, count = self._run()
        self.assertEqual(rc, 10)
        self.assertGreater(count, 20)
        self.assertGreater(report["requests"], 20)


class FastCommandTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self._work = G.WORKROOT
        G.WORKROOT = self.tmp.name

    def tearDown(self):
        G.WORKROOT = self._work
        self.tmp.cleanup()

    def _cmd(self, opts):
        job = G.Job(["http://127.0.0.1:9/"], opts)
        called = []

        def fake_exec(cmd, log_path, timeout):
            called.append(cmd)
            return 50, "stub"

        job._exec = fake_exec
        job._run_one(job.targets[0])
        return called[0]

    def test_fast_flag_suppresses_deep(self):
        cmd = self._cmd({"mode": "recon", "fast": True, "deep": True,
                         "timeout": 5, "concurrency": 1})
        self.assertIn("--fast", cmd)
        self.assertNotIn("--deep", cmd)

    def test_deep_flag_without_fast(self):
        cmd = self._cmd({"mode": "recon", "fast": False, "deep": True,
                         "timeout": 5, "concurrency": 1, "budget": 3, "delay": 0,
                         "probe_sizes": "1,2"})
        self.assertNotIn("--fast", cmd)
        self.assertIn("--deep", cmd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
