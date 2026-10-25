#!/usr/bin/env python3
"""成功判据的回归测试：proof 必须是本次新写入且内容匹配，回读必须排除软 404。"""
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "attack"))
sys.path.insert(0, os.path.join(ROOT, "poc_eness"))

import php2shell_rce as R  # noqa: E402
import p2s_ext as E        # noqa: E402


class ProofWatchTest(unittest.TestCase):
    def test_stale_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "p1")
            with open(p, "wb") as f:
                f.write(b"uid=0(root) gid=0(root)\n")
            w = R.ProofWatch(p, r"uid=\d+")
            self.assertIsNone(w.hit())

    def test_new_file_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "p1")
            w = R.ProofWatch(p, r"uid=\d+")
            time.sleep(0.01)
            with open(p, "wb") as f:
                f.write(b"uid=33(www-data) gid=33(www-data)\n")
            self.assertIsNotNone(w.hit())

    def test_new_file_wrong_content_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "p1")
            w = R.ProofWatch(p, r"uid=\d+")
            with open(p, "wb") as f:
                f.write(b"<html>not executed</html>\n")
            self.assertIsNone(w.hit())

    def test_empty_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "p1")
            w = R.ProofWatch(p, r"uid=\d+")
            open(p, "wb").close()
            self.assertIsNone(w.hit())

    def test_no_path_never_succeeds(self):
        self.assertIsNone(R.ProofWatch(None, r"uid=\d+").hit())


class HitsTest(unittest.TestCase):
    def test_soft404_rejected(self):
        base = b"<html><body>welcome to our site</body></html>"
        self.assertFalse(E.hits(200, base, baseline=base))

    def test_marker_required(self):
        base = b"<html>welcome</html>"
        self.assertFalse(E.hits(200, base, baseline=base, expect=rb"uid=\d+"))
        self.assertTrue(E.hits(200, b"uid=33(www-data) gid=33", expect=rb"uid=\d+"))

    def test_empty_and_404_rejected(self):
        self.assertFalse(E.hits(200, b""))
        self.assertFalse(E.hits(404, b"uid=33(www-data)", expect=rb"uid=\d+"))
        self.assertFalse(E.hits(200, b"Not Found"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
