#!/usr/bin/env python3
"""回归：oneclick 在 scan 判定“不该继续”时必须早退，不能撞 900s 超时。"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "attack"))

import p2s_ext as P  # noqa: E402


class OneclickStopTest(unittest.TestCase):
    def test_not_affected_or_patched_stops(self):
        self.assertEqual(P.oneclick_stop_exit(30, "NOT_AFFECTED_OR_PATCHED"), 30)

    def test_no_session_sink_stops(self):
        self.assertEqual(P.oneclick_stop_exit(40, "NO_SESSION_SINK"), 40)

    def test_dos_only_stops(self):
        self.assertEqual(P.oneclick_stop_exit(20, "AFFECTED_DOS_ONLY"), 20)

    def test_unreachable_stops(self):
        self.assertEqual(P.oneclick_stop_exit(50, "UNREACHABLE"), 50)

    def test_rc_wins_even_with_unknown_verdict(self):
        self.assertEqual(P.oneclick_stop_exit(30, "WHATEVER"), 30)

    def test_likely_continues(self):
        self.assertIsNone(P.oneclick_stop_exit(10, "LIKELY_RCE"))

    def test_premises_continues_to_force_gate(self):
        self.assertIsNone(P.oneclick_stop_exit(15, "PREMISES_ONLY_UNVERIFIED"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
