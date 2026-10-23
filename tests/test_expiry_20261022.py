"""Regression tests (2026-10-22): the expiry check used str.isdigit() and then int(). Digits such as superscript two pass isdigit() but int() raises ValueError, which escaped
as a crash instead of a recorded refusal."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redteam_1_chip import Rig  # noqa: E402
from vega_chip import geu as G  # noqa: E402


class ExpiryText(unittest.TestCase):
    def test_non_ascii_digits_are_a_refusal_not_a_crash(self):
        for bad in ("²", "٣٤", "１２", "12²", "", " 5", "1.5", "-3"):
            r = Rig()
            p = {"n": 1}
            with self.assertRaises(G.Denied, msg=repr(bad)) as cm:
                r.geu.request("send_report", p, {"nonce": "n", "signature": "00", "expiry": bad}, "net")
            self.assertEqual(cm.exception.reason, "bad_fields", repr(bad))


if __name__ == "__main__":
    unittest.main()
