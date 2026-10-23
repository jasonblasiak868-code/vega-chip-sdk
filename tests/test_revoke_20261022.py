"""Regression tests (2026-10-22): a Run captured the locked step list when it began, so after revoke() (a human-only act) a run that was already open kept executing the rest
of its locked steps. Revoking (or re-locking) a workflow now stops runs opened before it."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import redteam_1_chip as T  # noqa: E402
from vega_chip import pre_unit as P  # noqa: E402


class RevokeStopsOpenRuns(unittest.TestCase):
    setUp, sha, lock = T.PREUnit.setUp, T.PREUnit.sha, T.PREUnit.lock

    def revoke(self, name="daily-report"):
        self.pre.revoke(name, self.r.human.sign("revoke_authority", {"workflow": name}))

    def test_an_open_run_stops_when_its_workflow_is_revoked(self):
        self.lock()
        run = self.pre.begin("daily-report")
        run.step("fetch", self.code[0], self.inputs[0], lambda m: self.out[0])
        self.revoke()
        ran = []
        with self.assertRaises(P.Trap) as cm:
            run.step("summarise", self.code[1], self.inputs[1], lambda m: ran.append(1) or self.out[1])
        self.assertEqual((cm.exception.reason, ran), ("revoked", []))

    def test_a_relock_does_not_revive_a_run_opened_before_the_revoke(self):
        self.lock()
        run = self.pre.begin("daily-report")
        self.revoke()
        self.lock()
        with self.assertRaises(P.Trap) as cm:
            run.step("fetch", self.code[0], self.inputs[0], lambda m: self.out[0])
        self.assertEqual(cm.exception.reason, "revoked")
        fresh = self.pre.begin("daily-report")                                  # a run opened after the relock works
        self.assertEqual(fresh.step("fetch", self.code[0], self.inputs[0], lambda m: self.out[0]), self.out[0])


if __name__ == "__main__":
    unittest.main()
