"""Regression tests (2026-10-20): the gate unit is modelled as one sequential device, but as a library it can be called from threads. One grant must carry one transaction,
and one signed approval must open one gate, however the calls interleave."""
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redteam_1_chip import Rig  # noqa: E402
from vega_chip import geu as G  # noqa: E402


def race(n, fn):
    gate, out, lock = threading.Barrier(n), [], threading.Lock()

    def go(i):
        gate.wait()
        try:
            fn(i)
            r = "ok"
        except G.Denied:
            r = "denied"
        with lock:
            out.append(r)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    return sorted(out)


class OneGrantOneTransaction(unittest.TestCase):
    def test_one_grant_carries_one_write_under_concurrency(self):
        import time
        for _ in range(10):
            r = Rig()
            g = r.go(params={"n": 1})
            real = r.geu.clock.read
            r.geu.clock.read = lambda: (time.sleep(0.02), real())[1]          # a slow clock read widens the window between 'is the grant unused?' and 'mark it used'
            self.assertEqual(race(4, lambda i: r.geu.transact(g, b"x%d" % i)), ["denied", "denied", "denied", "ok"])
            self.assertEqual(len(r.geu.port_log("net")), 1)

    def test_one_approval_opens_one_gate_under_concurrency(self):
        for _ in range(30):
            r = Rig(ports=("net", "disk"))
            signed = r.human.sign("send_report", {"n": 1})
            self.assertEqual(race(2, lambda i: r.geu.request("send_report", {"n": 1}, signed, ("net", "disk")[i])), ["denied", "ok"])
            burns = [x for x in r.geu.chain() if x["data"].get("op") == "burn"]
            self.assertEqual(len(burns), 1)


if __name__ == "__main__":
    unittest.main()
