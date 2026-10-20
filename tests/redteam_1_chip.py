"""Tests and attacks for the governance-hardware reference model: non-volatile memory and power cuts, the GEU's order of checks, the gate, hard stop, the side door, the PRE unit, and conformance with the jacket."""
import hashlib
import json
import pathlib
import tempfile
import unittest

from vega_chip import conformance as CF, geu as G, nv as NV, pre_unit as P

NOW = CF.NOW


class Rig:
    def __init__(self, ports=("net", "disk"), trip=True):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self.human = CF.Signer()
        self.clock = G.MonotonicClock(NOW)
        self.nv = NV.NVStore(self.d / "a.nv", self.d / "b.nv")
        self.geu = G.GEU(self.nv, self.clock, ports=ports, device=CF.DEVICE, surface=CF.SURFACE, trip_on_side_door=trip)
        self.geu.program_keys([self.human.public])

    def reopen(self, clock=None, ports=("net", "disk")):
        store = NV.NVStore(self.d / "a.nv", self.d / "b.nv")
        return G.GEU(store, clock or self.clock, ports=ports, device=CF.DEVICE, surface=CF.SURFACE)

    def go(self, action="send_report", params=None, port="net", **kw):
        params = params or {"n": 1}
        return self.geu.request(action, params, self.human.sign(action, params, **kw), port)

    def reasons(self):
        return [r["data"].get("reason") for r in self.geu.chain() if r["data"].get("op") == "decision" and r["data"]["result"] == "DENIED"]


class NonVolatile(unittest.TestCase):
    def test_records_are_chained_and_read_back_from_both_regions(self):
        d = pathlib.Path(tempfile.mkdtemp())
        s = NV.NVStore(d / "a", d / "b")
        r1, r2 = s.append({"x": 1}), s.append({"x": 2})
        self.assertEqual((r2["prev"], r2["i"], s.head), (r1["sha256"], 1, r2["sha256"]))
        self.assertEqual(NV.NVStore(d / "a", d / "b").records, s.records)
        self.assertEqual((d / "a").read_bytes(), (d / "b").read_bytes())

    def test_a_region_that_silently_drops_or_alters_a_write_is_caught_by_the_read_back(self):
        for stuck in (lambda line: b"", lambda line: line.replace(b"1", b"7", 1)):
            d = pathlib.Path(tempfile.mkdtemp())
            s = NV.NVStore(d / "a", d / "b")
            s.b.stuck = stuck
            with self.assertRaises(NV.NVFault):
                s.append({"x": 1})
            self.assertEqual(s.records, [])                                               # nothing was relied on

    def test_a_power_cut_mid_write_is_discarded_and_leaves_the_unit_failed_until_restart(self):
        d = pathlib.Path(tempfile.mkdtemp())
        s = NV.NVStore(d / "a", d / "b")
        s.append({"x": 1})
        s.a.cut_after = 10
        with self.assertRaises(NV.PowerCut):
            s.append({"x": 2})
        s2 = NV.NVStore(d / "a", d / "b")                                         # restart: the torn tail is dropped, nothing was ever relied on
        self.assertEqual([r["data"] for r in s2.records], [{"x": 1}])
        self.assertEqual((d / "a").read_bytes(), (d / "b").read_bytes())

    def test_a_cut_after_one_region_finished_is_repaired_from_it(self):
        d = pathlib.Path(tempfile.mkdtemp())
        s = NV.NVStore(d / "a", d / "b")
        s.append({"x": 1})
        s.b.cut_after = 5                                                         # region A got the whole record, region B only a few bytes
        with self.assertRaises(NV.PowerCut):
            s.append({"x": 2})
        s2 = NV.NVStore(d / "a", d / "b")
        self.assertEqual([r["data"] for r in s2.records], [{"x": 1}, {"x": 2}])
        self.assertEqual((d / "a").read_bytes(), (d / "b").read_bytes())

    def test_damage_anywhere_but_the_tail_and_split_histories_are_faults_not_guesses(self):
        d = pathlib.Path(tempfile.mkdtemp())
        s = NV.NVStore(d / "a", d / "b")
        for i in range(4):
            s.append({"x": i})
        lines = (d / "a").read_bytes().split(b"\n")
        (d / "a").write_bytes(b"\n".join(lines[:1] + [lines[1].replace(b'"x":1', b'"x":9')] + lines[2:]))
        with self.assertRaises(NV.NVFault):
            NV.NVStore(d / "a", d / "b")
        d2 = pathlib.Path(tempfile.mkdtemp())
        s2 = NV.NVStore(d2 / "a", d2 / "b")
        s2.append({"x": 1})
        other = NV.NVStore(d2 / "c", d2 / "d")
        other.append({"x": 2})
        (d2 / "b").write_bytes((d2 / "d").read_bytes())                              # two valid but different histories
        with self.assertRaises(NV.NVFault):
            NV.NVStore(d2 / "a", d2 / "b")
        d3 = pathlib.Path(tempfile.mkdtemp())
        s3 = NV.NVStore(d3 / "a", d3 / "b")
        for i in range(3):
            s3.append({"x": i})
        (d3 / "b").write_bytes(b"\n".join((d3 / "b").read_bytes().split(b"\n")[:1]) + b"\n")   # one region two records behind
        with self.assertRaises(NV.NVFault):
            NV.NVStore(d3 / "a", d3 / "b")

    def test_a_stuck_bit_is_caught_by_the_read_back(self):
        d = pathlib.Path(tempfile.mkdtemp())
        s = NV.NVStore(d / "a", d / "b")
        s.append({"x": 1})
        s.b.stuck = lambda line: line.replace(b'"x":2', b'"x":3')
        with self.assertRaises(NV.NVFault):
            s.append({"x": 2})


class Unit(unittest.TestCase):
    def test_keys_are_written_once(self):
        r = Rig()
        with self.assertRaises(G.Denied) as cm:
            r.geu.program_keys([CF.Signer().public])
        self.assertEqual(cm.exception.reason, "keys_blown")
        fresh = Rig()
        for n, bad in enumerate(([], [b"short"], [bytes(32)] * 2, "x", None, [CF.Signer().public] * 5)):
            u = G.GEU(NV.NVStore(fresh.d / ("x%d" % n), fresh.d / ("y%d" % n)), G.MonotonicClock(NOW))
            with self.assertRaises(G.Denied):
                u.program_keys(bad)
        self.assertEqual([k.hex() for k in Rig().geu.keys].__len__(), 1)
        u = G.GEU(NV.NVStore(fresh.d / "k1", fresh.d / "k2"), G.MonotonicClock(NOW))
        with self.assertRaises(G.Denied) as cm:
            u.request("send_report", {}, {}, "net")
        self.assertEqual(cm.exception.reason, "no_keys")

    def test_the_gate_is_closed_by_default_and_opens_for_one_transaction_on_the_granted_port(self):
        r = Rig()
        with self.assertRaises(G.Denied):
            r.geu.transact(None, b"x")
        grant = r.go()
        self.assertEqual(r.geu.transact(grant, b"hello"), 5)
        self.assertEqual(r.geu.port_log("net"), [b"hello"])
        with self.assertRaises(G.Denied) as cm:
            r.geu.transact(grant, b"again")                                            # one transaction, then closed
        self.assertEqual(cm.exception.reason, "gate_closed")
        g2 = r.go(params={"n": 2})
        other = G.Grant("net", g2.action_hash, g2.expiry)                              # a forged grant object is not the one the unit opened
        with self.assertRaises(G.Denied):
            r.geu.transact(other, b"x")
        with self.assertRaises(G.Denied):
            r.geu.transact(g2, "text")
        self.assertEqual(r.geu.port_log("disk"), [])

    def test_a_commitment_that_expires_exactly_now_is_refused_at_the_request_not_later(self):
        r = Rig()
        with self.assertRaises(G.Denied) as cm:
            r.go(expiry=NOW)
        self.assertEqual(cm.exception.reason, "expired")
        self.assertEqual(len(r.geu.burned), 0)

    def test_the_grant_dies_with_its_lease_and_a_second_grant_replaces_the_first_on_that_port(self):
        r = Rig()
        g = r.go()
        r.clock.advance(400)
        with self.assertRaises(G.Denied) as cm:
            r.geu.transact(g, b"x")
        self.assertEqual(cm.exception.reason, "expired")
        g1, g2 = r.go(params={"n": 5}, expiry=NOW + 700), r.go(params={"n": 6}, expiry=NOW + 700)
        with self.assertRaises(G.Denied):
            r.geu.transact(g1, b"x")
        r.geu.transact(g2, b"ok")

    def test_every_refusal_has_its_own_reason_and_is_written_to_the_chain(self):
        r = Rig()
        h = r.human
        p = {"n": 1}
        cases = [("wildcard", lambda: r.geu.request("*", p, h.sign("*", p), "net")),
                 ("odd_spelling", lambda: r.geu.request("Release-Public", p, h.sign("Release-Public", p), "net")),
                 ("bad_fields", lambda: r.geu.request("send_report", p, {"nonce": "n", "signature": "00"}, "net")),
                 ("expired", lambda: r.geu.request("send_report", p, h.sign("send_report", p, expiry=NOW - 1), "net")),
                 ("lease_too_long", lambda: r.geu.request("send_report", p, h.sign("send_report", p, expiry=NOW + 901), "net")),
                 ("bad_signature", lambda: r.geu.request("send_report", {"n": 2}, h.sign("send_report", p), "net")),
                 ("no_port", lambda: r.geu.request("send_report", p, h.sign("send_report", p), "usb")),
                 ("bad_params", lambda: r.geu.request("send_report", {"n": float("nan")}, h.sign("send_report", p), "net"))]
        for reason, fn in cases:
            with self.assertRaises(G.Denied, msg=reason) as cm:
                fn()
            self.assertEqual(cm.exception.reason, reason)
        good = h.sign("send_report", p)
        r.geu.request("send_report", p, good, "net")
        with self.assertRaises(G.Denied) as cm:
            r.geu.request("send_report", p, good, "net")
        self.assertEqual(cm.exception.reason, "replay")
        self.assertEqual(sorted(set(r.reasons())), sorted({c[0] for c in cases} | {"replay"}) if "no_port" in r.reasons() else sorted({c[0] for c in cases if c[0] != "no_port"} | {"replay"}))
        self.assertEqual(sum(1 for x in r.geu.chain() if x["data"].get("result") == "GRANTED"), 1)

    def test_the_burn_comes_before_the_gate_and_a_refused_request_burns_nothing(self):
        r = Rig()
        p = {"n": 1}
        s = r.human.sign("send_report", p)
        ops = [x["data"]["op"] for x in r.geu.chain()]
        r.geu.request("send_report", p, s, "net")
        new = [x["data"]["op"] for x in r.geu.chain()][len(ops):]
        self.assertEqual(new, ["burn", "decision"])
        before = len(r.geu.chain())
        with self.assertRaises(G.Denied):
            r.geu.request("send_report", {"n": 9}, r.human.sign("send_report", p), "net")
        self.assertEqual([x["data"]["op"] for x in r.geu.chain()][before:], ["decision"])              # the denial is recorded; no burn
        self.assertEqual(len(r.geu.burned), 1)

    def test_a_memory_fault_closes_everything_and_it_stays_closed(self):
        r = Rig()
        r.nv.b.stuck = lambda line: line.replace(b"burn", b"b0rn")
        with self.assertRaises(G.Denied) as cm:
            r.go()
        self.assertEqual(cm.exception.reason, "faulted")
        self.assertTrue(r.geu.faulted)
        r.nv.b.stuck = None
        with self.assertRaises(G.Denied) as cm:
            r.go(params={"n": 99})
        self.assertEqual(cm.exception.reason, "faulted")
        with self.assertRaises(G.Denied):
            r.geu.transact(G.Grant("net", "x", NOW + 100), b"x")
        self.assertEqual(r.geu.port_log("net"), [])

    def test_a_power_cut_before_the_burn_finished_leaves_the_approval_unused_and_after_it_leaves_it_spent(self):
        r = Rig()
        p = {"n": 1}
        s1 = r.human.sign("send_report", p)
        r.nv.a.cut_after = 7                                                          # cut while region A is being written
        with self.assertRaises(G.Denied):
            r.geu.request("send_report", p, s1, "net")
        self.assertTrue(r.geu.faulted)
        u = r.reopen()
        g = u.request("send_report", p, s1, "net")                                    # no gate ever opened, so using it now is the FIRST use
        u.transact(g, b"once")
        r2 = Rig()
        s2 = r2.human.sign("send_report", p)
        r2.nv.b.cut_after = 7                                                         # region A finished, region B cut
        with self.assertRaises(G.Denied):
            r2.geu.request("send_report", p, s2, "net")
        u2 = r2.reopen()
        with self.assertRaises(G.Denied) as cm:
            u2.request("send_report", p, s2, "net")                                   # repaired: the burn stands, the approval is spent
        self.assertEqual(cm.exception.reason, "replay")

    def test_a_clock_that_reads_earlier_than_the_record_makes_the_unit_refuse(self):
        r = Rig()
        r.go()
        r.clock.advance(100)
        r.go(params={"n": 2}, expiry=NOW + 300)
        u = r.reopen(clock=G.MonotonicClock(NOW))                                       # the counter was set back
        self.assertTrue(u.faulted)
        with self.assertRaises(G.Denied):
            u.request("send_report", {"n": 3}, r.human.sign("send_report", {"n": 3}), "net")
        self.assertFalse(r.reopen(clock=G.MonotonicClock(NOW + 100)).faulted)
        for bad in (-1, True, "5", 1.5):
            with self.assertRaises(ValueError):
                G.MonotonicClock(bad)
        with self.assertRaises(ValueError):
            r.clock.advance(-1)

    def test_state_survives_a_restart(self):
        r = Rig()
        p = {"n": 1}
        s = r.human.sign("send_report", p)
        r.geu.request("send_report", p, s, "net")
        u = r.reopen()
        self.assertEqual((len(u.keys), len(u.burned)), (1, 1))
        with self.assertRaises(G.Denied):
            u.request("send_report", p, s, "net")


class HardStopAndSideDoor(unittest.TestCase):
    def test_a_stopped_unit_refuses_to_transact_even_if_a_live_grant_somehow_survives(self):
        r = Rig()
        grant = r.go()
        r.geu.hard_stop()
        r.geu._open[grant.port] = grant                                                   # simulate a race that left the grant open
        with self.assertRaises(G.Denied) as cm:
            r.geu.transact(grant, b"x")
        self.assertEqual(cm.exception.reason, "hard_stop")
        self.assertEqual(r.geu.port_log("net"), [])

    def test_a_hard_stop_by_anyone_and_a_restore_only_by_the_human(self):
        r = Rig()
        r.geu.hard_stop()
        with self.assertRaises(G.Denied) as cm:
            r.go()
        self.assertEqual(cm.exception.reason, "hard_stop")
        with self.assertRaises(G.Denied):
            r.geu.restore(r.human.sign("send_report", {}))                              # a signature for another action
        with self.assertRaises(G.Denied):
            r.geu.restore(CF.Signer().sign("restore_after_hard_stop", {}))              # another key
        with self.assertRaises(G.Denied):
            r.geu.restore(r.human.sign("restore_after_hard_stop", {}, expiry=NOW - 1))
        sig = r.human.sign("restore_after_hard_stop", {})
        r.geu.restore(sig)
        r.go(params={"n": 77})
        with self.assertRaises(G.Denied):
            r.geu.restore(r.human.sign("restore_after_hard_stop", {}))                  # not stopped
        r.geu.hard_stop()
        with self.assertRaises(G.Denied) as cm:
            r.geu.restore(sig)                                                          # a spent restore cannot be reused
        self.assertEqual(cm.exception.reason, "replay")
        self.assertTrue(r.reopen().hard_stopped)                                          # the stop survives a power cycle

    def test_a_grant_issued_before_a_hard_stop_cannot_be_used_after_it(self):
        r = Rig()
        g = r.go()
        r.geu.hard_stop()
        with self.assertRaises(G.Denied):
            r.geu.transact(g, b"x")

    def test_dma_reaches_a_port_only_through_the_table_the_human_signed(self):
        r = Rig()
        g = r.go()
        with self.assertRaises(G.Denied) as cm:
            r.geu.egress("nic", "net", b"x", g)
        self.assertEqual(cm.exception.reason, "dma_not_allowed")
        table = {"nic": ["net"]}
        with self.assertRaises(G.Denied):
            r.geu.program_dma(table, r.human.sign("change_gate_config", {"dma_table": {"nic": ["disk"]}}))     # signed for another table
        with self.assertRaises(G.Denied):
            r.geu.program_dma({"nic": ["warp"]}, r.human.sign("change_gate_config", {"dma_table": {"nic": ["warp"]}}))
        r.geu.program_dma(table, r.human.sign("change_gate_config", {"dma_table": {"nic": ["net"]}}))
        r.geu.egress("nic", "net", b"through the table", g)
        self.assertEqual(r.geu.port_log("net"), [b"through the table"])
        g2 = r.go(params={"n": 2}, port="disk")
        with self.assertRaises(G.Denied):
            r.geu.egress("nic", "disk", b"x", g2)                                        # that initiator was not given the disk
        self.assertEqual(r.reopen().dma, {"nic": {"net"}})

    def test_a_write_that_skips_the_unit_is_refused_recorded_and_trips_the_stop(self):
        r = Rig()
        with self.assertRaises(G.Denied):
            r.geu.raw_port_write("net", b"sneak")
        self.assertEqual(r.geu.port_log("net"), [])
        self.assertTrue(r.geu.hard_stopped)
        self.assertIn("side_door", r.reasons())
        q = Rig(trip=False)
        with self.assertRaises(G.Denied):
            q.geu.raw_port_write("net", b"sneak")
        self.assertFalse(q.geu.hard_stopped)
        with self.assertRaises(G.Denied):
            q.geu.raw_port_write("nowhere", b"x")
        with self.assertRaises(G.Denied):
            q.geu._ports["net"].write(object(), b"direct")                                 # the port wants the unit's own gate token
        self.assertEqual(q.geu.port_names(), ["disk", "net"])


class PREUnit(unittest.TestCase):
    def setUp(self):
        self.r = Rig()
        self.pre = P.PREUnit(self.r.geu)
        self.code = [b"def step0(): pass", b"def step1(): pass"]
        self.inputs = [b"input-0", b"input-1"]
        self.out = [b"result-0", b"result-1"]
        self.steps = [{"id": "fetch", "code_sha256": hashlib.sha256(self.code[0]).hexdigest(), "inputs_sha256": hashlib.sha256(self.inputs[0]).hexdigest(), "budget": {"tokens": 100, "bytes": 1000}},
                      {"id": "summarise", "code_sha256": hashlib.sha256(self.code[1]).hexdigest(), "inputs_sha256": hashlib.sha256(self.inputs[1]).hexdigest(),
                       "output_sha256": hashlib.sha256(self.out[1]).hexdigest(), "budget": {"tokens": 50}}]

    def sha(self):
        return hashlib.sha256(json.dumps(self.steps, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def lock(self, name="daily-report"):
        self.pre.lock(name, self.steps, self.r.human.sign("lock_pre", {"workflow": name, "steps_sha256": self.sha()}))

    def test_locking_needs_a_human_commitment_for_exactly_this_workflow_and_steps(self):
        with self.assertRaises(G.Denied):
            self.pre.lock("daily-report", self.steps, self.r.human.sign("lock_pre", {"workflow": "other", "steps_sha256": self.sha()}))
        with self.assertRaises(G.Denied):
            self.pre.lock("daily-report", self.steps, self.r.human.sign("lock_pre", {"workflow": "daily-report", "steps_sha256": "0" * 64}))
        self.assertEqual(self.pre.locked, {})
        self.lock()
        with self.assertRaises(G.Denied) as cm:
            self.lock()
        self.assertEqual(cm.exception.reason, "already_locked")
        for bad in ([], "x", [{}], [dict(self.steps[0], id="Bad Id")], [dict(self.steps[0], code_sha256="zz")], [self.steps[0], self.steps[0]], [dict(self.steps[0], budget={"fuel": 1})],
                    [dict(self.steps[0], budget={"tokens": -1})], [dict(self.steps[0], output_sha256="no")]):
            sha = hashlib.sha256(json.dumps(bad, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            with self.assertRaises(G.Denied) as cm:                                    # the human DID sign this list: only the unit's own validation can refuse it
                self.pre.lock("another", bad, self.r.human.sign("lock_pre", {"workflow": "another", "steps_sha256": sha}))
            self.assertEqual(cm.exception.reason, "bad_steps")
        with self.assertRaises(G.Denied):
            self.pre.lock("Bad Name", self.steps, {})

    def test_a_locked_workflow_runs_in_order_and_each_result_hash_is_on_the_chain_first(self):
        self.lock()
        run = self.pre.begin("daily-report")
        before = len(self.r.geu.chain())
        res0 = run.step("fetch", self.code[0], self.inputs[0], lambda m: (m.charge(tokens=10, nbytes=20), self.out[0])[1])
        self.assertEqual(res0, self.out[0])
        rec = self.r.geu.chain()[before]["data"]
        self.assertEqual((rec["op"], rec["step"], rec["result_sha256"]), ("pre_result", "fetch", hashlib.sha256(self.out[0]).hexdigest()))
        res1 = run.step("summarise", self.code[1], self.inputs[1], lambda m: self.out[1])
        self.assertEqual(res1, self.out[1])
        self.assertTrue(run.complete())
        with self.assertRaises(P.Trap) as cm:
            run.step("fetch", self.code[0], self.inputs[0], lambda m: b"x")
        self.assertEqual(cm.exception.reason, "workflow_already_complete")

    def test_every_deviation_traps_before_anything_runs(self):
        self.lock()
        ran = []

        def spy(m):
            ran.append(1)
            return b"x"
        cases = [("out_of_order", "summarise", self.code[1], self.inputs[1]), ("code_mismatch", "fetch", b"def step0(): evil()", self.inputs[0]), ("inputs_mismatch", "fetch", self.code[0], b"other input")]
        for reason, sid, code, inp in cases:
            run = self.pre.begin("daily-report")
            with self.assertRaises(P.Trap) as cm:
                run.step(sid, code, inp, spy)
            self.assertEqual(cm.exception.reason, reason)
        self.assertEqual(ran, [])
        refusals = [x["data"]["reason"] for x in self.r.geu.chain() if x["data"].get("op") == "pre_refused"]
        self.assertEqual(refusals, ["out_of_order", "code_mismatch", "inputs_mismatch"])
        run = self.pre.begin("daily-report")
        for bad in ((self.code[0], "text", spy), ("text", self.inputs[0], spy), (self.code[0], self.inputs[0], None)):
            with self.assertRaises(P.Trap):
                run.step("fetch", *bad)

    def test_budgets_crashes_wrong_outputs_and_non_bytes_all_trap_and_release_nothing(self):
        self.lock()
        run = self.pre.begin("daily-report")
        with self.assertRaises(P.Trap) as cm:
            run.step("fetch", self.code[0], self.inputs[0], lambda m: (m.charge(tokens=101), b"x")[1])
        self.assertEqual(cm.exception.reason, "budget_exceeded:tokens")
        run = self.pre.begin("daily-report")
        with self.assertRaises(P.Trap):
            run.step("fetch", self.code[0], self.inputs[0], lambda m: (m.charge(nbytes=500), m.charge(nbytes=501), b"x")[2])
        run = self.pre.begin("daily-report")
        with self.assertRaises(P.Trap) as cm:
            run.step("fetch", self.code[0], self.inputs[0], lambda m: 1 / 0)
        self.assertTrue(cm.exception.reason.startswith("step_crashed"))
        run = self.pre.begin("daily-report")
        with self.assertRaises(P.Trap) as cm:
            run.step("fetch", self.code[0], self.inputs[0], lambda m: "not bytes")
        self.assertEqual(cm.exception.reason, "result_not_bytes")
        run = self.pre.begin("daily-report")
        run.step("fetch", self.code[0], self.inputs[0], lambda m: b"x")
        with self.assertRaises(P.Trap) as cm:
            run.step("summarise", self.code[1], self.inputs[1], lambda m: b"a different output")
        self.assertEqual(cm.exception.reason, "output_mismatch")
        self.assertFalse(run.complete())
        with self.assertRaises(P.Trap):
            P.Meter({}, self.pre, run, "x").charge(tokens=-1)
        with self.assertRaises(P.Trap):
            P.Meter({}, self.pre, run, "x").charge(tokens=True)
        self.assertFalse(any(x["data"].get("result_sha256") == hashlib.sha256(b"a different output").hexdigest() for x in self.r.geu.chain()))

    def test_an_unlocked_workflow_runs_only_in_quarantine_and_the_gate_refuses_its_output(self):
        run = self.pre.begin("never-locked")
        self.assertTrue(run.quarantined)
        out = run.step("anything", b"any code", b"any input", lambda m: b"payload")
        self.assertIsInstance(out, P.Quarantined)
        g = self.r.go()
        with self.assertRaises(G.Denied) as cm:
            self.r.geu.transact(g, out)
        self.assertEqual(cm.exception.reason, "bad_payload")
        self.assertFalse(run.complete())
        self.assertTrue(any(x["data"].get("quarantined") for x in self.r.geu.chain() if x["data"].get("op") == "pre_result"))

    def test_an_accelerators_output_is_tainted_unless_a_locked_hash_vouches_for_it(self):
        self.lock()
        run = self.pre.begin("daily-report")
        t = run.step("fetch", self.code[0], self.inputs[0], lambda m: self.out[0], accelerator=True)              # no locked output hash for this step
        self.assertIsInstance(t, P.Tainted)
        g = self.r.go()
        with self.assertRaises(G.Denied):
            self.r.geu.transact(g, t)
        ok = run.step("summarise", self.code[1], self.inputs[1], lambda m: self.out[1], accelerator=True)           # the locked output hash matches
        self.assertEqual(ok, self.out[1])

    def test_revocation_needs_its_own_commitment_and_locks_survive_a_restart(self):
        self.lock()
        again = P.PREUnit(self.r.reopen())
        self.assertIn("daily-report", again.locked)
        with self.assertRaises(G.Denied):
            self.pre.revoke("nothing", self.r.human.sign("revoke_authority", {"workflow": "nothing"}))
        with self.assertRaises(G.Denied):
            self.pre.revoke("daily-report", self.r.human.sign("revoke_authority", {"workflow": "other"}))
        self.pre.revoke("daily-report", self.r.human.sign("revoke_authority", {"workflow": "daily-report"}))
        self.assertNotIn("daily-report", P.PREUnit(self.r.reopen()).locked)
        self.assertTrue(self.pre.begin("daily-report").quarantined)

    def test_nothing_runs_while_the_unit_is_stopped_or_faulted(self):
        self.lock()
        run = self.pre.begin("daily-report")
        self.r.geu.hard_stop()
        with self.assertRaises(P.Trap):
            run.step("fetch", self.code[0], self.inputs[0], lambda m: b"x")
        with self.assertRaises(P.Trap):
            self.pre.begin("daily-report")


class Conformance(unittest.TestCase):
    def test_the_hardware_model_and_the_software_jacket_decide_alike_on_every_vector(self):
        res = CF.run_conformance()
        self.assertEqual(res["mismatches"], [])
        self.assertGreaterEqual(res["vectors"], 20)
        self.assertGreaterEqual(res["attempts"], 28)

    def test_the_suite_notices_a_hardware_model_that_is_looser_than_the_software(self):
        real = G.GEU._check

        def loose(self, action, params, signed, port=""):
            self.burned.clear()                                                         # forget burned nonces: replay protection removed
            return real(self, action, params, signed, port)
        G.GEU._check = loose
        try:
            res = CF.run_conformance()
        finally:
            G.GEU._check = real
        self.assertTrue(any(m[0] == "replay of a spent commitment" for m in res["mismatches"]))

    def test_the_suite_notices_a_hardware_model_that_is_stricter_than_the_software(self):
        real = G.GEU.request

        def strict(self, action, params, signed, port):
            if action == "release_public":
                raise G.Denied("too_strict")
            return real(self, action, params, signed, port)
        G.GEU.request = strict
        try:
            res = CF.run_conformance()
        finally:
            G.GEU.request = real
        self.assertTrue(any(m[0] == "a human-only action signed correctly" for m in res["mismatches"]))


if __name__ == "__main__":
    unittest.main()
