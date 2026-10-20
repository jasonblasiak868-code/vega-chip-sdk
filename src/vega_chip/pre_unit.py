"""pre_unit.py - the PRE RUNTIME UNIT: 'secure boot for workflows', as a software reference model.

A PRE is a pre-registered executable path: a workflow whose steps were declared in advance (each step's code identity, declared inputs, optional expected output and a budget) and locked.
  lock(workflow, steps, signed)     entered in the registry only with a human commitment for exactly this workflow and step list; locking the same name again is refused (no silent replacement)
  revoke(workflow, signed)          needs its own commitment ('revoke_authority', human-only)
  begin(workflow) -> Run            a LOCKED workflow runs step by step in order: before each step the unit hashes the step's code and inputs and compares them with the locked list (a mismatch TRAPS: nothing
                                    runs, a refusal is recorded), meters the budget (tokens, bytes, seconds; exceeding it traps), and appends the result's hash to the chain BEFORE the result is released.
                                    An UNLOCKED workflow still runs, but only in QUARANTINE: its results come back wrapped, and the output gate refuses anything that is not plain released bytes.
  accelerator=True                  the step runs on an untrusted accelerator (a photonic or other matrix engine): its result is TAINTED unless the step's locked output hash matches; the gate refuses tainted results.
HONEST LIMITS: in this model the meter is driven by what the harness reports (charge()), where the silicon would count real cycles and bytes; the 'code identity' is the hash of the bytes handed to the unit,
which a real unit would take from a measured boot. The model fixes the RULES and the ORDER; it is not a circuit."""
import hashlib
import json
import re

from vega_chip.geu import GEU, Denied


class Trap(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class Quarantined:
    def __init__(self, value):
        self.value = value


class Tainted:
    def __init__(self, value, producer="accelerator"):
        self.value, self.producer = value, producer


HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,59}$")


def _sha(b: bytes) -> str:
    return hashlib.sha256(bytes(b)).hexdigest()


class Meter:
    def __init__(self, budget, unit, run, step):
        self.budget, self.used, self._unit, self._run, self._step = budget, {"tokens": 0, "bytes": 0, "seconds": 0}, unit, run, step

    def charge(self, tokens: int = 0, nbytes: int = 0, seconds: int = 0):
        for name, v in (("tokens", tokens), ("bytes", nbytes), ("seconds", seconds)):
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise Trap("bad_charge")
            self.used[name] += v
            cap = self.budget.get(name)
            if cap is not None and self.used[name] > cap:
                self._unit._refuse(self._run, self._step, "budget_exceeded:" + name)
                raise Trap("budget_exceeded:" + name)


class PREUnit:
    def __init__(self, geu: GEU):
        self.geu = geu
        self.locked = {}
        for rec in geu.nv.records:
            d = rec["data"]
            if d.get("op") == "pre_lock":
                self.locked[d["workflow"]] = d["steps"]
            elif d.get("op") == "pre_revoke":
                self.locked.pop(d["workflow"], None)

    @staticmethod
    def _check_steps(steps):
        if not isinstance(steps, list) or not 1 <= len(steps) <= 200:
            raise Denied("bad_steps")
        seen = set()
        for s in steps:
            if not isinstance(s, dict) or not isinstance(s.get("id"), str) or not NAME.fullmatch(s["id"]) or s["id"] in seen or not isinstance(s.get("code_sha256"), str) or not HEX64.fullmatch(s["code_sha256"]) \
                    or not isinstance(s.get("inputs_sha256"), str) or not HEX64.fullmatch(s["inputs_sha256"]):
                raise Denied("bad_steps")
            if s.get("output_sha256") is not None and not (isinstance(s["output_sha256"], str) and HEX64.fullmatch(s["output_sha256"])):
                raise Denied("bad_steps")
            b = s.get("budget", {})
            if not isinstance(b, dict) or not set(b) <= {"tokens", "bytes", "seconds"} or not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in b.values()):
                raise Denied("bad_steps")
            seen.add(s["id"])

    def lock(self, workflow: str, steps, signed):
        if not isinstance(workflow, str) or not NAME.fullmatch(workflow):
            raise Denied("bad_workflow")
        self._check_steps(steps)
        if workflow in self.locked:
            raise Denied("already_locked")
        steps_sha = _sha(json.dumps(steps, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        self.geu._check("lock_pre", {"workflow": workflow, "steps_sha256": steps_sha}, signed, "")
        if not self.geu._append({"op": "pre_lock", "workflow": workflow, "steps": steps}):
            raise Denied("faulted")
        self.locked[workflow] = steps

    def revoke(self, workflow: str, signed):
        if workflow not in self.locked:
            raise Denied("not_locked")
        self.geu._check("revoke_authority", {"workflow": workflow}, signed, "")
        if not self.geu._append({"op": "pre_revoke", "workflow": workflow}):
            raise Denied("faulted")
        del self.locked[workflow]

    def _refuse(self, run, step, reason):
        self.geu._append({"op": "pre_refused", "workflow": run.workflow, "step": str(step)[:60], "reason": reason})

    def begin(self, workflow: str) -> "Run":
        if self.geu.faulted or self.geu.hard_stopped:
            raise Trap("faulted" if self.geu.faulted else "hard_stop")
        return Run(self, workflow, self.locked.get(workflow))


class Run:
    def __init__(self, unit: PREUnit, workflow: str, steps):
        self.unit, self.workflow, self.steps, self.pos, self.done = unit, workflow, steps, 0, []

    @property
    def quarantined(self) -> bool:
        return self.steps is None

    def step(self, step_id: str, code: bytes, inputs: bytes, fn, accelerator: bool = False):
        u = self.unit
        if u.geu.faulted or u.geu.hard_stopped:
            raise Trap("faulted" if u.geu.faulted else "hard_stop")
        if not isinstance(code, (bytes, bytearray)) or not isinstance(inputs, (bytes, bytearray)) or not callable(fn):
            raise Trap("bad_step")
        expect, budget = None, {}
        if not self.quarantined:
            if self.pos >= len(self.steps):
                u._refuse(self, step_id, "workflow_already_complete")
                raise Trap("workflow_already_complete")
            expect = self.steps[self.pos]
            if step_id != expect["id"]:
                u._refuse(self, step_id, "out_of_order")
                raise Trap("out_of_order")
            if _sha(code) != expect["code_sha256"]:
                u._refuse(self, step_id, "code_mismatch")
                raise Trap("code_mismatch")
            if _sha(inputs) != expect["inputs_sha256"]:
                u._refuse(self, step_id, "inputs_mismatch")
                raise Trap("inputs_mismatch")
            budget = expect.get("budget", {})
        meter = Meter(budget, u, self, step_id)
        try:
            result = fn(meter)
        except Trap:
            raise
        except Exception as exc:                                         # noqa: BLE001 - a crashing step is a refused step
            u._refuse(self, step_id, "step_crashed:" + type(exc).__name__)
            raise Trap("step_crashed")
        if not isinstance(result, (bytes, bytearray)):
            u._refuse(self, step_id, "result_not_bytes")
            raise Trap("result_not_bytes")
        rh = _sha(result)
        if expect is not None and expect.get("output_sha256") is not None and rh != expect["output_sha256"]:
            u._refuse(self, step_id, "output_mismatch")
            raise Trap("output_mismatch")
        if not u.geu._append({"op": "pre_result", "workflow": self.workflow, "step": step_id, "result_sha256": rh, "quarantined": self.quarantined, "accelerator": bool(accelerator)}):
            raise Trap("faulted")                                         # the result's hash is on the chain BEFORE it is released
        if not self.quarantined:
            self.pos += 1
            self.done.append(step_id)
        if self.quarantined:
            return Quarantined(bytes(result))
        if accelerator and (expect is None or expect.get("output_sha256") is None):
            return Tainted(bytes(result))                                 # nothing locked says this output is right: it stays tainted
        return bytes(result)

    def complete(self) -> bool:
        return (not self.quarantined) and self.pos == len(self.steps)
