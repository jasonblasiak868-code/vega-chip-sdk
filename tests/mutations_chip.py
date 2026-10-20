"""Mutation check for the governance-hardware model: each rule removed in a COPY must make tests/redteam_1_chip.py fail.
Run: source SDK_FAMILY/env_family.sh; python tests/mutations_chip.py"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
NVF, GE, PR = "nv.py", "geu.py", "pre_unit.py"
MUTATIONS = [
    ("nv read-back", NVF, "if torn or len(recs) != len(self.records) + 1 or recs[-1] != rec:", "if False:"),
    ("nv torn tail discarded", NVF, "            if torn:", "            if False:"),
    ("nv histories must agree", NVF, 'if [r["sha256"] for r in ra[:common]] != [r["sha256"] for r in rb[:common]]:', "if False:"),
    ("nv gap refused", NVF, "if len(ra) - len(rb) > 1 or len(rb) - len(ra) > 1:", "if False:"),
    ("nv chain checked on read", NVF, 'ok = isinstance(rec, dict) and rec.get("i") == n and rec.get("prev") == prev and rec.get("sha256") == _hash(rec)', "ok = True"),
    ("keys written once", GE, 'if self.keys:\n            raise Denied("keys_blown")', 'if False:\n            raise Denied("keys_blown")'),
    ("no keys no service", GE, 'if not self.keys:\n            self._deny("no_keys"', 'if False:\n            self._deny("no_keys"'),
    ("wildcard refused", GE, 'if not isinstance(action, str) or action in WILDCARDS or "*" in action:', "if False:"),
    ("odd spelling refused", GE, "if human_only.is_human_only(action) and action not in human_only.HUMAN_ONLY:", "if False:"),
    ("fields checked", GE, 'if not isinstance(signed, dict) or not isinstance(signed.get("nonce"), str) or not isinstance(signed.get("signature"), str):', "if False:"),
    ("replay refused", GE, "if nh in self.burned:", "if False:"),
    ("expiry boundary", GE, "if exp <= now:", "if exp < now:"),
    ("lease cap", GE, "if exp - now > MAX_LEASE_SECONDS:", "if False:"),
    ("signature checked", GE, "if not any(self._verifies(k, sig, msg) for k in self.keys):", "if False:"),
    ("burn before the gate", GE, 'if not self._append({"op": "burn", "nonce_sha256": nh}):', "if False:"),
    ("the port must exist", GE, 'if port not in self._ports:\n            self._deny("no_port"', 'if False:\n            self._deny("no_port"'),
    ("hard stop blocks requests", GE, 'if self.hard_stopped:\n            self._deny("hard_stop"', 'if False:\n            self._deny("hard_stop"'),
    ("hard stop blocks the gate", GE, 'if self.faulted or self.hard_stopped:\n            raise Denied("faulted" if self.faulted else "hard_stop")', 'if self.faulted:\n            raise Denied("faulted")'),
    ("grant expires", GE, "if self.clock.read() >= grant.expiry:", "if False:"),
    ("restore needs the human", GE, 'self._check("restore_after_hard_stop", {}, signed, "")', "pass"),
    ("dma table needs the human", GE, 'self._check("change_gate_config", {"dma_table": canon}, signed, "")', "pass"),
    ("dma table enforced", GE, "if port not in self._ports or port not in self.dma.get(initiator, set()):", "if port not in self._ports:"),
    ("side door trips the stop", GE, "if self.trip:\n            self.hard_stop()", "if False:\n            self.hard_stop()"),
    ("ports demand the gate token", GE, 'if gate is not _GATE:\n            raise Denied("side_door")', 'if False:\n            raise Denied("side_door")'),
    ("clock roll-back", GE, "if clock.read() < last_t:", "if False:"),
    ("a fault stays a fault", GE, "def _fault(self):\n        self.faulted = True", "def _fault(self):\n        self.faulted = False"),
    ("pre: order", PR, 'if step_id != expect["id"]:', "if False:"),
    ("pre: code identity", PR, 'if _sha(code) != expect["code_sha256"]:', "if False:"),
    ("pre: inputs", PR, 'if _sha(inputs) != expect["inputs_sha256"]:', "if False:"),
    ("pre: locked output", PR, 'if expect is not None and expect.get("output_sha256") is not None and rh != expect["output_sha256"]:', "if False:"),
    ("pre: quarantine wrapper", PR, "if self.quarantined:\n            return Quarantined(bytes(result))", "if False:\n            return Quarantined(bytes(result))"),
    ("pre: taint", PR, 'if accelerator and (expect is None or expect.get("output_sha256") is None):', "if False:"),
    ("pre: budget", PR, 'if cap is not None and self.used[name] > cap:', "if False:"),
    ("pre: result hash before release", PR, 'if not u.geu._append({"op": "pre_result", "workflow": self.workflow, "step": step_id, "result_sha256": rh, "quarantined": self.quarantined, "accelerator": bool(accelerator)}):\n            raise Trap("faulted")', "pass"),
    ("pre: lock needs the human", PR, 'self.geu._check("lock_pre", {"workflow": workflow, "steps_sha256": steps_sha}, signed, "")', "pass"),
    ("pre: no silent replacement", PR, 'if workflow in self.locked:\n            raise Denied("already_locked")', 'if False:\n            raise Denied("already_locked")'),
    ("pre: revoke needs the human", PR, 'self.geu._check("revoke_authority", {"workflow": workflow}, signed, "")', "pass"),
    ("pre: step list validated", PR, "if not isinstance(steps, list) or not 1 <= len(steps) <= 200:", "if False:"),
    ("pre: a finished workflow stays finished", PR, "if self.pos >= len(self.steps):", "if False:"),
    ("pre: nothing begins while stopped", PR, 'if self.geu.faulted or self.geu.hard_stopped:\n            raise Trap("faulted" if self.geu.faulted else "hard_stop")\n        return Run', 'if False:\n            raise Trap("faulted")\n        return Run'),
]
if __name__ != "__main__":
    MUTATIONS = []                       # importing this file (test discovery) must not start the mutation run
survivors = []
for name, fname, old, new in MUTATIONS:
    tmp = pathlib.Path(tempfile.mkdtemp())
    shutil.copytree(REPO / "src" / "vega_chip", tmp / "vega_chip")
    f = tmp / "vega_chip" / fname
    text = f.read_text(encoding="utf-8")
    if old not in text:
        print("CANNOT APPLY", name)
        survivors.append(name + " (could not apply)")
        continue
    f.write_text(text.replace(old, new, 1), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp) + os.pathsep + env.get("PYTHONPATH", "")
    r = subprocess.run([sys.executable, "-W", "ignore", str(REPO / "tests" / "redteam_1_chip.py")], capture_output=True, text=True, env=env, timeout=600)
    print(("killed   " if r.returncode != 0 else "SURVIVED ") + name, flush=True)
    if r.returncode == 0:
        survivors.append(name)
    shutil.rmtree(tmp, ignore_errors=True)
print("survivors:", survivors or "none")
