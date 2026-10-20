"""geu.py - the GOVERNANCE ENFORCEMENT UNIT: a software reference model of the small electronic unit that sits on the only path from compute to the outside world.

Parts (each is a hardware block in the design):  write-once KEY STORE (public keys only) | SIGNATURE VERIFIER (the same signed message the software jacket uses) | NONCE BURN in non-volatile memory |
monotonic LEASE CLOCK | HASH-CHAIN appender across two separate regions with read-back | OUTPUT GATE per port, closed by default | HARD STOP | SIDE-DOOR table for DMA.
THE ORDER, EVERY TIME (a request is refused at the first step that fails; any internal fault closes everything):
  1 unit healthy and not hard-stopped, the port exists     2 the action name is not wildcard and not an odd spelling of a human-only action
  3 the commitment has not been used (burned set)          4 expiry in the future, lease within the cap, signature valid under a programmed key
  5 BURN the nonce in both regions and read back           6 append the decision to the chain, read back      7 open the gate for THIS action hash, ONE transaction
The burn comes before the gate opens, so a power cut can never leave an approval both spent and unused-looking: an append that did not return led to no action, and a repaired burn stays burned.
Clock roll-back: the unit records the clock reading with every decision and refuses to start if the clock reads lower than the last record.
WHAT THIS IS: an executable specification. It proves the decision rules and the recovery rules; it is not a circuit. The same signed bytes must give the same accept/deny as the software jacket: conformance.py checks that.
LIMITS (the design's own): the human signing device must be out of reach of what is governed; a physical attacker with a probe is out of scope; Python's 'private' parts are a convention, so the model shows the
architecture (compute only reaches a port through the unit) rather than enforcing it against code running in the same process."""
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vega_chip import nv as NV
from vega_jacket.humanauth import human_only
from vega_jacket.humanauth.verify import MAX_LEASE_SECONDS, WILDCARDS, HumanAuthError, action_hash, message

_GATE = object()                                                      # what a port demands before it will move a byte


class Denied(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class MonotonicClock:
    """A counter that only moves forward. In hardware: a battery-backed counter the compute side cannot set. `start` is set once, at provisioning, to the real epoch time."""

    def __init__(self, start: int):
        if isinstance(start, bool) or not isinstance(start, int) or start < 0:
            raise ValueError("start is a non-negative whole number of seconds")
        self._t = start

    def read(self) -> int:
        return self._t

    def advance(self, n: int) -> None:
        if isinstance(n, bool) or not isinstance(n, int) or n < 0:
            raise ValueError("a clock only moves forward")
        self._t += n


class _Port:
    def __init__(self, name):
        self.name, self.log = name, []

    def write(self, gate, payload: bytes):
        if gate is not _GATE:
            raise Denied("side_door")
        self.log.append(bytes(payload))


class Grant:
    __slots__ = ("port", "action_hash", "expiry", "used")

    def __init__(self, port, action_hash, expiry):
        self.port, self.action_hash, self.expiry, self.used = port, action_hash, expiry, False


class GEU:
    def __init__(self, store: NV.NVStore, clock: MonotonicClock, ports=("net", "disk", "display"), device="dev", surface="surf", trip_on_side_door: bool = True):
        self.nv, self.clock, self.device, self.surface, self.trip = store, clock, device, surface, trip_on_side_door
        self._ports = {p: _Port(p) for p in ports}
        self._open = {}
        self.faulted = False
        self.keys, self.burned, self.hard_stopped, self.dma = [], set(), False, {}
        last_t = 0
        for rec in store.records:
            d = rec["data"]
            op = d.get("op")
            if op == "keys":
                self.keys = [bytes.fromhex(k) for k in d["pubs"]]
            elif op == "burn":
                self.burned.add(d["nonce_sha256"])
            elif op == "hard_stop":
                self.hard_stopped = True
            elif op == "restore":
                self.hard_stopped = False
            elif op == "dma":
                self.dma = {k: set(v) for k, v in d["table"].items()}
            last_t = max(last_t, d.get("t", 0))
        if clock.read() < last_t:
            self.faulted = True                                       # the clock reads earlier than something already recorded: roll-back, so the unit refuses to run

    # ---- helpers ---------------------------------------------------------------------------------------------------------
    def port_names(self):
        return sorted(self._ports)

    def port_log(self, name):
        return list(self._ports[name].log)

    def _fault(self):
        self.faulted = True
        self._open.clear()

    def _append(self, data) -> bool:
        try:
            self.nv.append(dict(data, t=self.clock.read()))
            return True
        except (NV.NVFault, NV.PowerCut, OSError):
            self._fault()
            return False

    def _deny(self, reason, action="", ah="", port=""):
        self._append({"op": "decision", "result": "DENIED", "reason": reason, "action": str(action)[:60], "action_hash": ah, "port": str(port)[:20]})   # best effort: a denial stays a denial
        raise Denied(reason)

    # ---- the key store (write once) ---------------------------------------------------------------------------------------------------
    def program_keys(self, pubs):
        if self.keys:
            raise Denied("keys_blown")
        if not isinstance(pubs, (list, tuple)) or not 1 <= len(pubs) <= 4 or not all(isinstance(p, (bytes, bytearray)) and len(p) == 32 for p in pubs) or len({bytes(p) for p in pubs}) != len(pubs):
            raise Denied("bad_keys")
        for p in pubs:
            try:
                Ed25519PublicKey.from_public_bytes(bytes(p))
            except ValueError:
                raise Denied("bad_keys")
        if not self._append({"op": "keys", "pubs": [bytes(p).hex() for p in pubs]}):
            raise Denied("faulted")
        self.keys = [bytes(p) for p in pubs]

    # ---- steps 2 to 5: one commitment, exactly once ----------------------------------------------------------------------------------------
    def _check(self, action, params, signed, port=""):
        if self.faulted:
            raise Denied("faulted")
        if not self.keys:
            self._deny("no_keys", action, "", port)
        if not isinstance(action, str) or action in WILDCARDS or "*" in action:
            self._deny("wildcard", action, "", port)
        if human_only.is_human_only(action) and action not in human_only.HUMAN_ONLY:
            self._deny("odd_spelling", action, "", port)
        try:
            ah = action_hash(params)
        except HumanAuthError:
            self._deny("bad_params", action, "", port)
        if not isinstance(signed, dict) or not isinstance(signed.get("nonce"), str) or not isinstance(signed.get("signature"), str):
            self._deny("bad_fields", action, ah, port)
        nh = hashlib.sha256(signed["nonce"].encode("utf-8")).hexdigest()
        if nh in self.burned:
            self._deny("replay", action, ah, port)
        exp = signed.get("expiry")
        if isinstance(exp, bool) or not isinstance(exp, (int, str)) or (isinstance(exp, str) and not exp.isdigit()):
            self._deny("bad_fields", action, ah, port)
        exp = int(exp)
        now = self.clock.read()
        if exp <= now:
            self._deny("expired", action, ah, port)
        if exp - now > MAX_LEASE_SECONDS:
            self._deny("lease_too_long", action, ah, port)
        try:
            msg = message(self.device, self.surface, action, ah, signed["nonce"], exp)
            sig = bytes.fromhex(signed["signature"])
        except (HumanAuthError, ValueError):
            self._deny("bad_fields", action, ah, port)
        if not any(self._verifies(k, sig, msg) for k in self.keys):
            self._deny("bad_signature", action, ah, port)
        if not self._append({"op": "burn", "nonce_sha256": nh}):          # burn first; if it cannot be made durable and read back, nothing opens
            raise Denied("faulted")
        self.burned.add(nh)
        return ah, exp

    @staticmethod
    def _verifies(key, sig, msg):
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False

    # ---- steps 1, 6, 7: the gate ------------------------------------------------------------------------------------------------------------------------
    def request(self, action, params, signed, port) -> Grant:
        if self.faulted:
            raise Denied("faulted")
        if self.hard_stopped:
            self._deny("hard_stop", action, "", port)
        if port not in self._ports:
            self._deny("no_port", action, "", port)
        ah, exp = self._check(action, params, signed, port)
        if not self._append({"op": "decision", "result": "GRANTED", "action": action[:60], "action_hash": ah, "port": port}):
            raise Denied("faulted")
        g = Grant(port, ah, exp)
        self._open[port] = g
        return g

    def transact(self, grant, payload) -> int:
        if self.faulted or self.hard_stopped:
            raise Denied("faulted" if self.faulted else "hard_stop")
        if not isinstance(grant, Grant) or self._open.get(grant.port) is not grant or grant.used:
            raise Denied("gate_closed")
        if self.clock.read() >= grant.expiry:
            self._open.pop(grant.port, None)
            raise Denied("expired")
        if not isinstance(payload, (bytes, bytearray)):
            raise Denied("bad_payload")
        grant.used = True
        self._open.pop(grant.port, None)                                  # one transaction, then closed
        self._ports[grant.port].write(_GATE, payload)
        return len(payload)

    # ---- hard stop ----------------------------------------------------------------------------------------------------------------------------------------------
    def hard_stop(self):
        """Anyone (or anything) can engage it. Nothing opens while it is engaged."""
        self.hard_stopped = True
        self._open.clear()
        self._append({"op": "hard_stop"})

    def restore(self, signed):
        """Lifting the stop is HUMAN_ONLY: it needs its own signed commitment for 'restore_after_hard_stop'."""
        if self.faulted:
            raise Denied("faulted")
        if not self.hard_stopped:
            raise Denied("not_stopped")
        was, self.hard_stopped = self.hard_stopped, False                 # _check must not refuse on the stop it is about to lift
        try:
            self._check("restore_after_hard_stop", {}, signed, "")
        except Denied:
            self.hard_stopped = was
            raise
        if not self._append({"op": "restore"}):
            raise Denied("faulted")

    # ---- the side door ------------------------------------------------------------------------------------------------------------------------------------------------------
    def program_dma(self, table: dict, signed):
        """Which initiators may reach which ports. Changing it is a gate-config change: HUMAN_ONLY, one commitment over the exact table."""
        if not isinstance(table, dict) or not all(isinstance(k, str) and isinstance(v, list) and set(v) <= set(self._ports) for k, v in table.items()):
            raise Denied("bad_table")
        canon = {k: sorted(v) for k, v in sorted(table.items())}
        self._check("change_gate_config", {"dma_table": canon}, signed, "")
        if not self._append({"op": "dma", "table": canon}):
            raise Denied("faulted")
        self.dma = {k: set(v) for k, v in canon.items()}

    def egress(self, initiator: str, port: str, payload, grant):
        if port not in self._ports or port not in self.dma.get(initiator, set()):
            self._deny("dma_not_allowed", "egress", "", port)
        return self.transact(grant, payload)

    def raw_port_write(self, port: str, payload):
        """What a bypass looks like: compute reaching a port without the unit. Always refused, always recorded; with trip_on_side_door the unit also hard-stops."""
        self._append({"op": "decision", "result": "DENIED", "reason": "side_door", "action": "raw_write", "action_hash": "", "port": str(port)[:20]})
        if self.trip:
            self.hard_stop()
        try:
            self._ports[port].write(object(), payload)
        except KeyError:
            raise Denied("no_port")

    def chain(self):
        return list(self.nv.records)
