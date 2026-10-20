"""conformance.py - the software family is the executable specification of the governance hardware; this is the test that says so.

It runs the SAME signed attempts through (a) the software jacket's exit gate (Verifier + Commit + ExitGate from vega-governance-jacket-sdk) and (b) the GEU model, and compares the decision on every attempt:
allowed or refused. ANY difference is a mismatch: either the hardware model is looser than the software (a hole) or stricter (a behaviour the software does not promise), and either is a finding.
A hardware build (an FPGA prototype, later silicon) is conformant when it gives the same decisions on the same vectors. The vectors cover: a good commitment, replay, expiry, over-long lease, a signature for
another action or other parameters, wildcard and odd-spelled action names, a human-only action signed correctly, a flipped signature bit, a missing nonce, malformed expiry values, a nonce holding the field
separator, a look-alike (non-ASCII) action name, a signature by another key, and a fresh commitment after a refused one.
THE MODEL OF TIME: both sides read one fixed clock, so a vector's expiry means the same thing to each."""
import os
import pathlib
import secrets
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vega_chip import geu as GEUMOD, nv as NV
from vega_custody.dag.dag import Dag
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
from vega_jacket import humanauth
from vega_jacket.commit.commit import Commit
from vega_jacket.gate.exit_gate import Denied as SoftDenied, ExitGate
from vega_jacket.humanauth.verify import HumanAuthError, action_hash, message

NOW = 1_900_000_000
DEVICE, SURFACE = "dev-conf", "surf-conf"


class Signer:
    """The human's side: signs exactly what it is told to, so vectors can build good and bad commitments."""

    def __init__(self):
        self._sk = Ed25519PrivateKey.generate()
        self.public = self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, action, params, nonce=None, expiry=None, device=DEVICE, surface=SURFACE):
        nonce = nonce or secrets.token_hex(16)
        expiry = NOW + 300 if expiry is None else expiry
        try:
            msg = message(device, surface, action, action_hash(params), nonce, expiry)
        except HumanAuthError:                                        # the signing tool itself refuses odd names: the attacker presents a signature made for a different action
            msg = message(device, surface, "an_unrelated_action", action_hash(params), nonce, expiry)
        return {"nonce": nonce, "expiry": expiry, "signature": self._sk.sign(msg).hex()}


class Rig:
    def __init__(self, directory=None):
        d = pathlib.Path(directory or tempfile.mkdtemp())
        self.human = Signer()
        self.dag = Dag([d / "c.jsonl"], [d / "l.jsonl"])
        self.ledger = Ledger([LocalBackend(d / "led.jsonl")])
        verifier = humanauth.Verifier(self.human.public, DEVICE, SURFACE, clock=lambda: NOW)
        self.soft = ExitGate(Commit(verifier, self.ledger, self.dag), self.ledger, verifier, self.dag)
        self.clock = GEUMOD.MonotonicClock(NOW)
        self.hw = GEUMOD.GEU(NV.NVStore(d / "a.nv", d / "b.nv"), self.clock, ports=("net",), device=DEVICE, surface=SURFACE)
        self.hw.program_keys([self.human.public])

    def attempt(self, action, params, signed):
        """-> (software allowed, hardware allowed). Each side sees the same bytes."""
        try:
            self.soft.release(action, params, signed, route="human")
            soft = True
        except SoftDenied:
            soft = False
        try:
            grant = self.hw.request(action, params, signed, "net")
            self.hw.transact(grant, b"x")
            hw = True
        except GEUMOD.Denied:
            hw = False
        return soft, hw


def vectors(h: Signer):
    """[(name, [(action, params, signed, expected_allowed), ...]), ...]; expected is what BOTH sides must say."""
    p = {"target": "records", "n": 1}
    good = h.sign("send_report", p)
    out = [
        ("a good commitment", [("send_report", p, h.sign("send_report", p), True)]),
        ("replay of a spent commitment", [("send_report", p, good, True), ("send_report", p, good, False)]),
        ("expired", [("send_report", p, h.sign("send_report", p, expiry=NOW - 1), False)]),
        ("expires exactly now", [("send_report", p, h.sign("send_report", p, expiry=NOW), False)]),
        ("lease one second over the cap", [("send_report", p, h.sign("send_report", p, expiry=NOW + 901), False)]),
        ("lease exactly at the cap", [("send_report", p, h.sign("send_report", p, expiry=NOW + 900), True)]),
        ("signed for another action", [("send_other", p, h.sign("send_report", p), False)]),
        ("signed for other parameters", [("send_report", {"target": "other", "n": 1}, h.sign("send_report", p), False)]),
        ("wildcard action", [("*", p, h.sign("*", p), False), ("all", p, h.sign("all", p), False), ("", p, h.sign("", p), False)]),
        ("odd spelling of a human-only action", [("Release-Public", p, h.sign("Release-Public", p), False), ("RELEASE_PUBLIC", p, h.sign("RELEASE_PUBLIC", p), False)]),
        ("a human-only action signed correctly", [("release_public", p, h.sign("release_public", p), True)]),
        ("a flipped signature bit", [("send_report", p, dict(good, nonce="n-" + secrets.token_hex(8), signature=("0" if good["signature"][0] != "0" else "1") + good["signature"][1:]), False)]),
        ("no nonce", [("send_report", p, {k: v for k, v in good.items() if k != "nonce"}, False)]),
        ("no signature", [("send_report", p, {k: v for k, v in good.items() if k != "signature"}, False)]),
        ("expiry as a float", [("send_report", p, dict(h.sign("send_report", p), expiry=float(NOW + 100)), False)]),
        ("expiry as a bool", [("send_report", p, dict(h.sign("send_report", p), expiry=True), False)]),
        ("expiry as a word", [("send_report", p, dict(h.sign("send_report", p), expiry="soon"), False)]),
        ("a nonce holding the field separator", [("send_report", p, dict(h.sign("send_report", p, nonce="a" * 8), nonce="aaaa|aaaa"), False)]),
        ("a look-alike action name", [("send_repоrt", p, h.sign("send_repоrt", p), False)]),
        ("another key", [("send_report", p, Signer().sign("send_report", p), False)]),
        ("another device", [("send_report", p, h.sign("send_report", p, device="dev-other"), False)]),
        ("a good one after a refused one", [("send_report", p, h.sign("send_report", p, expiry=NOW - 5), False), ("send_report", p, h.sign("send_report", p), True)]),
        ("junk instead of a commitment", [("send_report", p, "text", False), ("send_report", p, None, False), ("send_report", p, {}, False)]),
    ]
    return out


def run_conformance(directory=None):
    """-> {'vectors', 'attempts', 'mismatches': [(vector, attempt index, software, hardware, expected)]}. A fresh rig per vector so one vector's spent commitments never leak into another."""
    n_attempts, mismatches = 0, []
    names = [name for name, _ in vectors(Signer())]
    for idx, name in enumerate(names):
        rig = Rig()
        _, steps = vectors(rig.human)[idx]
        for k, (action, params, signed, expected) in enumerate(steps):
            soft, hw = rig.attempt(action, params, signed)
            n_attempts += 1
            if not (soft == hw == expected):
                mismatches.append((name, k, soft, hw, expected))
    return {"vectors": len(names), "attempts": n_attempts, "mismatches": mismatches}
