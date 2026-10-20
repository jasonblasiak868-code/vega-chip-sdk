"""nv.py - a model of non-volatile memory for the governance unit: two PHYSICALLY SEPARATE regions, append-only hash-chained records, read-back before trust, and faults you can inject (a power cut in the
middle of a write, a stuck bit) so the recovery rules can be tested.

A record is {i, prev, data, sha256}; a region is a file of such lines. APPEND writes the record to region A and region B and then READS BOTH BACK and compares them with what was meant: only then does it
return. If anything differs it raises NVFault and the unit must treat itself as failed.
RECOVERY (open): each region is read as far as it is valid. A torn LAST line (a write the power cut interrupted) is discarded: that is safe because the unit never opens its gate until an append has
returned, so an interrupted append never led to any action. If one region is exactly one record ahead of the other, the shorter is repaired from the longer. Any other difference (different history,
a broken hash in the middle, a gap) is a FAULT and the unit refuses to start: it never guesses which history is true."""
import hashlib
import json
import os

ZERO = "0" * 64


class NVFault(Exception):
    pass


class PowerCut(Exception):
    """Raised by the fault injector in the middle of a write."""


def _hash(rec) -> str:
    return hashlib.sha256(b"VEGA-NV-1|" + json.dumps({k: v for k, v in rec.items() if k != "sha256"}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


class Region:
    def __init__(self, path):
        self.path = os.fspath(path)
        self.cut_after = None                                       # fault injection: cut power after this many bytes of the next write
        self.stuck = None                                           # fault injection: a callable that corrupts what is written

    def read_raw(self) -> bytes:
        try:
            with open(self.path, "rb") as fh:
                return fh.read()
        except FileNotFoundError:
            return b""

    def write_line(self, line: bytes):
        if self.stuck is not None:
            line = self.stuck(line)
        with open(self.path, "ab") as fh:
            if self.cut_after is not None:
                fh.write(line[:self.cut_after])
                fh.flush()
                self.cut_after = None
                raise PowerCut("power lost mid-write")
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

    def valid_prefix(self):
        """-> (records, torn_tail: bool). Raises NVFault for damage anywhere but the last line."""
        raw = self.read_raw()
        lines = raw.split(b"\n")
        torn = lines[-1] != b""
        complete = lines[:-1]
        recs, prev = [], ZERO
        for n, ln in enumerate(complete):
            try:
                rec = json.loads(ln.decode("utf-8"))
                ok = isinstance(rec, dict) and rec.get("i") == n and rec.get("prev") == prev and rec.get("sha256") == _hash(rec)
            except (ValueError, UnicodeDecodeError):
                ok = False
            if not ok:
                raise NVFault("region %s is damaged at record %d" % (os.path.basename(self.path), n))
            recs.append(rec)
            prev = rec["sha256"]
        return recs, torn


class NVStore:
    def __init__(self, path_a, path_b):
        self.a, self.b = Region(path_a), Region(path_b)
        self.records = []
        self._recover()

    def _recover(self):
        ra, torn_a = self.a.valid_prefix()
        rb, torn_b = self.b.valid_prefix()
        for region, torn in ((self.a, torn_a), (self.b, torn_b)):
            if torn:                                                # discard an interrupted last write: no action ever depended on it
                raw = region.read_raw()
                keep = raw[:raw.rfind(b"\n") + 1]
                with open(region.path, "wb") as fh:
                    fh.write(keep)
        common = min(len(ra), len(rb))
        if [r["sha256"] for r in ra[:common]] != [r["sha256"] for r in rb[:common]]:
            raise NVFault("the two regions hold different histories: refusing to guess")
        if len(ra) - len(rb) > 1 or len(rb) - len(ra) > 1:
            raise NVFault("the regions differ by more than one record: refusing to repair")
        if len(ra) == len(rb) + 1:
            self.b.write_line(self._line(ra[-1]))
            rb = ra
        elif len(rb) == len(ra) + 1:
            self.a.write_line(self._line(rb[-1]))
            ra = rb
        self.records = list(ra)

    @staticmethod
    def _line(rec) -> bytes:
        return json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"

    @property
    def head(self) -> str:
        return self.records[-1]["sha256"] if self.records else ZERO

    def append(self, data: dict) -> dict:
        rec = {"i": len(self.records), "prev": self.head, "data": data}
        rec["sha256"] = _hash(rec)
        line = self._line(rec)
        self.a.write_line(line)
        self.b.write_line(line)
        for region in (self.a, self.b):                             # read back and compare before anyone may rely on it
            recs, torn = region.valid_prefix()
            if torn or len(recs) != len(self.records) + 1 or recs[-1] != rec:
                raise NVFault("read-back of region %s does not match what was written" % os.path.basename(region.path))
        self.records.append(rec)
        return rec

    def find(self, key, value):
        return [r for r in self.records if r["data"].get(key) == value]
