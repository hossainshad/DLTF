"""
audit/hashchain.py

Local append-only audit ledger: an HMAC-signed hash chain persisted as JSONL.
Replaces the blockchain stack from the old design with the property the thesis
actually needs: a tamper-EVIDENT record of every trust decision, verifiable
offline. Any edit, reorder, or deletion breaks the chain loudly.

Entry layout (one JSON object per line):
  {"seq", "ts", "type", "payload", "prev", "hash", "sig"}
  hash = SHA256 over the canonical JSON of all fields except hash and sig
  sig  = HMAC-SHA256(key, hash)

Hash links give integrity (an edit breaks every later link); the HMAC gives
authenticity (file access without the key cannot re-mint a consistent chain).
Honest scope for the writeup: a centralized audit log with offline
verifiability, not consensus. Publishing the head hash externally (the one-line
"anchor") is the future-work bridge to a public ledger.

The server writes: ENROLL, WHITEWASH_REJECTED, EVENT (non-neutral), BAN (with
EK hash, the O2 evidence), PROBATION_ENTER, PROBATION_DECISION, ROUND.
"""
import os
import json
import time
import hmac
import hashlib
import secrets

GENESIS_PREV = "0" * 64


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class HashChain:
    def __init__(self, path=None, key=None):
        self.path = path
        self.key = key or self._load_or_create_key()
        self._entries = []
        if path and os.path.exists(path):
            self._load()
        else:
            self._append_raw("GENESIS", {"chain_id": secrets.token_hex(8)})

    # ---- key handling ----------------------------------------------------

    def _load_or_create_key(self):
        if self.path is None:
            return os.urandom(32)
        kp = self.path + ".key"
        if os.path.exists(kp):
            with open(kp, "rb") as f:
                return f.read()
        key = os.urandom(32)
        with open(kp, "wb") as f:
            f.write(key)
        try:
            os.chmod(kp, 0o600)
        except OSError:
            pass
        return key

    # ---- core ------------------------------------------------------------

    def _hash(self, body):
        return hashlib.sha256(_canon(body)).hexdigest()

    def _sig(self, h):
        return hmac.new(self.key, h.encode(), hashlib.sha256).hexdigest()

    def _append_raw(self, event_type, payload):
        prev = self._entries[-1]["hash"] if self._entries else GENESIS_PREV
        body = {"seq": len(self._entries), "ts": round(time.time(), 3),
                "type": event_type, "payload": payload, "prev": prev}
        entry = dict(body)
        entry["hash"] = self._hash(body)
        entry["sig"] = self._sig(entry["hash"])
        self._entries.append(entry)
        if self.path:
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def append(self, event_type, payload):
        if event_type == "GENESIS":
            raise ValueError("GENESIS is reserved")
        return self._append_raw(event_type, payload)

    def verify(self):
        prev = GENESIS_PREV
        for i, e in enumerate(self._entries):
            body = {k: e[k] for k in ("seq", "ts", "type", "payload", "prev")}
            if e["seq"] != i:
                return False, f"seq mismatch at {i}"
            if e["prev"] != prev:
                return False, f"broken link at seq {i}"
            if self._hash(body) != e["hash"]:
                return False, f"hash mismatch at seq {i}"
            if not hmac.compare_digest(self._sig(e["hash"]), e["sig"]):
                return False, f"signature mismatch at seq {i}"
            prev = e["hash"]
        return True, None

    def _load(self):
        with open(self.path) as f:
            self._entries = [json.loads(line) for line in f if line.strip()]
        ok, err = self.verify()
        if not ok:
            raise ValueError(f"audit chain corrupted: {err}")

    # ---- queries -----------------------------------------------------------

    def entries(self, event_type=None):
        if event_type is None:
            return list(self._entries)
        return [e for e in self._entries if e["type"] == event_type]

    def head_hash(self):
        return self._entries[-1]["hash"]

    def __len__(self):
        return len(self._entries)


def _self_test():
    import tempfile
    print("audit/hashchain.py self-test")

    c = HashChain()
    c.append("ENROLL", {"device": "h0", "tier": "HARDWARE"})
    c.append("EVENT", {"device": "h0", "severity": "MAJOR"})
    c.append("BAN", {"device": "s1", "ek_hash": "abc"})
    ok, err = c.verify()
    assert ok and err is None and len(c) == 4
    print("✓ append and verify on a clean chain")

    c._entries[2]["payload"]["severity"] = "POSITIVE"
    ok, err = c.verify()
    assert not ok and "hash mismatch at seq 2" in err
    print("✓ payload edit detected (hash mismatch)")

    c2 = HashChain()
    c2.append("EVENT", {"x": 1})
    e = c2._entries[1]
    e["payload"]["x"] = 999
    body = {k: e[k] for k in ("seq", "ts", "type", "payload", "prev")}
    e["hash"] = c2._hash(body)                      # attacker recomputes hash
    ok, err = c2.verify()
    assert not ok and ("signature mismatch" in err or "broken link" in err)
    print("✓ keyless re-mint detected (HMAC) even with recomputed hashes")

    c3 = HashChain()
    c3.append("A", {}); c3.append("B", {})
    del c3._entries[1]                              # deletion / reorder
    ok, err = c3.verify()
    assert not ok
    print("✓ deletion breaks the chain")

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "audit.jsonl")
        c4 = HashChain(path=p)
        c4.append("ENROLL", {"device": "r0"})
        head = c4.head_hash()
        c5 = HashChain(path=p)                       # reload from disk
        assert len(c5) == 2 and c5.head_hash() == head
        c5.append("ROUND", {"round": 0})
        c6 = HashChain(path=p)
        assert len(c6) == 3
        ok, _ = c6.verify(); assert ok
        print("✓ persists, reloads, key file reused across restarts")

        with open(p) as f:
            lines = f.readlines()
        tampered = json.loads(lines[1]); tampered["payload"]["device"] = "evil"
        lines[1] = json.dumps(tampered, sort_keys=True) + "\n"
        with open(p, "w") as f:
            f.writelines(lines)
        try:
            HashChain(path=p); raise AssertionError("should have raised")
        except ValueError as e:
            assert "corrupted" in str(e)
        print("✓ on-disk tampering refuses to load")

    assert len(c.entries("BAN")) == 1
    print("✓ entries() filters by type")
    print("✓ all hashchain self-tests passed")


if __name__ == "__main__":
    _self_test()