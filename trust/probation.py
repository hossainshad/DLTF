"""
trust/probation.py

Rehabilitation trial for devices placed on probation by reputation.py. Only Tier 1
identities ever reach here (reputation bans lower tiers outright), so this is the
mechanism that lets a non-evadable identity earn reinstatement.

  O3 quantified trust : recovery is decided by the OLS slope of an isolated shadow
                        model, with documented thresholds. Not a heuristic.

Anti-gaming properties:
  - Window length is HMAC(device_id, entry_round), random per process, so an
    attacker cannot time a "behave just long enough" attack.
  - The shadow model accumulates ONLY this device's gradients on a frozen global
    snapshot, so improvement from the honest federation cannot mask a bad actor.
  - The window extension is one-shot.

reputation.py is reached through a duck-typed engine (reinstate, record_event),
so this module has no import dependency on it and self-tests standalone.
"""
import os
import hmac
import hashlib
import struct
from enum import Enum
from dataclasses import dataclass, field

# Recovery thresholds (O3). Slope is accuracy change per probation round.
REINSTATE_SLOPE = 0.005
EXTEND_SLOPE = 0.001
EXTENSION_ROUNDS = 3
WINDOW_MIN, WINDOW_MAX = 4, 9

# Random per process. An attacker who knows device_id and entry_round still cannot
# predict the window length.
HMAC_SALT = os.urandom(16)


class ProbationOutcome(str, Enum):
    PENDING = "PENDING"
    EXTENDED = "EXTENDED"
    REINSTATED = "REINSTATED"
    PERMANENT_BAN = "PERMANENT_BAN"


TERMINAL = {ProbationOutcome.REINSTATED, ProbationOutcome.PERMANENT_BAN}


def ols_slope(y):
    """Least-squares slope of series y against x = 0..n-1. 0.0 for n < 2."""
    n = len(y)
    if n < 2:
        return 0.0
    xs = range(n)
    mx = sum(xs) / n
    my = sum(y) / n
    num = sum((x - mx) * (v - my) for x, v in zip(xs, y))
    den = sum((x - mx) ** 2 for x in xs)
    return num / den if den else 0.0


def derive_window(device_id, entry_round):
    msg = device_id.encode() + struct.pack(">Q", entry_round)
    digest = hmac.new(HMAC_SALT, msg, hashlib.sha256).digest()
    return WINDOW_MIN + (digest[0] % (WINDOW_MAX - WINDOW_MIN + 1))


@dataclass
class ProbationRecord:
    device_id: str
    entry_round: int
    window: int
    extended: bool = False
    shadow_params: list = field(default_factory=list)
    accuracy_series: list = field(default_factory=list)
    outcome: ProbationOutcome = ProbationOutcome.PENDING
    outcome_round: int = None

    @property
    def eval_round(self):
        return self.entry_round + self.window

    @property
    def is_terminal(self):
        return self.outcome in TERMINAL

    def current_slope(self):
        return ols_slope(self.accuracy_series)


class ProbationPoolManager:
    def __init__(self, rep_engine=None):
        # rep_engine is any object exposing reinstate(device_id) and
        # record_event(device_id, severity). The real one is trust.reputation.
        self.rep = rep_engine
        self._records = {}

    def enter_probation(self, device_id, entry_round, global_params):
        rec = ProbationRecord(
            device_id=device_id,
            entry_round=entry_round,
            window=derive_window(device_id, entry_round),
            shadow_params=list(global_params),
        )
        self._records[device_id] = rec
        return rec

    def is_on_probation(self, device_id):
        r = self._records.get(device_id)
        return r is not None and not r.is_terminal

    def active(self):
        return [d for d, r in self._records.items() if not r.is_terminal]

    def get_record(self, device_id):
        return self._records.get(device_id)

    def step(self, round_id, device_gradients, eval_fn):
        """Advance every active probation trial by one round. Returns the list of
        (device_id, outcome) for trials that reached a decision this round."""
        decided = []
        for device_id in self.active():
            rec = self._records[device_id]
            grad = device_gradients.get(device_id)
            if grad is not None:
                rec.shadow_params = [s + g for s, g in zip(rec.shadow_params, grad)]
            rec.accuracy_series.append(eval_fn(rec.shadow_params))

            if round_id >= rec.eval_round:
                decided.append((device_id, self._decide(rec, round_id)))
        return decided

    def _decide(self, rec, round_id):
        slope = rec.current_slope()
        if slope >= REINSTATE_SLOPE:
            rec.outcome = ProbationOutcome.REINSTATED
            rec.outcome_round = round_id
            if self.rep:
                self.rep.reinstate(rec.device_id)
        elif slope >= EXTEND_SLOPE and not rec.extended:
            rec.extended = True
            rec.window += EXTENSION_ROUNDS
            rec.outcome = ProbationOutcome.EXTENDED          # non-terminal, trial continues
        else:
            rec.outcome = ProbationOutcome.PERMANENT_BAN
            rec.outcome_round = round_id
            if self.rep:
                self.rep.record_event(rec.device_id, "CRITICAL")
        return rec.outcome

    def summary(self, device_id):
        r = self._records[device_id]
        return {
            "device_id": r.device_id,
            "entry_round": r.entry_round,
            "window": r.window,
            "extended": r.extended,
            "outcome": r.outcome.value,
            "outcome_round": r.outcome_round,
            "ols_slope": round(r.current_slope(), 6),
            "accuracy_series": [round(a, 6) for a in r.accuracy_series],
        }


class _StubRep:
    def __init__(self):
        self.reinstated = []
        self.banned = []
    def reinstate(self, device_id):
        self.reinstated.append(device_id)
        return True
    def record_event(self, device_id, severity):
        self.banned.append((device_id, severity))


def _self_test():
    print("trust/probation.py self-test")

    assert ols_slope([1, 2, 3, 4]) == 1.0
    assert ols_slope([0.5, 0.5, 0.5]) == 0.0
    assert ols_slope([7]) == 0.0
    print("✓ OLS slope correct on linear, flat, single-point series")

    for did, rnd in [("a", 0), ("b", 5), ("client3", 99)]:
        w = derive_window(did, rnd)
        assert WINDOW_MIN <= w <= WINDOW_MAX
    print(f"✓ HMAC window always in [{WINDOW_MIN}, {WINDOW_MAX}]")

    rep = _StubRep()
    mgr = ProbationPoolManager(rep_engine=rep)
    g0 = [0.0, 0.0, 0.0, 0.0]
    mgr.enter_probation("recover", 0, g0)   # rising accuracy
    mgr.enter_probation("fail", 0, g0)      # flat accuracy
    mgr.enter_probation("extend", 0, g0)    # marginal accuracy

    grads = {"recover": [1.0, 0, 0, 0], "fail": [0.0, 0, 0, 0], "extend": [0.1, 0, 0, 0]}
    eval_fn = lambda p: 0.5 + 0.02 * p[0]

    seen = {}
    for round_id in range(40):
        if not mgr.active():
            break
        for device_id, outcome in mgr.step(round_id, grads, eval_fn):
            seen.setdefault(device_id, []).append(outcome)

    assert mgr.get_record("recover").outcome == ProbationOutcome.REINSTATED
    assert "recover" in rep.reinstated
    print("✓ rising shadow accuracy -> REINSTATED, reputation.reinstate called")

    assert mgr.get_record("fail").outcome == ProbationOutcome.PERMANENT_BAN
    assert ("fail", "CRITICAL") in rep.banned
    print("✓ flat shadow accuracy -> PERMANENT_BAN, CRITICAL pushed to reputation")

    assert ProbationOutcome.EXTENDED in seen["extend"]
    assert mgr.get_record("extend").outcome == ProbationOutcome.PERMANENT_BAN
    assert mgr.get_record("extend").extended is True
    print("✓ marginal accuracy -> one-shot EXTENDED, then PERMANENT_BAN")

    assert mgr.is_on_probation("recover") is False
    s = mgr.summary("fail")
    assert s["outcome"] == "PERMANENT_BAN" and "ols_slope" in s
    print("✓ terminal trials closed, summary exports for audit")

    print("✓ all probation self-tests passed")


if __name__ == "__main__":
    _self_test()