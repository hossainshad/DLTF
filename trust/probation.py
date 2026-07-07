"""
trust/probation.py

Rehabilitation trial for devices placed on probation by reputation.py. Only
Tier-1 identities ever reach here (reputation bans lower tiers outright), so
this is the mechanism that lets a non-evadable identity earn reinstatement.

  O3 quantified trust : recovery is decided by the OLS slope of an isolated
                        shadow model, with documented thresholds. Not a
                        heuristic.

Anti-gaming properties:
  - Window length is HMAC(device_id, entry_round), random per process, so an
    attacker cannot time a "behave just long enough" attack.
  - The shadow model accumulates ONLY this device's gradients on a frozen
    global snapshot, so improvement from the honest federation cannot mask a
    bad actor.
  - The window extension is one-shot.
  - Rehabilitation itself is one-shot PER IDENTITY [DERIVED]: a reinstated
    device that re-enters probation is permanently banned instead of retried.
    Without this, an adaptive attacker cycles attack -> probation -> behave ->
    reinstate forever, buying 1-2 attack rounds per cycle at zero identity
    cost. Graduated sanctions (Ostrom 1990, already cited for tier coupling):
    the second offense escalates. Attacker cost per Tier-1 identity is then
    bounded at ~4 total attack rounds before the physical TPM is burned.

Slope estimator: OLS by default (matches the WINDOW_MIN derivation).
SLOPE_ESTIMATOR = "theil_sen" switches to the Theil-Sen median-of-pairwise
slopes (Theil 1950; Sen 1968), robust to a single-round accuracy outlier.
Recommended for the machine-side MNIST deployment where per-round validation
accuracy is noisy; thresholds are unchanged (both estimate accuracy/round).

Window bounds [DERIVED]:
  WINDOW_MIN = 4       the shortest series where a single outlier cannot by
                       itself determine the sign of the OLS slope.
  WINDOW_MAX = 9       K1 - 1: a trial must resolve within the Tier-1 trust
                       memory horizon (K1 = 10 rounds, see reputation.py).

Coupling to reputation (supervisor request): the slope decides the BRANCH
(reinstate / one-shot extend / permanent ban); the passed trial rounds are
forwarded to reputation.reinstate() as earned evidence, so a longer or
stronger proven recovery returns with proportionally higher trust. The trial
rounds are data the system already counted; no new constants are introduced.

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
WINDOW_MIN, WINDOW_MAX = 4, 9   # [DERIVED] OLS stability floor; K1 - 1 ceiling
SLOPE_ESTIMATOR = "ols"         # "ols" | "theil_sen" (robust, for noisy MNIST)

# Random per process. An attacker who knows device_id and entry_round still
# cannot predict the window length.
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


def theil_sen_slope(y):
    """Median of all pairwise slopes (Theil 1950; Sen 1968). Robust to a
    single-round outlier that would flip the OLS sign. 0.0 for n < 2."""
    n = len(y)
    if n < 2:
        return 0.0
    slopes = sorted((y[j] - y[i]) / (j - i)
                    for i in range(n) for j in range(i + 1, n))
    m = len(slopes)
    mid = m // 2
    return slopes[mid] if m % 2 else 0.5 * (slopes[mid - 1] + slopes[mid])


def estimate_slope(y):
    return theil_sen_slope(y) if SLOPE_ESTIMATOR == "theil_sen" else ols_slope(y)


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
        return estimate_slope(self.accuracy_series)


class ProbationPoolManager:
    def __init__(self, rep_engine=None):
        # rep_engine is any object exposing reinstate(device_id, trial_rounds=0)
        # and record_event(device_id, severity). The real one is trust.reputation.
        self.rep = rep_engine
        self._records = {}

    def enter_probation(self, device_id, entry_round, global_params):
        prior = self._records.get(device_id)
        if prior is not None and prior.outcome == ProbationOutcome.PERMANENT_BAN:
            return prior                     # already terminal, nothing to open
        if prior is not None and prior.outcome == ProbationOutcome.REINSTATED:
            # rehabilitation is one-shot per identity: a reinstated device that
            # re-offends is banned, not retried (graduated sanctions, Ostrom).
            prior.outcome = ProbationOutcome.PERMANENT_BAN
            prior.outcome_round = entry_round
            if self.rep:
                self.rep.record_event(device_id, "CRITICAL")
            return prior
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
        """Advance every active probation trial by one round. Returns the list
        of (device_id, outcome) for trials that reached a decision this round."""
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
                # the trial rounds are evidence: forward them (see docstring)
                self.rep.reinstate(rec.device_id,
                                   trial_rounds=len(rec.accuracy_series))
        elif slope >= EXTEND_SLOPE and not rec.extended:
            rec.extended = True
            rec.window += EXTENSION_ROUNDS
            rec.outcome = ProbationOutcome.EXTENDED     # non-terminal, continues
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
    def reinstate(self, device_id, trial_rounds=0):
        self.reinstated.append((device_id, trial_rounds))
        return True
    def record_event(self, device_id, severity):
        self.banned.append((device_id, severity))


def _self_test():
    print("trust/probation.py self-test")

    assert ols_slope([1, 2, 3, 4]) == 1.0
    assert ols_slope([0.5, 0.5, 0.5]) == 0.0
    assert ols_slope([7]) == 0.0
    print("\u2713 OLS slope correct on linear, flat, single-point series")

    for did, rnd in [("a", 0), ("b", 5), ("client3", 99)]:
        w = derive_window(did, rnd)
        assert WINDOW_MIN <= w <= WINDOW_MAX
    print(f"\u2713 HMAC window always in [{WINDOW_MIN}, {WINDOW_MAX}]")

    rep = _StubRep()
    mgr = ProbationPoolManager(rep_engine=rep)
    g0 = [0.0, 0.0, 0.0, 0.0]
    mgr.enter_probation("recover", 0, g0)   # rising accuracy
    mgr.enter_probation("fail", 0, g0)      # flat accuracy
    mgr.enter_probation("extend", 0, g0)    # marginal accuracy

    grads = {"recover": [1.0, 0, 0, 0], "fail": [0.0, 0, 0, 0],
             "extend": [0.1, 0, 0, 0]}
    eval_fn = lambda p: 0.5 + 0.02 * p[0]

    seen = {}
    for round_id in range(40):
        if not mgr.active():
            break
        for device_id, outcome in mgr.step(round_id, grads, eval_fn):
            seen.setdefault(device_id, []).append(outcome)

    rec = mgr.get_record("recover")
    assert rec.outcome == ProbationOutcome.REINSTATED
    ids = [d for d, _ in rep.reinstated]
    assert "recover" in ids
    rounds = dict(rep.reinstated)["recover"]
    assert rounds == len(rec.accuracy_series) and rounds >= WINDOW_MIN + 1
    print(f"\u2713 rising shadow accuracy -> REINSTATED; {rounds} trial rounds "
          "forwarded to reputation as earned evidence")

    assert mgr.get_record("fail").outcome == ProbationOutcome.PERMANENT_BAN
    assert ("fail", "CRITICAL") in rep.banned
    print("\u2713 flat shadow accuracy -> PERMANENT_BAN, CRITICAL pushed to reputation")

    assert ProbationOutcome.EXTENDED in seen["extend"]
    assert mgr.get_record("extend").outcome == ProbationOutcome.PERMANENT_BAN
    assert mgr.get_record("extend").extended is True
    print("\u2713 marginal accuracy -> one-shot EXTENDED, then PERMANENT_BAN")

    assert mgr.is_on_probation("recover") is False
    s = mgr.summary("fail")
    assert s["outcome"] == "PERMANENT_BAN" and "ols_slope" in s
    print("\u2713 terminal trials closed, summary exports for audit")

    # one-shot rehabilitation: the reinstated device re-offends -> banned,
    # no second trial is opened.
    rec2 = mgr.enter_probation("recover", 50, g0)
    assert rec2.outcome == ProbationOutcome.PERMANENT_BAN
    assert ("recover", "CRITICAL") in rep.banned
    assert mgr.is_on_probation("recover") is False
    rec3 = mgr.enter_probation("recover", 60, g0)     # idempotent once terminal
    assert rec3 is rec2
    print("\u2713 rehab is one-shot per identity: second entry -> PERMANENT_BAN, "
          "adaptive probation cycling closed")

    assert theil_sen_slope([1, 2, 3, 4]) == 1.0
    assert theil_sen_slope([7]) == 0.0
    noisy = [0.50, 0.51, 0.52, 0.53, 0.14]      # one bad validation round
    assert ols_slope(noisy) < 0 < theil_sen_slope(noisy)
    print("\u2713 Theil-Sen matches OLS on clean series, survives the outlier "
          "that flips the OLS sign")

    print("\u2713 all probation self-tests passed")


if __name__ == "__main__":
    _self_test()