"""
trust/filter.py

Gradient anomaly detection. Detection is NOT the contribution, so this layer is
assembled from established techniques. It emits the severity strings that
reputation.py consumes, which is its only contract with the rest of the system.

Four stages, one per attack class, combined by a max-severity rule:
  Stage 1  norm clipping vs the median norm           -> MINOR     (scale attack)
  Stage 2  cosine deviation from a robust reference    -> MAJOR     (targeted poisoning)
  Stage 3  FoolsGold sustained pairwise similarity      -> CRITICAL  (Sybil collusion)
  Stage 4  temporal self-consistency                   -> MAJOR     (sleeper agent)

Robustness choices that matter at the viva:
  - The reference direction is the coordinate median over devices that held
    positive weight last round, so zero-weight Sybils cannot drag it.
  - Stage 3 compares CURRENT-round updates, not cumulative history, with a high
    threshold and a sustained-rounds requirement. Honest clients share a descent
    direction but inject fresh per-round variation, so they stay below threshold;
    colluding Sybils submit near-identical updates every round and trip it.
  - Stages 2 and 4 use conservative thresholds calibrated for realistic
    signal-to-noise: honest per-round updates can be noise-dominated (honest
    pairwise cosine ~0.2 under non-IID data), and a single noisy round must not
    burn a one-strike Tier 2 identity. Stage 4 additionally requires the flip
    to persist 2 consecutive rounds; noise does not anti-correlate twice in a
    row, persistent attackers do. The eval sweep maps this FPR/latency curve.
  - History is written AFTER classification, never before.

Severities match trust.reputation.EventTier names; no import is needed because
record_event accepts the strings directly.
"""
from collections import deque
from dataclasses import dataclass
import numpy as np

# Thresholds. Operating points are calibrated empirically in eval/ (sweep).
NORM_CLIP_FACTOR = 2.5
COSINE_MEDIAN_THRESHOLD = -0.45
FOOLSGOLD_SIM = 0.95
FOOLSGOLD_SUSTAINED = 2
TEMPORAL_FLIP = -0.45
TEMPORAL_SUSTAINED = 2
MIN_HISTORY = 3
REF_MIN_WEIGHT = 0.0
HISTORY_WINDOW = 10

_ORDER = {"NEUTRAL": 0, "MINOR": 1, "MAJOR": 2, "CRITICAL": 3}


def _worse(a, b):
    return a if _ORDER[a] >= _ORDER[b] else b


def _cos(a, b):
    na, nb = float(np.linalg.norm(a)), float(np.linalg.norm(b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


@dataclass
class Classification:
    severity: str
    stage: int
    reason: str


class GradientFilter:
    def __init__(self, window=HISTORY_WINDOW):
        self.window = window
        self._hist = {}            # device_id -> deque of gradient arrays
        self._sustain = {}         # device_id -> consecutive high-similarity rounds
        self._flip_sustain = {}    # device_id -> consecutive temporal-flip rounds

    def classify(self, round_id, gradients, prev_weights=None):
        """gradients: dict[device_id, list[float]]. prev_weights: dict[device_id, float]
        from the previous round. Returns dict[device_id, Classification]."""
        prev_weights = prev_weights or {}
        ids = list(gradients.keys())
        arr = {i: np.asarray(gradients[i], dtype=np.float64) for i in ids}

        # Robust reference over prior-trusted contributors, leave-one-out:
        # excluding the evaluated client stops an attacker from diluting the
        # very reference it is scored against.
        contribs = [i for i in ids if prev_weights.get(i, 0.0) > REF_MIN_WEIGHT] or ids
        cstack = np.stack([arr[i] for i in contribs])
        norms = {i: float(np.linalg.norm(arr[i])) for i in ids}
        med_norm = float(np.median(list(norms.values()))) or 1.0

        def _ref_for(i):
            others = [arr[j] for j in contribs if j != i]
            if not others:
                return np.median(cstack, axis=0)
            return np.median(np.stack(others), axis=0)

        out = {}
        for i in ids:
            sev, stage, reason = "NEUTRAL", 0, "within bounds"

            if norms[i] > NORM_CLIP_FACTOR * med_norm:
                sev = _worse(sev, "MINOR")
                stage, reason = 1, f"norm {norms[i]:.2f} exceeds {NORM_CLIP_FACTOR}x median"

            c_ref = _cos(arr[i], _ref_for(i))
            if c_ref < COSINE_MEDIAN_THRESHOLD:
                sev = _worse(sev, "MAJOR")
                stage, reason = 2, f"cosine {c_ref:.2f} below {COSINE_MEDIAN_THRESHOLD}"

            hist = self._hist.get(i)
            if hist is not None and len(hist) >= MIN_HISTORY:
                own = np.mean(np.stack(list(hist)), axis=0)
                c_self = _cos(arr[i], own)
                if c_self < TEMPORAL_FLIP:
                    self._flip_sustain[i] = self._flip_sustain.get(i, 0) + 1
                else:
                    self._flip_sustain[i] = 0
                if self._flip_sustain.get(i, 0) >= TEMPORAL_SUSTAINED:
                    sev = _worse(sev, "MAJOR")
                    stage, reason = 4, (f"temporal flip, cosine {c_self:.2f} sustained "
                                        f"{self._flip_sustain[i]} rounds")

            out[i] = Classification(sev, stage, reason)

        self._foolsgold(arr, out)

        for i in ids:
            self._hist.setdefault(i, deque(maxlen=self.window)).append(arr[i])
        return out

    def _foolsgold(self, arr, out):
        # Current-round pairwise similarity, sustained across rounds. Identical
        # colluding updates trip this; correlated honest updates do not.
        ids = list(arr.keys())
        for i in ids:
            max_sim = max((_cos(arr[i], arr[j]) for j in ids if j != i), default=0.0)
            self._sustain[i] = self._sustain.get(i, 0) + 1 if max_sim >= FOOLSGOLD_SIM else 0
            if self._sustain[i] >= FOOLSGOLD_SUSTAINED:
                out[i] = Classification(
                    _worse(out[i].severity, "CRITICAL"), 3,
                    f"sybil similarity {max_sim:.2f} sustained {self._sustain[i]} rounds")


def _grad(dim, bulk, scale=1.0, noise=0.0, seed=0):
    """Synthetic gradient: a shared descent direction plus per-device noise."""
    rng = np.random.default_rng(seed)
    v = np.zeros(dim)
    for k in bulk:
        v[k] = 1.0
    v = v / (np.linalg.norm(v) or 1.0)
    return (scale * v + noise * rng.standard_normal(dim)).tolist()


def _self_test():
    print("trust/filter.py self-test")
    dim, BULK = 6, [0, 1, 2]

    # Honest baseline: shared descent direction, distinct per-device noise.
    gf = GradientFilter()
    honest = {f"h{k}": _grad(dim, BULK, 1.0, 0.6, seed=k) for k in range(4)}
    res = gf.classify(0, honest, {})
    assert all(c.severity == "NEUTRAL" for c in res.values())
    print("✓ honest baseline -> all NEUTRAL (no false positives)")

    # Scale attack: aligned direction, large norm.
    gf = GradientFilter()
    g = {f"h{k}": _grad(dim, BULK, 1.0, 0.6, seed=k) for k in range(4)}
    g["bad"] = _grad(dim, BULK, 8.0, 0.0)
    res = gf.classify(0, g, {})
    assert res["bad"].severity == "MINOR" and res["bad"].stage == 1
    print("✓ scale attack -> MINOR (stage 1)")

    # Targeted poisoning: points against the consensus.
    gf = GradientFilter()
    g = {f"h{k}": _grad(dim, BULK, 1.0, 0.6, seed=k) for k in range(4)}
    g["bad"] = _grad(dim, BULK, -1.0, 0.0)
    res = gf.classify(0, g, {})
    assert res["bad"].severity == "MAJOR" and res["bad"].stage == 2
    print("✓ targeted poisoning -> MAJOR (stage 2)")

    # Sybil pair: identical updates each round, flagged once sustained.
    gf = GradientFilter()
    sybil = _grad(dim, [3, 4, 5], 1.0, 0.5, seed=777)
    base = {f"h{k}": _grad(dim, BULK, 1.0, 0.6, seed=k) for k in range(3)}
    g = dict(base); g["s1"] = list(sybil); g["s2"] = list(sybil)
    r0 = gf.classify(0, g, {})
    assert r0["s1"].severity != "CRITICAL"            # not yet sustained
    g = dict(base); g["s1"] = list(sybil); g["s2"] = list(sybil)
    r1 = gf.classify(1, g, {})
    assert r1["s1"].severity == "CRITICAL" and r1["s2"].severity == "CRITICAL"
    assert all(r1[h].severity != "CRITICAL" for h in base)
    print("✓ sybil pair -> CRITICAL after sustained rounds, honest untouched (stage 3)")

    # Sleeper: looks honest for several rounds, then flips direction.
    gf = GradientFilter()
    for rnd in range(3):
        g = {f"h{k}": _grad(dim, BULK, 1.0, 0.6, seed=10 * rnd + k) for k in range(4)}
        g["sleep"] = _grad(dim, BULK, 1.0, 0.2, seed=99 + rnd)
        gf.classify(rnd, g, {})
    g = {f"h{k}": _grad(dim, BULK, 1.0, 0.6, seed=900 + k) for k in range(4)}
    g["sleep"] = _grad(dim, BULK, -1.0, 0.0)          # wake up, flip
    res = gf.classify(3, g, {})
    assert res["sleep"].severity == "MAJOR"
    print("✓ sleeper wake-up -> MAJOR (consensus cosine catches the full flip)")

    # Stage-4-specific sleeper: stays plausible vs consensus, contradicts own
    # history. Personal direction e5 reverses while the small bulk part stays.
    gf = GradientFilter()
    e5 = [5]
    for rnd in range(3):
        g = {f"h{k}": _grad(dim, BULK, 1.0, 0.3, seed=40 * rnd + k) for k in range(4)}
        g["sly"] = [0.3 * a + b for a, b in zip(_grad(dim, BULK, 1.0, 0.0),
                                                _grad(dim, e5, 1.0, 0.0))]
        gf.classify(rnd, g, {})
    flip = [0.3 * a - b for a, b in zip(_grad(dim, BULK, 1.0, 0.0),
                                        _grad(dim, e5, 1.0, 0.0))]
    g = {f"h{k}": _grad(dim, BULK, 1.0, 0.3, seed=400 + k) for k in range(4)}
    g["sly"] = list(flip)
    r3 = gf.classify(3, g, {})
    assert r3["sly"].severity == "NEUTRAL"            # first flip round: not yet
    g = {f"h{k}": _grad(dim, BULK, 1.0, 0.3, seed=440 + k) for k in range(4)}
    g["sly"] = list(flip)
    r4 = gf.classify(4, g, {})
    assert r4["sly"].severity == "MAJOR" and r4["sly"].stage == 4
    print("✓ consensus-plausible flip caught by stage 4 only after sustaining")

    # Realistic-SNR regression: noisy honest clients, many rounds, zero flags.
    # Encodes the false-positive bug found during eval bring-up.
    gf = GradientFilter()
    for rnd in range(12):
        g = {f"h{k}": _grad(20, [0, 1, 2], 1.0, 0.5, seed=1000 * rnd + k)
             for k in range(7)}
        res = gf.classify(rnd, g, {})
        bad = {i: c.severity for i, c in res.items() if c.severity != "NEUTRAL"}
        assert not bad, (rnd, bad)
    print("✓ realistic SNR, 7 honest x 12 rounds -> zero false positives")

    print("✓ all filter self-tests passed")


if __name__ == "__main__":
    _self_test()