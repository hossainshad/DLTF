"""
trust/reputation.py

Bayesian reputation engine in subjective-logic form (Josang 2001; Josang &
Ismail 2002) with a TIER-COUPLED response policy: sanction severity and
reversibility depend on the hardware-trust tier assigned at enrollment
(identity replacement cost), not on behaviour alone.

  O2 anti-whitewashing  : bans bind to the EK hash; a returning banned identity
                          is re-banned at registration.
  O3 quantified trust   : T = E(opinion) = b + a*u = (a0+s)/(a0+b0+s+f).
  O4 aggregator-agnostic: get_all_weights() returns dict[str, float].

DERIVATION CHAIN. Every constant below traces to a citation [CITED], a stated
rule plus algebra [DERIVED], or a sweep-defended engineering choice [ENG]:

  B0 = 2              prior doubt for EVERY tier = Josang's non-informative
                      prior weight [CITED]. Identity proof says nothing about
                      future behaviour, so doubt never shrinks with tier.
  W_MINOR = 1         one observation = one count [CITED].
  W_MAJOR = 3         noise separation: the detector's sustained window is 2
                      rounds, so 2 spurious MINORs must stay below 1 deliberate
                      MAJOR; minimal integer with 2*1 < w [DERIVED].
  A0(T1) = B0+2w = 8  policy P1: fresh Tier-1 reaches probation (T <= 0.5) at
                      EXACTLY its 2nd MAJOR. Start trust 0.80 is an OUTPUT of
                      this rule, not an input [DERIVED].
  A0(T2) = A0(T1)/2   activation-only proof earns half credit (mirrors the 0.5
                      cap). Verified: sanctioned by 1 MAJOR (4/9 = 0.44),
                      survives 1 MINOR (4/7 = 0.57) [DERIVED].
  A0(T3) = B0 = 2     principle of insufficient reason, a = 0.5 [CITED]. Zero
                      tolerance EMERGES: one MINOR puts 2/5 = 0.40 <= 0.5.
  K = A0 + B0         prior mass; RULE: memory span N = K (prior mass and
                      memory are the same currency, rounds of evidence), so
                      gamma = 1 - 1/K and T_max = 1 - 1/K [DERIVED].
  PROBATION_T = 0.5   indifference point; Kang's trusted-worker threshold
                      [CITED].
  REINSTATE_T = 0.55  reinstatement survives one unit of noise:
                      0.5 * (1 + 1/K1) exactly [DERIVED].
  BAN_T = 0.3         redundant backstop; probation fires first on every
                      reachable trajectory (6 MINORs vs 17) [ENG, sweep].
  CRITICAL            a rule, not a weight: confirmed Sybil evidence is
                      identity abuse; any finite weight would let banked
                      history offset it (the sleeper exploit) [DERIVED].
  M3 = 2              banked history buys weight, not strikes: veteran strike
                      budget = fresh budget from P1 (Sun et al. on-off)
                      [DERIVED].
  FORGIVE_AFTER = 5   probation W_MIN + 1: informal forgetting must not
                      undercut the formal trial [DERIVED].
  FORGET = 0.95       distrust fades at half the rate trust decays:
                      1 - (1-gamma1)/2 (Slovic asymmetry) [ENG, sweep].

tpm/common.py is the canonical source of the Tier enum. A local fallback is
kept only so this module self-tests standalone.
"""
from enum import Enum
from dataclasses import dataclass

try:
    from tpm.common import Tier
except Exception:
    from enum import IntEnum
    class Tier(IntEnum):
        HARDWARE = 1
        TPM_RESIDENT = 2
        SOFTWARE = 3


class EventTier(str, Enum):
    POSITIVE = "POSITIVE"
    NEUTRAL = "NEUTRAL"
    MINOR = "MINOR"
    MAJOR = "MAJOR"
    CRITICAL = "CRITICAL"


class Status(str, Enum):
    ACTIVE = "ACTIVE"
    PROBATION = "PROBATION"
    BANNED = "BANNED"


# ---- derived constants (see chain in the module docstring) -------------------
B0 = 2.0                                          # [CITED] Josang prior weight
W_MINOR = 1.0                                     # [CITED] unit offence
W_MAJOR = 3.0                                     # [DERIVED] 2 noise MINORs < 1 MAJOR

A0 = {Tier.HARDWARE: B0 + 2.0 * W_MAJOR,          # 8  [DERIVED] probation at 2nd MAJOR
      Tier.TPM_RESIDENT: (B0 + 2.0 * W_MAJOR) / 2.0,  # 4  [DERIVED] half credit
      Tier.SOFTWARE: B0}                          # 2  [CITED] insufficient reason
PRIORS = {t: (A0[t], B0) for t in A0}
K = {t: A0[t] + B0 for t in A0}                   # prior mass = memory span (rule N = K)
GAMMA_GOOD = {t: 1.0 - 1.0 / K[t] for t in A0}    # [DERIVED] 0.900 / 0.833 / 0.750

TIER_CAP = {Tier.HARDWARE: 1.0, Tier.TPM_RESIDENT: 0.5, Tier.SOFTWARE: 0.1}  # [ENG, bounded]
REHAB = {Tier.HARDWARE: True, Tier.TPM_RESIDENT: False, Tier.SOFTWARE: False}
FORGET = {Tier.HARDWARE: 1.0 - (1.0 - GAMMA_GOOD[Tier.HARDWARE]) / 2.0,      # 0.95 [ENG]
          Tier.TPM_RESIDENT: 1.0, Tier.SOFTWARE: 1.0}                        # 1.0 = never

FORGIVE_AFTER = 5           # [DERIVED] probation W_MIN + 1
MAJOR_RUN_TO_ESCALATE = 2   # [DERIVED] M3: veteran strike budget = fresh budget

GOOD_EVIDENCE = {"POSITIVE": 1.0, "NEUTRAL": 1.0}
BAD_EVIDENCE = {"MINOR": W_MINOR, "MAJOR": W_MAJOR}   # CRITICAL is a rule, not a weight

PROBATION_T = 0.5                                            # [CITED]
REINSTATE_T = PROBATION_T * (1.0 + 1.0 / K[Tier.HARDWARE])   # 0.55 [DERIVED]
BAN_T = 0.3                                                  # [ENG] backstop
PROBATION_WEIGHT_CAP = TIER_CAP[Tier.SOFTWARE]   # suspect <= unproven identity [DERIVED]


@dataclass
class Device:
    device_id: str
    tier: Tier
    ek_hash: str
    s: float
    f: float
    status: Status
    clean_run: int = 0     # consecutive clean rounds (drives M2 earned forgetting)
    major_run: int = 0     # consecutive MAJORs (drives M3 sustained escalation)

    @property
    def trust(self):
        a0, b0 = PRIORS[self.tier]
        return (a0 + self.s) / (a0 + b0 + self.s + self.f)

    @property
    def opinion(self):
        """Subjective-logic opinion (b, d, u, a); trust == b + a*u exactly.
        u = K/(K+s+f) is the sample-size term: it shrinks as evidence grows."""
        a0, b0 = PRIORS[self.tier]
        n = a0 + b0 + self.s + self.f
        return {"b": self.s / n, "d": self.f / n,
                "u": (a0 + b0) / n, "a": a0 / (a0 + b0)}


class ReputationEngine:
    def __init__(self):
        self._dev = {}
        self._banned_ek = set()

    def register(self, device_id, tier, ek_hash=None):
        tier = Tier(tier)
        banned = ek_hash is not None and ek_hash in self._banned_ek
        d = Device(device_id, tier, ek_hash, 0.0, 0.0,
                   Status.BANNED if banned else Status.ACTIVE)     # O2
        self._dev[device_id] = d
        return d.status

    def record_event(self, device_id, severity):
        d = self._dev[device_id]
        if d.status == Status.BANNED:
            return d.status
        if hasattr(severity, "value"):
            severity = severity.value

        if severity == "CRITICAL":         # rule, non-compensable, no arithmetic
            d.clean_run = 0
            d.major_run = 0
            self._ban(d)
            return d.status

        g = GAMMA_GOOD[d.tier]
        if severity in GOOD_EVIDENCE:
            d.s = g * d.s + GOOD_EVIDENCE[severity]    # M1: bounded recency
            d.clean_run += 1
            d.major_run = 0
            if REHAB[d.tier] and d.clean_run >= FORGIVE_AFTER:
                d.f *= FORGET[d.tier]                  # M2: earned, asymmetric
        else:
            d.s = g * d.s
            d.f += BAD_EVIDENCE[severity]
            d.clean_run = 0
            d.major_run = d.major_run + 1 if severity == "MAJOR" else 0

        self._transition(d)
        return d.status

    def _transition(self, d):
        if d.trust <= BAN_T:                            # backstop
            self._ban(d)
            return
        if d.major_run >= MAJOR_RUN_TO_ESCALATE:        # M3, bypasses the score
            if REHAB[d.tier]:
                d.status = Status.PROBATION
            else:
                self._ban(d)
            return
        if d.status == Status.ACTIVE and d.trust <= PROBATION_T:
            if REHAB[d.tier]:
                d.status = Status.PROBATION
            else:
                self._ban(d)

    def _ban(self, d):
        d.status = Status.BANNED
        if d.ek_hash is not None:
            self._banned_ek.add(d.ek_hash)

    def reinstate(self, device_id, trial_rounds=0):
        """Reinstate a probated device. The passed probation rounds are credited
        as earned good evidence (the trial IS evidence), then trust is floored
        at REINSTATE_T = 0.55 via the closed form. Stronger proven recovery
        therefore returns with proportionally higher trust."""
        d = self._dev[device_id]
        if d.status == Status.PROBATION and REHAB[d.tier]:
            a0, b0 = PRIORS[d.tier]
            d.s += float(trial_rounds)
            need_s = (REINSTATE_T / (1.0 - REINSTATE_T)) * (b0 + d.f) - a0
            d.s = max(d.s, need_s)                     # floor: T >= 0.55
            d.status = Status.ACTIVE
            d.clean_run = 0
            d.major_run = 0
            return True
        return False

    def get_status(self, device_id):
        return self._dev[device_id].status

    def get_opinion(self, device_id):
        return self._dev[device_id].opinion

    def rank(self, device_ids=None):
        """Josang Def. 10 ordering: highest trust first; ties broken by least
        uncertainty, so at equal trust the client with more evidence wins.
        Banned devices are excluded."""
        ids = list(self._dev) if device_ids is None else list(device_ids)
        ids = [i for i in ids if self._dev[i].status != Status.BANNED]
        return sorted(ids, key=lambda i: (-self._dev[i].trust,
                                          self._dev[i].opinion["u"]))

    def get_weight(self, device_id):
        d = self._dev[device_id]
        if d.status == Status.BANNED:
            return 0.0
        cap = TIER_CAP[d.tier]
        if d.status == Status.PROBATION:
            cap = min(cap, PROBATION_WEIGHT_CAP)
        return round(cap * d.trust, 4)

    def get_all_weights(self):
        return {i: self.get_weight(i) for i, d in self._dev.items()
                if d.status != Status.BANNED}

    def banned_ek_hashes(self):
        return set(self._banned_ek)


def _self_test():
    print("trust/reputation.py self-test")

    assert PRIORS[Tier.HARDWARE] == (8.0, 2.0)
    assert PRIORS[Tier.TPM_RESIDENT] == (4.0, 2.0)
    assert PRIORS[Tier.SOFTWARE] == (2.0, 2.0)
    assert abs(GAMMA_GOOD[Tier.HARDWARE] - 0.90) < 1e-9
    assert abs(GAMMA_GOOD[Tier.TPM_RESIDENT] - (1.0 - 1.0 / 6.0)) < 1e-9
    assert abs(GAMMA_GOOD[Tier.SOFTWARE] - 0.75) < 1e-9
    assert abs(REINSTATE_T - 0.55) < 1e-9
    assert abs(FORGET[Tier.HARDWARE] - 0.95) < 1e-9
    assert "CRITICAL" not in BAD_EVIDENCE
    assert PROBATION_WEIGHT_CAP == TIER_CAP[Tier.SOFTWARE] == 0.1
    print("\u2713 derivation chain reproduces: priors (8,2)/(4,2)/(2,2), "
          "gamma = 1-1/K, theta_R = 0.55, FORGET = 0.95")

    e = ReputationEngine()
    e.register("hw", Tier.HARDWARE, "ek_hw")
    e.register("tr", Tier.TPM_RESIDENT, "ek_tr")
    e.register("sw", Tier.SOFTWARE, "ek_sw")
    assert abs(e._dev["hw"].trust - 0.8) < 1e-9
    assert abs(e._dev["tr"].trust - 4 / 6) < 1e-9
    assert abs(e._dev["sw"].trust - 0.5) < 1e-9
    o = e.get_opinion("hw")
    assert abs(o["b"] + o["d"] + o["u"] - 1.0) < 1e-9
    assert abs((o["b"] + o["a"] * o["u"]) - e._dev["hw"].trust) < 1e-9
    print("\u2713 starting trust 0.80/0.67/0.50 = base rates; opinion sane, T = b + a*u")

    assert e.record_event("hw", "MAJOR") == Status.ACTIVE
    assert e.record_event("hw", "MAJOR") == Status.PROBATION
    assert abs(e._dev["hw"].trust - 0.5) < 1e-9
    print("\u2713 P1 emergent: fresh Tier-1 hits probation at exactly the 2nd MAJOR")

    assert e.record_event("tr", "MINOR") == Status.ACTIVE   # survives noise
    assert e.record_event("tr", "MAJOR") == Status.BANNED   # P2
    assert e.record_event("sw", "MINOR") == Status.BANNED   # P3 emerges from a=0.5
    print("\u2713 P2/P3 emergent: Tier-2 survives a MINOR, one MAJOR strike; "
          "Tier-3 zero tolerance")

    b = ReputationEngine()
    b.register("vet", Tier.HARDWARE, "ek_vet")
    for _ in range(100):
        b.record_event("vet", "NEUTRAL")
    cap = K[Tier.HARDWARE]                       # s_max = 1/(1-gamma) = K
    assert 9.0 < b._dev["vet"].s < cap + 1e-6
    assert b._dev["vet"].trust < 1.0 - 1.0 / cap + 1e-9   # T_max = 1 - 1/K
    print(f"\u2713 M1 bounded memory: 100 clean rounds saturate s at "
          f"{b._dev['vet'].s:.2f} (cap {cap:.0f}); T_max = {1-1/cap:.2f}")

    assert b.record_event("vet", "MAJOR") == Status.ACTIVE
    st = b.record_event("vet", "MAJOR")
    assert st == Status.PROBATION and b._dev["vet"].trust > 0.5
    print("\u2713 M3 sleeper defense: veteran probated at the 2nd MAJOR even though "
          f"its score ({b._dev['vet'].trust:.3f}) is still above 0.5")

    o = ReputationEngine()
    o.register("onoff", Tier.HARDWARE, "ek_on")
    o.record_event("onoff", "MAJOR")
    f_atk = o._dev["onoff"].f
    for _ in range(FORGIVE_AFTER - 1):
        o.record_event("onoff", "NEUTRAL")
    assert o._dev["onoff"].f == f_atk
    for _ in range(20):
        o.record_event("onoff", "NEUTRAL")
    assert o._dev["onoff"].f < f_atk and o._dev["onoff"].trust > 0.8
    print(f"\u2713 M2 earned forgetting: {FORGIVE_AFTER - 1} clean rounds launder "
          f"nothing; a sustained streak fades f {f_atk:.1f} -> "
          f"{o._dev['onoff'].f:.2f}")

    t2 = ReputationEngine()
    t2.register("c", Tier.TPM_RESIDENT, "ek_c2")
    t2.record_event("c", "MINOR")
    f0 = t2._dev["c"].f
    for _ in range(50):
        t2.record_event("c", "NEUTRAL")
    assert t2._dev["c"].f == f0
    print("\u2713 tier-coupled: only accountable Tier-1 hardware earns fading")

    e2 = ReputationEngine()
    e2.register("x", Tier.HARDWARE, "ek_x")
    for _ in range(100):
        e2.record_event("x", "NEUTRAL")
    assert e2.record_event("x", "CRITICAL") == Status.BANNED
    assert e2._dev["x"].f == 0.0                       # rule, no arithmetic
    assert e2.register("x2", Tier.HARDWARE, "ek_x") == Status.BANNED
    print("\u2713 CRITICAL bans by rule (no dead weight), regardless of banked "
          "history; banned EK stays banned (O2)")

    p = ReputationEngine()
    p.register("p", Tier.HARDWARE, "ek_p")
    p.record_event("p", "MAJOR"); p.record_event("p", "MAJOR")
    assert p.get_status("p") == Status.PROBATION
    assert p.get_weight("p") <= PROBATION_WEIGHT_CAP
    p.register("q", Tier.HARDWARE, "ek_q")
    p.record_event("q", "MAJOR"); p.record_event("q", "MAJOR")
    p.register("r", Tier.HARDWARE, "ek_r")
    p.record_event("r", "MAJOR"); p.record_event("r", "MAJOR")
    assert p.reinstate("r") is True                    # no trial credit: floor
    assert abs(p._dev["r"].trust - REINSTATE_T) < 1e-6
    assert p.reinstate("p", trial_rounds=6) is True
    assert p.reinstate("q", trial_rounds=9) is True
    assert p._dev["q"].trust > p._dev["p"].trust >= REINSTATE_T
    assert p._dev["p"].major_run == 0 and p._dev["p"].clean_run == 0
    print(f"\u2713 reinstatement: floor T = {REINSTATE_T}; trial rounds are "
          f"evidence, stronger recovery returns higher "
          f"({p._dev['q'].trust:.3f} > {p._dev['p'].trust:.3f})")

    rk = ReputationEngine()
    rk.register("new", Tier.HARDWARE, "ek_new")
    rk.register("old", Tier.HARDWARE, "ek_old")
    for _ in range(60):
        rk.record_event("old", "NEUTRAL")
    for _ in range(3):
        rk.record_event("new", "NEUTRAL")
    assert rk.rank() == ["old", "new"]
    assert rk.get_opinion("old")["u"] < rk.get_opinion("new")["u"]
    print(f"\u2713 fairness (Def. 10): veteran ({rk._dev['old'].trust:.3f}, "
          f"u={rk.get_opinion('old')['u']:.2f}) outranks newcomer "
          f"({rk._dev['new'].trust:.3f}, u={rk.get_opinion('new')['u']:.2f})")

    print("\u2713 all reputation self-tests passed")


if __name__ == "__main__":
    _self_test()
