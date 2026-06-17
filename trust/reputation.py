"""
trust/reputation.py

Reputation engine with a TIER-COUPLED response policy. This is the core of the
contribution: the severity and reversibility of a sanction depend on the
hardware-trust tier assigned at enrollment, not on behaviour alone.

  O2 anti-whitewashing  : a banned EK hash is retained; a returning banned identity
                          is re-banned at registration, so a ban cannot be reset.
  O3 quantified trust   : trust is the posterior expectation of a Beta distribution.
  O4 aggregator-agnostic: get_all_weights() returns dict[str, float].

ARITHMETIC (Bayesian beta reputation, Josang & Ismail 2002):

    T = (a0 + s) / (a0 + s + b0 + f)

s, f are accumulated good/bad evidence; (a0, b0) the prior. Every round is one
observation: a clean round adds 1 unit of good evidence, offenses add severity-
weighted bad evidence (MINOR 1, MAJOR 3, CRITICAL 8).

Hardware-informed priors (a0, b0) are set by enrollment tier, so strike tolerance
EMERGES from the posterior instead of a policy table: a fresh Tier-1 crosses
probation (T <= 0.5) at exactly its 2nd MAJOR, Tier-2 at its 1st, Tier-3 at any
offense.

ON-OFF / SLEEPER HARDENING. A naive forgetting factor is itself the attack
surface. Three mechanisms close both wash-out holes, every constant traceable to
a rule used elsewhere in DLTF (Sun et al. on-off defense; CONFIDANT recency;
Slovic 1993 trust asymmetry):

  M1 BOUNDED RECENT GOOD-EVIDENCE. s decays each round at a tier-coupled rate g,
     so it saturates at 1/(1-g): a clean history cannot bank unbounded cushion.
     Effective memory 10/5/3 rounds by tier mirrors the weight-cap hierarchy
     (memory ~ identity replacement cost).
  M2 EARNED, ASYMMETRIC FORGETTING. Bad evidence is STICKY: it fades only after
     FORGIVE_AFTER consecutive clean rounds, and only for a tier allowed to
     rehabilitate. A single good round never launders an offense.
  M3 SUSTAINED-OFFENSE ESCALATION. Two consecutive MAJORs escalate
     NON-COMPENSABLY, bypassing the trust score, so a high-s veteran sleeper is
     still caught in two rounds.

tpm/common.py is the canonical source of the Tier enum. A local fallback is kept
only so this module self-tests standalone before the package is assembled.
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


# THE NOVELTY. Response policy keyed on the hardware-trust tier.
#   PRIORS     : Beta prior (a0, b0); a manufacturer-certified TPM is itself
#                evidence of accountability, so it starts with more good prior.
#   TIER_CAP   : max aggregation weight, independent of trust.
#   REHAB      : whether a sanctioned device of this tier may be rehabilitated.
#   GAMMA_GOOD : M1 recency decay; effective memory 1/(1-g) = 10 / 5 / 3 rounds.
#   FORGET     : M2 decay applied to bad evidence once forgiveness is earned.
PRIORS = {Tier.HARDWARE: (8.0, 2.0), Tier.TPM_RESIDENT: (4.0, 2.0),
          Tier.SOFTWARE: (2.0, 2.0)}
TIER_CAP = {Tier.HARDWARE: 1.0, Tier.TPM_RESIDENT: 0.5, Tier.SOFTWARE: 0.1}
REHAB = {Tier.HARDWARE: True, Tier.TPM_RESIDENT: False, Tier.SOFTWARE: False}
GAMMA_GOOD = {Tier.HARDWARE: 0.90, Tier.TPM_RESIDENT: 0.80, Tier.SOFTWARE: 0.67}
FORGET = {Tier.HARDWARE: 0.95, Tier.TPM_RESIDENT: 1.0, Tier.SOFTWARE: 1.0}

FORGIVE_AFTER = 5          # consecutive clean rounds before bad evidence may fade
MAJOR_RUN_TO_ESCALATE = 2  # consecutive MAJORs -> non-compensable escalation (M3)

GOOD_EVIDENCE = {"POSITIVE": 1.0, "NEUTRAL": 1.0}
BAD_EVIDENCE = {"MINOR": 1.0, "MAJOR": 3.0, "CRITICAL": 8.0}

PROBATION_T = 0.5          # trust at or below -> probation review
BAN_T = 0.3                # trust at or below -> ban
REINSTATE_T = 0.55         # closed-form target trust on reinstatement
PROBATION_WEIGHT_CAP = 0.1


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
        return (a0 + self.s) / (a0 + self.s + b0 + self.f)


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
        g = GAMMA_GOOD[d.tier]

        if severity in GOOD_EVIDENCE:
            d.s = g * d.s + GOOD_EVIDENCE[severity]    # M1: bounded, recency-weighted
            d.clean_run += 1
            d.major_run = 0
            if REHAB[d.tier] and d.clean_run >= FORGIVE_AFTER:
                d.f *= FORGET[d.tier]                  # M2: earned, asymmetric forgetting
        else:
            d.s = g * d.s
            d.f += BAD_EVIDENCE[severity]
            d.clean_run = 0
            d.major_run = d.major_run + 1 if severity == "MAJOR" else 0

        self._transition(d, severity)
        return d.status

    def _transition(self, d, severity):
        if severity == "CRITICAL" or d.trust <= BAN_T:             # non-compensable
            self._ban(d)
            return
        if d.major_run >= MAJOR_RUN_TO_ESCALATE:                   # M3
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

    def reinstate(self, device_id):
        d = self._dev[device_id]
        if d.status == Status.PROBATION and REHAB[d.tier]:
            a0, b0 = PRIORS[d.tier]
            need_a = (REINSTATE_T / (1.0 - REINSTATE_T)) * (b0 + d.f)
            d.s = max(d.s, need_a - a0)                # closed-form lift to T >= 0.55
            d.status = Status.ACTIVE
            d.clean_run = 0
            d.major_run = 0
            return True
        return False

    def get_status(self, device_id):
        return self._dev[device_id].status

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
    e = ReputationEngine()
    e.register("hw", Tier.HARDWARE, "ek_hw")
    e.register("tr", Tier.TPM_RESIDENT, "ek_tr")
    e.register("sw", Tier.SOFTWARE, "ek_sw")
    assert abs(e._dev["hw"].trust - 0.8) < 1e-9
    assert abs(e._dev["tr"].trust - 4 / 6) < 1e-9
    assert abs(e._dev["sw"].trust - 0.5) < 1e-9
    print("\u2713 hardware-informed priors: starting trust 0.80 / 0.67 / 0.50 by tier")

    assert e.record_event("hw", "MAJOR") == Status.ACTIVE
    assert e.record_event("hw", "MAJOR") == Status.PROBATION
    assert abs(e._dev["hw"].trust - 0.5) < 1e-9
    print("\u2713 emergent policy preserved: fresh Tier-1 probation at the 2nd MAJOR")

    assert e.record_event("tr", "MINOR") == Status.ACTIVE
    assert e.record_event("tr", "MAJOR") == Status.BANNED
    assert e.record_event("sw", "MINOR") == Status.BANNED
    print("\u2713 emergent policy: Tier-2 one MAJOR strike, Tier-3 zero tolerance")

    b = ReputationEngine()
    b.register("vet", Tier.HARDWARE, "ek_vet")
    for _ in range(100):
        b.record_event("vet", "NEUTRAL")
    cap = 1.0 / (1.0 - GAMMA_GOOD[Tier.HARDWARE])
    assert b._dev["vet"].s < cap + 1e-6 and b._dev["vet"].s > 9.0
    print(f"\u2713 M1 bounded buffer: 100 clean rounds saturate s at "
          f"{b._dev['vet'].s:.2f} (cap {cap:.0f}), not 100")

    assert b.record_event("vet", "MAJOR") == Status.ACTIVE
    assert b._dev["vet"].trust > 0.5
    assert b.record_event("vet", "MAJOR") == Status.PROBATION
    print("\u2713 M3 sleeper defense: veteran (high banked trust) caught at the 2nd MAJOR")

    o = ReputationEngine()
    o.register("onoff", Tier.HARDWARE, "ek_on")
    o.record_event("onoff", "MAJOR")
    f_atk = o._dev["onoff"].f
    for _ in range(FORGIVE_AFTER - 1):
        o.record_event("onoff", "NEUTRAL")
    assert o._dev["onoff"].f == f_atk
    print(f"\u2713 M2 on-off blocked: {FORGIVE_AFTER - 1} clean rounds launder nothing "
          f"(f stays {f_atk:.1f})")

    for _ in range(20):
        o.record_event("onoff", "NEUTRAL")
    assert o._dev["onoff"].f < f_atk and o._dev["onoff"].trust > 0.8
    print(f"\u2713 M2 earned forgiveness: a sustained streak fades the offense "
          f"(f {f_atk:.1f} -> {o._dev['onoff'].f:.2f})")

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
    assert e2.register("x2", Tier.HARDWARE, "ek_x") == Status.BANNED
    print("\u2713 CRITICAL non-compensable even for a veteran; banned EK stays banned (O2)")

    p = ReputationEngine()
    p.register("p", Tier.HARDWARE, "ek_p")
    p.record_event("p", "MAJOR"); p.record_event("p", "MAJOR")
    assert p.get_status("p") == Status.PROBATION
    assert p.get_weight("p") <= PROBATION_WEIGHT_CAP
    assert p.reinstate("p") is True
    assert p.get_status("p") == Status.ACTIVE and p._dev["p"].trust >= 0.55
    assert p._dev["p"].major_run == 0 and p._dev["p"].clean_run == 0
    print("\u2713 probation cap, closed-form reinstatement, streak reset on re-entry")

    print("\u2713 all reputation self-tests passed")


if __name__ == "__main__":
    _self_test()