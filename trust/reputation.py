"""
trust/reputation.py

Reputation state machine with a TIER-COUPLED response policy. This is the core of
the contribution: the severity and reversibility of a sanction depend on the
hardware-trust tier assigned at enrollment, not on behaviour alone.

  O2 anti-whitewashing  : a banned EK hash is retained; a returning banned identity
                          is re-banned at registration, so a ban cannot be reset.
  O3 quantified trust   : R is a deterministic bounded score with documented deltas.
  O4 aggregator-agnostic: get_all_weights() returns dict[str, float].

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

# Reputation scale and parameters (O3). Asymmetric deltas: trust is slow to earn,
# fast to lose. A single CRITICAL is unrecoverable by design.
R_INIT, R_MIN, R_MAX = 100.0, 0.0, 100.0
PROBATION_R = 50.0          # at or below -> probation review
BAN_R = 20.0                # at or below -> ban
PROBATION_WEIGHT_CAP = 0.1


class EventTier(str, Enum):
    POSITIVE = "POSITIVE"
    NEUTRAL = "NEUTRAL"
    MINOR = "MINOR"
    MAJOR = "MAJOR"
    CRITICAL = "CRITICAL"


DELTA = {
    EventTier.POSITIVE: +5.0,
    EventTier.NEUTRAL: 0.0,
    EventTier.MINOR: -10.0,
    EventTier.MAJOR: -25.0,
    EventTier.CRITICAL: -60.0,
}


class Status(str, Enum):
    ACTIVE = "ACTIVE"
    PROBATION = "PROBATION"
    BANNED = "BANNED"


# THE NOVELTY. Response policy keyed on the hardware-trust tier.
#   weight_cap         : max aggregation weight, independent of reputation.
#   major_to_probation : MAJOR strikes tolerated before a forced transition.
#   rehab              : may a probation device be reinstated, or is probation terminal?
# Tier 1 identities cannot be re-minted, so patience is safe: more slack, rehab allowed.
# Tier 2 and 3 identities are cheap to re-mint, so patience would be farmed: one strike,
# no rehab. Their damage is bounded instead by a low weight_cap.
POLICY = {
    Tier.HARDWARE:     {"weight_cap": 1.0, "major_to_probation": 2, "rehab": True},
    Tier.TPM_RESIDENT: {"weight_cap": 0.5, "major_to_probation": 1, "rehab": False},
    Tier.SOFTWARE:     {"weight_cap": 0.1, "major_to_probation": 1, "rehab": False},
}


def _clamp(x, lo, hi):
    return max(lo, min(hi, x))


@dataclass
class Device:
    device_id: str
    tier: Tier
    ek_hash: str
    reputation: float
    status: Status
    major_count: int


class ReputationEngine:
    """In-memory trust state. Ban persistence (EK hashes) is mirrored to the audit
    ledger elsewhere; kept in-process here so the engine self-tests alone."""

    def __init__(self):
        self._dev = {}
        self._banned_ek = set()

    def register(self, device_id, tier, ek_hash=None):
        tier = Tier(tier)
        if ek_hash is not None and ek_hash in self._banned_ek:
            d = Device(device_id, tier, ek_hash, BAN_R, Status.BANNED, 0)   # O2
        else:
            d = Device(device_id, tier, ek_hash, R_INIT, Status.ACTIVE, 0)
        self._dev[device_id] = d
        return d.status

    def record_event(self, device_id, severity):
        d = self._dev[device_id]
        if d.status == Status.BANNED:
            return d.status
        sev = EventTier(severity)
        d.reputation = _clamp(d.reputation + DELTA[sev], R_MIN, R_MAX)
        if sev == EventTier.MAJOR:
            d.major_count += 1
        self._transition(d, sev)
        return d.status

    def _transition(self, d, sev):
        pol = POLICY[d.tier]
        if sev == EventTier.CRITICAL or d.reputation <= BAN_R:
            self._ban(d)
            return
        if d.status == Status.ACTIVE:
            if d.reputation <= PROBATION_R or d.major_count >= pol["major_to_probation"]:
                if pol["rehab"]:
                    d.status = Status.PROBATION
                else:
                    self._ban(d)

    def _ban(self, d):
        d.status = Status.BANNED
        d.reputation = min(d.reputation, BAN_R)
        if d.ek_hash is not None:
            self._banned_ek.add(d.ek_hash)

    def reinstate(self, device_id):
        """Called by probation.py when the shadow-model slope shows recovery.
        Only tiers whose policy allows rehab can be reinstated."""
        d = self._dev[device_id]
        if d.status == Status.PROBATION and POLICY[d.tier]["rehab"]:
            d.status = Status.ACTIVE
            d.reputation = max(d.reputation, PROBATION_R + 5.0)
            d.major_count = 0
            return True
        return False

    def get_status(self, device_id):
        return self._dev[device_id].status

    def get_weight(self, device_id):
        d = self._dev[device_id]
        if d.status == Status.BANNED:
            return 0.0
        cap = POLICY[d.tier]["weight_cap"]
        if d.status == Status.PROBATION:
            cap = min(cap, PROBATION_WEIGHT_CAP)
        return round(cap * (d.reputation / R_MAX), 4)

    def get_all_weights(self):
        # O4. Banned devices are excluded from aggregation entirely.
        return {i: self.get_weight(i) for i, d in self._dev.items()
                if d.status != Status.BANNED}

    def banned_ek_hashes(self):
        return set(self._banned_ek)

    @staticmethod
    def max_influence(tier):
        # Ceiling on what a fresh identity at this tier can buy. Used by the
        # attacker-cost analysis in eval/.
        return POLICY[Tier(tier)]["weight_cap"]


def _self_test():
    print("trust/reputation.py self-test")
    eng = ReputationEngine()

    eng.register("h1", Tier.HARDWARE, ek_hash="EKH1")
    assert eng.record_event("h1", "MAJOR") == Status.ACTIVE
    print("✓ Tier1 tolerates first MAJOR (active)")
    assert eng.record_event("h1", "MAJOR") == Status.PROBATION
    assert eng.get_weight("h1") <= PROBATION_WEIGHT_CAP
    print("✓ Tier1 second MAJOR -> probation, weight capped")
    assert eng.reinstate("h1") is True
    assert eng.get_status("h1") == Status.ACTIVE
    print("✓ Tier1 reinstated after recovery")

    eng.register("t2", Tier.TPM_RESIDENT, ek_hash="EKT2")
    assert eng.record_event("t2", "MAJOR") == Status.BANNED
    assert eng.get_weight("t2") == 0.0
    print("✓ Tier2 single MAJOR -> ban (policy, not reputation, drives it)")

    eng.register("h2", Tier.HARDWARE, ek_hash="EKH2")
    assert eng.record_event("h2", "CRITICAL") == Status.BANNED
    print("✓ CRITICAL bans regardless of tier")

    assert eng.register("t2_again", Tier.TPM_RESIDENT, ek_hash="EKT2") == Status.BANNED
    print("✓ banned EK re-registering stays banned (anti-whitewashing)")

    eng.register("t3", Tier.SOFTWARE, ek_hash="EKT3")
    w = eng.get_all_weights()
    assert isinstance(w, dict) and all(isinstance(v, float) for v in w.values())
    assert "t2" not in w and "h2" not in w
    assert w["t3"] <= 0.1
    assert eng.get_weight("h1") <= 1.0
    print("✓ get_all_weights -> dict[str,float], banned excluded, caps held")

    assert ReputationEngine.max_influence(Tier.HARDWARE) == 1.0
    assert ReputationEngine.max_influence(Tier.TPM_RESIDENT) == 0.5
    assert ReputationEngine.max_influence(Tier.SOFTWARE) == 0.1
    print("✓ per-tier max influence exposed for attacker-cost metric")

    print("✓ all reputation self-tests passed")


if __name__ == "__main__":
    _self_test()