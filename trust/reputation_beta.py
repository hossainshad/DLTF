"""
trust/reputation_beta.py

Bayesian (beta) reputation engine: an alternative arithmetic behind the SAME
interface as trust/reputation.py, used as an ablation arm in the thesis.

    FederatedServer(..., reputation_engine=BetaReputationEngine())

Trust is the posterior expectation of a Beta distribution over the probability
that a device behaves honestly (Josang & Ismail 2002):

    T = (a0 + s) / (a0 + s + b0 + f)

with s, f accumulated positive/negative evidence and (a0, b0) the prior.
Every round contributes one observation: a clean round adds 1 unit of good
evidence; offenses add severity-weighted bad evidence (MINOR 1, MAJOR 3,
CRITICAL 8), the asymmetric weighting used in CONFIDANT-style trust systems,
so trust falls faster than it recovers.

Two extensions are this thesis's contribution:

1. HARDWARE-INFORMED PRIORS. The prior is set by the enrollment tier, because
   a manufacturer-certified TPM is itself evidence of accountability:
       Tier 1 Beta(8, 2)   Tier 2 Beta(4, 2)   Tier 3 Beta(2, 2)
   Strike tolerance then EMERGES from the posterior instead of a policy table:
   Tier 1 crosses probation (T <= 0.5) at exactly its 2nd MAJOR
   (8/(8+2+6) = 0.5); Tier 2 at its 1st (4/(4+2+3) = 0.444); Tier 3 has no
   evidence buffer, so any offense sanctions it.

2. TIER-COUPLED FORGETTING. The forgetting factor of Josang & Ismail (2002)
   and the reputation fading of Buchegger & Le Boudec (2004) let old offenses
   decay, but here it is applied only on clean rounds (offenses fade through
   demonstrated good behaviour, never during an attack) and only for tiers
   whose identity cannot be discarded: lambda = 0.95 for Tier 1, 1.0 (never
   forget) for Tier 2/3. Forgiveness is a privilege of accountable hardware.

Sanction structure (statuses, EK-bound ban persistence for O2, probation
weight cap, CRITICAL as non-compensable) is identical to the additive engine,
so any behavioural difference in experiments isolates the arithmetic.
"""
from dataclasses import dataclass

from trust.reputation import Status, PROBATION_WEIGHT_CAP

try:
    from tpm.common import Tier
except ImportError:
    from enum import IntEnum

    class Tier(IntEnum):
        HARDWARE = 1
        TPM_RESIDENT = 2
        SOFTWARE = 3


PRIORS = {Tier.HARDWARE: (8.0, 2.0), Tier.TPM_RESIDENT: (4.0, 2.0),
          Tier.SOFTWARE: (2.0, 2.0)}
TIER_CAP = {Tier.HARDWARE: 1.0, Tier.TPM_RESIDENT: 0.5, Tier.SOFTWARE: 0.1}
REHAB = {Tier.HARDWARE: True, Tier.TPM_RESIDENT: False, Tier.SOFTWARE: False}
FORGET = {Tier.HARDWARE: 0.95, Tier.TPM_RESIDENT: 1.0, Tier.SOFTWARE: 1.0}

GOOD_EVIDENCE = {"POSITIVE": 1.0, "NEUTRAL": 1.0}
BAD_EVIDENCE = {"MINOR": 1.0, "MAJOR": 3.0, "CRITICAL": 8.0}
PROBATION_T = 0.5
BAN_T = 0.3
REINSTATE_T = 0.55


@dataclass
class BetaDevice:
    device_id: str
    tier: Tier
    ek_hash: str
    s: float
    f: float
    status: Status

    @property
    def trust(self):
        a0, b0 = PRIORS[self.tier]
        return (a0 + self.s) / (a0 + self.s + b0 + self.f)


class BetaReputationEngine:
    def __init__(self):
        self._dev = {}
        self._banned_ek = set()

    def register(self, device_id, tier, ek_hash=None):
        tier = Tier(tier)
        banned = ek_hash is not None and ek_hash in self._banned_ek
        d = BetaDevice(device_id, tier, ek_hash, 0.0, 0.0,
                       Status.BANNED if banned else Status.ACTIVE)     # O2
        self._dev[device_id] = d
        return d.status

    def record_event(self, device_id, severity):
        d = self._dev[device_id]
        if d.status == Status.BANNED:
            return d.status
        if severity in GOOD_EVIDENCE:
            d.f *= FORGET[d.tier]              # offenses fade only on clean rounds
            d.s += GOOD_EVIDENCE[severity]
        else:
            d.f += BAD_EVIDENCE[severity]
        self._transition(d, severity)
        return d.status

    def _transition(self, d, severity):
        if severity == "CRITICAL" or d.trust <= BAN_T:                 # non-compensable
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
            d.s = max(d.s, need_a - a0)        # closed-form lift to T >= 0.55
            d.status = Status.ACTIVE
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
    print("trust/reputation_beta.py self-test")
    e = BetaReputationEngine()
    e.register("hw", Tier.HARDWARE, "ek_hw")
    e.register("tr", Tier.TPM_RESIDENT, "ek_tr")
    e.register("sw", Tier.SOFTWARE, "ek_sw")
    assert abs(e._dev["hw"].trust - 0.8) < 1e-9
    assert abs(e._dev["tr"].trust - 4 / 6) < 1e-9
    assert abs(e._dev["sw"].trust - 0.5) < 1e-9
    print("✓ hardware-informed priors: starting trust 0.80 / 0.67 / 0.50 by tier")

    assert e.record_event("hw", "MAJOR") == Status.ACTIVE      # strike 1 tolerated
    assert e.record_event("hw", "MAJOR") == Status.PROBATION   # strike 2: T = 0.5
    assert abs(e._dev["hw"].trust - 0.5) < 1e-9
    print("✓ emergent policy: Tier-1 probation at exactly the 2nd MAJOR")

    assert e.record_event("tr", "MINOR") == Status.ACTIVE      # minor tolerated
    assert e.record_event("tr", "MAJOR") == Status.BANNED      # one strike, no rehab
    assert e.record_event("sw", "MINOR") == Status.BANNED      # no evidence buffer
    print("✓ emergent policy: Tier-2 one MAJOR strike, Tier-3 zero tolerance")

    e2 = BetaReputationEngine()
    e2.register("c", Tier.TPM_RESIDENT, "ek_c")
    assert e2.record_event("c", "CRITICAL") == Status.BANNED
    assert e2.register("c2", Tier.TPM_RESIDENT, "ek_c") == Status.BANNED
    print("✓ CRITICAL is non-compensable; banned EK re-registering stays banned (O2)")

    e3 = BetaReputationEngine()
    e3.register("hw", Tier.HARDWARE, "x")
    e3.register("tr", Tier.TPM_RESIDENT, "y")
    e3.record_event("hw", "MAJOR")
    e3.record_event("tr", "MINOR")
    f_hw0, f_tr0 = e3._dev["hw"].f, e3._dev["tr"].f
    for _ in range(20):
        e3.record_event("hw", "NEUTRAL")
        e3.record_event("tr", "NEUTRAL")
    assert e3._dev["hw"].f < f_hw0 * 0.4          # offense fades for Tier 1
    assert e3._dev["tr"].f == f_tr0               # never forgotten for Tier 2
    assert e3._dev["hw"].trust > 0.8
    print("✓ tier-coupled forgetting: only accountable hardware earns fading")

    one_major = BetaReputationEngine()
    one_major.register("d", Tier.HARDWARE, "z")
    one_major.record_event("d", "MAJOR")
    t_after = one_major._dev["d"].trust
    rounds = 0
    while one_major._dev["d"].trust < 0.8 and rounds < 50:
        one_major.record_event("d", "NEUTRAL")
        rounds += 1
    assert rounds > 3
    print(f"✓ asymmetry: one MAJOR ({t_after:.2f}) takes {rounds} clean rounds to repair")

    eng = BetaReputationEngine()
    eng.register("p", Tier.HARDWARE, "ek_p")
    eng.record_event("p", "MAJOR"); eng.record_event("p", "MAJOR")
    assert eng.get_status("p") == Status.PROBATION
    assert eng.get_weight("p") <= PROBATION_WEIGHT_CAP
    assert eng.reinstate("p") is True
    assert eng.get_status("p") == Status.ACTIVE and eng._dev["p"].trust >= 0.55
    w = eng.get_all_weights()
    assert abs(w["p"] - 1.0 * eng._dev["p"].trust) < 1e-6
    print("✓ probation cap, closed-form reinstatement, weight = cap x posterior")

    # Drop-in proof: full federation lifecycle with this engine injected.
    import numpy as np
    from tpm.common import b64e
    from tpm.client import make_signer
    from fl.server import FederatedServer

    DIM, BULK = 6, [0, 1, 2]

    def grad(scale=1.0, noise=0.0, seed=0):
        rng = np.random.default_rng(seed)
        v = np.zeros(DIM)
        for k in BULK:
            v[k] = 1.0
        v = v / np.linalg.norm(v)
        return (scale * v + noise * rng.standard_normal(DIM)).tolist()

    class H:
        def __init__(s, label, signer, trainer):
            s.device_label, s.tpm_backend = label, "mock"
            s._s, s._t = signer, trainer

        def enroll_payload(s):
            p = s._s.provision()
            return {"device_label": s.device_label, "ek_hash": p.ek_hash,
                    "ak_name": p.ak_name,
                    "ek_cert_b64": b64e(p.ek_cert_der) if p.ek_cert_der else None}

        def activate_credential(s, b):
            return s._s.activate_credential(b)

        def train(s, r, p):
            u, n = s._t(r, p)
            return {"update": u, "num_samples": n}

    srv = FederatedServer([0.0] * DIM, reputation_engine=BetaReputationEngine())
    hs = [H(f"h{k}", make_signer("mock", f"h{k}"),
            (lambda i: (lambda r, p: (grad(1.0, 0.4, seed=100 * r + i), 64)))(k))
          for k in range(3)]
    sy = lambda r, p: (grad(1.0, 0.5, seed=9000 + r), 64)
    hs += [H("s1", make_signer("mock", "s1"), sy), H("s2", make_signer("mock", "s2"), sy)]
    for h in hs:
        srv.enroll(h)
    for r in range(3):
        srv.run_round(r, hs)
    assert srv.rep.get_status("s1") == Status.BANNED
    assert srv.enroll(H("s1", make_signer("mock", "s1"), sy))["status"] == "BANNED"
    w = srv.rep.get_all_weights()
    assert "s1" not in w and all(w[f"h{k}"] > 0.3 for k in range(3))
    print("✓ drop-in: sybil ban + whitewash block + weights, same server, new math")
    print("✓ all beta reputation self-tests passed")


if __name__ == "__main__":
    _self_test()