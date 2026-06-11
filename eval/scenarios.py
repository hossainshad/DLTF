"""
eval/scenarios.py

Attack scenarios on a synthetic substrate, plus a no-trust baseline server.

Why synthetic is valid for the trust-layer claims: the trust layer sees only
gradient vectors, so detection and sanction behavior is invariant to whether
those vectors come from MNIST SGD or a controlled generator. Synthetic gives
exact ground truth (attack start round, true direction), so latency and FPR
are measured, not estimated. End-model accuracy on MNIST is produced by the
same round loop machine-side and reported separately in the thesis.

Accuracy proxy: alignment x saturation,
  acc(p) = max(0, 0.5*(1+cos(p, target))) * (1 - exp(-||p|| / 25))
Direction attacks (poisoning) cut the cosine term; dilution attacks (sybil
side-pull, weight starvation) slow norm growth. Both show up.
"""
import math
import numpy as np

from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from tpm.client import make_signer, MockTPMSigner
from fl.client import FLClient
from fl.server import FederatedServer
from fl.aggregator import fedavg
from net.handles import LocalClientHandle

DIM = 20
NORM_SCALE = 25.0


class SyntheticWorld:
    def __init__(self, seed=0, dim=DIM):
        rng = np.random.default_rng(seed)
        t = rng.standard_normal(dim)
        self.target = t / np.linalg.norm(t)
        s = rng.standard_normal(dim)
        s = s - (s @ self.target) * self.target          # orthogonal side direction
        self.side = s / np.linalg.norm(s)
        self.dim = dim

    def accuracy(self, params):
        a = np.asarray(params, dtype=float)
        n = float(np.linalg.norm(a))
        if n == 0.0:
            return 0.05
        cos = float(a @ self.target / n)
        return max(0.0, 0.5 * (1.0 + cos)) * (1.0 - math.exp(-n / NORM_SCALE))

    def honest_update(self, rng, scale=1.0, noise=0.5):
        return (scale * self.target + noise * rng.standard_normal(self.dim)).tolist()

    def attack_update(self, scale=1.0):
        return (-scale * self.target).tolist()

    def sybil_update(self, group_seed, round_id, scale=2.0):
        rng = np.random.default_rng(group_seed * 7919 + round_id)   # identical per group
        return (scale * self.side + 0.05 * rng.standard_normal(self.dim)).tolist()


def behavior(world, kind, seed, attack_start=0, group_seed=1):
    rng = np.random.default_rng(seed)
    if kind == "honest":
        return lambda r, p: (world.honest_update(rng), 64)
    if kind == "sybil":
        return lambda r, p: (world.sybil_update(group_seed, r), 64)
    if kind == "poisoner":            # honest before attack_start, then flips
        return lambda r, p: ((world.honest_update(rng), 64) if r < attack_start
                             else (world.attack_update(), 64))
    if kind == "recovering":          # attacks briefly, then trains hard and honestly
        return lambda r, p: ((world.attack_update(), 64) if attack_start <= r < attack_start + 2
                             else ((world.target * 2.0).tolist(), 64))
    if kind == "persistent":          # attacks forever, including during probation
        return lambda r, p: ((world.honest_update(rng), 64) if r < attack_start
                             else (world.attack_update(), 64))
    raise ValueError(kind)


class FailingSigner(MockTPMSigner):
    """Cannot answer credential activation: enrolls as Tier 3 SOFTWARE."""
    def activate_credential(self, blob_b64):
        return b"\x00" * 16


def make_handle(label, trainer, ek_cert_der=None, fail_activation=False):
    signer = FailingSigner(label) if fail_activation \
        else make_signer("mock", label, ek_cert_der=ek_cert_der)
    return LocalClientHandle(label, signer, FLClient(label, trainer))


class BaselineServer:
    """Plain FedAvg, no identity, no trust: every enrollment accepted, equal
    weights forever. The control arm for every experiment."""

    def __init__(self, initial_params):
        self.global_params = list(initial_params)
        self.enrolled = set()
        self.rep = None

    def enroll(self, handle):
        self.enrolled.add(handle.device_label)
        return {"device_id": handle.device_label, "tier": "NONE", "status": "ACTIVE",
                "reason": "baseline accepts everything"}

    def run_round(self, round_id, handles):
        updates = {h.device_label: h.train(round_id, self.global_params)["update"]
                   for h in handles if h.device_label in self.enrolled}
        weights = {i: 1.0 for i in updates}
        agg = fedavg(updates, weights)
        self.global_params = [p + u for p, u in zip(self.global_params, agg)]
        return {"round": round_id, "events": {}, "weights": weights,
                "probation_decisions": [], "aggregated": True}


ATTACKS = {
    # name: (kind, n_attackers, attack_start)
    "none":    (None, 0, 0),
    "sybil":   ("sybil", 3, 0),
    "poison":  ("poisoner", 2, 5),
    "sleeper": ("poisoner", 2, 10),
}


def build(world, defense, attack, seed, n_honest=7, attacker_tier=2):
    kind, n_att, start = ATTACKS[attack]
    ca_key, ca_cert = generate_test_ca()

    if defense == "dltf":
        server = FederatedServer(initial_params=[0.0] * world.dim,
                                 ca_bundle_pem=ca_bundle_pem(ca_cert),
                                 shadow_eval_fn=world.accuracy)
    elif defense == "baseline":
        server = BaselineServer([0.0] * world.dim)
    else:
        raise ValueError(defense)

    handles = [make_handle(f"h{k}", behavior(world, "honest", seed * 100 + k))
               for k in range(n_honest)]
    attackers = []
    for k in range(n_att):
        label = f"a{k}"
        trainer = behavior(world, kind, seed * 100 + 50 + k,
                           attack_start=start, group_seed=seed + 1)
        cert = None
        fail = False
        if attacker_tier == 1:
            cert, _ = issue_ek_cert(ca_key, ca_cert, label)
        elif attacker_tier == 3:
            fail = True
        handles.append(make_handle(label, trainer, ek_cert_der=cert, fail_activation=fail))
        attackers.append(label)

    for h in handles:
        server.enroll(h)
    return server, handles, attackers, start, (ca_key, ca_cert)


def run_rounds(server, handles, world, rounds):
    """Returns per-round records: accuracy, weights, events, banned set."""
    out = []
    for r in range(rounds):
        rep = server.run_round(r, handles)
        banned = set()
        if getattr(server, "rep", None):
            from trust.reputation import Status
            banned = {h.device_label for h in handles
                      if h.device_label in server.enrolled
                      and server.rep.get_status(h.device_label) == Status.BANNED}
        out.append({"round": r, "accuracy": world.accuracy(server.global_params),
                    "weights": rep["weights"], "events": rep["events"],
                    "probation_decisions": rep["probation_decisions"],
                    "banned": banned})
    return out


def _self_test():
    print("eval/scenarios.py self-test")
    w = SyntheticWorld(seed=0)
    assert abs(np.linalg.norm(w.target) - 1.0) < 1e-9
    assert abs(float(w.side @ w.target)) < 1e-9
    assert w.accuracy([0.0] * DIM) == 0.05
    assert w.accuracy((w.target * 100).tolist()) > 0.95
    assert w.accuracy((-w.target * 100).tolist()) < 0.02
    print("✓ world: aligned params score high, reversed score ~0")

    srv, hs, att, start, _ = build(w, "dltf", "none", seed=1)
    rec = run_rounds(srv, hs, w, 15)
    assert rec[-1]["accuracy"] > 0.4 and not any(r["banned"] for r in rec)
    assert all(e["severity"] == "NEUTRAL" for r in rec for e in r["events"].values())
    print("✓ honest-only DLTF: accuracy rises, zero sanctions (no false positives)")

    srv_d, hs_d, att_d, _, _ = build(w, "dltf", "sybil", seed=1)
    rec_d = run_rounds(srv_d, hs_d, w, 15)
    assert set(att_d) <= rec_d[-1]["banned"]
    srv_b, hs_b, _, _, _ = build(w, "baseline", "sybil", seed=1)
    rec_b = run_rounds(srv_b, hs_b, w, 15)
    assert rec_d[-1]["accuracy"] > rec_b[-1]["accuracy"] + 0.05
    print("✓ sybil: DLTF bans the group and beats baseline accuracy")

    print("✓ all scenario self-tests passed")


if __name__ == "__main__":
    _self_test()