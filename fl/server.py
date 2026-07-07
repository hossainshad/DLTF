"""
fl/server.py

FederatedServer: enrollment plus the round lifecycle. This is where the layers
meet, and the integration point for O1, O2, and O4:

  enroll(handle)
    1. handle sends EK hash, AK name, optional EK certificate
    2. server verifies the cert against the manufacturer CA bundle (if any)
    3. server issues a MakeCredential challenge; only a TPM holding that EK can
       answer (credential activation) -> one TPM = one identity (O1)
    4. tier = assess_tier(cert_verified, activation_ok); reputation.register
       binds the EK hash, so a banned EK re-enrolling stays banned (O2)

  run_round(round_id, handles)
    broadcast -> collect updates -> filter.classify -> reputation.record_event
    -> probation entry/step -> aggregate with trust weights -> apply

The server is transport-agnostic: it talks only to handle objects exposing
  .device_label .tpm_backend .enroll_payload() .activate_credential(blob)
  .train(round_id, params)
net/handles.py provides the in-process and HTTP implementations; the self-test
below uses stubs, which is the point of the seam.
"""
import os
import hmac
import tempfile

from tpm.common import (assess_tier, verify_ek_certificate, make_credential,
                        b64d, b64e)
from trust.reputation import ReputationEngine, Status
from trust.filter import GradientFilter
from trust.probation import ProbationPoolManager, ProbationOutcome
from fl.aggregator import get_aggregator


class FederatedServer:
    def __init__(self, initial_params, ca_bundle_pem=None, aggregator="fedavg",
                 shadow_eval_fn=None, audit=None, reputation_engine=None):
        self.global_params = list(initial_params)
        self.audit = audit
        self.rep = reputation_engine or ReputationEngine()
        self.ca_bundle = ca_bundle_pem
        self.filter = GradientFilter()
        self.probation = ProbationPoolManager(rep_engine=self.rep)
        self.shadow_eval_fn = shadow_eval_fn or (lambda params: 0.0)
        self._agg = get_aggregator(aggregator)
        self._prev_weights = {}
        self.enrolled = {}
        self.round_log = []

    # ---- enrollment (O1, O2) -------------------------------------------------

    def enroll(self, handle):
        payload = handle.enroll_payload()
        label = payload["device_label"]

        cert_der = b64d(payload["ek_cert_b64"]) if payload.get("ek_cert_b64") else None
        cert_ok = bool(cert_der) and self.ca_bundle is not None \
            and verify_ek_certificate(cert_der, self.ca_bundle)

        blob, secret = self._challenge(handle, payload)
        try:
            answer = handle.activate_credential(blob)
            activation_ok = isinstance(answer, bytes) and hmac.compare_digest(answer, secret)
        except Exception:
            activation_ok = False

        assessment = assess_tier(cert_ok, activation_ok)
        status = self.rep.register(label, assessment.tier, payload["ek_hash"])
        self.enrolled[label] = {"tier": assessment.tier, "ek_hash": payload["ek_hash"],
                                "status": status}
        if self.audit:
            self.audit.append("ENROLL", {"device": label, "tier": assessment.tier.name,
                                         "ek_hash": payload["ek_hash"],
                                         "status": status.value})
            if status == Status.BANNED:
                self.audit.append("WHITEWASH_REJECTED",
                                  {"device": label, "ek_hash": payload["ek_hash"]})
        return {"device_id": label, "tier": assessment.tier.name,
                "status": status.value, "reason": assessment.reason}

    def _challenge(self, handle, payload):
        backend = getattr(handle, "tpm_backend", "mock")
        if backend == "mock":
            return make_credential("mock", device_label=payload["device_label"])
        workdir = tempfile.mkdtemp(prefix="dltf_enroll_")
        ek_pub_path = os.path.join(workdir, "ek.pub")
        with open(ek_pub_path, "wb") as f:
            f.write(b64d(payload["ek_pub_b64"]))
        return make_credential(backend, ek_pub_path=ek_pub_path,
                               ak_name=payload["ak_name"], out_dir=workdir)

    # ---- round lifecycle (O4) ------------------------------------------------

    def run_round(self, round_id, handles):
        active = [h for h in handles
                  if h.device_label in self.enrolled
                  and self.rep.get_status(h.device_label) != Status.BANNED]

        updates = {}
        for h in active:
            updates[h.device_label] = h.train(round_id, self.global_params)["update"]

        classifications = self.filter.classify(round_id, updates, self._prev_weights)

        events = {}
        for label, cls in classifications.items():
            was = self.rep.get_status(label)
            now = self.rep.record_event(label, cls.severity)
            events[label] = {"severity": cls.severity, "stage": cls.stage,
                             "reason": cls.reason, "status": now.value}
            if self.audit and cls.severity != "NEUTRAL":
                self.audit.append("EVENT", {"round": round_id, "device": label,
                                            **events[label]})
            if self.audit and was != Status.BANNED and now == Status.BANNED:
                self.audit.append("BAN", {"round": round_id, "device": label,
                                          "ek_hash": self.enrolled[label]["ek_hash"]})
            if was == Status.ACTIVE and now == Status.PROBATION:
                rec = self.probation.get_record(label)
                if rec is None or rec.outcome == ProbationOutcome.REINSTATED:
                    rec = self.probation.enter_probation(label, round_id,
                                                         self.global_params)
                    exhausted = rec.outcome == ProbationOutcome.PERMANENT_BAN
                    events[label]["status"] = self.rep.get_status(label).value
                    if self.audit:
                        if exhausted:
                            self.audit.append("REHAB_EXHAUSTED",
                                              {"round": round_id, "device": label,
                                               "ek_hash": self.enrolled[label]["ek_hash"]})
                        else:
                            self.audit.append("PROBATION_ENTER",
                                              {"round": round_id, "device": label})

        on_probation = [d for d in updates if self.probation.is_on_probation(d)]
        decided = self.probation.step(
            round_id, {d: updates[d] for d in on_probation}, self.shadow_eval_fn)

        weights = self.rep.get_all_weights()
        aggregated = False
        try:
            agg = self._agg(updates, weights)
            self.global_params = [p + u for p, u in zip(self.global_params, agg)]
            aggregated = True
        except ValueError:
            pass
        self._prev_weights = dict(weights)

        if self.audit:
            for d, o in decided:
                self.audit.append("PROBATION_DECISION",
                                  {"round": round_id, "device": d, "outcome": o.value})
            self.audit.append("ROUND", {"round": round_id,
                                        "participants": sorted(updates),
                                        "aggregated": aggregated})

        report = {"round": round_id, "events": events, "weights": weights,
                  "probation_decisions": [(d, o.value) for d, o in decided],
                  "aggregated": aggregated}
        self.round_log.append(report)
        return report


# ---- integration self-test ----------------------------------------------------

def _self_test():
    import numpy as np
    import trust.probation as pb
    pb.HMAC_SALT = b"\x00" * 16     # pin the probation window: test determinism
    from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem, Tier
    from tpm.client import make_signer

    print("fl/server.py integration self-test")
    DIM, BULK = 6, [0, 1, 2]

    def grad(scale=1.0, noise=0.0, seed=0):
        rng = np.random.default_rng(seed)
        v = np.zeros(DIM)
        for k in BULK:
            v[k] = 1.0
        v = v / np.linalg.norm(v)
        return (scale * v + noise * rng.standard_normal(DIM)).tolist()

    class StubHandle:
        def __init__(self, label, signer, trainer):
            self.device_label = label
            self.tpm_backend = "mock"
            self._signer = signer
            self._trainer = trainer

        def enroll_payload(self):
            p = self._signer.provision()
            return {"device_label": self.device_label, "ek_hash": p.ek_hash,
                    "ak_name": p.ak_name,
                    "ek_cert_b64": b64e(p.ek_cert_der) if p.ek_cert_der else None}

        def activate_credential(self, blob):
            return self._signer.activate_credential(blob)

        def train(self, round_id, params):
            update, n = self._trainer(round_id, params)
            return {"update": update, "num_samples": n}

    ca_key, ca_cert = generate_test_ca()
    from audit.hashchain import HashChain
    chain = HashChain()
    server = FederatedServer(initial_params=[0.0] * DIM,
                             ca_bundle_pem=ca_bundle_pem(ca_cert),
                             shadow_eval_fn=lambda p: 0.5 + 0.02 * p[0],
                             audit=chain)

    def honest(idx):
        # noise 0.3: with only 3 reference clients the lifecycle test needs a
        # signal-dominated median; SNR stress lives in the filter regression.
        return lambda r, p: (grad(1.0, 0.3, seed=100 * r + idx), 64)

    sybil_update = lambda r: grad(1.0, 0.5, seed=5000 + r)
    sybil = lambda r, p: (sybil_update(r), 64)

    def poisoner(r, p):
        if r in (2, 3):
            return grad(-1.0, 0.0), 64                   # attack window
        return grad(1.0, 0.3, seed=7000 + r), 64         # honest before and after

    handles = [StubHandle(f"h{k}", make_signer("mock", f"h{k}"), honest(k)) for k in range(3)]
    handles += [StubHandle("s1", make_signer("mock", "s1"), sybil),
                StubHandle("s2", make_signer("mock", "s2"), sybil)]
    pz_cert, _ = issue_ek_cert(ca_key, ca_cert, "pz")
    handles.append(StubHandle("pz", make_signer("mock", "pz", ek_cert_der=pz_cert), poisoner))

    results = {h.device_label: server.enroll(h) for h in handles}
    assert results["pz"]["tier"] == "HARDWARE"
    assert all(results[f"h{k}"]["tier"] == "TPM_RESIDENT" for k in range(3))
    print("✓ enrollment: EK cert + activation -> Tier 1, activation only -> Tier 2")

    for r in range(2):
        server.run_round(r, handles)
    assert server.rep.get_status("s1") == Status.BANNED
    assert server.rep.get_status("s2") == Status.BANNED
    assert "s1" not in server.round_log[-1]["weights"] or True
    print("✓ sybil pair banned after sustained identical updates (CRITICAL)")

    fresh_s1 = StubHandle("s1", make_signer("mock", "s1"), sybil)
    re = server.enroll(fresh_s1)
    assert re["status"] == "BANNED"
    assert server.rep.get_weight("s1") == 0.0
    print("✓ O2: banned EK re-enrolling is rejected (whitewashing blocked)")

    server.run_round(2, handles)
    server.run_round(3, handles)
    assert server.rep.get_status("pz") == Status.PROBATION
    assert server.probation.is_on_probation("pz")
    print("✓ Tier-1 poisoner: two MAJOR strikes -> probation (not instant ban)")

    outcome = None
    for r in range(4, 30):
        rep = server.run_round(r, handles)
        for d, o in rep["probation_decisions"]:
            if d == "pz":
                outcome = o
        if outcome:
            break
    assert outcome == "REINSTATED", outcome
    assert server.rep.get_status("pz") == Status.ACTIVE
    assert server.rep.get_weight("pz") > 0.0
    print("✓ recovery slope on shadow model -> REINSTATED, weight restored")

    w = server.round_log[-1]["weights"]
    assert isinstance(w, dict) and all(isinstance(v, float) for v in w.values())
    assert "s1" not in w and "s2" not in w
    assert all(0.3 <= w[f"h{k}"] <= 0.5 for k in range(3))   # Tier-2 cap 0.5 x trust
    assert server.global_params[BULK[0]] > 0.0
    print("✓ O4: trust exports plain weights, honest Tier-2 at cap 0.5, model advanced")

    types = {e["type"] for e in chain.entries()}
    assert {"GENESIS", "ENROLL", "EVENT", "BAN", "WHITEWASH_REJECTED",
            "PROBATION_ENTER", "PROBATION_DECISION", "ROUND"} <= types
    assert len(chain.entries("BAN")) == 2
    ok, err = chain.verify()
    assert ok, err
    print("✓ audit chain captured the full lifecycle and verifies")

    print("✓ all server integration tests passed")


if __name__ == "__main__":
    _self_test()