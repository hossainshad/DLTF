"""
run_local.py  (project root)

Single-PC simulation: one server + N in-process clients (no network, no agents).
Choose the reputation engine with --engine additive|beta.

  PYTHONPATH=. python3 run_local.py --clients 5 --rounds 12 --engine beta
"""
import argparse
import numpy as np

from tpm.client import make_signer
from fl.client import FLClient
from fl.server import FederatedServer
from net.handles import LocalClientHandle
from trust.reputation import ReputationEngine

DIM, BULK = 20, [0, 1, 2, 3]


def grad(scale=1.0, noise=0.4, seed=0):
    rng = np.random.default_rng(seed)
    v = np.zeros(DIM)
    for k in BULK:
        v[k] = 1.0
    v = v / np.linalg.norm(v)
    return (scale * v + noise * rng.standard_normal(DIM)).tolist()


def honest(idx):
    return lambda r, p: (grad(1.0, 0.4, seed=100 * r + idx), 64)


def sybil(r, p):
    rng = np.random.default_rng(9000 + r)          # identical across the group
    v = np.zeros(DIM); v[7] = v[8] = 1.0
    v = v / np.linalg.norm(v)
    return (v + 0.05 * rng.standard_normal(DIM)).tolist(), 64


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=5)
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--engine", choices=["additive", "beta"], default="additive")
    ap.add_argument("--attackers", type=int, default=0,
                    help="how many of the clients are colluding sybils")
    args = ap.parse_args()

    engine = ReputationEngine()
    server = FederatedServer([0.0] * DIM, reputation_engine=engine)
    print(f"engine: {args.engine}")

    handles = []
    n_honest = args.clients - args.attackers
    for k in range(n_honest):
        h = LocalClientHandle(f"client{k}", make_signer("mock", f"client{k}"),
                              FLClient(f"client{k}", honest(k)))
        handles.append(h)
    for k in range(args.attackers):
        lbl = f"attacker{k}"
        h = LocalClientHandle(lbl, make_signer("mock", lbl), FLClient(lbl, sybil))
        handles.append(h)

    for h in handles:
        r = server.enroll(h)
        print(f"enrolled {r['device_id']:10s} tier {r['tier']:13s} status {r['status']}")

    for rnd in range(args.rounds):
        rep = server.run_round(rnd, handles)
        flags = {d: e["severity"] for d, e in rep["events"].items()
                 if e["severity"] != "NEUTRAL"}
        w = {d: round(v, 3) for d, v in rep["weights"].items()}
        print(f"round {rnd:2d}: weights {w} flags {flags}")
    print("done")


if __name__ == "__main__":
    main()