"""
run_server.py  (place in dltf/ project root, run on the SERVER PC)

Builds RemoteClientHandles from config.CLIENTS, enrolls every client agent,
runs FL rounds, prints a per-round report. Audit chain written to results/.

  PYTHONPATH=. python3 run_server.py --rounds 10            # real MNIST model
  PYTHONPATH=. python3 run_server.py --rounds 5 --stub --dim 6   # networking smoke test
"""
import argparse
import os
import config
from fl.server import FederatedServer
from net.handles import RemoteClientHandle
from audit.hashchain import HashChain


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--stub", action="store_true",
                    help="send a tiny --dim vector instead of the real model (no-torch net test)")
    ap.add_argument("--dim", type=int, default=6, help="param size when --stub")
    args = ap.parse_args()

    os.makedirs("results", exist_ok=True)

    if args.stub:
        initial = [0.0] * args.dim
        print(f"stub mode: sending {args.dim}-value vector")
    else:
        from fl.model import MNISTModel
        initial = MNISTModel().get_parameters()
        print(f"real MNIST model: {len(initial)} parameters")

    handles = []
    for c in config.CLIENTS:
        label = c["device_label"] if isinstance(c, dict) else c.device_label
        endpoint = c["endpoint"] if isinstance(c, dict) else c.endpoint
        backend = (c.get("tpm_backend", "mock") if isinstance(c, dict)
                   else getattr(c, "tpm_backend", "mock"))
        handles.append(RemoteClientHandle(label, endpoint, tpm_backend=backend))

    ca_pem = open("tpm/ca/amd_ftpm_ca.pem", "rb").read()
    server = FederatedServer(initial, ca_bundle_pem=ca_pem, audit=HashChain(path="results/audit.jsonl"))
    for h in handles:
        r = server.enroll(h)
        print(f"enrolled {r['device_id']}: tier {r['tier']}, status {r['status']}")

    for rnd in range(args.rounds):
        rep = server.run_round(rnd, handles)
        flags = {d: e["severity"] for d, e in rep["events"].items()
                 if e["severity"] != "NEUTRAL"}
        print(f"round {rnd}: weights {rep['weights']} flags {flags}")
    print("✓ done, audit at results/audit.jsonl")


if __name__ == "__main__":
    main()
