# DLTF: Hardware-Rooted Trust Lifecycle for Federated Learning

The contribution is not detection. It is the response after detection: a sanction
and rehabilitation lifecycle bound to an unforgeable TPM hardware identity, with
the response policy and reversibility made a function of the hardware-trust tier.

## Objectives
- O1 Sybil resistance: one TPM EK equals one identity, proven by credential activation.
- O2 Anti-whitewashing: a ban binds to the EK hash, so it cannot be shed by re-registering.
- O3 Quantified trust: reputation is deterministic; attacker cost per tier is measured.
- O4 Aggregator-agnostic: trust outputs dict[str, float] weights for FedAvg, Krum, TrimmedMean.

## Trust tiers (set at enrollment)
- Tier 1 HARDWARE: EK certificate chains to a manufacturer CA AND credential activation
  passes. Weight cap 1.0, two MAJOR strikes before probation, rehabilitation allowed.
- Tier 2 TPM_RESIDENT: activation passes, no verifiable cert. Weight cap 0.5, one strike,
  no rehabilitation.
- Tier 3 SOFTWARE / TOFU: no hardware proof. Weight cap 0.1, one strike.

Core idea: identity replacement cost drives policy. Expensive identities (Tier 1) get
patience and a path back; free identities get low caps and instant bans.

## Real-hardware status (AMD fTPM, verified June 2026)
The dev laptop (Ryzen 5 5600X, AMD fTPM) DOES expose a fetchable EK certificate
(issuer "Advanced Micro Devices, CN = PRG-RN") that chain-verifies through PRG-RN to
the self-signed AMDTPM root. So this machine reaches a REAL Tier 1, not a simulated
one. Two findings came out of bringing this up:
- Not all AMD fTPMs expose a cert; it depends on board/BIOS provisioning. The tier
  model degrades correctly to Tier 2 when absent.
- AMD EK certs are technically malformed (a non-spec DEFAULT encoding on an extension
  `critical` field). Python's strict parser rejects them; openssl accepts them.
  verify_ek_certificate falls back to openssl for such certs, so both paths work.

## Layout
- config.py        topology and run mode. The single local-to-real switch.
- run_server.py    server-PC runner: enrolls remote agents, runs rounds, writes audit.
- tpm/             Layer 1. EK + AIK, EK-cert verification, MakeCredential/ActivateCredential.
- trust/           Detection (filter.py) and the contribution (reputation.py / reputation_beta.py, probation.py).
- fl/              CNN, non-IID data, client (compute only), server (enrollment + rounds), aggregators.
- net/             Transport seam. ClientHandle implementations and the client HTTP agent.
- audit/           Local append-only HMAC-signed hash chain for enrollments, bans, rounds.
- eval/            Scenarios, multi-seed CSV runner, figures. Produces the Chapter 4 numbers.
- tests/           End-to-end pipeline self-test.

Run everything from the project root with PYTHONPATH set, so top-level imports resolve:
`PYTHONPATH=. python3 <module>`.

## Quick start (one PC, dev mode)
```
PYTHONPATH=. python3 tests/test_pipeline.py
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 --rounds 30 --out results --check
PYTHONPATH=. python3 -m eval.plot_results --results results
```

## Reputation engines (ablation)
Two engines behind one interface. Additive (default) uses fixed deltas; beta uses a
Bayesian posterior with hardware-informed priors.
```
from trust.reputation import ReputationEngine          # default
from trust.reputation_beta import BetaReputationEngine
server = FederatedServer(params, reputation_engine=BetaReputationEngine())
```

## Multi-PC deployment
1. Copy dltf/ to every machine; edit config.py identically (labels + endpoints).
2. Each client PC: `PYTHONPATH=. python3 -m net.agent --label clientN --port 8470 [--stub]`.
3. Server PC: `PYTHONPATH=. python3 run_server.py --rounds 10`.
Bring-up order: mock backend + --stub (network test), then drop --stub (real MNIST),
then tpm_backend="real" on TPM-equipped boxes.

Over the internet (not one LAN): install Tailscale on every machine, `sudo tailscale up`
under one account, put the 100.x.y.z addresses in config.py endpoints. No port
forwarding, no code change. Bonus: traffic is WireGuard-encrypted, mitigating the
plain-HTTP limitation.

## Checking a machine's tier
```
PYTHONPATH=. python3 -m tpm.check_ek_cert                                  # live fetch
PYTHONPATH=. python3 -m tpm.check_ek_cert --ek-cert ek.crt --ca-bundle tpm/ca/amd_ftpm_ca.pem
```
See tpm/FETCH_EK_CERT.md for the full step-by-step of fetching and verifying an EK
certificate on a new AMD client.

## Honest scope
The hardware-rooted guarantee holds only where a verifiable EK certificate exists
(Tier 1). Without it, whitewashing is hardware-cost-bound, not impossible. Tier 1
soundness depends on the CA allow-list: trusting a cloud vTPM CA admits real-but-rented
hardware identities, bounded by rental cost. Stated as results and limitations, not hidden.
