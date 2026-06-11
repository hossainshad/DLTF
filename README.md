# DLTF: Hardware-Rooted Trust Lifecycle for Federated Learning

The contribution is not detection. It is the response after detection: a sanction
and rehabilitation lifecycle bound to an unforgeable TPM hardware identity, with
the response policy and reversibility made a function of the hardware-trust tier.

## Objectives
- O1 Sybil resistance: one TPM EK equals one identity, proven by credential activation.
- O2 Anti-whitewashing: a ban binds to the EK, so it cannot be shed by re-registering.
- O3 Quantified trust: R(c,T) is deterministic; attacker cost per tier is measured.
- O4 Aggregator-agnostic: trust outputs dict[str, float] weights for FedAvg, Krum, TrimmedMean.

## Deployment model
Target is 1 server PC + 5 client PCs on a LAN, all Ubuntu. For development one PC
plays every role. Moving between the two is a config edit, not a code change,
because of two seams:

1. Transport. fl/server.py talks only to ClientHandle objects. LocalClientHandle
   wraps an in-process client; RemoteClientHandle does HTTP to net/agent.py on a
   client machine. The round lifecycle is identical in both modes.
2. TPM backend, per client (config.py). real uses the machine's hardware TPM;
   swtpm uses a software TPM per simulated client; mock is a pure-Python signer.

Switch: set MODE="real" in config.py, fill in the 5 endpoints, set every client's
tpm_backend to "real", run net/agent.py on each machine.

## Trust tiers (set at enrollment)
- Tier 1 hardware-attested: EK cert chains to a manufacturer CA AND activation passes.
  Full weight, slow escalation, rehabilitation allowed.
- Tier 2 TPM-resident: activation passes, no verifiable cert (AMD fTPM, or swtpm).
  Capped weight, fast escalation, no rehabilitation.
- Tier 3 software / TOFU: no hardware proof. Minimal weight, rate-limited.

## Layout
- config.py   topology and run mode. The single local-to-real switch.
- tpm/        Layer 1. EK + AIK, EK-cert verification, MakeCredential/ActivateCredential.
- trust/      Detection (filter.py) and the contribution (reputation.py, probation.py).
- fl/         CNN, non-IID data, client (compute only), server (enrollment + rounds), aggregators.
- net/        Transport seam. ClientHandle implementations and the client HTTP agent.
- audit/      Local append-only signed hash chain for bans and round anchors.
- eval/       Scenarios, multi-seed CSV runner, figures. Produces the Chapter 4 numbers.
- tests/      End-to-end self-test.

Run scripts from the project root so top-level imports (import config,
from fl.server import ...) resolve.

## Honest scope
The hardware-rooted guarantee holds only where a verifiable EK certificate exists
(Tier 1). Without it, whitewashing is hardware-cost-bound, not impossible. Stated
as a result, not hidden.
