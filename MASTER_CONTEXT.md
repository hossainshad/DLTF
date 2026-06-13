# MASTER_CONTEXT.md — DLTF Thesis Project Handoff

Purpose of this document: complete context transfer to a new AI session so development
can continue without the original conversation. Read fully before touching code.

---
## SESSION-2 UPDATE (latest — read this first; supersedes conflicting older notes)

This project was set up and verified ON THE USER'S REAL LAPTOP this session.
PIPELINE GREEN was achieved on hardware. Key new facts and changes:

A. REAL TIER 1 ACHIEVED (major result). Contrary to the earlier assumption that the
   AMD fTPM has no EK cert, the dev laptop (Ryzen 5 5600X) DOES expose a fetchable EK
   certificate: issuer "Advanced Micro Devices, CN = PRG-RN", chaining PRG-RN ->
   self-signed AMDTPM root. It chain-verifies in DLTF's own verify_ek_certificate
   (returns True) and via `openssl verify` (ek.pem: OK). So the thesis can now
   demonstrate a REAL Tier 1 node, not only the test-CA simulation. CA bundle saved at
   tpm/ca/amd_ftpm_ca.pem (= PRG-RN intermediate + AMDTPM root, PEM). EK cert saved as
   ek.crt (DER, 1262 bytes). Reframe the thesis claim accordingly:
   "Tier 1 demonstrated on commodity AMD hardware with manufacturer-verified attestation."
   NOTE: not all AMD fTPMs have this; it is board/BIOS dependent. Tier model still
   degrades correctly to Tier 2 when the cert is absent.

B. INTEROP FINDING (good viva material). AMD EK certs are technically malformed: a
   non-spec DEFAULT encoding on an extension `critical` field. Python `cryptography`
   (strict, Rust parser) REJECTS them with ParseError(EncodedDefault); openssl is
   lenient and accepts them. Fix applied: tpm/common.py verify_ek_certificate now
   falls back to `_verify_with_openssl` (shells `openssl verify -partial_chain`) when
   the strict parser throws. Synthetic test-CA path still uses the strict parser.

C. FILE FIXES applied this session (the corrected versions are the source of truth):
   - tpm/client.py: _Tpm2Signer._try_ek_cert now calls
     `tpm2_getekcertificate -u <ek.pub> -o <out> -X` (was missing -u, always failed).
   - tpm/check_ek_cert.py: fetch_ek_cert now runs tpm2_createek THEN getekcertificate
     with -u and -X; added a `--ek-cert <file>` flag to verify a saved cert without the
     flaky live network fetch (AMD's PKI server is unreliable). Verification (chain
     check) is NOT skipped by this flag; only the fetch is.
   - tpm/common.py: openssl fallback (see B). PSS-aware _sig_ok also added.
   - trust/filter.py: classify() now returns {} on empty input (crash fix: the eval
     sweep, with no attackers and aggressive thresholds, banned ALL honest clients,
     leaving updates empty -> np.stack([]) crashed). One-line guard added.
   - fl/server.py: reputation_engine is now an injectable constructor arg
     (default ReputationEngine), enabling the beta-engine ablation.

D. NEW FILES this session:
   - trust/reputation_beta.py: Bayesian beta engine, same interface, ablation arm
     (hardware-informed priors Beta(8,2)/(4,2)/(2,2); tier-coupled forgetting; strike
     policy EMERGES from the math). Added to tests/test_pipeline.py.
   - run_server.py (project root): server-PC runner (build handles from config, enroll,
     run rounds, write audit to results/audit.jsonl).
   - tpm/FETCH_EK_CERT.md: step-by-step to fetch+verify an EK cert on any AMD client.
   - tpm/ca/amd_ftpm_ca.pem, ek.crt: real-hardware artifacts (on the user's machine).

E. FULL EVAL RAN on the user's machine (5 seeds, 30 rounds), all --check assertions
   passed. Representative numbers: attacker cost per identity Tier1 ~0.86 vs Tier2 ~0.017
   vs Tier3 ~0.003 (identities burned: ~7.8 Tier1 vs 30 Tier2/3 over 30 rounds);
   rehab recovering 5/5 REINSTATED, persistent 0/5; sweep honest FPR 0.000 through
   COSINE_MEDIAN_THRESHOLD -0.35, rising to 0.057 at -0.25 and 0.400 at -0.15 (so the
   -0.45 default sits safely on the zero-FPR shelf). FoolsGold/NormClip FPR 0.000 across
   their grids. NOTE: the value-arithmetic numbers above are from the ADDITIVE engine.

F. COMMON SETUP GOTCHA: the two files both named client.py (tpm/client.py vs
   fl/client.py) collide on download. The user hit ImportError because an OLD
   tpm_client.py (top-level `from common import EK_RSA_CERT_NV`, class TPMClient, no
   make_signer) had been placed at tpm/client.py. Correct tpm/client.py begins with
   `from tpm.common import (b64d, b64e, sha256_hex, run, mock_key, mock_ek_hash)` and
   ends with a make_signer() factory. Always verify that first import line after copying.

G. CA ALLOW-LIST caveat (limitation to state): Tier 1 is only as sound as the trusted
   CA bundle. A real cloud/VM TPM with a genuine vendor-signed EK cert WOULD verify if
   that vendor CA is trusted; defense is to allow-list only intended manufacturer roots
   (AMD/Intel/Infineon). Mass Tier-1 identities then require renting real attested VMs
   = bounded by rental cost, consistent with the hardware-cost-bound claim.
---


User context: Sazzad, CS undergraduate thesis at BRAC University, defending Summer 2026.
Dev machine: Ryzen 5 5600X with AMD fTPM (which has NO fetchable EK certificate — this
fact shaped the architecture). Communication style: terse, direct, wants short answers,
tables, bottom-line first. House code style: no em dashes, ✓/✗ in prints, minimal
comments, every module has a `__main__` self-test with assertions, code comments map
features to objectives O1–O4.

---

## 1. Thesis objective

DLTF (Decentralized Learning Trust Framework): a federated learning (FL) security
system that decides how much to trust each client's gradient based on hardware-proven
identity, sanctions misbehavior in a way attackers cannot escape by re-registering,
and rehabilitates devices that provably reform.

Four formal objectives (cited throughout the code):
- **O1 Sybil resistance** — one TPM chip = one identity (credential activation).
- **O2 Anti-whitewashing** — bans bind to the TPM's EK hash and survive re-registration.
- **O3 Quantified trust** — deterministic reputation formula + measured attacker cost per tier.
- **O4 Aggregator-agnostic** — trust layer outputs plain weight dicts consumed by any aggregator.

## 2. Problem being solved

FL servers cannot verify who sends gradients. Attacks: **Sybil** (one machine, many fake
clients), **poisoning** (malicious gradients), **sleeper** (behave, then attack),
**whitewashing** (get banned, re-register fresh). Existing reputation systems fail
because identities are free (Friedman & Resnick 2001, "The Social Cost of Cheap
Pseudonyms" — the theoretical backbone). DLTF makes identity expensive to replace via
TPM hardware, which makes negative reputation (bans) and rehabilitation meaningful.

**The novelty is NOT detection** (crowded field; existing techniques used). The novelty:
(a) hardware-rooted sanction-and-rehabilitation lifecycle, (b) the sanction policy
itself is a function of hardware trust tier (identity replacement cost), (c) attacker
cost per tier is quantified ("trust is priced").

## 3. System architecture overview

Five layers:
1. **Identity (tpm/)** — TPM 2.0 enrollment: EK cert verification + credential activation → trust Tier.
2. **Trust (trust/)** — detection (filter) → reputation (score/status/weights) → probation (rehab trials).
3. **Learning (fl/)** — model, data, clients, server round loop, pluggable aggregators.
4. **Transport (net/)** — handle abstraction: in-process (dev) or HTTP (LAN), switched by config.
5. **Audit (audit/)** — tamper-evident hash chain of every trust decision.
Plus **eval/** (Chapter 4 experiment harness) and **tests/** (pipeline capstone).

**Trust tiers** (assigned at enrollment, drive ALL policy):
| Tier | Proof | Weight cap | Strikes | Rehab |
|---|---|---|---|---|
| 1 HARDWARE | EK cert chains to manufacturer CA AND credential activation passes | 1.0 | 2 MAJOR | Yes |
| 2 TPM_RESIDENT | Activation only (swtpm passes this). NOTE: the user's AMD fTPM DOES have a cert and reaches Tier 1; see Session-2 Update A | 0.5 | 1 | No |
| 3 SOFTWARE | Nothing proven (TOFU) | 0.1 | 1 | No |

Core idea: identity replacement cost determines policy. Expensive identities (Tier 1)
get patience and rehabilitation; free identities get low caps and instant bans.

## 4. Folder structure

```
dltf/
├── config.py                  # MODE local/real switch, CLIENTS list (the ONE deploy knob)
├── run_server.py              # server-side runner: builds RemoteClientHandles from
│                              #   config, enrolls agents, runs rounds, writes audit
├── README.md
├── requirements.txt
├── setup.sh                   # scaffold generator
├── tpm/
│   ├── FETCH_EK_CERT.md       # step-by-step EK cert fetch+verify for new AMD clients
│   ├── ca/amd_ftpm_ca.pem     # real AMD CA bundle (PRG-RN + AMDTPM root) [on user machine]
│   ├── common.py              # Tier enum (canonical), assess_tier, EK cert verify,
│   │                          #   make_credential, test CA generator
│   ├── client.py              # TPMSigner backends: mock / swtpm / real + factory
│   └── check_ek_cert.py       # standalone machine diagnostic: which tier can this box reach
├── trust/
│   ├── reputation.py          # THE CONTRIBUTION: additive engine, tier-coupled policy
│   ├── reputation_beta.py     # ablation arm: Bayesian beta engine, same interface
│   ├── probation.py           # rehabilitation trials (shadow model, OLS slope)
│   └── filter.py              # detection: 4 stages, existing techniques
├── fl/
│   ├── model.py               # MNIST CNN, flat list[float] param interface (torch)
│   ├── dataset.py             # non-IID MNIST partition (numpy core, lazy torch)
│   ├── client.py              # FLClient shell + TorchTrainer
│   ├── aggregator.py          # fedavg / trimmed_mean / krum (O4)
│   └── server.py              # FederatedServer: enrollment + round lifecycle
├── net/
│   ├── handles.py             # LocalClientHandle / RemoteClientHandle (the seam)
│   └── agent.py               # HTTP agent run on each client PC
├── audit/
│   └── hashchain.py           # HMAC-signed hash chain, JSONL persistence
├── eval/
│   ├── scenarios.py           # synthetic world, attacker behaviors, baseline server
│   ├── run_experiments.py     # Chapter 4 CSVs + summary + --check assertions
│   └── plot_results.py        # 8 thesis figures from CSVs
├── tests/
│   └── test_pipeline.py       # one command, whole stack verified
├── data/                      # MNIST download target
└── results/                   # CSVs, summary.txt, figs/
```

## 5–6. Purpose of every folder and file

(See tree annotations above; expanded reasoning:)

- **tpm/common.py** — identity root. `assess_tier(cert_ok, activation_ok)` is the tiering
  policy. `verify_ek_certificate` = real X.509 chain verification (cryptography lib) —
  the ONLY check distinguishing real silicon from software TPM. `make_credential` =
  server-side challenge (mock path = HMAC-sealed; real path shells `tpm2_makecredential
  -T none`). `generate_test_ca`/`issue_ek_cert` mint Tier-1 mock devices for experiments.
- **tpm/client.py** — client side. `MockTPMSigner` (deterministic per label, dev),
  `SwtpmSigner`/`RealTPMSigner` (tpm2-tools sequences incl. endorsement-policy session
  for activatecredential; machine-side only). `make_signer(backend, ...)` factory.
- **trust/reputation.py** — additive engine. R starts 100; deltas POSITIVE +5, NEUTRAL 0,
  MINOR −10, MAJOR −25, CRITICAL −60. PROBATION_R=50, BAN_R=20, PROBATION_WEIGHT_CAP=0.1.
  POLICY dict keyed by Tier (cap / major_to_probation / rehab). weight = cap·R/100.
  Bans recorded against EK hash; `register()` returns BANNED for known-banned EKs (O2).
- **trust/reputation_beta.py** — Bayesian alternative, SAME interface. T=(a0+s)/(a0+s+b0+f).
  Priors by tier: (8,2)/(4,2)/(2,2). Evidence: clean round +1 good; MINOR/MAJOR/CRITICAL
  = 1/3/8 bad. Thresholds T≤0.5 probation, T≤0.3 or CRITICAL ban. Novel: hardware-informed
  priors (strike policy EMERGES from math: Tier-1 hits 0.5 at exactly 2nd MAJOR), and
  tier-coupled forgetting (λ=0.95 Tier-1 only, applied only on clean rounds).
  Swap via `FederatedServer(..., reputation_engine=BetaReputationEngine())`.
- **trust/probation.py** — Tier-1-only rehab. Suspect's updates feed an ISOLATED shadow
  model from a frozen snapshot; reinstatement requires OLS slope ≥ 0.005 over an
  HMAC-randomized window [4,9] (salt = os.urandom per process so attackers can't time
  it); 0.001–0.005 → one-shot 3-round extension; else PERMANENT_BAN. Duck-typed engine
  interface (reinstate / record_event).
- **trust/filter.py** — detection, max-severity composition: Stage1 norm > 2.5× median
  → MINOR; Stage2 cosine to LEAVE-ONE-OUT median of prior-trusted contributors < −0.45
  → MAJOR; Stage3 FoolsGold-style current-round pairwise sim ≥ 0.95 sustained 2 rounds
  → CRITICAL; Stage4 self-history cosine < −0.45 sustained 2 rounds → MAJOR.
- **fl/server.py** — integration point. `enroll(handle)`: payload → cert verify →
  MakeCredential challenge → activation check → assess_tier → rep.register → audit.
  `run_round`: collect updates → filter.classify(prev round's weights) →
  rep.record_event → probation enter/step → get_all_weights → aggregate → apply → audit.
  Talks ONLY to duck-typed handles (device_label, tpm_backend, enroll_payload,
  activate_credential, train).
- **fl/aggregator.py** — all aggregators consume (updates dict, weights dict) → flat list.
  Banned devices absent from weights ⇒ structurally excluded. Krum uses weights as
  eligibility mask (O4: trust plugs into averaging AND selection aggregators).
- **fl/model.py** — ~409k-param CNN; flat get/set_parameters; NO dropout/batchnorm/momentum
  so the local-training delta is a clean gradient proxy. Self-test NOT yet run (needs torch).
- **fl/dataset.py** — contiguous class blocks per client + 10% leak; stratified 50/class
  validation held out for the shadow model. Numpy core tested; torch loaders lazy.
- **run_server.py** — server-PC entry point for LAN/internet runs: reads
  config.CLIENTS, builds RemoteClientHandles, enrolls all agents, runs N rounds,
  prints weights/flags per round, writes audit to results/audit.jsonl. (Created at
  wrap-up; lives in /mnt/user-data/outputs, must be placed in project root.)
- **net/handles.py / net/agent.py** — the local↔LAN seam. Agent routes: GET /health,
  POST /enroll /activate /train (JSON, base64 binaries, plain HTTP). Run:
  `python3 -m net.agent --label client1 --port 8470 [--stub]`.
- **audit/hashchain.py** — entries {seq, ts, type, payload, prev, hash, sig};
  hash=SHA256(canonical body), sig=HMAC-SHA256(key, hash); JSONL + sidecar .key file;
  refuses to load tampered files. Server writes ENROLL, WHITEWASH_REJECTED, EVENT
  (non-neutral), BAN (with EK hash — the O2 evidence), PROBATION_ENTER/DECISION, ROUND.
- **eval/scenarios.py** — SyntheticWorld: target direction t; accuracy proxy =
  max(0, 0.5(1+cos(p,t)))·(1−e^(−||p||/25)) (cosine term catches direction attacks,
  norm term catches dilution). Behaviors: honest (t + 0.5·noise), sybil (identical
  orthogonal-side updates), poisoner/sleeper (−t after start), recovering/persistent.
  BaselineServer = plain FedAvg, accepts everything, equal weights (control arm).
  Validity argument: trust layer sees only vectors, so trust-layer claims are
  substrate-independent; MNIST runs (machine-side) report end-model accuracy.
- **eval/run_experiments.py** — experiments: accuracy (DLTF vs baseline × 4 attacks),
  detection latency, whitewash, cost (attacker re-mints identity on every ban; counts
  identities + weight-rounds injected per tier), rehab (ADAPTIVE attacker: attacks
  until probation, then reforms or persists), sweep (threshold grids vs FPR/latency).
  `--check` asserts headline claims. CLI: `--exp all --seeds 5 --rounds 30 --out results --check`.
- **eval/plot_results.py** — 8 PNGs (accuracy 2×2, detection, whitewash, cost, rehab, 3 sweeps).
- **tests/test_pipeline.py** — runs all 14 module self-tests as subprocesses,
  py_compiles 4 machine-side files, end-to-end HTTP+audit smoke, eval whitewash smoke.
  `PYTHONPATH=. python3 tests/test_pipeline.py` → "✓ PIPELINE GREEN".

## 7. End-to-end workflow

Enrollment (once): agent provisions EK+AK → sends ek_hash/ak_name/cert → server verifies
cert chain → sends MakeCredential blob → agent answers via ActivateCredential → server
compares secret → tier assigned → reputation.register(label, tier, ek_hash) → audit ENROLL.

Per round: server broadcasts params → clients train locally, return deltas → filter
classifies (severity per client) → reputation records events (status/weight updates) →
new PROBATION devices enter shadow trials; trials step; verdicts reinstate or perma-ban →
aggregator merges updates with trust weights → global model += aggregate → audit ROUND.

## 8. Data flow (text diagram)

```
client agent ──train──► delta ──HTTP/JSON──► FederatedServer
                                              │
                                              ▼
                                   filter.classify ──severity──► reputation.record_event
                                              │                        │ status, weights
                                              ▼                        ▼
                                   probation.step ◄──suspects── get_all_weights
                                       │ verdicts                      │
                                       ▼                               ▼
                                 reinstate/ban                aggregator(updates, weights)
                                                                       │
                  audit.hashchain ◄── every decision ──────────────────┤
                                                                       ▼
                                                          global_params += aggregate
```

## 9. Module interaction & security mechanisms

- Credential activation = the O1 mechanism (only the EK-holding TPM can decrypt the challenge).
- EK certificate chain = the ONLY real-silicon proof; swtpm passes activation for free,
  hence it can never exceed Tier 2 (honest security boundary).
- Leave-one-out reference median = attacker cannot dilute the reference it is scored against.
- Sustained requirements (FoolsGold 2 rounds, temporal 2 rounds) = single noisy rounds
  never burn one-strike identities.
- Probation window HMAC-randomized = "behave just long enough" timing attacks blocked.
- Shadow model isolation = honest federation's improvement cannot mask a bad actor.
- Hash chain HMAC = file access without the key cannot re-mint a consistent audit log.
- Module coupling: reputation imports Tier from tpm.common (canonical); probation and
  server use duck typing; severities are plain strings ("MAJOR" etc.) matching EventTier names.

## 10 & 12. Blockchain / smart contract status — IMPORTANT HONESTY NOTE

An EARLIER project iteration used Polygon Amoy testnet with a `DLTFRegistry.sol`
contract and `polygon_connector.py`. The clean rebuild (this codebase) REPLACED that
with `audit/hashchain.py`: a local append-only HMAC-signed hash chain. Rationale: the
thesis needs tamper-EVIDENT, offline-verifiable trust records, not consensus; a public
chain added cost/complexity without strengthening the claims. There are NO smart
contracts in the current codebase. Framing for the thesis: hashchain = the audit layer;
publishing the head hash to a public chain is stated future work (one-line bridge).
Do not reintroduce blockchain unless the user explicitly asks. If asked, the agreed
scope is a thin ANCHOR only: a new audit/anchor.py that periodically writes the hash
chain's head hash to a minimal contract on Polygon Amoy (~1-2 days, zero trust-system
changes), upgrading the claim from tamper-evident to publicly tamper-proof. Putting
per-round reputation/bans on-chain was evaluated and rejected (gas cost, latency, new
failure modes, no added proof).

## 11. Federated Learning components

FedAvg (weighted), Krum, TrimmedMean in aggregator.py. MNIST CNN (2 conv + 2 FC,
409,034 params). Non-IID: contiguous class blocks + 10% leak. Plain SGD, 1 local epoch,
lr 0.05 default, no momentum (delta = gradient proxy). 5 LAN clients planned; eval
simulates ~10 synthetically.

## 13. Trust model

Server is trusted (centralized FL). Clients untrusted. TPM manufacturer CAs trusted as
roots. Mock backend trusts nothing (dev only). Tier table in §3 IS the trust model:
trust granted proportional to hardware proof; policy strictness inversely proportional
to identity replacement cost.

## 14. Threat model

In scope: Sybil (caught Stage 3, CRITICAL), blatant/targeted poisoning (Stage 2),
scaling (Stage 1), sleeper (Stage 2/4), whitewashing (EK-bound bans), probation gaming
(randomized window, isolated shadow). Out of scope / limitations: TPM physical attacks,
compromised manufacturer CA, server compromise, network MITM (no TLS on LAN testbed),
gradient inversion privacy attacks, subtle below-threshold poisoning (sweep maps the boundary).

## 15. Dependencies

Python 3.10+. numpy (trust/eval), cryptography ≥ 41 (X.509, test CA), matplotlib (plots),
torch + torchvision (fl/model, real training ONLY — everything else runs without),
tpm2-tools (machine-side real/swtpm). Stdlib elsewhere (http.server, urllib, hmac,
hashlib, csv, statistics). pip installs need `--break-system-packages` on Ubuntu 24.

## 16. Configuration

`config.py`: MODE = "local" | "real"; CLIENTS = list of {device_label, tpm_backend
("mock"/"swtpm"/"real"), tcti, endpoint}; NUM_CLIENTS=5. Local→LAN = edit MODE, fill 5
IPs, set tpm_backend="real", run net/agent.py on each box. Suggested addition (not yet
wired): REPUTATION_ENGINE = "additive" | "beta" passed through to FederatedServer and
eval/scenarios.py build() for a pure-config ablation flip.

## 17. Storage

No database. In-memory engine state (restart = re-enroll; accepted prototype limitation).
Audit: JSONL + .key sidecar. Eval: CSVs + summary.txt + PNGs in results/. MNIST in data/.

## 18. APIs / network

Agent HTTP API (JSON, base64 binaries): GET /health; POST /enroll → provision payload;
POST /activate {blob} → {secret}; POST /train {round, params} → {update, num_samples}.
Timeouts 30s (600s for train). Plain HTTP, trusted LAN assumption (limitation).

## 19. Deployment

Dev: everything in-process via LocalClientHandle (one PC plays server and all clients).

LAN: server PC runs `PYTHONPATH=. python3 run_server.py --rounds N` (builds
RemoteClientHandles from config, enrolls, loops rounds, audit to results/audit.jsonl);
each client PC opens port 8470 (`sudo ufw allow 8470`) and runs
`PYTHONPATH=. python3 -m net.agent --label clientN --port 8470 [--stub]`.
config.py must be identical on all machines (labels must match agent --label flags).
Recommended bring-up order: tpm_backend="mock" + --stub agents (network smoke test),
then drop --stub (real MNIST training; first start downloads MNIST), then
tpm_backend="real" on TPM-equipped boxes (verify tier with `python3 -m tpm.check_ek_cert`).
Agents partition MNIST identically (same seed) and take their own shard — no data
distribution step.

INTERNET deployment (machines NOT on one LAN): zero code changes. Home routers/CGNAT
(common with Bangladeshi ISPs) block direct inbound connections, so use Tailscale
(free WireGuard mesh VPN): install + `sudo tailscale up` on every machine under one
account, each gets a stable 100.x.y.z IP (`tailscale status`), put those IPs in
config.py endpoints. No port forwarding or router config needed. Side benefit for the
thesis: all agent traffic is then WireGuard-encrypted, mitigating the "plain HTTP, no
TLS" limitation in deployment — state this in the limitations section. Expect slower
rounds than LAN (the 600s train timeout already accommodates this). Avoid the
VPS + port-forwarding alternative; CGNAT usually defeats it.

## 20. Testing methodology

Every module: `__main__` self-test with assertions (run `PYTHONPATH=. python3 <file>`).
Capstone: `PYTHONPATH=. python3 tests/test_pipeline.py` (subprocess-isolated module
tests + compile checks + HTTP/audit e2e + eval smoke). Eval has `--check` asserting
headline claims. Verified results (3 seeds, 25 rounds, synthetic):
- No attack: DLTF 0.620 = baseline 0.620 (defense costs nothing).
- Under attack: DLTF 0.614–0.618 vs baseline 0.460–0.521.
- Detection ≤ 1 round; whitewash blocked 15/15 (baseline 0/15).
- Attacker cost: 0.906 weight-rounds/identity Tier-1 (price: physical TPM) vs 0.021
  Tier-2 (free) vs 0.004 Tier-3 — "trust is priced" (O3).
- Rehab: recovering 3/3 REINSTATED; persistent 0/3.
- Sweep: honest FPR 0.000 at default −0.45, cliffs to 0.095/0.334 at −0.35/−0.25.

DONE on the user's machine: full pipeline (PIPELINE GREEN), full eval 5seeds/30rounds
(all --check passed), real Tier-1 EK cert verification on the AMD fTPM.
STILL PENDING machine-side: fl/model.py self-test (needs torch), full MNIST accuracy
runs (synthetic substrate used so far), swtpm/real signer enrollment end-to-end,
beta-engine ablation eval run, live multi-PC / Tailscale demo.

## 21. Known limitations (state ALL in thesis)

X.509 path validation simplified (name chain + signatures; no revocation/full RFC 5280/EK
profile OIDs). No TLS/auth on the HTTP transport itself (mitigated in internet deployment by running over Tailscale/WireGuard; request-level auth still future work). AMD fTPMs cap at Tier 2 (no fetchable EK cert) —
hardware-rooted bans only where verifiable certs exist; claim is "whitewashing becomes
hardware-cost-bound", NEVER "impossible". Audit log centralized (verifiable, not
consensus). In-memory state. Synthetic substrate for trust metrics (MNIST machine-side).
Small federation (5 LAN / ~10 simulated). Constants are design parameters (see §23).
FoolsGold variant simplified — cite as "FoolsGold-style".

## 22. Future improvements

Config-driven engine ablation wiring; MNIST eval substrate plug; TLS + request auth;
posterior lower-confidence-bound (subjective logic uncertainty) in beta engine; public
anchor for audit head hash; persistence/restart recovery; larger federations; full
RFC 5280 validation.

## 23. Important implementation decisions (and bugs fixed — defense gold)

1. Old scripts were security theater: tpm2_checkquote proves signature math only;
   device ID = SHA256(EK_pub) is attacker-chosen; same-machine "binding" checks prove
   nothing. Rebuilt around the only two real mechanisms: EK cert chain + credential activation.
2. Tiered graceful degradation instead of demanding certs (would reject user's own AMD box).
3. Constants derivation (supervisor asked): scale 0–100 arbitrary (ratios matter); each
   value derived from a stated rule — "2 majors → probation" ⇒ MAJOR=−25 (100−50=2×25);
   "5 minors ≈ 2 majors" ⇒ MINOR=−10; "one chance after probation" ⇒ BAN=20; "trust
   falls 5× faster than it rises" ⇒ POSITIVE=+5 (asymmetry principle: Slovic 1993,
   CONFIDANT 2002); graduated sanctions: Ostrom 1990; cheap-pseudonym result: Friedman
   & Resnick 2001. Sweep shows robustness to exact values.
4. Bugs found during build (tell this story in the defense):
   a. Cumulative-history FoolsGold falsely flagged honest correlated clients → switched
      to current-round pairwise + sustained counter.
   b. Stage-4 single-round temporal check fired on ~20% of honest client-rounds at
      realistic SNR → sustained-2 requirement + threshold −0.45.
   c. Self-inclusion in the reference median let attackers dilute their own deviation
      score → leave-one-out reference.
   d. Probation salt (os.urandom per process) made a server test flaky → tests pin the
      salt; recovering poisoner given seeded noise.
5. Eval rehab uses an ADAPTIVE attacker (attacks until sanctioned, then reforms) —
   conditions the experiment on probation entry, which is the question rehab answers.
6. Detection thresholds: −0.45 cosine defended EMPIRICALLY by the sweep FPR cliff.
7. Two reputation engines, one interface = ablation ("structure, not arithmetic, drives
   the defense"). Beta engine novelty: hardware-informed priors (strike policy emerges
   from math), tier-coupled forgetting (only on clean rounds, only Tier 1).

## 24. Glossary

TPM (security chip), EK (Endorsement Key — permanent chip-bound key = silicon
fingerprint), EK certificate (manufacturer-signed proof of genuine chip), AIK/AK
(attestation key), MakeCredential/ActivateCredential (challenge only the EK-holder's
TPM can answer), swtpm (software TPM emulator), fTPM (firmware TPM), Sybil/whitewashing/
sleeper (attacks, §2), FedAvg (weighted averaging), Krum (selects most-consensual
update), non-IID (skewed per-client data), shadow model (isolated copy trained only on
a suspect's updates), EK hash (SHA256 of EK public = identity fingerprint), TOFU
(trust on first use), weight-rounds (Σ of aggregation weight over rounds = influence bought).

## 25. Defense explanation in simple language

"Imagine an online classroom where students submit homework that gets merged into one
shared answer. Cheaters can join with fake names, submit garbage, and when caught,
rejoin under a new name. Our system checks each student's ID card at the door — a chip
soldered into their computer that can't be faked or copied. Students with a
manufacturer-verified chip get full voting power and, because we'd recognize them
forever, we can afford to give them second chances: if they misbehave, they enter a
supervised trial where only their own work is graded, and they're readmitted only if it
measurably improves. Students with weak or no ID get little voting power and one
strike, because banning a free identity means nothing — they'd just come back. The key
insight: how much you trust someone, and how you punish them, should depend on how
expensive their identity is to replace. We measured it: a fake-ID attacker buys almost
zero influence per identity; a real-chip attacker buys 43× more but must purchase a new
physical chip every time we ban them. And honest classrooms lose nothing — with no
cheaters present, our system performs identically to having no security at all."

---

## Quick-start commands for the next session

```
PYTHONPATH=. python3 tests/test_pipeline.py                                   # verify all
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 --rounds 30 --out results --check
PYTHONPATH=. python3 -m eval.plot_results --results results
PYTHONPATH=. python3 -m net.agent --label client1 --port 8470 --stub          # client agent
PYTHONPATH=. python3 run_server.py --rounds 10                                # server runner
# internet deployment: tailscale up on all machines, use 100.x IPs in config
python3 -m tpm.check_ek_cert                                                  # tier diagnostic
```

Engine swap: `FederatedServer(params, reputation_engine=BetaReputationEngine())`
(default = additive `ReputationEngine`).
