# MASTER_CONTEXT.md — DLTF Thesis, Current State

Complete context for continuing the DLTF thesis in a new session. This describes
the system AS IT STANDS NOW. Read fully before touching code.

User: Sazzad, CS undergraduate thesis, BRAC University, defending Summer 2026.
Style: terse, direct, bottom-line-first, tables over prose, wants short answers,
corrects verbosity and factual/citation errors directly. House code style: no em
dashes, ✓/✗ in prints, minimal comments, every module has a `__main__` self-test
with assertions, comments map features to objectives O1–O4.

---

## 1. What DLTF is

DLTF (Decentralized Learning Trust Framework): a federated-learning security
system that decides how much to trust each client's gradient based on
hardware-proven identity, sanctions misbehavior so attackers cannot escape by
re-registering, and rehabilitates devices that provably reform.

Four objectives (cited throughout the code):
- O1 Sybil resistance — one TPM chip = one identity (credential activation).
- O2 Anti-whitewashing — bans bind to the TPM's EK hash, survive re-registration.
- O3 Quantified trust — deterministic reputation formula + measured attacker cost.
- O4 Aggregator-agnostic — trust layer outputs plain weight dicts.

Novelty (NOT detection — that uses existing techniques): (a) hardware-rooted
sanction-and-rehabilitation lifecycle, (b) the sanction policy itself is a
function of hardware trust tier (identity replacement cost), (c) attacker cost
per tier is quantified.

---

## 2. Live deployment state

WORKING: 3 physical machines on a Tailscale WireGuard mesh (account tpm97510@),
all Ryzen boxes with AMD firmware TPMs:
- 100.95.144.127 (ubuntu)    → SERVER (runs run_server.py; NOT in CLIENTS list)
- 100.70.28.2   (s4zz4d HP)  → client1 (runs net/agent.py)
- 100.73.178.45 (tafsir HP)  → client2 (runs net/agent.py)

ACHIEVED: Both clients enroll as real Tier 1 (HARDWARE) with DISTINCT EK hashes
(client1 ac6971…, client2 e7c273…), confirming one-chip-one-identity (O1). Real
409,034-param MNIST model is sent by the server. Round loop runs over real HTTP.
Audit chain writes to results/audit.jsonl.

Deployment facts:
- Tailscale is required (Bangladeshi CGNAT blocks direct inbound). All machines
  must be on ONE Tailscale account or only some appear in `tailscale status`.
- The SERVER dials OUT to clients on port 8470; clients never dial the server,
  so the server's own IP is not in config.CLIENTS.
- torch + torchvision needed on SERVER and all CLIENTS (server imports MNISTModel).
- Traffic is WireGuard-encrypted, mitigating the plain-HTTP limitation.

Run order (real, over Tailscale):
  0. All machines on one Tailscale account; `tailscale status` shows all three.
  1. Each CLIENT: `PYTHONPATH=. python3 -m net.agent --label clientN --port 8470`
     (no --stub for real MNIST; first start downloads MNIST). LEAVE RUNNING.
  2. SERVER: `curl http://<clientIP>:8470/health` each (expect {"ok":true}), then
     `PYTHONPATH=. python3 run_server.py --rounds 5` (must print "real MNIST
     model: 409034 parameters").

---

## 3. TPM / hardware attestation — RESOLVED

Both clients reach real Tier 1. Certs live per-machine in `cert/` (each chip has
its OWN cert; certs are NOT shared between machines). Verified chain:
EK cert → AMD intermediate → AMD root; `verify_ek_certificate` returns True.

Key facts and fixes already applied:
- Cert is read from disk (`cert/ek.crt`), NOT live-fetched at enroll time. AMD's
  PKI live-fetch is flaky and returned a different (failing) 1262-byte cert.
  `_try_ek_cert` in tpm/client.py now reads the on-disk cert first, fetch is only
  a fallback.
- `run_server.py` loads `tpm/ca/amd_ftpm_ca.pem` as the server's `ca_bundle_pem`
  and passes it to FederatedServer (without this, cert_ok is always False → all
  Tier 2).
- CA bundle must contain the RIGHT intermediate. AMD chips chain through
  different intermediates: client certs use CN=PRG-RN, but the original bundle
  only had CN=PRG-SSP. Bundle now includes BOTH intermediates + AMDTPM root, so
  the server trusts any AMD chip chaining through either.
- `verify_ek_certificate` (tpm/common.py): tries the strict Rust X.509 parser
  first, falls back to `openssl verify -partial_chain` on ANY failure (parse OR
  chain-walk), because AMD certs are technically malformed (non-spec DEFAULT
  encoding on a critical field) AND chain via partial_chain. Both paths needed.

Enrollment tier gate (fl/server.py): tier is HARDWARE only if
`cert_ok = (cert present) AND (ca_bundle loaded) AND verify_ek_certificate()`
AND credential activation passes. The tier the SERVER assigns depends on what the
AGENT provisions (its tpm_backend), not on files sitting in cert/. config.py
must set `tpm_backend: "real"` and `tcti: "device:/dev/tpmrm0"` for a client to
present its cert.

Diagnostic: `check_tiers.py` (project root) enrolls both clients and prints tier
only, no training — use this to verify tiers before any training run.

DATA MODEL (enrollment, JSON over HTTP, binary fields base64):
  ek_cert    ≜ ⟨EK_pub, issuer, validity, manufacturer_sig⟩
  provision  ≜ ⟨device_label, ek_hash, ak_name, ek_cert, ek_pub⟩  (POST /enroll)
  challenge  ≜ ⟨blob⟩  where blob = MakeCredential(ek_pub, secret) (POST /activate)
  response   ≜ ⟨secret'⟩  where secret' = ActivateCredential(blob)
  identity   ≜ ⟨device_label, ek_hash, tier, status⟩
  ek_hash = SHA256(EK_pub) is the identity fingerprint; bans bind to it (O2).

---

## 4. Reputation engine — FINALIZED (trust/reputation.py)

Bayesian engine in subjective-logic form (Josang 2001; Josang & Ismail 2002),
tier-coupled policy. Class name ReputationEngine. Exports Status, EventTier,
PROBATION_WEIGHT_CAP unchanged.

TRUST SCORE (identical to Josang's probability expectation E = b + a·u):

    T = (α₀ + s) / (α₀ + β₀ + s + f)

s = accumulated good evidence, f = accumulated bad evidence, (α₀, β₀) = tier
prior. Opinion (b, d, u, a) is also exposed: b = s/n, d = f/n, u = (α₀+β₀)/n,
a = α₀/(α₀+β₀), where n = α₀+β₀+s+f. u is the sample-size term (shrinks as
evidence grows). Aggregation weight w = cap(tier)·T, 0 if banned.

THE DERIVATION CHAIN (every constant is [CITED] / [DERIVED] / [ENG], nothing
picked arbitrarily — this is the answer to the supervisor's "why these numbers"):

  β₀ = 2 (all tiers)     [CITED] Josang non-informative prior weight. Identity
                         proof ≠ behavioral proof, so doubt never shrinks by tier.
  w(MINOR) = 1           [CITED] one observation = one count.
  w(MAJOR) = 3           [DERIVED] noise separation: detector's sustained window
                         is 2 rounds, so 2 spurious MINORs must stay below 1
                         deliberate MAJOR; minimal integer with 2·1 < w.
  α₀(Tier1) = β₀+2w = 8  [DERIVED] policy P1: fresh Tier-1 hits probation
                         (T≤0.5) at EXACTLY its 2nd MAJOR. Start trust 0.80 is an
                         OUTPUT of this, not chosen.
  α₀(Tier2) = 8/2 = 4    [DERIVED] activation-only earns half the credit (mirrors
                         0.5 cap). Verified: banned by 1 MAJOR (4/10=0.4),
                         survives 1 MINOR (4/7=0.57).
  α₀(Tier3) = β₀ = 2     [CITED] insufficient reason, a=0.5. Zero tolerance
                         EMERGES: 1 MINOR → 2/5 = 0.40 ≤ 0.5.
  K = α₀+β₀; memory N=K  [DERIVED] rule: prior mass and memory are the same
                         currency (rounds), set equal. → γ = 1−1/K,
                         T_max = 1−1/K.
  θ_probation = 0.5      [CITED] indifference point; Kang trusted-worker threshold.
  θ_reinstate = 0.55     [DERIVED] survives one noise unit: 0.5·(1+1/K₁).
  θ_ban = 0.3            [ENG, sweep] backstop; probation fires first on every
                         reachable path (6 MINORs vs 17). Value immaterial.
  CRITICAL               [DERIVED] a RULE not a weight: confirmed Sybil evidence
                         is identity abuse; any finite weight would let banked
                         history offset it. Bans non-compensably. (Old dead
                         weight of 8 removed.)
  M3 = 2 consec MAJORs   [DERIVED] banked history buys weight not strikes;
                         veteran strike budget = fresh budget from P1.
  FORGIVE_AFTER = 5      [DERIVED] probation W_min + 1.
  FORGET = 0.95 (T1 only)[ENG, sweep] distrust fades at half trust's decay rate:
                         1−(1−γ₁)/2 (Slovic asymmetry). T2/T3 = 1.0 (never).

CURRENT CONSTANT VALUES (verified from code):
  PRIORS  HARDWARE (8,2)  TPM_RESIDENT (4,2)  SOFTWARE (2,2)
  Start T   0.80             0.667               0.50
  K = N     10               6                   4
  γ         0.900            0.8333              0.750
  T_max     0.90             0.833               0.75
  cap       1.0              0.5                 0.1
  strikes   2 MAJOR          1 MAJOR             any
  rehab     yes              no                  no
  BAD_EVIDENCE = {MINOR:1, MAJOR:3}   (CRITICAL is a rule, not in this dict)
  θ_p 0.5 | θ_r 0.55 | θ_b 0.3 | FORGIVE_AFTER 5 | FORGET{HW:0.95}

HARDENING MECHANISMS:
  M1 bounded recency: s ← γ·s + 1 each round, saturates at 1/(1−γ)=K, so a
     sleeper cannot bank unbounded cushion.
  M2 earned asymmetric forgetting: f is sticky, never decays round-by-round;
     fades (×0.95) only after 5 consecutive clean rounds, only for Tier 1. One
     good round launders nothing — defeats on-off attacks.
  M3 sustained escalation: 2 consecutive MAJORs → probation/ban bypassing the
     score, so a high-s veteran sleeper is caught even when its score is >0.5
     (e.g. saturated veteran's 2nd MAJOR: T=0.663 but M3 fires).

METHODS: register(id,tier,ek_hash) / record_event(id,severity) /
reinstate(id, trial_rounds=0) / get_status / get_weight / get_all_weights /
get_opinion(id) → (b,d,u,a) / rank(ids=None) → Josang Def.10 ordering (highest
T first, ties broken by least uncertainty u) / banned_ek_hashes.

---

## 5. Probation engine — FINALIZED (trust/probation.py)

Tier-1-only rehabilitation. A probated client's updates train an ISOLATED shadow
model (frozen global snapshot + only that client's gradients). Reinstatement is
decided by the OLS slope of the shadow model's accuracy over the trial.

  REINSTATE_SLOPE = 0.005  → REINSTATED (calls rep.reinstate with trial rounds)
  EXTEND_SLOPE = 0.001     → one-shot EXTENDED (+3 rounds), else PERMANENT_BAN
  WINDOW = HMAC(device_id, entry_round) ∈ [4, 9]  [DERIVED] 4 = OLS sign-stability
     floor, 9 = K₁−1 (resolve within trust memory). HMAC salt = os.urandom per
     process, so "behave just long enough" timing attacks are blocked.

SLOPE→REPUTATION COUPLING (supervisor's request, now wired): the slope decides
the BRANCH; the passed trial rounds are forwarded to rep.reinstate(id,
trial_rounds=len(accuracy_series)) as EARNED EVIDENCE (s += trial_rounds) before
the θ_r=0.55 floor. So a longer/stronger proven recovery returns with
proportionally higher trust (e.g. 9-round recovery → 0.680 vs 6-round → 0.636).
No new constants. Duck-typed engine interface (reinstate, record_event); module
self-tests standalone.

---

## 6. Worked example (real engine output, for intuition)

  Honest T1: enroll 0.80 → climbs slowly toward 0.90 (s saturates ~10).
  Two MAJORs: 0.80 → 0.615 → 0.500 (probation at exactly 2nd, weight drops to 0.05).
  Tier-2 MINOR then MAJOR: 0.667 → 0.571 (survives) → 0.400 (BANNED, no rehab).
  Sleeper (30 clean then attack): banks 0.898, MAJOR#1→0.769, MAJOR#2→0.663
    (score >0.5 but M3 fires → probation).
  On-off (MAJOR then clean spam): f stays 3.0 through 4 clean rounds (not
    laundered), fades only after the 5th.
  Probation trial: shadow acc 0.52→0.62, slope +0.02 ≥ 0.005 → REINSTATED at
    T=0.636 (0.55 floor + 5 trial rounds credited).

---

## 7. Architecture (5 layers + eval + tests)

  tpm/     identity: EK cert verify + credential activation → tier
  trust/   reputation.py (above), probation.py (above), filter.py (detection)
  fl/      model (MNIST CNN 409k params), dataset (non-IID), client, aggregator
           (fedavg/krum/trimmed_mean), server (enroll + round lifecycle)
  net/     handles.py (local↔remote seam), agent.py (per-client HTTP agent)
  audit/   hashchain.py (HMAC-signed tamper-evident JSONL chain)
  eval/    scenarios, run_experiments (Chapter-4 CSVs + --check), plot_results
  tests/   test_pipeline.py (all module self-tests + compile + HTTP/audit e2e)

Detection (filter.py, existing techniques, max-severity compose):
  Stage1 norm > 2.5× median → MINOR
  Stage2 cosine to leave-one-out median of prior-trusted < −0.45 → MAJOR
  Stage3 FoolsGold-style pairwise sim ≥ 0.95 sustained 2 rounds → CRITICAL
  Stage4 self-history cosine < −0.45 sustained 2 rounds → MAJOR

Audit is a LOCAL hash chain, not blockchain. An earlier Polygon iteration was
replaced by audit/hashchain.py. No smart contracts in the current codebase. A
thin public anchor (write head hash to a minimal contract) is stated FUTURE
WORK only — do not reintroduce blockchain unless explicitly asked.

Trust model: server trusted (centralized FL); clients untrusted; only the
manufacturer roots/intermediates in the CA bundle are trusted. Weight =
cap(tier)·T; banned devices absent from weights → structurally excluded from
aggregation. Krum uses weights as an eligibility mask (O4).

---

## 8. Related work positioning (for thesis Ch.2 / defense)

  FoolsGold [Fung 2018]: gradient-similarity detection only; no identity, no
    cost to re-register. DLTF includes a FoolsGold-style stage but adds
    hardware-bound identity that detection binds to.
  Kang 2019/2020 (multi-weight subjective logic FL reputation): DLTF's flagship
    citation. Source of two principles used — negative weighted > positive
    (interaction effects), recent > past (interaction timeliness). Do NOT copy
    their numeric weights (vehicular-specific) — would erase DLTF's tier priors.
    Sui 2024 review documents Kang's new-vs-old-client flaw = the same flaw the
    supervisor flagged.
  Josang 2001 (subjective logic): the formal foundation. DLTF's trust formula IS
    his E = b + a·u; his Def.10 (least-uncertainty ordering) = DLTF's rank().
  Wang 2022 (TPM + blockchain oracle FL): uses TPM for update INTEGRITY, not
    persistent identity binding. DLTF binds identity so bans survive re-join.
  Friedman & Resnick 2001 (cheap pseudonyms) + Ostrom 1990 (graduated
    sanctions): justify tier-coupling (policy scales with identity cost).
  Honesty rule: NO paper prescribes the 1/3/8-style values — they are derived
    from DLTF's own policy rules. Claiming a paper gives them = fabricated
    citation. Defend by derivation, not citation.

---

## 9. Known limitations (state ALL in thesis)

  X.509 path validation simplified (name chain + signatures; no revocation /
  full RFC 5280 / EK-profile OIDs). Plain HTTP at request level (mitigated by
  Tailscale/WireGuard in deployment; request-level auth is future work). Tier 1
  only where a verifiable EK cert exists — claim is "whitewashing becomes
  hardware-cost-bound", never "impossible". Audit log centralized (verifiable,
  not consensus). In-memory engine state (restart = re-enroll). Synthetic
  substrate for trust metrics; MNIST accuracy machine-side. Small federation
  (2 real / ~10 simulated). Three reputation constants remain [ENG] inside
  derived bounds (exact caps, 2:1 forgetting ratio, θ_ban backstop) — defended
  by the threshold sweep, not citation. Uncertainty u never reaches 0 (bounded
  memory) — deliberate, this is what defeats sleepers.

---

## 10. PENDING / next steps

  ⚠ RE-RUN Chapter-4 evaluations. Reputation constants changed (γ for Tier 2/3
    now 0.833/0.750; CRITICAL de-weighted), so prior CSV numbers are stale.
    Command: `PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5
    --rounds 30 --out results --check`, then plot_results.
  - Before re-run: `grep -rn "BAD_EVIDENCE\[.CRITICAL" eval/ trust/` — CRITICAL
    is no longer a BAD_EVIDENCE key; any code reading it will KeyError.
  - Verify pipeline still green after the reputation/probation swap:
    `PYTHONPATH=. python3 tests/test_pipeline.py` (expect "✓ PIPELINE GREEN";
    downstream Tier-2 honest weights confirmed in range 0.3–0.5).
  - Live attack demo over Tailscale: one client sends poisoned updates to show a
    real flag → ban → EK-bound whitewash rejection.
  - fl/model.py self-test needs torch (machine-side).

Quick-start commands:
  PYTHONPATH=. python3 tests/test_pipeline.py
  PYTHONPATH=. python3 check_tiers.py                 # tiers only, no training
  PYTHONPATH=. python3 run_server.py --rounds 5       # real MNIST over Tailscale
  PYTHONPATH=. python3 -m net.agent --label client1 --port 8470   # on each client
  PYTHONPATH=. python3 trust/reputation.py            # reputation self-test
  PYTHONPATH=. python3 trust/probation.py             # probation self-test
