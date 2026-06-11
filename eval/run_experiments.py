"""
eval/run_experiments.py

Chapter 4 generator. Runs every experiment multi-seed on the synthetic
substrate (see scenarios.py for why that is valid for trust-layer claims) and
writes CSVs plus a summary to --out. The MNIST runs reuse the same round loop
machine-side and report end-model accuracy separately.

  accuracy   DLTF vs no-trust baseline under none/sybil/poison/sleeper (O4)
  detection  flag and ban latency per attack (written with accuracy)
  whitewash  banned EK re-registration attempts blocked vs baseline (O2)
  cost       attacker identities consumed and influence bought per tier (O3)
  rehab      probation outcomes: recovering vs persistent Tier-1 attacker
  sweep      threshold calibration: FPR vs detection latency (defends defaults)

  python3 -m eval.run_experiments --exp all --seeds 5 --rounds 30 --out results --check
"""
import os
import csv
import argparse
import statistics as st

import trust.filter as tfmod
from trust.reputation import Status
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from fl.server import FederatedServer
from eval.scenarios import (SyntheticWorld, BaselineServer, ATTACKS,
                            build, run_rounds, make_handle, behavior)


def _write(path, header, rows):
    with open(path, "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(header)
        wr.writerows(rows)
    print(f"✓ wrote {path} ({len(rows)} rows)")


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return st.mean(xs) if xs else float("nan")


def _sd(xs):
    xs = [x for x in xs if x is not None]
    return st.stdev(xs) if len(xs) > 1 else 0.0


def first_flag(records, attackers):
    for rec in records:
        for a in attackers:
            e = rec["events"].get(a)
            if e and e["severity"] != "NEUTRAL":
                return rec["round"]
    return None


def first_all_banned(records, attackers):
    for rec in records:
        if set(attackers) <= rec["banned"]:
            return rec["round"]
    return None


def _mini(world, defense, seed, n_honest, attacker_specs):
    """Custom federation: attacker_specs = [(label, kind, start, tier), ...]."""
    ca_key, ca_cert = generate_test_ca()
    if defense == "dltf":
        srv = FederatedServer([0.0] * world.dim, ca_bundle_pem=ca_bundle_pem(ca_cert),
                              shadow_eval_fn=world.accuracy)
    else:
        srv = BaselineServer([0.0] * world.dim)
    hs = [make_handle(f"h{k}", behavior(world, "honest", seed * 100 + k))
          for k in range(n_honest)]
    for label, kind, start, tier in attacker_specs:
        cert, fail = None, False
        if tier == 1:
            cert, _ = issue_ek_cert(ca_key, ca_cert, label)
        elif tier == 3:
            fail = True
        hs.append(make_handle(label, behavior(world, kind, seed * 100 + 99,
                                              attack_start=start),
                              ek_cert_der=cert, fail_activation=fail))
    for h in hs:
        srv.enroll(h)
    return srv, hs, (ca_key, ca_cert)


# ---- experiments ----------------------------------------------------------------

def exp_accuracy(seeds, rounds, out):
    acc, det = [], []
    for attack in ATTACKS:
        for defense in ("dltf", "baseline"):
            for seed in range(seeds):
                w = SyntheticWorld(seed)
                srv, hs, att, start, _ = build(w, defense, attack, seed)
                rec = run_rounds(srv, hs, w, rounds)
                for r in rec:
                    acc.append([attack, defense, seed, r["round"],
                                round(r["accuracy"], 4), len(r["banned"])])
                if defense == "dltf" and att:
                    ff, fb = first_flag(rec, att), first_all_banned(rec, att)
                    det.append([attack, seed, start, ff,
                                None if ff is None else ff - start,
                                fb, None if fb is None else fb - start])
    _write(os.path.join(out, "accuracy.csv"),
           ["attack", "defense", "seed", "round", "accuracy", "n_banned"], acc)
    _write(os.path.join(out, "detection.csv"),
           ["attack", "seed", "attack_start", "first_flag_round", "flag_latency",
            "all_banned_round", "ban_latency"], det)
    return acc, det


def exp_whitewash(seeds, out, attempts=5):
    rows = []
    for defense in ("dltf", "baseline"):
        for seed in range(seeds):
            w = SyntheticWorld(seed)
            srv, hs, _ = _mini(w, defense, seed, 4, [("w0", "persistent", 0, 2)])
            rec = run_rounds(srv, hs, w, 6)
            banned_at = first_all_banned(rec, ["w0"])
            blocked = 0
            for _ in range(attempts):
                res = srv.enroll(make_handle("w0", behavior(w, "persistent", seed,
                                                            attack_start=0)))
                if res["status"] == "BANNED":
                    blocked += 1
            rows.append([defense, seed, banned_at, attempts, blocked])
    _write(os.path.join(out, "whitewash.csv"),
           ["defense", "seed", "banned_at_round", "reenroll_attempts", "blocked"], rows)
    return rows


def exp_cost(seeds, rounds, out):
    rows = []
    for tier in (1, 2, 3):
        for seed in range(seeds):
            w = SyntheticWorld(seed)
            label0 = f"t{tier}a0"
            srv, hs, (ca_key, ca_cert) = _mini(w, "dltf", seed, 6,
                                               [(label0, "persistent", 0, tier)])
            current, identities = label0, 1
            weight_rounds, active_rounds, first_ban = 0.0, 0, None
            for r in range(rounds):
                rep = srv.run_round(r, hs)
                wgt = rep["weights"].get(current, 0.0)
                if wgt > 0:
                    active_rounds += 1
                    weight_rounds += wgt
                if srv.rep.get_status(current) == Status.BANNED:
                    if first_ban is None:
                        first_ban = r
                    nxt = f"t{tier}a{identities}"      # mint a fresh identity
                    cert, fail = None, tier == 3
                    if tier == 1:
                        cert, _ = issue_ek_cert(ca_key, ca_cert, nxt)
                    h = make_handle(nxt, behavior(w, "persistent", seed + identities,
                                                  attack_start=0),
                                    ek_cert_der=cert, fail_activation=fail)
                    srv.enroll(h)
                    hs.append(h)
                    current, identities = nxt, identities + 1
            rows.append([tier, seed, rounds, identities, active_rounds,
                         round(weight_rounds, 3),
                         round(weight_rounds / identities, 4), first_ban])
    _write(os.path.join(out, "cost.csv"),
           ["tier", "seed", "rounds", "identities_consumed", "active_rounds",
            "weight_rounds_injected", "weight_rounds_per_identity",
            "first_ban_round"], rows)
    return rows


def exp_rehab(seeds, out, max_rounds=40):
    """Adaptive attacker: attacks until sanctioned (guaranteeing probation
    entry, which is the event this experiment conditions on), then either
    reforms (recovering) or keeps attacking (persistent)."""
    rows = []
    for kind in ("recovering", "persistent"):
        for seed in range(seeds):
            w = SyntheticWorld(seed)
            srv, hs, (ca_key, ca_cert) = _mini(w, "dltf", seed, 5, [])
            mode = {"attack": True}

            def trainer(r, p, _w=w, _m=mode):
                if _m["attack"]:
                    return _w.attack_update(), 64
                return (_w.target * 2.0).tolist(), 64

            cert, _ = issue_ek_cert(ca_key, ca_cert, "rz")
            h = make_handle("rz", trainer, ek_cert_der=cert)
            srv.enroll(h)
            hs.append(h)

            outcome = oround = entered = None
            for r in range(max_rounds):
                rep = srv.run_round(r, hs)
                if entered is None and srv.rep.get_status("rz") == Status.PROBATION:
                    entered = r
                    if kind == "recovering":
                        mode["attack"] = False
                for d, o in rep["probation_decisions"]:
                    if d == "rz" and o in ("REINSTATED", "PERMANENT_BAN"):
                        outcome, oround = o, r
                if outcome:
                    break
            summ = (srv.probation.summary("rz")
                    if srv.probation.get_record("rz") else {})
            rows.append([kind, seed, outcome, oround, entered, summ.get("window"),
                         summ.get("extended"), summ.get("ols_slope")])
    _write(os.path.join(out, "rehab.csv"),
           ["behavior", "seed", "outcome", "decision_round", "probation_entry",
            "window", "extended", "ols_slope"], rows)
    return rows


SWEEP_GRID = {
    "COSINE_MEDIAN_THRESHOLD": [-0.65, -0.55, -0.45, -0.35, -0.25, -0.15],
    "FOOLSGOLD_SIM": [0.85, 0.90, 0.95, 0.99],
    "NORM_CLIP_FACTOR": [1.5, 2.0, 2.5, 3.5],
}


def exp_sweep(seeds, out):
    rows = []
    for param, values in SWEEP_GRID.items():
        orig = getattr(tfmod, param)
        for v in values:
            setattr(tfmod, param, v)
            for seed in range(seeds):
                w = SyntheticWorld(seed)
                srv, hs, _ = _mini(w, "dltf", seed, 7, [])
                rec = run_rounds(srv, hs, w, 12)
                flagged = {d for r in rec for d, e in r["events"].items()
                           if e["severity"] != "NEUTRAL"}
                fpr = len(flagged) / 7
                lat = {}
                for attack in ("sybil", "poison"):
                    s2, h2, att, start, _ = build(w, "dltf", attack, seed)
                    r2 = run_rounds(s2, h2, w, 15)
                    ff = first_flag(r2, att)
                    lat[attack] = None if ff is None else ff - start
                rows.append([param, v, seed, round(fpr, 3),
                             lat["sybil"], lat["poison"]])
        setattr(tfmod, param, orig)
    _write(os.path.join(out, "sweep.csv"),
           ["param", "value", "seed", "honest_fpr", "flag_latency_sybil",
            "flag_latency_poison"], rows)
    return rows


# ---- summary and checks ----------------------------------------------------------

def write_summary(out, acc, det, ww, cost, rehab, sweep, rounds):
    L = []
    L.append("DLTF evaluation summary (synthetic substrate)")
    L.append(f"rounds per run: {rounds}\n")

    L.append("[accuracy] final-round accuracy, mean +/- sd over seeds")
    final = {}
    for a, d, s, r, v, nb in acc:
        if int(r) == rounds - 1:
            final.setdefault((a, d), []).append(float(v))
    for (a, d), vs in sorted(final.items()):
        L.append(f"  {a:<8} {d:<9} {_mean(vs):.3f} +/- {_sd(vs):.3f}")

    L.append("\n[detection] latency in rounds from attack start (DLTF)")
    by = {}
    for a, s, st_, ff, fl, fb, bl in det:
        by.setdefault(a, {"flag": [], "ban": []})
        by[a]["flag"].append(fl)
        by[a]["ban"].append(bl)
    for a, dd in sorted(by.items()):
        L.append(f"  {a:<8} flag {_mean(dd['flag']):.1f}  full ban {_mean(dd['ban']):.1f}")

    L.append("\n[whitewash] banned-EK re-registration (O2)")
    for d in ("dltf", "baseline"):
        rs = [r for r in ww if r[0] == d]
        blocked = sum(r[4] for r in rs)
        total = sum(r[3] for r in rs)
        L.append(f"  {d:<9} blocked {blocked}/{total}")

    L.append("\n[attacker cost] per tier (O3), persistent blatant attacker")
    for t in (1, 2, 3):
        rs = [r for r in cost if r[0] == t]
        L.append(f"  tier {t}: identities {_mean([r[3] for r in rs]):.1f}, "
                 f"influence bought {_mean([r[5] for r in rs]):.2f} weight-rounds, "
                 f"per identity {_mean([r[6] for r in rs]):.3f}")
    L.append("  identity price: tier1 = physical TPM per identity, "
             "tier2/3 = free (software)")

    L.append("\n[rehabilitation] tier-1 probation outcomes")
    for k in ("recovering", "persistent"):
        rs = [r for r in rehab if r[0] == k]
        outs = [r[2] for r in rs]
        L.append(f"  {k:<11} -> {sorted(set(outs), key=str)} "
                 f"({len([o for o in outs if o == 'REINSTATED'])}/{len(outs)} reinstated)")

    L.append("\n[sweep] honest FPR vs flag latency (mean over seeds)")
    byp = {}
    for p, v, s, fpr, ls, lp in sweep:
        byp.setdefault((p, float(v)), {"fpr": [], "ls": [], "lp": []})
        e = byp[(p, float(v))]
        e["fpr"].append(float(fpr)); e["ls"].append(ls); e["lp"].append(lp)
    for (p, v), e in sorted(byp.items()):
        L.append(f"  {p:<26} {v:>6}: fpr {_mean(e['fpr']):.3f}  "
                 f"lat sybil {_mean(e['ls']):.1f}  poison {_mean(e['lp']):.1f}")

    text = "\n".join(L) + "\n"
    with open(os.path.join(out, "summary.txt"), "w") as f:
        f.write(text)
    print(f"✓ wrote {os.path.join(out, 'summary.txt')}")
    return text


def run_checks(acc, det, ww, cost, rehab, sweep, rounds, seeds):
    final = {}
    for a, d, s, r, v, nb in acc:
        if int(r) == rounds - 1:
            final.setdefault((a, d), []).append(float(v))
    for attack, margin in (("sybil", 0.04), ("poison", 0.04), ("sleeper", 0.03)):
        gap = _mean(final[(attack, "dltf")]) - _mean(final[(attack, "baseline")])
        assert gap >= margin, (attack, gap)
    assert abs(_mean(final[("none", "dltf")]) - _mean(final[("none", "baseline")])) <= 0.05
    print("✓ check: DLTF beats baseline under attack, costs ~nothing without")

    for row in det:
        assert row[4] is not None and row[4] <= 3, row
    print("✓ check: every attack flagged within 3 rounds of starting")

    for d, s, b, att, blk in ww:
        assert (blk == att) if d == "dltf" else (blk == 0), (d, blk)
    print("✓ check: O2 whitewash 100% blocked by DLTF, 0% by baseline")

    t1 = [r for r in cost if r[0] == 1]
    t2 = [r for r in cost if r[0] == 2]
    assert _mean([r[6] for r in t1]) > _mean([r[6] for r in t2])
    assert _mean([r[3] for r in t2]) >= rounds * 0.5
    print("✓ check: O3 per-identity influence highest at tier 1; tier 2 burns "
          "an identity nearly every round")

    for k, want in (("recovering", "REINSTATED"), ("persistent", "PERMANENT_BAN")):
        outs = [r[2] for r in rehab if r[0] == k]
        assert outs and all(o == want for o in outs), (k, outs)
    print("✓ check: rehabilitation separates recovering from persistent attackers")

    dflt = [r for r in sweep
            if (r[0], float(r[1])) in (("COSINE_MEDIAN_THRESHOLD", -0.45),
                                       ("FOOLSGOLD_SIM", 0.95),
                                       ("NORM_CLIP_FACTOR", 2.5))]
    assert _mean([float(r[3]) for r in dflt]) <= 0.05
    print("✓ check: honest FPR ~0 at default thresholds")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", default="all",
                    choices=["accuracy", "whitewash", "cost", "rehab", "sweep", "all"])
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--out", default="results")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    want = lambda e: args.exp in (e, "all")
    acc = det = ww = cost = rehab = sweep = None
    if want("accuracy"):
        acc, det = exp_accuracy(args.seeds, args.rounds, args.out)
    if want("whitewash"):
        ww = exp_whitewash(args.seeds, args.out)
    if want("cost"):
        cost = exp_cost(args.seeds, args.rounds, args.out)
    if want("rehab"):
        rehab = exp_rehab(args.seeds, args.out)
    if want("sweep"):
        sweep = exp_sweep(args.seeds, args.out)

    if args.exp == "all":
        print()
        print(write_summary(args.out, acc, det, ww, cost, rehab, sweep, args.rounds))
        if args.check:
            run_checks(acc, det, ww, cost, rehab, sweep, args.rounds, args.seeds)
            print("✓ all evaluation checks passed")


if __name__ == "__main__":
    main()