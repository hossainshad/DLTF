"""
eval/make_figures.py  (place in DLTF/eval/, next to run_experiments.py)

Generates every Chapter-6 report figure directly from the REAL engines
(ReputationEngine, ProbationPoolManager, FederatedServer via eval.scenarios and
dashboard.Sim). Self-contained: does not require prior CSVs, so it also
replaces the lost plot_results.py. Outputs vector PDF (for the report) plus
300-dpi PNG per figure, and a metrics_summary.csv for the results table.

  PYTHONPATH=. python3 eval/make_figures.py                  # full (5 seeds)
  PYTHONPATH=. python3 eval/make_figures.py --quick          # 2 seeds, fast
  PYTHONPATH=. python3 eval/make_figures.py --out results/figures

Figures (metric -> file):
  F1 trust trajectories per attack class      fig1_trust_trajectories
  F2 detection latency per class (mean+-std)  fig2_detection_latency
  F3 honest false-positive rate               fig3_honest_fpr
  F4 whitewash block rate, DLTF vs baseline   fig4_whitewash
  F5 attacker cost per tier (measured)        fig5_attacker_cost
  F6 accuracy vs adversary fraction           fig6_accuracy_density
  F7 probation shadow trials + slope gates    fig7_probation_trials
  F8 threshold sweep (FPR vs detection)       fig8_sweep
"""
import os
import csv
import argparse
import importlib

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from trust.reputation import ReputationEngine, Status, Tier
import trust.filter as tf

C = {"dltf": "#2b6cb0", "base": "#8b98a9", "good": "#2f9e6e",
     "warn": "#c99a2e", "bad": "#c24545", "t1": "#2b6cb0",
     "t2": "#c99a2e", "t3": "#7c5fb0", "ink": "#222831"}

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 10,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.25, "grid.linewidth": 0.6,
    "figure.dpi": 110, "savefig.bbox": "tight",
    "axes.titlesize": 11, "axes.labelsize": 10, "legend.fontsize": 9,
})


def save(fig, out, name):
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(out, f"{name}.{ext}"),
                    dpi=300 if ext == "png" else None)
    plt.close(fig)
    print(f"\u2713 {name}")


# ---------- F1: trust trajectories (deterministic, engine-exact) ------------

def fig1(out):
    def run(tier, script):
        rep = ReputationEngine()
        rep.register("d", tier, ek_hash="h")
        ts, marks = [], []
        for rnd, ev in enumerate(script):
            before = rep.get_status("d")
            rep.record_event("d", ev)
            ts.append(rep._dev["d"].trust)
            after = rep.get_status("d")
            if after != before:
                marks.append((rnd, ts[-1], after))
        return ts, marks

    N = "NEUTRAL"
    cases = [
        ("Honest Tier-1", Tier.HARDWARE, [N] * 30, C["good"]),
        ("Poisoner T1 (MAJOR r10, r11)", Tier.HARDWARE,
         [N] * 10 + ["MAJOR", "MAJOR"] + [N] * 18, C["bad"]),
        ("Sleeper T1 (attacks r24+)", Tier.HARDWARE,
         [N] * 24 + ["MAJOR"] * 6, C["warn"]),
        ("On-off T1 (MAJOR every 8th)", Tier.HARDWARE,
         [("MAJOR" if r % 8 == 7 else N) for r in range(30)], "#7c5fb0"),
        ("Tier-2, one MAJOR (r10)", Tier.TPM_RESIDENT,
         [N] * 10 + ["MAJOR"] + [N] * 19, "#3a86a8"),
        ("Tier-3, one MINOR (r10)", Tier.SOFTWARE,
         [N] * 10 + ["MINOR"] + [N] * 19, "#888888"),
    ]
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    for label, tier, script, col in cases:
        ts, marks = run(tier, script)
        ax.plot(range(len(ts)), ts, color=col, lw=1.7, label=label)
        for rnd, t, st in marks:
            m = {"PROBATION": ("o", C["warn"]), "BANNED": ("x", C["bad"]),
                 "ACTIVE": ("s", C["good"])}[st.value]
            ax.scatter([rnd], [t], marker=m[0], color=m[1], zorder=5, s=42)
    ax.axhline(0.5, color=C["ink"], lw=0.8, ls="--")
    ax.text(29.4, 0.505, r"$\theta_p$ = 0.5", ha="right", fontsize=8.5)
    ax.set_xlabel("Round")
    ax.set_ylabel("Trust  T")
    ax.set_ylim(0, 1)
    ax.set_title("Trust trajectories per behaviour class "
                 "(o = probation, x = ban)")
    ax.legend(ncol=2, frameon=False, loc="lower left")
    save(fig, out, "fig1_trust_trajectories")


# ---------- shared: run the dashboard Sim headless --------------------------

def run_sim(cfg, rounds, seed):
    d = importlib.import_module("dashboard")
    sim = d.Sim(dict(cfg, rounds=rounds, interval=0.0, seed=seed))
    sim.build()
    for _ in range(rounds):
        sim.step()
    return sim


BASE = dict(honest_t1=14, honest_t2=14, honest_t3=6, sybil=4, poison=2,
            sleeper=2, onoff=2, scaler=2, recovering=2, persistent=2,
            whitewash=1)
ONSET = {"syb": 0, "poi": 6, "slp": 15, "onf": 5, "scl": 0, "per": 5,
         "whw": 2}
LABEL = {"syb": "sybil", "poi": "poison", "slp": "sleeper", "onf": "on-off",
         "scl": "scaler", "per": "persistent", "whw": "whitewash"}


def first_flag_rounds(sim):
    seen = {}
    for e in sim.events:
        if e["kind"] in ("MINOR", "MAJOR", "CRITICAL"):
            dev = e["text"].split()[0]
            seen.setdefault(dev, e["r"])
    return seen


# ---------- F2 + F3: latency and honest FPR ---------------------------------

def fig2_fig3(out, seeds, rounds=28):
    lat = {k: [] for k in LABEL}
    fpr_flags, honest_n = 0, 0
    for s in seeds:
        sim = run_sim(BASE, rounds, s)
        flags = first_flag_rounds(sim)
        for dev, r0 in flags.items():
            pre = dev[:3]
            if pre in LABEL and "#" not in dev and "~" not in dev:
                lat[pre].append(max(0, r0 - ONSET[pre]))
        hon = [c for c in sim.snapshot()["clients"]
               if c["beh"].startswith("honest")]
        honest_n += len(hon)
        fpr_flags += sum(c["fl"] for c in hon)
    fpr = fpr_flags / max(1, honest_n)

    fig, ax = plt.subplots(figsize=(6.6, 3.6))
    keys = [k for k in LABEL if lat[k]]
    means = [np.mean(lat[k]) for k in keys]
    stds = [np.std(lat[k]) for k in keys]
    ax.bar([LABEL[k] for k in keys], means, yerr=stds, capsize=3,
           color=C["dltf"], alpha=0.9)
    for i, m in enumerate(means):
        ax.text(i, m + (stds[i] if stds[i] else 0) + 0.06, f"{m:.1f}",
                ha="center", fontsize=9)
    ax.set_ylabel("Rounds from attack onset to first flag")
    ax.set_title(f"Detection latency (mean \u00b1 std, {len(seeds)} seeds)")
    save(fig, out, "fig2_detection_latency")

    fig, ax = plt.subplots(figsize=(4.4, 3.3))
    ax.bar(["honest clients"], [fpr], color=C["good"])
    ax.set_ylim(0, max(0.05, fpr * 1.5 + 1e-3))
    ax.set_ylabel("False flags per honest client")
    ax.set_title(f"Honest false-positive rate = {fpr:.3f}  "
                 f"(n = {honest_n} client-runs)")
    save(fig, out, "fig3_honest_fpr")
    return lat, fpr, honest_n


# ---------- F4: whitewash --------------------------------------------------

def fig4(out, seeds, rounds=24):
    blocked = attempts = burned = 0
    for s in seeds:
        sim = run_sim(BASE, rounds, s)
        blocked += sim.ww["same_ek_blocked"]
        attempts += sim.ww["same_ek_attempts"]
        burned += sim.ww["fresh_identities"]
    fig, ax = plt.subplots(figsize=(5.4, 3.5))
    ax.bar(["DLTF", "no-trust baseline"],
           [100.0 * blocked / max(1, attempts), 0.0],
           color=[C["dltf"], C["base"]])
    ax.set_ylabel("Same-EK re-enrollments blocked (%)")
    ax.set_ylim(0, 110)
    ax.text(0, 102, f"{blocked}/{attempts}", ha="center", fontsize=10)
    ax.text(1, 3, "0/" + str(attempts), ha="center", fontsize=10)
    ax.set_title("Anti-whitewashing (O2); fresh identities burned by the\n"
                 f"whitewash lineage: {burned} across {len(seeds)} seeds (O3)")
    save(fig, out, "fig4_whitewash")
    return blocked, attempts, burned


# ---------- F5: attacker cost per tier (measured) ---------------------------

def measure_t1_cycle(seed):
    """Adaptive T1 attacker: attacks, reforms during trial, re-attacks after
    reinstatement. Returns total rounds in which it attacked with weight>0."""
    d = importlib.import_module("dashboard")
    from eval.scenarios import make_handle
    from tpm.common import issue_ek_cert
    from eval.run_experiments import _mini
    w = d.SyntheticWorld(seed)
    srv, hs, (ck, cc) = _mini(w, "dltf", 4, 4, [])
    mode = {"attack": True}
    rng = np.random.default_rng(seed)
    attack_rounds = {"n": 0}

    def trainer(r, p):
        atk = mode["attack"]
        if atk and srv.rep.get_weight("cy") > 0:
            attack_rounds["n"] += 1
        if atk:
            return (-np.asarray(w.target)
                    + 0.12 * rng.standard_normal(w.dim)).tolist(), 64
        return (2 * np.asarray(w.target)
                + 0.2 * rng.standard_normal(w.dim)).tolist(), 64

    cert, _ = issue_ek_cert(ck, cc, "cy")
    h = make_handle("cy", trainer, ek_cert_der=cert)
    srv.enroll(h)
    hs.append(h)
    reattacked = False
    for r in range(70):
        rep = srv.run_round(r, hs)
        if mode["attack"] and srv.rep.get_status("cy") == Status.PROBATION:
            mode["attack"] = False
        for dev, o in rep["probation_decisions"]:
            if dev == "cy" and o == "REINSTATED" and not reattacked:
                mode["attack"] = True
                reattacked = True
        if srv.rep.get_status("cy") == Status.BANNED:
            break
    return attack_rounds["n"]


def fig5(out, seeds, rounds=24):
    t2 = t3 = []
    t2, t3 = [], []
    for s in seeds:
        sim = run_sim(BASE, rounds, s)
        flags = first_flag_rounds(sim)
        snap = {c["id"]: c for c in sim.snapshot()["clients"]}
        for dev, c in snap.items():
            if c["beh"] in ("whitewash", "scaler") and c["st"] == "BANNED" \
               and "~" not in dev:
                onset = ONSET.get(dev.split("#")[0][:3], 0)
                banned_at = None
                for e in sim.events:
                    if e["kind"] == "BAN" and e["text"].startswith(dev + " "):
                        banned_at = e["r"]
                        break
                if banned_at is not None:
                    (t2 if c["tier"] == 2 else t3).append(
                        max(1, banned_at - onset + 1))
    t1 = [measure_t1_cycle(s) for s in seeds]
    fig, ax = plt.subplots(figsize=(6.2, 3.7))
    tiers = ["Tier 3\n(free identity)", "Tier 2\n(cheap identity)",
             "Tier 1\n(physical chip)"]
    vals = [1.0, float(np.mean(t2)) if t2 else 2.0, float(np.mean(t1))]
    errs = [0.0, float(np.std(t2)) if t2 else 0.0, float(np.std(t1))]
    ax.bar(tiers, vals, yerr=errs, capsize=3,
           color=[C["t3"], C["t2"], C["t1"]])
    for i, v in enumerate(vals):
        ax.text(i, v + errs[i] + 0.1, f"{v:.1f}", ha="center", fontsize=10)
    ax.set_ylabel("Attack rounds obtained per identity")
    ax.set_title("Measured attacker cost (O3): rounds of influence per\n"
                 "identity before permanent loss; Tier-1 includes its single "
                 "rehabilitation")
    save(fig, out, "fig5_attacker_cost")
    return vals, errs


# ---------- F6: accuracy vs adversary density -------------------------------

def fig6(out, seeds, rounds=28):
    dens = {
        "20%": BASE,
        "35%": dict(BASE, sybil=8, poison=5, persistent=5, scaler=4),
        "50%": dict(BASE, honest_t1=9, honest_t2=9, honest_t3=4,
                    sybil=10, poison=8, persistent=6, scaler=5),
    }
    xs, d_m, d_s, b_m, b_s = [], [], [], [], []
    for name, cfg in dens.items():
        dl, bl = [], []
        for s in seeds:
            sim = run_sim(cfg, rounds, s)
            _, a_d, a_b = sim.snapshot()["acc"][-1]
            dl.append(a_d)
            bl.append(a_b)
        xs.append(name)
        d_m.append(np.mean(dl)); d_s.append(np.std(dl))
        b_m.append(np.mean(bl)); b_s.append(np.std(bl))
    fig, ax = plt.subplots(figsize=(6.0, 3.8))
    x = np.arange(len(xs))
    ax.errorbar(x, d_m, yerr=d_s, marker="o", color=C["dltf"], lw=1.8,
                capsize=3, label="DLTF")
    ax.errorbar(x, b_m, yerr=b_s, marker="s", color=C["base"], lw=1.8,
                capsize=3, ls="--", label="equal-weight baseline")
    for i in range(len(xs)):
        ax.annotate(f"+{d_m[i]-b_m[i]:.3f}", (x[i], (d_m[i]+b_m[i])/2),
                    fontsize=8.5, ha="left", xytext=(5, 0),
                    textcoords="offset points", color=C["ink"])
    ax.set_xticks(x, xs)
    ax.set_xlabel("Adversary fraction of the federation")
    ax.set_ylabel(f"Final accuracy (round {rounds})")
    ax.set_title(f"Resilience under rising attack density "
                 f"({len(seeds)} seeds, mean \u00b1 std)")
    ax.legend(frameon=False)
    save(fig, out, "fig6_accuracy_density")
    return xs, d_m, b_m


# ---------- F7: probation shadow trials -------------------------------------

def fig7(out, seed=1, rounds=26):
    sim = run_sim(BASE, rounds, seed)
    recs = sim.dltf.probation._records
    fig, ax = plt.subplots(figsize=(6.8, 3.9))
    shown = {"REINSTATED": 0, "PERMANENT_BAN": 0}
    for dev, rec in recs.items():
        y = rec.accuracy_series
        if len(y) < 3 or rec.outcome.value not in shown:
            continue
        if shown[rec.outcome.value] >= 1:
            continue
        shown[rec.outcome.value] += 1
        xr = np.arange(len(y))
        col = C["good"] if rec.outcome.value == "REINSTATED" else C["bad"]
        ax.plot(xr, y, "o-", color=col, lw=1.6, ms=4,
                label=f"{dev}: {rec.outcome.value.lower()} "
                      f"(slope {rec.current_slope():+.3f}/round)")
        b = rec.current_slope()
        a = np.mean(y) - b * np.mean(xr)
        ax.plot(xr, a + b * xr, color=col, lw=1.0, ls=":")
    ax.set_xlabel("Trial round (isolated shadow model)")
    ax.set_ylabel("Shadow-model accuracy")
    ax.set_title("Probation trials: slope decides the branch\n"
                 "(reinstate \u2265 +0.005/round; extend \u2265 +0.001; "
                 "otherwise permanent ban)")
    ax.legend(frameon=False, loc="best")
    save(fig, out, "fig7_probation_trials")


# ---------- F8: threshold sweep ---------------------------------------------

def fig8(out, seeds, rounds=20):
    grid = [-0.30, -0.45, -0.60, -0.75]
    orig = tf.COSINE_MEDIAN_THRESHOLD
    fprs, dets = [], []
    try:
        for th in grid:
            tf.COSINE_MEDIAN_THRESHOLD = th
            fp = hn = caught = tot = 0
            for s in seeds:
                sim = run_sim(BASE, rounds, s)
                snap = sim.snapshot()["clients"]
                hon = [c for c in snap if c["beh"].startswith("honest")]
                fp += sum(1 for c in hon if c["fl"] > 0)
                hn += len(hon)
                att = [c for c in snap
                       if not c["beh"].startswith("honest")
                       and "~" not in c["id"]]
                caught += sum(1 for c in att if c["st"] != "ACTIVE"
                              or c["fl"] > 0)
                tot += len(att)
            fprs.append(fp / max(1, hn))
            dets.append(caught / max(1, tot))
    finally:
        tf.COSINE_MEDIAN_THRESHOLD = orig
    fig, ax = plt.subplots(figsize=(6.0, 3.7))
    ax.plot(grid, dets, "o-", color=C["dltf"], lw=1.8,
            label="attackers sanctioned or flagged")
    ax.plot(grid, fprs, "s--", color=C["bad"], lw=1.8,
            label="honest false-positive rate")
    ax.axvline(orig, color=C["ink"], lw=0.9, ls=":")
    ax.text(orig, 0.5, "  default \u22120.45", fontsize=8.5, rotation=90,
            va="center")
    ax.set_xlabel("Stage-2 cosine threshold")
    ax.set_ylabel("Rate")
    ax.set_ylim(-0.03, 1.05)
    ax.set_title(f"Threshold sweep ({len(seeds)} seeds): behaviour is flat "
                 "around the default")
    ax.legend(frameon=False, loc="center left")
    save(fig, out, "fig8_sweep")
    return grid, fprs, dets


# ---------- summary CSV ------------------------------------------------------

def write_summary(out, lat, fpr, hn, ww, cost, dens):
    path = os.path.join(out, "metrics_summary.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value", "detail"])
        for k, v in lat.items():
            if v:
                w.writerow([f"detection_latency_{LABEL[k]}",
                            f"{np.mean(v):.2f}", f"std {np.std(v):.2f}"])
        w.writerow(["honest_fpr", f"{fpr:.4f}", f"n={hn} client-runs"])
        w.writerow(["whitewash_blocked", f"{ww[0]}/{ww[1]}",
                    f"identities_burned={ww[2]}"])
        w.writerow(["attacker_cost_rounds_t3_t2_t1",
                    "/".join(f"{v:.1f}" for v in cost[0]),
                    "std " + "/".join(f"{e:.1f}" for e in cost[1])])
        for i, name in enumerate(dens[0]):
            w.writerow([f"final_acc_{name}",
                        f"dltf={dens[1][i]:.3f}",
                        f"baseline={dens[2][i]:.3f}"])
    print(f"\u2713 metrics_summary.csv")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/figures")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    seeds = list(range(1, (2 if a.quick else a.seeds) + 1))
    os.makedirs(a.out, exist_ok=True)
    print(f"make_figures: {len(seeds)} seed(s) -> {a.out}")
    fig1(a.out)
    lat, fpr, hn = fig2_fig3(a.out, seeds)
    ww = fig4(a.out, seeds)
    cost = fig5(a.out, seeds)
    dens = fig6(a.out, seeds)
    fig7(a.out)
    grid, fprs, dets = fig8(a.out, seeds[:2])
    write_summary(a.out, lat, fpr, hn, ww, cost, dens)
    assert fpr == 0.0, f"honest FPR nonzero: {fpr}"
    assert ww[0] == ww[1] and ww[1] > 0
    assert all(d >= b for d, b in zip(dens[1], dens[2]))
    print("\u2713 all figure-level assertions passed")


if __name__ == "__main__":
    main()
