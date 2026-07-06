"""
dashboard.py  (place in DLTF project root, next to run_server.py)

Single-machine stress console: hundreds of simulated clients across all three
tiers and every attack class, run through the REAL stack (FederatedServer +
GradientFilter + ReputationEngine + ProbationPoolManager), with a no-trust
BaselineServer in parallel as the control arm. Serves a live web UI instead of
terminal output.

  PYTHONPATH=. python3 dashboard.py                 # open http://127.0.0.1:8765
  PYTHONPATH=. python3 dashboard.py --port 9000
  PYTHONPATH=. python3 dashboard.py --selftest      # headless assertions

Behavior cohorts (all configurable in the UI, mapped to objectives):
  honest t1/t2/t3   control population per tier
  sybil             colluding identical updates            -> CRITICAL, O1
  poison            tier-1 flips at round 6                -> probation, O3
  sleeper           tier-1 clean 15 rounds then attacks    -> M3 sleeper defense
  onoff             tier-1 one MAJOR every 6th round       -> M2 sticky distrust
  scaler            tier-2 8x norm updates                 -> MINOR accumulation
  recovering        tier-1 attacks then reforms            -> REINSTATED, rehab
  persistent        tier-1 attacks through probation       -> PERMANENT_BAN
  whitewash         tier-2 attacker; on ban: same-EK re-enroll (blocked, O2)
                    then fresh identity re-joins (cheap pseudonym, O3 cost)
"""
import os
import json
import time
import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import numpy as np

from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from tpm.client import make_signer
from fl.client import FLClient
from fl.server import FederatedServer
from net.handles import LocalClientHandle
from trust.reputation import Status
from eval.scenarios import (SyntheticWorld, BaselineServer, behavior,
                            make_handle, FailingSigner)

DEFAULT_CFG = {
    "honest_t1": 40, "honest_t2": 40, "honest_t3": 20,
    "sybil": 6, "poison": 4, "sleeper": 3, "onoff": 3, "scaler": 3,
    "recovering": 2, "persistent": 2, "whitewash": 2,
    "rounds": 60, "interval": 0.6, "seed": 1,
}
LIMITS = {"rounds": 300, "interval": 5.0}
WHITEWASH_MAX_GEN = 5
ATTACK_START = {"poison": 6, "sleeper": 15, "recovering": 4,
                "persistent": 5, "whitewash": 2}


def _noisy_attack(world, rng, noise=0.12):
    # independent attackers are NOT bit-identical; only true sybils are.
    # noise 0.12 keeps pairwise cos ~0.8 (< FOOLSGOLD_SIM) while staying
    # anti-aligned with the honest reference (stage-2 MAJOR fires).
    v = -np.asarray(world.target) + noise * rng.standard_normal(world.dim)
    return v.tolist()


def flip_trainer(world, seed, start, reform_after=None):
    """Honest before `start`; attacks from `start`; if reform_after is set,
    trains hard and honestly from round `reform_after` onward."""
    rng = np.random.default_rng(seed)
    def t(r, p):
        if r < start:
            return world.honest_update(rng), 64
        if reform_after is not None and r >= reform_after:
            v = 2.0 * np.asarray(world.target) \
                + 0.2 * rng.standard_normal(world.dim)
            return v.tolist(), 64
        return _noisy_attack(world, rng), 64
    return t


def onoff_trainer(world, seed, period=6):
    rng = np.random.default_rng(seed)
    def t(r, p):
        if r % period == period - 1:
            return _noisy_attack(world, rng), 64
        return world.honest_update(rng), 64
    return t


def scaler_trainer(world, seed, scale=8.0):
    # amplifies a self-serving direction: mostly orthogonal drift plus a small
    # aligned component, so stage 2 (cosine) stays quiet and only the norm
    # check (stage 1, MINOR) can catch it.
    rng = np.random.default_rng(seed)
    def t(r, p):
        v = 0.3 * np.asarray(world.target) + np.asarray(world.side)
        v = v / np.linalg.norm(v) * scale \
            + 0.05 * rng.standard_normal(world.dim)
        return v.tolist(), 64
    return t


def null_trainer(dim):
    return lambda r, p: ([0.0] * dim, 1)


class Sim:
    """Owns both servers, the client population, histories, and the round loop
    state. All public reads/writes go through self.lock."""

    def __init__(self, cfg):
        self.lock = threading.RLock()
        self.cfg = dict(DEFAULT_CFG)
        self.apply_cfg(cfg or {})
        self.phase = "idle"
        self.running = False
        self.round = 0
        self._reset_state()

    def apply_cfg(self, cfg):
        for k, v in cfg.items():
            if k not in DEFAULT_CFG:
                continue
            try:
                v = float(v) if k == "interval" else int(v)
            except (TypeError, ValueError):
                continue
            if k == "interval":
                v = min(max(v, 0.05), LIMITS["interval"])
            elif k == "rounds":
                v = min(max(v, 1), LIMITS["rounds"])
            elif k == "seed":
                v = max(v, 0)
            else:
                v = min(max(v, 0), 300)
            self.cfg[k] = v

    def _reset_state(self):
        self.world = None
        self.dltf = None
        self.base = None
        self.handles = []
        self.base_handles = []
        self.meta = {}
        self.hist = {}
        self.acc = []
        self.events = []
        self.sev_counts = {"MINOR": 0, "MAJOR": 0, "CRITICAL": 0}
        self.prev_status = {}
        self.ww = {"same_ek_attempts": 0, "same_ek_blocked": 0,
                   "fresh_identities": 0}
        self.lineage_gen = {}

    # ---- federation construction ------------------------------------------

    def _pair(self, label, kind, tier, seed, start=0, group_seed=1,
              local_trainer=None):
        """Build matched DLTF and baseline handles with identical rng streams,
        register meta, enroll on both servers."""
        cert = None
        fail = False
        if tier == 1:
            cert, _ = issue_ek_cert(self.ca_key, self.ca_cert, label)
        elif tier == 3:
            fail = True
        trainers = []
        for _ in range(2):
            if local_trainer is not None:
                trainers.append(local_trainer(self.world, seed))
            else:
                trainers.append(behavior(self.world, kind, seed,
                                         attack_start=start,
                                         group_seed=group_seed))
        h = make_handle(label, trainers[0], ek_cert_der=cert,
                        fail_activation=fail)
        hb = make_handle(label, trainers[1], ek_cert_der=cert,
                         fail_activation=fail)
        self.handles.append(h)
        self.base_handles.append(hb)
        self.meta[label] = {"beh": self.cur_beh, "tier": tier, "gen": 0,
                            "root": label}
        self.dltf.enroll(h)
        self.base.enroll(hb)

    def build(self):
        with self.lock:
            self.phase = "building"
            self._reset_state()
        cfg = dict(self.cfg)
        world = SyntheticWorld(cfg["seed"])
        ca_key, ca_cert = generate_test_ca()
        dltf = FederatedServer([0.0] * world.dim,
                               ca_bundle_pem=ca_bundle_pem(ca_cert),
                               shadow_eval_fn=world.accuracy)
        base = BaselineServer([0.0] * world.dim)
        with self.lock:
            self.world, self.ca_key, self.ca_cert = world, ca_key, ca_cert
            self.dltf, self.base = dltf, base
        s = cfg["seed"] * 1000

        def cohort(name, n, fn):
            self.cur_beh = name
            for k in range(n):
                fn(k)

        cohort("honest t1", cfg["honest_t1"],
               lambda k: self._pair(f"h1-{k:03d}", "honest", 1, s + k))
        cohort("honest t2", cfg["honest_t2"],
               lambda k: self._pair(f"h2-{k:03d}", "honest", 2, s + 400 + k))
        cohort("honest t3", cfg["honest_t3"],
               lambda k: self._pair(f"h3-{k:03d}", "honest", 3, s + 800 + k))
        cohort("sybil", cfg["sybil"],
               lambda k: self._pair(f"syb-{k:02d}", "sybil", 2, s + 1200 + k,
                                    group_seed=cfg["seed"] + 7))
        def flip(start, reform_after=None):
            return lambda w, seed: flip_trainer(w, seed, start, reform_after)

        cohort("poison", cfg["poison"],
               lambda k: self._pair(f"poi-{k:02d}", None, 1, s + 1300 + k,
                                    local_trainer=flip(ATTACK_START["poison"])))
        cohort("sleeper", cfg["sleeper"],
               lambda k: self._pair(f"slp-{k:02d}", None, 1, s + 1400 + k,
                                    local_trainer=flip(ATTACK_START["sleeper"])))
        cohort("onoff", cfg["onoff"],
               lambda k: self._pair(f"onf-{k:02d}", None, 1, s + 1500 + k,
                                    local_trainer=onoff_trainer))
        cohort("scaler", cfg["scaler"],
               lambda k: self._pair(f"scl-{k:02d}", None, 2, s + 1600 + k,
                                    local_trainer=scaler_trainer))
        st_rec = ATTACK_START["recovering"]
        cohort("recovering", cfg["recovering"],
               lambda k: self._pair(f"rec-{k:02d}", None, 1, s + 1700 + k,
                                    local_trainer=flip(st_rec, st_rec + 2)))
        cohort("persistent", cfg["persistent"],
               lambda k: self._pair(f"per-{k:02d}", None, 1, s + 1800 + k,
                                    local_trainer=flip(ATTACK_START["persistent"])))
        cohort("whitewash", cfg["whitewash"],
               lambda k: self._pair(f"whw-{k:02d}", None, 2, s + 1900 + k,
                                    local_trainer=flip(ATTACK_START["whitewash"])))
        with self.lock:
            for label in self.meta:
                self.prev_status[label] = self.dltf.rep.get_status(label)
            self.round = 0
            self.phase = "ready"
            self._log(0, "SETUP", f"{len(self.handles)} clients enrolled "
                      f"({sum(1 for m in self.meta.values() if m['tier'] == 1)} t1, "
                      f"{sum(1 for m in self.meta.values() if m['tier'] == 2)} t2, "
                      f"{sum(1 for m in self.meta.values() if m['tier'] == 3)} t3)")

    # ---- round loop ---------------------------------------------------------

    def _log(self, rnd, kind, text):
        self.events.append({"r": rnd, "kind": kind, "text": text})
        if len(self.events) > 500:
            self.events = self.events[-400:]

    def step(self):
        with self.lock:
            if self.phase not in ("ready", "done") or self.dltf is None:
                return
            if self.round >= self.cfg["rounds"]:
                self.running = False
                self.phase = "done"
                return
            r = self.round
            handles = list(self.handles)
            base_handles = list(self.base_handles)

        rep_d = self.dltf.run_round(r, handles)
        rep_b = self.base.run_round(r, base_handles)

        with self.lock:
            self.acc.append([r, round(self.world.accuracy(self.dltf.global_params), 4),
                             round(self.world.accuracy(self.base.global_params), 4)])
            for label, dev in self.dltf.rep._dev.items():
                self.hist.setdefault(label, []).append(round(dev.trust, 4))
            for label, e in rep_d["events"].items():
                if e["severity"] == "NEUTRAL":
                    continue
                self.sev_counts[e["severity"]] = \
                    self.sev_counts.get(e["severity"], 0) + 1
                self.meta[label]["flags"] = self.meta[label].get("flags", 0) + 1
                self._log(r, e["severity"],
                          f"{label} stage {e['stage']}: {e['reason']}")
            for d, o in rep_d["probation_decisions"]:
                t = self.dltf.rep._dev[d].trust
                self._log(r, "PROBATION",
                          f"{d} -> {o} (trust {t:.3f})")
            newly_banned = []
            for label in list(self.meta):
                if label not in self.dltf.rep._dev:
                    continue
                now = self.dltf.rep.get_status(label)
                was = self.prev_status.get(label)
                if was is not None and was != now:
                    if now == Status.BANNED:
                        newly_banned.append(label)
                        self._log(r, "BAN", f"{label} banned "
                                  f"(EK bound, tier {self.meta[label]['tier']})")
                    elif now == Status.PROBATION:
                        t = self.dltf.rep._dev[label].trust
                        extra = " despite trust > 0.5 (M3)" if t > 0.5 else ""
                        self._log(r, "PROBATION",
                                  f"{label} -> probation (trust {t:.3f}){extra}")
                    elif was == Status.PROBATION and now == Status.ACTIVE:
                        t = self.dltf.rep._dev[label].trust
                        self._log(r, "REINSTATE",
                                  f"{label} reinstated at trust {t:.3f}")
                self.prev_status[label] = now
            self.round = r + 1
            if self.round >= self.cfg["rounds"]:
                self.running = False
                self.phase = "done"

        for label in newly_banned:
            self._whitewash_probe(r, label)

    def _whitewash_probe(self, r, label):
        """O2 demo: same signer (same EK) re-enrolls under a fresh label; must
        come back BANNED. For the whitewash cohort, a genuinely fresh identity
        then joins (cheap pseudonym) and keeps attacking, tier 2."""
        with self.lock:
            meta = self.meta.get(label)
            handle = next((h for h in self.handles if h.device_label == label),
                          None)
        if meta is None or handle is None:
            return
        re_label = label + "~re"
        probe = LocalClientHandle(re_label, handle._signer,
                                  FLClient(re_label,
                                           null_trainer(self.world.dim)))
        res = self.dltf.enroll(probe)
        blocked = res["status"] == "BANNED"
        with self.lock:
            self.ww["same_ek_attempts"] += 1
            self.ww["same_ek_blocked"] += int(blocked)
            self.meta[re_label] = {"beh": "whitewash", "tier": meta["tier"],
                                   "gen": meta["gen"], "root": meta["root"],
                                   "probe": True}
            self.prev_status[re_label] = self.dltf.rep.get_status(re_label)
            mark = "\u2713 blocked" if blocked else "\u2717 ACCEPTED"
            self._log(r, "WHITEWASH", f"{label} same-EK re-enroll: {mark} (O2)")

        if meta["beh"] != "whitewash":
            return
        root = meta["root"]
        with self.lock:
            gen = self.lineage_gen.get(root, meta["gen"]) + 1
            if gen > WHITEWASH_MAX_GEN:
                return
            self.lineage_gen[root] = gen
        new_label = f"{root}#{gen}"
        trainer = flip_trainer(self.world,
                               self.cfg["seed"] * 1000 + 1950 + gen, start=0)
        nh = make_handle(new_label, trainer)  # fresh mock signer = fresh EK, t2
        self.dltf.enroll(nh)
        with self.lock:
            self.handles.append(nh)
            self.meta[new_label] = {"beh": "whitewash", "tier": 2, "gen": gen,
                                    "root": root}
            self.prev_status[new_label] = self.dltf.rep.get_status(new_label)
            self.ww["fresh_identities"] += 1
            self._log(r, "WHITEWASH",
                      f"{root} burned identity #{gen}: fresh EK accepted at "
                      f"tier 2 (identity is the cost, O3)")

    # ---- state for the UI ---------------------------------------------------

    def snapshot(self):
        with self.lock:
            clients = []
            counts = {"ACTIVE": 0, "PROBATION": 0, "BANNED": 0}
            if self.dltf is not None and self.phase not in ("building", "idle"):
                for label, dev in self.dltf.rep._dev.items():
                    m = self.meta.get(label, {})
                    st = dev.status.value
                    counts[st] = counts.get(st, 0) + 1
                    clients.append({
                        "id": label, "tier": int(dev.tier), "st": st,
                        "t": round(dev.trust, 4),
                        "w": self.dltf.rep.get_weight(label),
                        "u": round(dev.opinion["u"], 3),
                        "beh": m.get("beh", "?"),
                        "fl": m.get("flags", 0),
                        "probe": bool(m.get("probe")),
                    })
                prob = []
                for d, rec in list(self.dltf.probation._records.items()):
                    prob.append({
                        "id": d, "entry": rec.entry_round, "win": rec.window,
                        "ext": rec.extended,
                        "n": len(rec.accuracy_series),
                        "slope": round(rec.current_slope(), 5),
                        "series": [round(a, 4) for a in rec.accuracy_series[-24:]],
                        "out": rec.outcome.value,
                    })
            else:
                prob = []
            return {
                "phase": self.phase, "running": self.running,
                "round": self.round, "cfg": self.cfg,
                "counts": counts, "sev": self.sev_counts, "ww": self.ww,
                "acc": self.acc, "clients": clients, "prob": prob,
                "events": self.events[-150:],
            }

    def series(self, ids):
        with self.lock:
            return {i: self.hist.get(i, []) for i in ids}


class Runner(threading.Thread):
    def __init__(self, sim):
        super().__init__(daemon=True)
        self.sim = sim

    def run(self):
        while True:
            if self.sim.running and self.sim.phase == "ready":
                t0 = time.time()
                self.sim.step()
                dt = self.sim.cfg["interval"] - (time.time() - t0)
                if dt > 0:
                    time.sleep(dt)
            else:
                time.sleep(0.05)


def make_http_handler(sim):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/":
                self._send(200, PAGE.encode(), "text/html; charset=utf-8")
            elif u.path == "/api/state":
                self._send(200, sim.snapshot())
            elif u.path == "/api/series":
                ids = parse_qs(u.query).get("ids", [""])[0]
                ids = [i for i in ids.split(",") if i]
                self._send(200, sim.series(ids))
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if urlparse(self.path).path != "/api/control":
                self._send(404, {"error": "not found"})
                return
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n).decode() or "{}")
            action = body.get("action")
            if action == "start":
                if sim.phase == "idle":
                    threading.Thread(target=sim.build, daemon=True).start()
                sim.running = True
            elif action == "pause":
                sim.running = False
            elif action == "step":
                sim.running = False
                if sim.phase == "idle":
                    threading.Thread(target=sim.build, daemon=True).start()
                else:
                    threading.Thread(target=sim.step, daemon=True).start()
            elif action == "reset":
                sim.running = False
                sim.apply_cfg(body.get("cfg", {}))
                sim.phase = "idle"
                threading.Thread(target=sim.build, daemon=True).start()
            elif action == "speed":
                sim.apply_cfg({"interval": body.get("interval")})
            self._send(200, {"ok": True, "phase": sim.phase})
    return Handler


# ---- UI (single page, no external assets) --------------------------------------

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DLTF federation console</title>
<style>
:root{
  --bg:#10151d; --panel:#161d28; --panel2:#1b2432; --line:#26303f;
  --ink:#e8ecf1; --mut:#8b98a9; --dim:#5c6878;
  --good:#48c78e; --warn:#e9b44c; --bad:#e05252;
  --t1:#5aa9e6; --t2:#c9a227; --t3:#9a7fd1;
  --mono:ui-monospace,'JetBrains Mono','Cascadia Code',Menlo,Consolas,monospace;
  --sans:'Segoe UI',system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px}
header{display:flex;align-items:center;gap:14px;padding:12px 18px;
  border-bottom:1px solid var(--line);flex-wrap:wrap}
h1{font:600 15px var(--mono);letter-spacing:.06em}
h1 b{color:var(--t1)}
.badge{font:600 11px var(--mono);padding:3px 9px;border-radius:3px;
  border:1px solid var(--line);color:var(--mut);text-transform:uppercase}
.badge.run{color:var(--good);border-color:var(--good)}
.badge.build{color:var(--warn);border-color:var(--warn)}
#round{font:600 15px var(--mono)}
button{background:var(--panel2);color:var(--ink);border:1px solid var(--line);
  padding:6px 14px;border-radius:4px;font:600 12px var(--mono);cursor:pointer}
button:hover{border-color:var(--t1)}
button:focus-visible{outline:2px solid var(--t1);outline-offset:1px}
button.primary{background:#1e3a55;border-color:var(--t1)}
input[type=number]{width:58px;background:var(--panel2);color:var(--ink);
  border:1px solid var(--line);border-radius:3px;padding:4px 6px;
  font:12px var(--mono)}
label{font:11px var(--mono);color:var(--mut)}
main{display:grid;grid-template-columns:minmax(0,1fr) 380px;gap:14px;
  padding:14px 18px;max-width:1700px;margin:0 auto}
@media(max-width:1100px){main{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:6px;
  padding:12px 14px;margin-bottom:14px}
.card h2{font:600 11px var(--mono);color:var(--mut);letter-spacing:.12em;
  text-transform:uppercase;margin-bottom:10px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.stat{background:var(--panel2);border-radius:5px;padding:8px 10px}
.stat .v{font:600 20px var(--mono)}
.stat .k{font:10px var(--mono);color:var(--mut);text-transform:uppercase;
  letter-spacing:.08em}
.v.good{color:var(--good)}.v.warn{color:var(--warn)}.v.bad{color:var(--bad)}
canvas{width:100%;display:block}
#setup{display:none;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px}
#setup.open{display:grid}
#setup div{display:flex;flex-direction:column;gap:3px}
.legend{display:flex;gap:14px;flex-wrap:wrap;font:11px var(--mono);
  color:var(--mut);margin-bottom:8px}
.sw{display:inline-block;width:9px;height:9px;border-radius:2px;
  margin-right:5px;vertical-align:-1px}
.cohort{margin-bottom:8px}
.cohort .cl{font:10px var(--mono);color:var(--dim);letter-spacing:.08em;
  text-transform:uppercase;margin-bottom:3px}
.tiles{display:flex;flex-wrap:wrap;gap:3px}
.tile{width:13px;height:13px;border-radius:2px;cursor:pointer;
  border-bottom:2px solid transparent}
.tile:hover{outline:1px solid var(--ink)}
.tile.sel{outline:2px solid #fff}
.tile.probe{opacity:.45}
#detail table{width:100%;border-collapse:collapse;font:12px var(--mono)}
#detail td{padding:3px 4px;border-bottom:1px solid var(--line)}
#detail td:first-child{color:var(--mut)}
#feed{font:11.5px var(--mono);max-height:340px;overflow-y:auto;
  display:flex;flex-direction:column-reverse}
#feed p{padding:2px 0;border-bottom:1px solid #1c2430;color:var(--mut)}
#feed .r{color:var(--dim)}
#feed .MAJOR{color:var(--warn)}#feed .MINOR{color:#cfa964}
#feed .CRITICAL,#feed .BAN{color:var(--bad)}
#feed .REINSTATE{color:var(--good)}#feed .WHITEWASH{color:var(--t1)}
#feed .PROBATION{color:var(--warn)}
.prow{background:var(--panel2);border-radius:5px;padding:8px 10px;
  margin-bottom:8px;font:12px var(--mono)}
.prow .hd{display:flex;justify-content:space-between;margin-bottom:4px}
.prow .out-REINSTATED{color:var(--good)}
.prow .out-PERMANENT_BAN{color:var(--bad)}
.prow .out-PENDING,.prow .out-EXTENDED{color:var(--warn)}
.empty{color:var(--dim);font:12px var(--mono);padding:6px 0}
@media(prefers-reduced-motion:no-preference){.tile{transition:background .25s}}
</style></head><body>
<header>
  <h1><b>DLTF</b> FEDERATION CONSOLE</h1>
  <span id="phase" class="badge">idle</span>
  <span id="round">round 0 / 0</span>
  <button id="btnStart" class="primary">Start</button>
  <button id="btnPause">Pause</button>
  <button id="btnStep">Step 1 round</button>
  <button id="btnReset">Rebuild</button>
  <button id="btnSetup">Federation setup</button>
  <label>sec/round <input type="number" id="speed" step="0.1" min="0.05" max="5" value="0.6"></label>
</header>
<div style="padding:0 18px;max-width:1700px;margin:0 auto">
  <div class="card"><div id="setup"></div></div>
</div>
<main>
<section>
  <div class="card"><div class="stats" id="stats"></div></div>
  <div class="card"><h2>Global accuracy: DLTF vs no-trust baseline</h2>
    <div class="legend"><span><span class="sw" style="background:var(--t1)"></span>DLTF</span>
    <span><span class="sw" style="background:var(--dim)"></span>baseline (equal weights, no identity)</span></div>
    <canvas id="accChart" height="190"></canvas></div>
  <div class="card"><h2>Federation map <span style="color:var(--dim)">fill = status, underline = tier, click to inspect</span></h2>
    <div class="legend">
      <span><span class="sw" style="background:var(--good)"></span>active</span>
      <span><span class="sw" style="background:var(--warn)"></span>probation</span>
      <span><span class="sw" style="background:var(--bad)"></span>banned</span>
      <span><span class="sw" style="background:var(--t1)"></span>tier 1</span>
      <span><span class="sw" style="background:var(--t2)"></span>tier 2</span>
      <span><span class="sw" style="background:var(--t3)"></span>tier 3</span>
    </div>
    <div id="map"></div></div>
  <div class="card"><h2>Trust trajectories (selected clients)</h2>
    <canvas id="trustChart" height="170"></canvas>
    <div id="trustLegend" class="legend" style="margin-top:6px"></div></div>
</section>
<aside>
  <div class="card"><h2>Client detail</h2><div id="detail" class="empty">Click a tile.</div></div>
  <div class="card"><h2>Probation trials (shadow model, OLS slope)</h2><div id="prob" class="empty">None yet.</div></div>
  <div class="card"><h2>Event feed</h2><div id="feed"></div></div>
</aside>
</main>
<script>
const $=id=>document.getElementById(id);
const STC={ACTIVE:'var(--good)',PROBATION:'var(--warn)',BANNED:'var(--bad)'};
const TC={1:'var(--t1)',2:'var(--t2)',3:'var(--t3)'};
const SELC=['#5aa9e6','#e9b44c','#48c78e','#e05252'];
let sel=[], state=null, cfgFields=null;

const CFG_KEYS=[['honest_t1','honest t1'],['honest_t2','honest t2'],
 ['honest_t3','honest t3'],['sybil','sybil'],['poison','poison'],
 ['sleeper','sleeper'],['onoff','on-off'],['scaler','scaler'],
 ['recovering','recovering'],['persistent','persistent'],
 ['whitewash','whitewash'],['rounds','rounds'],['seed','seed']];

function buildSetup(cfg){
  const s=$('setup'); s.innerHTML='';
  cfgFields={};
  for(const [k,lbl] of CFG_KEYS){
    const d=document.createElement('div');
    d.innerHTML=`<label>${lbl}</label>`;
    const i=document.createElement('input');
    i.type='number'; i.min=0; i.value=cfg[k];
    d.appendChild(i); s.appendChild(d); cfgFields[k]=i;
  }
}
function readCfg(){const c={};for(const k in cfgFields)c[k]=+cfgFields[k].value;return c}

async function ctl(action,extra){await fetch('/api/control',{method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify(Object.assign({action},extra||{}))})}
$('btnStart').onclick=()=>ctl('start');
$('btnPause').onclick=()=>ctl('pause');
$('btnStep').onclick=()=>ctl('step');
$('btnReset').onclick=()=>{sel=[];ctl('reset',{cfg:readCfg()})};
$('btnSetup').onclick=()=>$('setup').classList.toggle('open');
$('speed').onchange=()=>ctl('speed',{interval:+$('speed').value});

function lineChart(cv,seriesList,ymin,ymax){
  const dpr=devicePixelRatio||1, W=cv.clientWidth, H=+cv.getAttribute('height');
  cv.width=W*dpr; cv.height=H*dpr;
  const g=cv.getContext('2d'); g.scale(dpr,dpr); g.clearRect(0,0,W,H);
  const P=28, n=Math.max(...seriesList.map(s=>s.data.length),2);
  g.strokeStyle='#26303f'; g.fillStyle='#5c6878'; g.font='10px monospace';
  for(let t=0;t<=4;t++){const y=P/2+(H-P)*(1-t/4);
    g.beginPath();g.moveTo(P,y);g.lineTo(W-4,y);g.stroke();
    g.fillText((ymin+(ymax-ymin)*t/4).toFixed(2),1,y+3);}
  for(const s of seriesList){
    if(s.data.length<2)continue;
    g.strokeStyle=s.color; g.lineWidth=1.6;
    g.setLineDash(s.dash?[5,4]:[]);
    g.beginPath();
    s.data.forEach((v,i)=>{
      const x=P+(W-P-6)*i/(n-1);
      const y=P/2+(H-P)*(1-(v-ymin)/(ymax-ymin));
      i?g.lineTo(x,y):g.moveTo(x,y);});
    g.stroke(); g.setLineDash([]);}
}

function renderStats(st){
  const c=st.counts, ww=st.ww, sev=st.sev;
  $('stats').innerHTML=`
   <div class="stat"><div class="v good">${c.ACTIVE||0}</div><div class="k">active</div></div>
   <div class="stat"><div class="v warn">${c.PROBATION||0}</div><div class="k">probation</div></div>
   <div class="stat"><div class="v bad">${c.BANNED||0}</div><div class="k">banned</div></div>
   <div class="stat"><div class="v">${sev.MINOR||0}/${sev.MAJOR||0}/${sev.CRITICAL||0}</div><div class="k">minor/major/crit</div></div>
   <div class="stat"><div class="v good">${ww.same_ek_blocked}/${ww.same_ek_attempts}</div><div class="k">same-EK blocked (O2)</div></div>
   <div class="stat"><div class="v warn">${ww.fresh_identities}</div><div class="k">identities burned (O3)</div></div>`;
}

function renderMap(st){
  const groups={};
  for(const cl of st.clients)(groups[cl.beh]=groups[cl.beh]||[]).push(cl);
  const map=$('map'); map.innerHTML='';
  for(const beh of Object.keys(groups)){
    const div=document.createElement('div'); div.className='cohort';
    div.innerHTML=`<div class="cl">${beh} (${groups[beh].length})</div>`;
    const tiles=document.createElement('div'); tiles.className='tiles';
    for(const cl of groups[beh]){
      const t=document.createElement('span');
      t.className='tile'+(sel.includes(cl.id)?' sel':'')+(cl.probe?' probe':'');
      t.style.background=STC[cl.st];
      t.style.borderBottomColor=TC[cl.tier];
      t.title=`${cl.id}  T${cl.tier}  ${cl.st}  trust ${cl.t}`;
      t.onclick=()=>{sel.includes(cl.id)?sel=sel.filter(x=>x!==cl.id)
        :(sel.length>=4&&sel.shift(),sel.push(cl.id));
        renderDetail(); renderMap(state);};
      tiles.appendChild(t);}
    div.appendChild(tiles); map.appendChild(div);}
}

function renderDetail(){
  const d=$('detail');
  if(!sel.length||!state){d.className='empty';d.textContent='Click a tile.';return}
  const cl=state.clients.find(c=>c.id===sel[sel.length-1]);
  if(!cl){d.className='empty';d.textContent='Client left the federation.';return}
  d.className='';
  d.innerHTML=`<table>
   <tr><td>id</td><td>${cl.id}</td></tr>
   <tr><td>behavior</td><td>${cl.beh}${cl.probe?' (same-EK re-enroll probe)':''}</td></tr>
   <tr><td>tier</td><td style="color:${TC[cl.tier]}">T${cl.tier}</td></tr>
   <tr><td>status</td><td style="color:${STC[cl.st]}">${cl.st}</td></tr>
   <tr><td>trust T</td><td>${cl.t}</td></tr>
   <tr><td>weight w</td><td>${cl.w}</td></tr>
   <tr><td>uncertainty u</td><td>${cl.u}</td></tr>
   <tr><td>flags</td><td>${cl.fl}</td></tr></table>`;
}

function renderProb(st){
  const p=$('prob');
  if(!st.prob.length){p.className='empty';p.textContent='None yet.';return}
  p.className=''; p.innerHTML='';
  for(const r of st.prob.slice().reverse().slice(0,10)){
    const div=document.createElement('div'); div.className='prow';
    const spark=r.series.map(v=>'▁▂▃▄▅▆▇█'[Math.min(7,Math.floor(v*8))]||'▁').join('');
    div.innerHTML=`<div class="hd"><span>${r.id}</span>
      <span class="out-${r.out}">${r.out}</span></div>
      entry r${r.entry} · window ${r.win}${r.ext?'+ext':''} · ${r.n} rounds<br>
      slope ${r.slope>=0?'+':''}${r.slope} <span style="color:var(--dim)">${spark}</span>`;
    p.appendChild(div);}
}

function renderFeed(st){
  $('feed').innerHTML=st.events.slice().map(e=>
    `<p><span class="r">r${String(e.r).padStart(3,'0')}</span>
     <span class="${e.kind}">${e.kind}</span> ${e.text}</p>`).join('');
}

async function renderTrust(){
  if(!sel.length){lineChart($('trustChart'),[],0,1);
    $('trustLegend').innerHTML='';return}
  const res=await fetch('/api/series?ids='+sel.join(','));
  const data=await res.json();
  const series=sel.map((id,i)=>({data:data[id]||[],color:SELC[i%4]}));
  lineChart($('trustChart'),series,0,1);
  $('trustLegend').innerHTML=sel.map((id,i)=>
    `<span><span class="sw" style="background:${SELC[i%4]}"></span>${id}</span>`).join('');
}

async function poll(){
  try{
    const st=await(await fetch('/api/state')).json();
    state=st;
    if(!cfgFields)buildSetup(st.cfg);
    const ph=$('phase');
    ph.textContent=st.phase+(st.running?' · running':'');
    ph.className='badge'+(st.running?' run':st.phase==='building'?' build':'');
    $('round').textContent=`round ${st.round} / ${st.cfg.rounds}`;
    renderStats(st);
    lineChart($('accChart'),[
      {data:st.acc.map(a=>a[1]),color:'#5aa9e6'},
      {data:st.acc.map(a=>a[2]),color:'#5c6878',dash:true}],0,1);
    renderMap(st); renderDetail(); renderProb(st); renderFeed(st);
    renderTrust();
  }catch(e){}
  setTimeout(poll,700);
}
poll();
</script></body></html>
"""


def _self_test():
    print("dashboard.py self-test (headless)")
    sim = Sim({"honest_t1": 5, "honest_t2": 5, "honest_t3": 2, "sybil": 3,
               "poison": 1, "sleeper": 0, "onoff": 0, "scaler": 1,
               "recovering": 1, "persistent": 1, "whitewash": 1,
               "rounds": 20, "interval": 0.0, "seed": 1})
    sim.build()
    assert sim.phase == "ready" and len(sim.handles) == 20
    tiers = {m["tier"] for m in sim.meta.values()}
    assert tiers == {1, 2, 3}
    print(f"\u2713 built {len(sim.handles)} clients across tiers {sorted(tiers)}")

    for _ in range(20):
        sim.step()
    snap = sim.snapshot()
    assert snap["phase"] == "done" and snap["round"] == 20

    by = {c["id"]: c for c in snap["clients"]}
    assert all(by[f"syb-{k:02d}"]["st"] == "BANNED" for k in range(3))
    print("\u2713 sybil group banned (CRITICAL, O1)")

    assert sim.ww["same_ek_attempts"] > 0
    assert sim.ww["same_ek_blocked"] == sim.ww["same_ek_attempts"]
    print(f"\u2713 O2: {sim.ww['same_ek_blocked']}/{sim.ww['same_ek_attempts']} "
          "same-EK re-enrollments blocked")
    assert sim.ww["fresh_identities"] >= 1
    print(f"\u2713 O3: whitewasher burned {sim.ww['fresh_identities']} fresh identities")

    assert snap["prob"], "no probation record created"
    outs = {p["id"]: p["out"] for p in snap["prob"]}
    assert "rec-00" in outs or "per-00" in outs or "poi-00" in outs
    print(f"\u2713 probation lifecycle exercised: {outs}")

    honest_active = [c for c in snap["clients"]
                     if c["beh"].startswith("honest") and c["st"] == "ACTIVE"]
    assert len(honest_active) == 12, len(honest_active)
    print("\u2713 zero false positives: all honest clients still ACTIVE")

    final = snap["acc"][-1]
    assert final[1] > final[2], final
    print(f"\u2713 DLTF accuracy {final[1]} beats baseline {final[2]}")

    trust_series = sim.series(["rec-00"])["rec-00"]
    assert len(trust_series) == 20
    print("\u2713 trust trajectories recorded for charting")
    print("\u2713 all dashboard self-tests passed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        _self_test()
        return
    sim = Sim({})
    Runner(sim).start()
    httpd = ThreadingHTTPServer((args.host, args.port), make_http_handler(sim))
    print(f"\u2713 DLTF console at http://{args.host}:{args.port} "
          "(Start builds the federation; first build mints Tier-1 certs, ~10s)")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
