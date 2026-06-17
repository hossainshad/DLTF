# DLTF — Full Setup and Run Guide (from a fresh clone)

Every command assumed to run from the project root (the `dltf/` folder) unless
stated. Prefix Python commands with `PYTHONPATH=.` so imports resolve.

====================================================================
SECTION 0 — ONE-TIME SETUP ON ANY MACHINE
====================================================================

# 0.1 system packages
sudo apt update
sudo apt install -y python3 python3-pip openssl curl tpm2-tools git

# 0.2 enter the project
cd ~/Documents/thesis/dltf        # adjust to where you cloned it

# 0.3 python libraries (numpy + cryptography are required everywhere)
pip install numpy cryptography matplotlib --break-system-packages

# 0.4 torch + torchvision (ONLY needed for real MNIST training:
#     install on the SERVER and on any CLIENT that does real training)
pip install torch torchvision --break-system-packages
# if that pulls a huge CUDA build and you have no NVIDIA GPU, use CPU build:
# pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu --break-system-packages

# 0.5 sanity check the install
python3 -c "import numpy, cryptography; print('core ok')"
python3 -c "import torch; print('torch', torch.__version__)"   # only if you installed torch

====================================================================
SECTION 1 — VERIFY THE WHOLE STACK (do this first, always)
====================================================================

# 1.1 run the full pipeline self-test (no network, no real TPM needed)
PYTHONPATH=. python3 tests/test_pipeline.py
# EXPECT the final line: "✓ PIPELINE GREEN"
# if a module fails, the name tells you which file is stale/missing.

# common gotcha: if it complains about make_signer / EK_RSA_CERT_NV, the file
# tpm/client.py is the OLD version. Its first line MUST be:
#   from tpm.common import (b64d, b64e, sha256_hex, run, mock_key, mock_ek_hash)
grep -n "from tpm.common import" tpm/client.py        # must print a line

====================================================================
SECTION 2 — RUN THE THESIS EXPERIMENTS (Chapter 4 numbers + figures)
====================================================================
# This is fully local (synthetic substrate). No network, no torch needed.

PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 --rounds 30 --out results --check
# EXPECT all "✓ check:" lines to pass, and CSVs + summary.txt in results/

PYTHONPATH=. python3 -m eval.plot_results --results results
# EXPECT 8 PNG figures in results/figs/

# quick look at the headline numbers
cat results/summary.txt

====================================================================
SECTION 3 — CHECK A MACHINE'S TPM TIER (optional, real hardware)
====================================================================
# 3.1 quick: does this machine even have an EK certificate?
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_getekcertificate -u ek.pub -o ek.crt -X 2>/dev/null
[ -s ek.crt ] && echo "HAS EK CERT" || echo "NO EK CERT (caps at Tier 2)"

# 3.2 if HAS EK CERT and you have built the CA bundle (see tpm/FETCH_EK_CERT.md):
PYTHONPATH=. python3 -m tpm.check_ek_cert --ek-cert ek.crt --ca-bundle tpm/ca/amd_ftpm_ca.pem
# EXPECT "Tier 1 HARDWARE" if the cert chains; otherwise "Tier 2".
# To build the bundle on a new AMD machine, follow tpm/FETCH_EK_CERT.md.

====================================================================
SECTION 4 — RUN IT FOR REAL ACROSS MACHINES (1 server + N clients)
====================================================================

# ---- 4A. NETWORK: put every machine on ONE Tailscale account ----
# on EVERY machine (server + all clients):
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up                 # log in with the SAME account on all machines
tailscale ip -4                   # note this machine's 100.x.y.z address
# verify they see each other (run on any machine, should list them all):
tailscale status

# ---- 4B. CONFIG: same config.py on ALL machines ----
# Edit config.py. List ONLY the client machines (server is NOT listed).
# NUM_CLIENTS = number of client machines. Example for 2 clients:
#
#   NUM_CLIENTS = 2
#   CLIENTS = [
#     {"device_label":"client1","tpm_backend":"mock","tcti":None,"endpoint":"http://100.70.28.2:8470"},
#     {"device_label":"client2","tpm_backend":"mock","tcti":None,"endpoint":"http://100.64.57.82:8470"},
#   ]
#
# tpm_backend: "mock" = Tier 2, zero deps (start here).
#              "real" = use the machine's hardware TPM (needs tpm2-tools + a real EK).

# ---- 4C. START EACH CLIENT (leave each running in its own terminal) ----
# on client1's machine:
PYTHONPATH=. python3 -m net.agent --label client1 --port 8470
# on client2's machine:
PYTHONPATH=. python3 -m net.agent --label client2 --port 8470
# EXPECT each to print: "✓ agent 'clientN' listening on 0.0.0.0:8470" and STAY running.
# add --stub to send zero updates (networking test only, no torch/training).

# ---- 4D. ON THE SERVER: confirm reachability, then run ----
mkdir -p results
curl http://100.70.28.2:8470/health    # expect {"ok": true, "device": "client1"}
curl http://100.64.57.82:8470/health    # expect {"ok": true, "device": "client2"}

# stub run (fast, no torch, proves networking + enrollment + rounds):
PYTHONPATH=. python3 run_server.py --rounds 10 --stub

# real run (real MNIST training; clients must run agents WITHOUT --stub;
# torch required on server AND clients):
PYTHONPATH=. python3 run_server.py --rounds 5
# EXPECT first line: "real MNIST model: 409034 parameters"
# then each client enrolls (tier TPM_RESIDENT under mock) and rounds print.

====================================================================
SECTION 5 — SINGLE-MACHINE REAL-MODE TEST (no second computer)
====================================================================
# One machine can play server AND one client over loopback. Two terminals.
# config.py: NUM_CLIENTS = 1, endpoint "http://127.0.0.1:8470".

# terminal 1 (agent):
PYTHONPATH=. python3 -m net.agent --label client1 --port 8470 --stub
# terminal 2 (server):
curl http://127.0.0.1:8470/health
PYTHONPATH=. python3 run_server.py --rounds 5 --stub

====================================================================
TROUBLESHOOTING (symptom -> cause -> fix)
====================================================================
# "PIPELINE GREEN" not reached, import error about make_signer/EK_RSA_CERT_NV
#   -> tpm/client.py is the OLD file. Replace with the rebuilt one.
#
# tailscale status shows only 1 machine
#   -> machines on different accounts. `sudo tailscale logout` then
#      `sudo tailscale up` into ONE account on every machine.
#
# curl to a client hangs
#   -> that client's agent isn't running, or wrong IP, or port blocked.
#      Confirm the agent terminal shows "listening"; check the IP.
#
# curl gives "Connection refused"
#   -> agent not running on that machine (start net.agent there).
#
# server: HTTP Error 500 during training
#   -> a CLIENT-side crash. Read the CLIENT agent terminal (it now prints the
#      full traceback). Most common: see next two lines.
#
# client traceback: "shape '[16,1,3,3]' is invalid for input of size 6"
#   -> server is sending the 6-value STUB. It is running the OLD run_server.py.
#      Replace run_server.py; real mode must print "real MNIST model: 409034 parameters".
#
# client traceback: ModuleNotFoundError: torch
#   -> install torch on that client (Section 0.4), restart the agent.
#
# run_server.py: FileNotFoundError results/audit.jsonl.key
#   -> `mkdir -p results` first (the updated run_server.py does this automatically).
#
# dataset.py: "a cannot be empty" with NUM_CLIENTS=1
#   -> use the updated fl/dataset.py (guards the leak step for single client).
#
# agent returns to the shell prompt instead of staying on "listening"
#   -> the agent crashed at startup; run it again and read the error (often a
#      missing torch on a real-training agent, or MNIST download failure).

====================================================================
DAILY QUICK REFERENCE
====================================================================
# verify stack:        PYTHONPATH=. python3 tests/test_pipeline.py
# experiments+figures: PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 --rounds 30 --out results --check
#                      PYTHONPATH=. python3 -m eval.plot_results --results results
# client agent:        PYTHONPATH=. python3 -m net.agent --label clientN --port 8470
# server (real):       PYTHONPATH=. python3 run_server.py --rounds 5
# tier check:          PYTHONPATH=. python3 -m tpm.check_ek_cert --ek-cert ek.crt --ca-bundle tpm/ca/amd_ftpm_ca.pem
# beta engine swap:    FederatedServer(params, reputation_engine=BetaReputationEngine())







Local running commands (one PC, in-process simulation — no agents, no network). Run from the dltf/ folder with PYTHONPATH=.

1. Verify everything works:

PYTHONPATH=. python3 tests/test_pipeline.py

Expect ✓ PIPELINE GREEN.

2. Local federation simulation (run_local.py) — the multi-client one PC test:

# 5 honest clients
PYTHONPATH=. python3 run_local.py --clients 5 --rounds 12

# 5 clients, 2 of them colluding sybil attackers (shows the defense working)
PYTHONPATH=. python3 run_local.py --clients 5 --attackers 2 --rounds 12

(flags: --clients N, --attackers M, --rounds R — no --engine anymore, one engine)

3. The thesis experiments + figures (Chapter 4):

PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 --rounds 30 --out results --check
PYTHONPATH=. python3 -m eval.plot_results --results results
cat results/summary.txt

4. Run any single module's own self-test:

PYTHONPATH=. python3 trust/reputation.py
PYTHONPATH=. python3 trust/filter.py
PYTHONPATH=. python3 fl/server.py