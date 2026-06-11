"""
DLTF topology and run mode. This is the ONLY file you edit to move from
single-machine simulation to the real 1-server + 5-client deployment.

  MODE = "local"  one machine plays the server and all clients in-process.
  MODE = "real"   the server runs here; each client runs net/agent.py on its
                  own Ubuntu machine and is reached over HTTP.
"""
import os

MODE = os.environ.get("DLTF_MODE", "local")   # "local" or "real"

# Server HTTP bind. Used in real mode only; ignored in local mode.
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8000

# Federation size. Keep 5 for the thesis.
NUM_CLIENTS = 5

# Per-client topology.
#   device_label : human name; also seeds the mock TPM identity
#   tpm_backend  : "real"  use this machine's hardware TPM (one client per machine)
#                  "swtpm" software TPM at `tcti` (distinct EK, real crypto, Tier 2)
#                  "mock"  pure-Python deterministic signer (zero deps, fastest)
#   tcti         : TPM2 TCTI string (swtpm backend only)
#   endpoint     : client agent URL (real mode only)
#
# To go real: set MODE="real", point each endpoint at the client machine's IP,
# set tpm_backend="real" on every client, run net/agent.py on each machine.
CLIENTS = [
    {
        "device_label": f"client{i}",
        "tpm_backend": "mock",
        "tcti":        f"swtpm:path=/tmp/dltf-swtpm-{i}/sock",
        "endpoint":    f"http://127.0.0.1:{9001 + i}",
    }
    for i in range(NUM_CLIENTS)
]