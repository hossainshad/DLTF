"""
DLTF topology. Tailscale tailnet (account tpm97510@).
  100.95.144.127 (ubuntu)      -> SERVER  (runs run_server.py; not in CLIENTS)
  100.70.28.2    (s4zz4d HP)   -> client1 (runs net/agent.py)
  100.64.57.82   (tafsir HP)   -> client2 (runs net/agent.py)
"""
import os
MODE = os.environ.get("DLTF_MODE", "real")

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8000

NUM_CLIENTS = 2

CLIENTS = [
    {
        "device_label": "client1",
        "tpm_backend":  "mock",
        "tcti":         None,
        "endpoint":     "http://100.70.28.2:8470",
    },
    {
        "device_label": "client2",
        "tpm_backend":  "mock",
        "tcti":         None,
        "endpoint":     "http://100.64.57.82:8470",
    },

 ]