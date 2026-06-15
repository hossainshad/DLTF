"""
net/agent.py

Per-client HTTP agent for the LAN deployment. Runs on each client PC and exposes
that machine's TPM signer and trainer to the server's RemoteClientHandle.

  GET  /health    -> {"ok": true, "device": label}
  POST /enroll    -> enrollment payload (ek_hash, ak_name, certs)
  POST /activate  -> {"secret": b64}   credential activation answer
  POST /train     -> {"update": [...], "num_samples": n}

Run on a client box (label must exist in config.CLIENTS):
  python3 -m net.agent --label client1 --port 8470            # torch trainer
  python3 -m net.agent --label client1 --port 8470 --stub     # smoke test

All agents partition MNIST identically (same seed, same client count from
config), each taking its own shard, so no data distribution step is needed.
Plain HTTP on a trusted LAN; TLS/auth is deployment hardening (limitations).
Run bare (no args) to self-test over a real localhost HTTP loop.
"""
import sys
import json
import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tpm.common import b64e
from tpm.client import make_signer
from fl.client import FLClient
from net.handles import _payload_from_provision


class DLTFAgent:
    def __init__(self, device_label, signer, fl_client):
        self.label = device_label
        self.signer = signer
        self.fl = fl_client

    def dispatch(self, path, body):
        if path == "/enroll":
            return _payload_from_provision(self.label, self.signer.provision())
        if path == "/activate":
            return {"secret": b64e(self.signer.activate_credential(body["blob"]))}
        if path == "/train":
            return self.fl.train(body["round"], body["params"])
        raise KeyError(path)

    def serve(self, host="0.0.0.0", port=8470):
        httpd = ThreadingHTTPServer((host, port), _make_handler(self))
        print(f"✓ agent '{self.label}' listening on {host}:{httpd.server_address[1]}")
        httpd.serve_forever()

    def serve_in_thread(self, host="127.0.0.1", port=0):
        httpd = ThreadingHTTPServer((host, port), _make_handler(self))
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        return httpd, httpd.server_address[1]


def _make_handler(agent):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/health":
                self._send(200, {"ok": True, "device": agent.label})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            chunks, remaining = [], n
            while remaining > 0:
                part = self.rfile.read(min(remaining, 1 << 20))
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            body = json.loads(b"".join(chunks).decode() or "{}")
            try:
                self._send(200, agent.dispatch(self.path, body))
            except KeyError:
                self._send(404, {"error": "not found"})
            except Exception as e:
                import traceback
                traceback.print_exc()
                self._send(500, {"error": str(e)})
    return Handler


def _cfg(entry, key, default=None):
    if isinstance(entry, dict):
        return entry.get(key, default)
    return getattr(entry, key, default)


def build_agent_from_config(label, stub=False, epochs=1, lr=0.05):
    import config
    entries = list(config.CLIENTS)
    idx = next((i for i, c in enumerate(entries) if _cfg(c, "device_label") == label), None)
    if idx is None:
        raise SystemExit(f"✗ label '{label}' not in config.CLIENTS")
    entry = entries[idx]
    signer = make_signer(_cfg(entry, "tpm_backend", "real"), label, tcti=_cfg(entry, "tcti"))
    if stub:
        trainer = lambda r, p: ([0.0] * len(p), 1)
    else:
        from fl.model import MNISTModel
        from fl.client import TorchTrainer
        from fl.dataset import load_mnist, build_client_loaders
        train_ds, _ = load_mnist()
        loaders, _ = build_client_loaders(train_ds, num_clients=len(entries), seed=0)
        trainer = TorchTrainer(MNISTModel, loaders[idx], epochs=epochs, lr=lr)
    return DLTFAgent(label, signer, FLClient(label, trainer))


def main(argv):
    ap = argparse.ArgumentParser(description="DLTF client agent")
    ap.add_argument("--label", required=True)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8470)
    ap.add_argument("--stub", action="store_true", help="zero-update trainer for smoke tests")
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--lr", type=float, default=0.05)
    args = ap.parse_args(argv)
    build_agent_from_config(args.label, args.stub, args.epochs, args.lr).serve(args.host, args.port)


def _self_test():
    import urllib.request
    from net.handles import RemoteClientHandle
    from fl.server import FederatedServer
    from tpm.common import make_credential

    print("net/agent.py self-test (real HTTP on localhost)")
    DIM = 4

    def trainer(idx):
        return lambda r, p: ([0.1 * (idx + 1)] * DIM, 32)

    agents, servers, handles = [], [], []
    for k in range(2):
        a = DLTFAgent(f"r{k}", make_signer("mock", f"r{k}"), FLClient(f"r{k}", trainer(k)))
        httpd, port = a.serve_in_thread()
        agents.append(a); servers.append(httpd)
        handles.append(RemoteClientHandle(f"r{k}", f"http://127.0.0.1:{port}",
                                          tpm_backend="mock"))

    with urllib.request.urlopen(handles[0].endpoint + "/health", timeout=5) as r:
        assert json.loads(r.read())["device"] == "r0"
    print("✓ /health answers over HTTP")

    blob, secret = make_credential("mock", device_label="r0")
    assert handles[0].activate_credential(blob) == secret
    print("✓ credential secret survives the b64/JSON wire round-trip")

    fed = FederatedServer(initial_params=[0.0] * DIM)
    res = [fed.enroll(h) for h in handles]
    assert all(x["tier"] == "TPM_RESIDENT" for x in res)
    report = fed.run_round(0, handles)
    assert report["aggregated"] is True and fed.global_params[0] > 0.0
    print("✓ FederatedServer enrolled and ran a round entirely over HTTP")

    out = handles[0].train(1, [0.0] * DIM)
    assert out["update"] == [0.1] * DIM and out["num_samples"] == 32
    print("✓ /train returns the trainer's update faithfully")

    for httpd in servers:
        httpd.shutdown()
    print("✓ all agent self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _self_test()
    else:
        main(sys.argv[1:])