"""
net/handles.py

The transport seam: the single point where local and LAN deployments differ.
FederatedServer talks only to handle objects exposing
  .device_label .tpm_backend .enroll_payload() .activate_credential(blob) .train(r, params)

  LocalClientHandle   in-process signer + FLClient        (config MODE="local")
  RemoteClientHandle  HTTP proxy to net/agent.py on a PC  (config MODE="real")

Same interface on both, so switching deployment is a config edit, not a code
change. Wire format is JSON with base64 for binary fields. Transport is plain
HTTP for a trusted LAN testbed; TLS and request auth are deployment hardening,
listed in the thesis limitations.
"""
import json
import urllib.request

from tpm.common import b64e, b64d


def _payload_from_provision(device_label, prov):
    ek_pub_b64 = None
    if prov.ek_pub_path:
        with open(prov.ek_pub_path, "rb") as f:
            ek_pub_b64 = b64e(f.read())
    return {"device_label": device_label,
            "ek_hash": prov.ek_hash,
            "ak_name": prov.ak_name,
            "ek_cert_b64": b64e(prov.ek_cert_der) if prov.ek_cert_der else None,
            "ek_pub_b64": ek_pub_b64}


class LocalClientHandle:
    def __init__(self, device_label, signer, fl_client, tpm_backend="mock"):
        self.device_label = device_label
        self.tpm_backend = tpm_backend
        self._signer = signer
        self._fl = fl_client

    def enroll_payload(self):
        return _payload_from_provision(self.device_label, self._signer.provision())

    def activate_credential(self, blob_b64):
        return self._signer.activate_credential(blob_b64)

    def train(self, round_id, params):
        return self._fl.train(round_id, params)


class RemoteClientHandle:
    def __init__(self, device_label, endpoint, tpm_backend="real",
                 timeout=30, train_timeout=600):
        self.device_label = device_label
        self.tpm_backend = tpm_backend
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout
        self.train_timeout = train_timeout

    def _post(self, path, obj, timeout):
        req = urllib.request.Request(
            self.endpoint + path, data=json.dumps(obj).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())

    def enroll_payload(self):
        return self._post("/enroll", {}, self.timeout)

    def activate_credential(self, blob_b64):
        return b64d(self._post("/activate", {"blob": blob_b64}, self.timeout)["secret"])

    def train(self, round_id, params):
        return self._post("/train", {"round": round_id, "params": list(params)},
                          self.train_timeout)


def _self_test():
    from tpm.client import make_signer
    from fl.client import FLClient
    from fl.server import FederatedServer

    print("net/handles.py self-test")
    DIM = 4

    def stub_trainer(idx):
        return lambda r, p: ([0.1 * (idx + 1)] * DIM, 32)

    handles = [LocalClientHandle(f"l{k}", make_signer("mock", f"l{k}"),
                                 FLClient(f"l{k}", stub_trainer(k)))
               for k in range(3)]
    server = FederatedServer(initial_params=[0.0] * DIM)
    res = [server.enroll(h) for h in handles]
    assert all(r["tier"] == "TPM_RESIDENT" for r in res)
    print("✓ LocalClientHandle enrolls through the standard flow (Tier 2)")

    report = server.run_round(0, handles)
    assert report["aggregated"] is True
    assert all(abs(w - 0.5) < 1e-9 for w in report["weights"].values())
    assert server.global_params[0] > 0.0
    print("✓ one local round aggregates with trust weights")

    rh = RemoteClientHandle("r0", "http://192.168.0.50:8470/")
    assert rh.endpoint == "http://192.168.0.50:8470"
    assert rh.tpm_backend == "real" and rh.train_timeout == 600
    print("✓ RemoteClientHandle wiring sane (HTTP loop tested in net/agent.py)")
    print("✓ all handle self-tests passed")


if __name__ == "__main__":
    _self_test()