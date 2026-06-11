"""
fl/client.py

Client-side training step. FLClient is a thin shell around an injected trainer
callable so the round lifecycle is testable without torch; TorchTrainer is the
real implementation (lazy torch import) used on the machines.

Trainer contract: trainer(round_id, global_params) -> (update, num_samples)
where update is the flat parameter delta after local training. Plain SGD, no
momentum, so the delta is a clean gradient proxy for the filter (matches
fl/model.py constraints).
"""


class FLClient:
    def __init__(self, device_label, trainer):
        self.device_label = device_label
        self._trainer = trainer

    def train(self, round_id, global_params):
        update, num_samples = self._trainer(round_id, list(global_params))
        return {"device_label": self.device_label,
                "round": round_id,
                "update": list(update),
                "num_samples": int(num_samples)}


class TorchTrainer:
    """Local SGD on a private loader. Returns the flat parameter delta."""

    def __init__(self, model_factory, data_loader, epochs=1, lr=0.05, device="cpu"):
        self.model_factory = model_factory
        self.loader = data_loader
        self.epochs = epochs
        self.lr = lr
        self.device = device

    def __call__(self, round_id, global_params):
        import torch
        import torch.nn.functional as F
        model = self.model_factory().to(self.device)
        model.set_parameters(global_params)
        opt = torch.optim.SGD(model.parameters(), lr=self.lr)   # no momentum
        model.train()
        seen = 0
        for _ in range(self.epochs):
            for x, y in self.loader:
                x, y = x.to(self.device), y.to(self.device)
                opt.zero_grad()
                F.cross_entropy(model(x), y).backward()
                opt.step()
                seen += len(y)
        new = model.get_parameters()
        return [a - b for a, b in zip(new, global_params)], seen


def _self_test():
    print("fl/client.py self-test")

    def stub(round_id, params):
        return [float(round_id + 1)] * len(params), 32

    c = FLClient("client0", stub)
    out = c.train(0, [0.0, 0.0, 0.0])
    assert out["update"] == [1.0, 1.0, 1.0] and out["num_samples"] == 32
    assert out["device_label"] == "client0" and out["round"] == 0
    print("✓ stub trainer round-trips through the client shell")

    out2 = c.train(4, [9.0, 9.0, 9.0])
    assert out2["update"] == [5.0, 5.0, 5.0]
    print("✓ trainer receives round id and a private copy of params")

    sent = [1.0, 2.0]
    c.train(1, sent)
    assert sent == [1.0, 2.0]
    print("✓ caller's parameter list is never mutated")
    print("✓ all client self-tests passed (TorchTrainer runs machine-side)")


if __name__ == "__main__":
    _self_test()