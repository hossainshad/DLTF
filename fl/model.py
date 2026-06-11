"""
fl/model.py

Compact CNN for MNIST. Two design constraints serve the rest of the system:

  - Flat list[float] interface (get_parameters / set_parameters). Every layer of
    DLTF speaks this one format, so gradients are just elementwise differences of
    two flat lists and aggregators stay model-agnostic (O4).
  - No dropout, batch-norm, or momentum. The parameter delta after local training
    is then a clean gradient proxy, which the filter and shadow model rely on.

Round-trip identity holds: set_parameters(get_parameters()) leaves the model
unchanged. Parameter count is ~409k, under the 500k ceiling.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F


class MNISTModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1 = nn.Conv2d(1, 16, 3, padding=1)
        self.conv2 = nn.Conv2d(16, 32, 3, padding=1)
        self.fc1 = nn.Linear(32 * 7 * 7, 256)
        self.fc2 = nn.Linear(256, 10)

    def forward(self, x):
        x = F.max_pool2d(F.relu(self.conv1(x)), 2)   # 28 -> 14
        x = F.max_pool2d(F.relu(self.conv2(x)), 2)   # 14 -> 7
        x = x.flatten(1)
        x = F.relu(self.fc1(x))
        return self.fc2(x)

    def get_parameters(self):
        return [v for p in self.parameters()
                for v in p.detach().cpu().flatten().tolist()]

    def set_parameters(self, flat):
        i = 0
        with torch.no_grad():
            for p in self.parameters():
                n = p.numel()
                chunk = torch.tensor(flat[i:i + n], dtype=p.dtype).view_as(p)
                p.copy_(chunk.to(p.device))
                i += n


def num_parameters(model):
    return sum(p.numel() for p in model.parameters())


def _self_test():
    print("fl/model.py self-test")
    torch.manual_seed(0)
    model = MNISTModel()

    n = num_parameters(model)
    assert n < 500_000, n
    print(f"✓ parameter count {n} is under the 500k ceiling")

    x = torch.randn(8, 1, 28, 28)
    y = model(x)
    assert tuple(y.shape) == (8, 10)
    print("✓ forward pass yields (batch, 10) logits")

    flat = model.get_parameters()
    assert len(flat) == n
    model.set_parameters(flat)
    flat2 = model.get_parameters()
    assert flat == flat2
    print("✓ round-trip identity: set(get()) == get()")

    old = model.get_parameters()
    opt = torch.optim.SGD(model.parameters(), lr=0.1)   # no momentum
    opt.zero_grad()
    loss = F.cross_entropy(model(x), torch.randint(0, 10, (8,)))
    loss.backward()
    opt.step()
    new = model.get_parameters()
    grad = [a - b for a, b in zip(new, old)]
    assert len(grad) == n and any(g != 0.0 for g in grad)
    print("✓ parameter delta is a usable flat gradient proxy")
    print("✓ all model self-tests passed")


if __name__ == "__main__":
    _self_test()