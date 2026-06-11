"""
fl/dataset.py

Non-IID MNIST partitioning for the federation, plus a held-out stratified
validation set used by the probation shadow model.

The partitioning logic (non_iid_partition, stratified_validation) is pure numpy
and self-tests here on synthetic labels. The torch/torchvision loaders are
imported lazily so this module loads, and its core logic tests, without torch.
"""
import numpy as np


def class_blocks(num_clients, num_classes=10):
    """Split classes into num_clients contiguous blocks, as evenly as possible."""
    base, rem = divmod(num_classes, num_clients)
    blocks, start = [], 0
    for k in range(num_clients):
        size = base + (1 if k < rem else 0)
        blocks.append(list(range(start, start + size)))
        start += size
    return blocks


def non_iid_partition(labels, num_clients, leak=0.1, seed=0):
    """labels: 1D array of class ids. Returns dict[client_idx -> array of indices].
    Each client owns a contiguous class block. A `leak` fraction of samples is
    reassigned to a random other client, so no client is missing every other class
    (pure block partitioning makes the global model untrainable)."""
    rng = np.random.default_rng(seed)
    labels = np.asarray(labels)
    num_classes = int(labels.max()) + 1
    owner = {}
    for c, blk in enumerate(class_blocks(num_clients, num_classes)):
        for cls in blk:
            owner[cls] = c
    assign = np.array([owner[int(l)] for l in labels])
    leak_idx = np.where(rng.random(len(labels)) < leak)[0]
    for idx in leak_idx:
        others = [c for c in range(num_clients) if c != assign[idx]]
        assign[idx] = rng.choice(others)
    return {c: np.where(assign == c)[0] for c in range(num_clients)}


def stratified_validation(labels, per_class=50, seed=0):
    """Hold out per_class samples of each class for the shadow model.
    Returns (val_indices, remaining_train_indices)."""
    rng = np.random.default_rng(seed)
    labels = np.asarray(labels)
    val = []
    for cls in np.unique(labels):
        idx = np.where(labels == cls)[0]
        take = min(per_class, len(idx))
        val.extend(rng.choice(idx, size=take, replace=False).tolist())
    val = np.array(sorted(val))
    mask = np.ones(len(labels), dtype=bool)
    mask[val] = False
    return val, np.where(mask)[0]


def load_mnist(root="data"):
    import torch  # noqa: F401
    from torchvision import datasets, transforms
    tf = transforms.Compose([transforms.ToTensor(),
                             transforms.Normalize((0.1307,), (0.3081,))])
    train = datasets.MNIST(root, train=True, download=True, transform=tf)
    test = datasets.MNIST(root, train=False, download=True, transform=tf)
    return train, test


def build_client_loaders(train_dataset, num_clients, batch_size=64,
                         leak=0.1, val_per_class=50, seed=0):
    """Returns (dict[client_idx -> DataLoader], val_loader). val is carved first,
    then the remainder is split non-IID across clients."""
    from torch.utils.data import DataLoader, Subset
    labels = np.array(train_dataset.targets)
    val_idx, pool_idx = stratified_validation(labels, val_per_class, seed)
    parts = non_iid_partition(labels[pool_idx], num_clients, leak, seed)
    loaders = {}
    for c, local in parts.items():
        orig = pool_idx[local].tolist()
        loaders[c] = DataLoader(Subset(train_dataset, orig),
                                batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(Subset(train_dataset, val_idx.tolist()),
                            batch_size=256, shuffle=False)
    return loaders, val_loader


def _self_test():
    print("fl/dataset.py self-test")
    rng = np.random.default_rng(0)
    labels = np.repeat(np.arange(10), 600)
    rng.shuffle(labels)

    assert class_blocks(5, 10) == [[0, 1], [2, 3], [4, 5], [6, 7], [8, 9]]
    print("✓ class blocks split 10 classes across 5 clients")

    val, train = stratified_validation(labels, per_class=50, seed=0)
    assert len(val) == 500 and len(set(val.tolist())) == 500
    assert len(np.intersect1d(val, train)) == 0
    print("✓ stratified validation holds out 500 disjoint samples")

    parts = non_iid_partition(labels[train], 5, leak=0.1, seed=0)
    allidx = np.concatenate([parts[c] for c in parts])
    assert len(allidx) == len(train) and len(set(allidx.tolist())) == len(train)
    print("✓ partition is disjoint and covers every training sample")

    for c, blk in enumerate(class_blocks(5, 10)):
        in_block = np.isin(labels[train][parts[c]], blk).mean()
        assert in_block > 0.8
    print("✓ each client is non-IID (>80% in-block) with ~10% leak")
    print("✓ all dataset self-tests passed")


if __name__ == "__main__":
    _self_test()