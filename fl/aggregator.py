"""
fl/aggregator.py

Aggregation strategies (O4). Every aggregator consumes the same two inputs,
  updates : dict[device_id, list[float]]
  weights : dict[device_id, float]      (from trust.reputation.get_all_weights)
and returns one flat update list. Trust therefore plugs into averaging-style
aggregators as weights and into selection-style aggregators (Krum) as an
eligibility mask, with no change to the trust layer. Banned devices never appear
in `weights`, so they are structurally excluded here, not specially cased.
"""
import numpy as np


def _eligible(updates, weights):
    ids = [i for i in updates if weights.get(i, 0.0) > 0.0]
    if not ids:
        raise ValueError("no eligible clients (all weights zero or banned)")
    mat = np.stack([np.asarray(updates[i], dtype=np.float64) for i in ids])
    w = np.array([weights[i] for i in ids], dtype=np.float64)
    return ids, mat, w


def fedavg(updates, weights):
    ids, mat, w = _eligible(updates, weights)
    w = w / w.sum()
    return (w[:, None] * mat).sum(axis=0).tolist()


def trimmed_mean(updates, weights, trim=0.2):
    ids, mat, _ = _eligible(updates, weights)
    n = len(ids)
    k = min(int(n * trim), (n - 1) // 2)
    s = np.sort(mat, axis=0)
    return s[k:n - k].mean(axis=0).tolist()


def krum(updates, weights, f=1):
    ids, mat, _ = _eligible(updates, weights)
    n = len(ids)
    m = max(n - f - 2, 1)
    d2 = ((mat[:, None, :] - mat[None, :, :]) ** 2).sum(axis=-1)
    scores = [np.sort(d2[i][np.arange(n) != i])[:m].sum() for i in range(n)]
    return mat[int(np.argmin(scores))].tolist()


AGGREGATORS = {"fedavg": fedavg, "trimmed_mean": trimmed_mean, "krum": krum}


def get_aggregator(name):
    if name not in AGGREGATORS:
        raise ValueError(f"unknown aggregator: {name} (have {sorted(AGGREGATORS)})")
    return AGGREGATORS[name]


def _self_test():
    print("fl/aggregator.py self-test")

    u = {"a": [0.0, 0.0], "b": [4.0, 8.0]}
    w = {"a": 1.0, "b": 3.0}
    assert fedavg(u, w) == [3.0, 6.0]
    print("✓ fedavg respects trust weights (hand-computed)")

    u["evil"] = [1e6, 1e6]
    w["evil"] = 0.0
    assert fedavg(u, w) == [3.0, 6.0]
    print("✓ zero-weight device is structurally excluded")

    cluster = {f"c{k}": [1.0 + 0.01 * k, 1.0] for k in range(3)}
    cluster["out"] = [50.0, -50.0]
    wk = {i: 1.0 for i in cluster}
    pick = krum(cluster, wk, f=1)
    assert abs(pick[0] - 1.0) < 0.1 and abs(pick[1] - 1.0) < 0.1
    print("✓ krum selects a consensus member, never the outlier")

    tm = trimmed_mean(cluster, wk, trim=0.25)
    assert abs(tm[0] - 1.01) < 0.05
    print("✓ trimmed mean suppresses the outlier coordinate")

    try:
        fedavg({"x": [1.0]}, {"x": 0.0}); raise AssertionError("should have raised")
    except ValueError:
        print("✓ raises when no client is eligible")
    try:
        get_aggregator("nope"); raise AssertionError("should have raised")
    except ValueError:
        print("✓ unknown aggregator name rejected")
    print("✓ all aggregator self-tests passed")


if __name__ == "__main__":
    _self_test()