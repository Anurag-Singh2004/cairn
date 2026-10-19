"""Unit tests for pure Python statistical functions per DEC-9."""

from __future__ import annotations

from cairn.auditor.stats import bootstrap_auc_ci, compute_auc


def test_auc_disjoint_distributions():
    positives = [10, 11, 12, 13]
    negatives = [1, 2, 3, 4]
    auc = compute_auc(positives, negatives)
    assert auc == 1.0


def test_auc_identical_distributions():
    positives = [1, 2, 3, 4]
    negatives = [1, 2, 3, 4]
    auc = compute_auc(positives, negatives)
    assert auc == 0.5


def test_auc_small_known_example():
    # Positives: [2, 4], Negatives: [1, 3]
    # Pairs (pos, neg):
    # (2, 1) -> 1
    # (2, 3) -> 0
    # (4, 1) -> 1
    # (4, 3) -> 1
    # Total positive ranks: U = 3 / 4 = 0.75
    auc = compute_auc([2, 4], [1, 3])
    assert auc == 0.75


def test_bootstrap_auc_ci_reproducible_with_seed():
    positives = [5, 6, 7, 8, 9, 10]
    negatives = [1, 2, 3, 4, 5, 6]
    auc1, low1, high1 = bootstrap_auc_ci(positives, negatives, n_resamples=500, seed=42)
    auc2, low2, high2 = bootstrap_auc_ci(positives, negatives, n_resamples=500, seed=42)

    assert auc1 == auc2
    assert low1 == low2
    assert high1 == high2
    assert low1 <= auc1 <= high1
