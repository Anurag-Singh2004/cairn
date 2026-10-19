"""Pure-Python statistical functions per context.md DEC-9 and flow.md §5 M4.

Implements:
- Mann-Whitney rank AUC with tie handling
- Seeded non-parametric bootstrap confidence intervals
- Exact chance recovery calculations
"""

from __future__ import annotations

import random
from collections.abc import Sequence


def compute_auc(positives: Sequence[float | int], negatives: Sequence[float | int]) -> float:
    """Compute Area Under the Receiver Operating Characteristic Curve (ROC AUC).

    Uses the Mann-Whitney U rank statistic with fractional ranking for ties.
    Returns 0.5 if either sample is empty.
    """
    n1 = len(positives)
    n2 = len(negatives)
    if n1 == 0 or n2 == 0:
        return 0.5

    # Combine and sort all observations with origin tags (1 for positive, 0 for negative)
    tagged = [(val, 1) for val in positives] + [(val, 0) for val in negatives]
    tagged.sort(key=lambda item: item[0])

    # Assign fractional ranks for ties
    n_total = len(tagged)
    ranks = [0.0] * n_total
    i = 0
    while i < n_total:
        j = i
        while j < n_total - 1 and tagged[j][0] == tagged[j + 1][0]:
            j += 1
        # Range i..j has identical values. Average rank (1-indexed) is:
        avg_rank = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            ranks[k] = avg_rank
        i = j + 1

    # Sum of ranks for positive class
    sum_ranks_pos = sum(ranks[idx] for idx in range(n_total) if tagged[idx][1] == 1)

    u1 = sum_ranks_pos - (n1 * (n1 + 1)) / 2.0
    auc = u1 / (n1 * n2)
    return float(auc)


def bootstrap_auc_ci(
    positives: Sequence[float | int],
    negatives: Sequence[float | int],
    n_resamples: int = 1000,
    confidence_level: float = 0.95,
    seed: int = 1337,
) -> tuple[float, float, float]:
    """Compute empirical AUC and two-sided percentile bootstrap confidence interval.

    Returns (auc, lower_ci, upper_ci).
    """
    point_auc = compute_auc(positives, negatives)
    n1 = len(positives)
    n2 = len(negatives)
    if n1 == 0 or n2 == 0:
        return 0.5, 0.5, 0.5

    rng = random.Random(seed)
    boot_aucs: list[float] = []

    pos_list = list(positives)
    neg_list = list(negatives)

    for _ in range(n_resamples):
        resample_pos = [pos_list[rng.randint(0, n1 - 1)] for _ in range(n1)]
        resample_neg = [neg_list[rng.randint(0, n2 - 1)] for _ in range(n2)]
        boot_aucs.append(compute_auc(resample_pos, resample_neg))

    boot_aucs.sort()
    alpha = (1.0 - confidence_level) / 2.0
    lower_idx = int(alpha * n_resamples)
    upper_idx = int((1.0 - alpha) * n_resamples)
    upper_idx = min(upper_idx, n_resamples - 1)

    return point_auc, boot_aucs[lower_idx], boot_aucs[upper_idx]
