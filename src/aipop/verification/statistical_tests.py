"""Statistical tests for multiple comparison correction.

Implements Holm-Bonferroni correction for controlling family-wise error rate
when comparing multiple attack methods or models.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def holm_bonferroni_correction(p_values: list[float], alpha: float = 0.05) -> list[bool]:
    """Holm-Bonferroni sequential correction for multiple comparisons.

    More powerful than simple Bonferroni correction while still controlling
    family-wise error rate (FWER).

    Algorithm:
    1. Sort p-values in ascending order
    2. For each p-value at rank i, compare to alpha / (n - i + 1)
    3. Reject hypotheses sequentially until first non-rejection
    4. All subsequent hypotheses are not rejected

    Args:
        p_values: List of p-values to correct
        alpha: Significance level (default: 0.05)

    Returns:
        List of booleans indicating whether each hypothesis is rejected

    References:
        Holm, S. (1979). "A simple sequentially rejective multiple test procedure".
        Scandinavian Journal of Statistics, 6(2), 65-70.

    Examples:
        >>> p_values = [0.01, 0.03, 0.05, 0.10]
        >>> rejections = holm_bonferroni_correction(p_values, alpha=0.05)
        >>> print(rejections)
        [True, True, False, False]  # First two rejected, last two not
    """
    if not p_values:
        return []

    n = len(p_values)

    # Sort p-values with original indices
    indexed_p_values = [(p, i) for i, p in enumerate(p_values)]
    indexed_p_values.sort(key=lambda x: x[0])

    # Initialize rejections
    rejections = [False] * n

    # Sequential testing
    for rank, (p_value, original_idx) in enumerate(indexed_p_values):
        # Adjusted alpha: alpha / (n - rank)
        adjusted_alpha = alpha / (n - rank)

        if p_value <= adjusted_alpha:
            rejections[original_idx] = True
        else:
            # Stop at first non-rejection (Holm procedure)
            break

    return rejections


def bonferroni_correction(p_values: list[float], alpha: float = 0.05) -> list[bool]:
    """Simple Bonferroni correction for multiple comparisons.

    More conservative than Holm-Bonferroni but simpler.

    Args:
        p_values: List of p-values to correct
        alpha: Significance level

    Returns:
        List of booleans indicating whether each hypothesis is rejected
    """
    if not p_values:
        return []

    n = len(p_values)
    adjusted_alpha = alpha / n

    return [p <= adjusted_alpha for p in p_values]


def benjamini_hochberg_correction(p_values: list[float], alpha: float = 0.05) -> list[bool]:
    """Benjamini-Hochberg FDR correction (less conservative than Bonferroni).

    Controls false discovery rate (FDR) rather than family-wise error rate.
    More powerful than Bonferroni/Holm but allows some false positives.

    Args:
        p_values: List of p-values to correct
        alpha: Significance level

    Returns:
        List of booleans indicating whether each hypothesis is rejected
    """
    if not p_values:
        return []

    n = len(p_values)

    # Sort p-values with original indices
    indexed_p_values = [(p, i) for i, p in enumerate(p_values)]
    indexed_p_values.sort(key=lambda x: x[0])

    # Initialize rejections
    rejections = [False] * n

    # Find largest k such that p(k) <= (k/n) * alpha
    for rank in range(n - 1, -1, -1):
        p_value, original_idx = indexed_p_values[rank]
        adjusted_alpha = ((rank + 1) / n) * alpha

        if p_value <= adjusted_alpha:
            # Reject this and all smaller p-values
            for j in range(rank + 1):
                _, idx = indexed_p_values[j]
                rejections[idx] = True
            break

    return rejections


def compare_methods(
    method_results: dict[str, dict[str, Any]], alpha: float = 0.05
) -> dict[str, Any]:
    """Compare multiple attack methods with statistical correction.

    Args:
        method_results: Dictionary mapping method names to results
            Each result should have 'successes' and 'trials' keys
        alpha: Significance level

    Returns:
        Dictionary with comparison results and corrected p-values
    """
    from scipy.stats import chi2_contingency

    methods = list(method_results.keys())
    n_methods = len(methods)

    if n_methods < 2:
        return {"error": "Need at least 2 methods to compare"}

    # Calculate p-values for each pairwise comparison
    p_values = []
    comparisons = []

    for i in range(n_methods):
        for j in range(i + 1, n_methods):
            method1 = methods[i]
            method2 = methods[j]

            result1 = method_results[method1]
            result2 = method_results[method2]

            successes1 = result1.get("successes", 0)
            trials1 = result1.get("trials", 0)
            successes2 = result2.get("successes", 0)
            trials2 = result2.get("trials", 0)

            # Chi-square test for independence
            contingency = [[successes1, trials1 - successes1], [successes2, trials2 - successes2]]
            try:
                chi2, p_value, _, _ = chi2_contingency(contingency)
                p_values.append(p_value)
                comparisons.append((method1, method2))
            except Exception as e:
                logger.warning(f"Chi-square test failed for {method1} vs {method2}: {e}")
                p_values.append(1.0)  # Conservative: don't reject
                comparisons.append((method1, method2))

    # Apply Holm-Bonferroni correction
    rejections = holm_bonferroni_correction(p_values, alpha)

    # Format results
    comparison_results = []
    for (method1, method2), p_value, rejected in zip(comparisons, p_values, rejections):
        comparison_results.append(
            {
                "method1": method1,
                "method2": method2,
                "p_value": p_value,
                "rejected": rejected,
                "significant": rejected,
            }
        )

    return {
        "comparisons": comparison_results,
        "alpha": alpha,
        "correction_method": "holm_bonferroni",
        "total_comparisons": len(comparisons),
        "significant_comparisons": sum(rejections),
    }
