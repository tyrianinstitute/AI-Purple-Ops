"""Confidence interval calculations for binomial proportions (ASR measurement).

This module implements multiple methods for calculating confidence intervals
for Attack Success Rate (ASR) measurements, which are binomial proportions.

METHODS:
1. Wilson Score Interval - Approximate method, good coverage for n≥20
2. Clopper-Pearson - Exact binomial method, conservative, recommended for n<20

RESEARCH BASIS:
- Wilson vs Clopper-Pearson comparison: MWSUG 2006 paper
- Small sample recommendations: Use exact method when n<20 or extreme p
- Coverage probability: Wilson ~95%, Clopper-Pearson ≥95% (often 98-99%)

USAGE:
    >>> from aipop.utils.confidence_intervals import calculate_asr_confidence_interval
    >>> result = calculate_asr_confidence_interval(successes=1, trials=15)
    >>> print(f"ASR: {result.point_estimate:.1%}")
    >>> print(f"95% CI: [{result.lower:.1%}, {result.upper:.1%}]")
    >>> print(f"Method: {result.method_used}")
"""

from __future__ import annotations

from dataclasses import dataclass
from math import sqrt

try:
    from scipy.stats import beta
except ImportError:
    beta = None  # type: ignore[assignment]


@dataclass
class ConfidenceIntervalResult:
    """Result of confidence interval calculation."""

    lower: float  # Lower bound of CI (0-1)
    upper: float  # Upper bound of CI (0-1)
    point_estimate: float  # Observed proportion (successes/trials)
    method_used: str  # "wilson" or "clopper-pearson"
    warning_message: str | None = None  # Optional warning (e.g., small sample)
    confidence_level: float = 0.95  # Confidence level used


def wilson_score_interval(
    successes: int,
    trials: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Calculate Wilson score confidence interval for binomial proportion.

    The Wilson score interval inverts the normal approximation test to provide
    better coverage than the normal approximation, especially near boundaries.

    Args:
        successes: Number of successful trials
        trials: Total number of trials
        confidence: Confidence level (default: 0.95 for 95% CI)

    Returns:
        Tuple of (lower_bound, upper_bound)

    References:
        Wilson, E. B. (1927). "Probable inference, the law of succession, and
        statistical inference". Journal of the American Statistical Association.
    """
    if beta is None:
        raise ImportError(
            "scipy is required for this feature. "
            "Install with: pip install ai-purple-ops[intelligence]"
        )

    if trials == 0:
        return (0.0, 0.0)

    # Calculate z-score for confidence level
    # For 95% CI, z = 1.96
    # For 99% CI, z = 2.576
    from scipy.stats import norm

    z = norm.ppf(1 - (1 - confidence) / 2)

    p = successes / trials

    # Wilson score formula
    denominator = 1 + (z**2 / trials)
    center = (p + (z**2 / (2 * trials))) / denominator
    margin = (z / denominator) * sqrt((p * (1 - p) / trials) + (z**2 / (4 * trials**2)))

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    return (lower, upper)


def clopper_pearson_interval(
    successes: int,
    trials: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Calculate Clopper-Pearson exact confidence interval for binomial proportion.

    The Clopper-Pearson method uses the beta distribution to compute exact
    confidence intervals. It is more conservative (wider) than Wilson but
    guarantees coverage at or above the nominal confidence level.

    Recommended for:
    - Small samples (n < 20)
    - Extreme proportions (p near 0 or 1)
    - When zero successes or zero failures

    Args:
        successes: Number of successful trials
        trials: Total number of trials
        confidence: Confidence level (default: 0.95 for 95% CI)

    Returns:
        Tuple of (lower_bound, upper_bound)

    References:
        Clopper, C. J.; Pearson, E. S. (1934). "The use of confidence or
        fiducial limits illustrated in the case of the binomial".
        Biometrika 26 (4): 404–413.
    """
    if beta is None:
        raise ImportError(
            "scipy is required for this feature. "
            "Install with: pip install ai-purple-ops[intelligence]"
        )

    if trials == 0:
        return (0.0, 0.0)

    alpha = 1 - confidence

    # Lower bound: If successes = 0, lower bound is 0
    if successes == 0:
        lower = 0.0
    else:
        # Lower bound is the alpha/2 quantile of Beta(successes, trials - successes + 1)
        lower = beta.ppf(alpha / 2, successes, trials - successes + 1)

    # Upper bound: If successes = trials, upper bound is 1
    if successes == trials:
        upper = 1.0
    else:
        # Upper bound is the 1-alpha/2 quantile of Beta(successes + 1, trials - successes)
        upper = beta.ppf(1 - alpha / 2, successes + 1, trials - successes)

    return (lower, upper)


def calculate_asr_confidence_interval(
    successes: int,
    trials: int,
    method: str = "auto",
    confidence: float = 0.95,
) -> ConfidenceIntervalResult:
    """Calculate confidence interval for Attack Success Rate (ASR).

    Automatically selects the best method based on sample size and proportion,
    or uses a specified method.

    AUTOMATIC METHOD SELECTION (method='auto'):
    - Use Clopper-Pearson if:
      - n < 20 (small sample)
      - successes = 0 (zero successes)
      - successes = trials (all successes)
    - Otherwise use Wilson score

    RATIONALE:
    - Wilson has good coverage and narrower intervals for n≥20
    - Clopper-Pearson is exact and conservative for edge cases
    - Research shows Wilson can under-cover (~93-94%) for n<20 with extreme p

    Args:
        successes: Number of successful jailbreak attempts
        trials: Total number of test cases
        method: "auto", "wilson", or "clopper-pearson"
        confidence: Confidence level (default: 0.95)

    Returns:
        ConfidenceIntervalResult with bounds, method used, and warnings

    Raises:
        ValueError: If method is not recognized or invalid inputs

    Examples:
        >>> # Small sample - auto uses Clopper-Pearson
        >>> result = calculate_asr_confidence_interval(1, 15)
        >>> print(result.method_used)
        'clopper-pearson'

        >>> # Larger sample - auto uses Wilson
        >>> result = calculate_asr_confidence_interval(10, 100)
        >>> print(result.method_used)
        'wilson'

        >>> # Force specific method
        >>> result = calculate_asr_confidence_interval(10, 100, method='clopper-pearson')
    """
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError(f"Invalid inputs: successes={successes}, trials={trials}")

    if method not in ["auto", "wilson", "clopper-pearson"]:
        raise ValueError(f"Unknown method: {method}. Use 'auto', 'wilson', or 'clopper-pearson'")

    point_estimate = successes / trials if trials > 0 else 0.0
    warning_message = None

    # Determine which method to use
    if method == "auto":
        # Use Clopper-Pearson for small samples or extreme proportions
        if trials < 20:
            selected_method = "clopper-pearson"
            warning_message = f"Small sample size (n={trials}): Using exact Clopper-Pearson method. Consider n≥30 for reliable estimates."
        elif successes == 0:
            selected_method = "clopper-pearson"
            warning_message = "Zero successes: Using exact Clopper-Pearson method."
        elif successes == trials:
            selected_method = "clopper-pearson"
            warning_message = "All successes: Using exact Clopper-Pearson method."
        else:
            selected_method = "wilson"
    else:
        selected_method = method

        # Add warnings even for forced methods
        if trials < 20 and selected_method == "wilson":
            warning_message = f"Small sample size (n={trials}): Wilson score may under-cover. Consider Clopper-Pearson or n≥30."
        elif trials < 30:
            warning_message = f"Small sample size (n={trials}): Confidence interval will be wide. Consider n≥30 for reliable estimates."

    # Calculate CI using selected method
    if selected_method == "clopper-pearson":
        lower, upper = clopper_pearson_interval(successes, trials, confidence)
    else:  # wilson
        lower, upper = wilson_score_interval(successes, trials, confidence)

    return ConfidenceIntervalResult(
        lower=lower,
        upper=upper,
        point_estimate=point_estimate,
        method_used=selected_method,
        warning_message=warning_message,
        confidence_level=confidence,
    )


def format_confidence_interval(
    result: ConfidenceIntervalResult,
    include_method: bool = True,
) -> str:
    """Format confidence interval result for display.

    Args:
        result: ConfidenceIntervalResult to format
        include_method: Whether to include method name in output

    Returns:
        Formatted string, e.g., "6.7% [95% CI: 1.2%-29.8%] (Clopper-Pearson)"

    Examples:
        >>> result = calculate_asr_confidence_interval(1, 15)
        >>> print(format_confidence_interval(result))
        '6.7% [95% CI: 1.2%-29.8%] (Clopper-Pearson exact)'
    """
    ci_pct = int(result.confidence_level * 100)

    method_suffix = ""
    if include_method:
        if result.method_used == "clopper-pearson":
            method_suffix = " (Clopper-Pearson exact)"
        elif result.method_used == "wilson":
            method_suffix = " (Wilson score)"

    return (
        f"{result.point_estimate:.1%} "
        f"[{ci_pct}% CI: {result.lower:.1%}-{result.upper:.1%}]"
        f"{method_suffix}"
    )
