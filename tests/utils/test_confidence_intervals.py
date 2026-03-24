"""Comprehensive tests for confidence interval calculations.

This test suite validates the statistical correctness of Wilson score and
Clopper-Pearson confidence interval methods used for ASR measurement.
"""

import pytest
from scipy.stats import binom

from aipop.utils.confidence_intervals import (
    ConfidenceIntervalResult,
    calculate_asr_confidence_interval,
    clopper_pearson_interval,
    format_confidence_interval,
    wilson_score_interval,
)


class TestWilsonScoreInterval:
    """Tests for Wilson score confidence interval calculation."""

    def test_wilson_score_basic(self):
        """Test Wilson score with typical values."""
        lower, upper = wilson_score_interval(successes=10, trials=100, confidence=0.95)

        # Should be around 10% with reasonable margin
        assert 0.04 < lower < 0.08, f"Lower bound {lower} outside expected range"
        assert 0.14 < upper < 0.18, f"Upper bound {upper} outside expected range"
        assert lower < 0.10 < upper, "CI should contain point estimate"

    def test_wilson_score_zero_successes(self):
        """Test Wilson score with zero successes."""
        lower, upper = wilson_score_interval(successes=0, trials=100, confidence=0.95)

        assert (
            lower < 1e-10
        ), "Lower bound should be essentially 0 for zero successes (allowing floating point precision)"
        assert 0 < upper < 0.05, "Upper bound should be small but non-zero"

    def test_wilson_score_all_successes(self):
        """Test Wilson score with all successes."""
        lower, upper = wilson_score_interval(successes=100, trials=100, confidence=0.95)

        assert 0.95 < lower < 1.0, "Lower bound should be high"
        assert upper == 1.0, "Upper bound should be 1 for all successes"

    def test_wilson_score_zero_trials(self):
        """Test Wilson score with zero trials."""
        lower, upper = wilson_score_interval(successes=0, trials=0, confidence=0.95)

        assert lower == 0.0
        assert upper == 0.0

    def test_wilson_score_99_confidence(self):
        """Test Wilson score with 99% confidence level."""
        lower_95, upper_95 = wilson_score_interval(successes=10, trials=100, confidence=0.95)
        lower_99, upper_99 = wilson_score_interval(successes=10, trials=100, confidence=0.99)

        # 99% CI should be wider than 95% CI
        assert lower_99 < lower_95, "99% CI should have lower lower bound"
        assert upper_99 > upper_95, "99% CI should have higher upper bound"

    def test_wilson_score_small_sample(self):
        """Test Wilson score with small sample (n=10)."""
        lower, upper = wilson_score_interval(successes=1, trials=10, confidence=0.95)

        # Should have wide interval due to small n
        interval_width = upper - lower
        assert interval_width > 0.3, f"Interval should be wide for small n, got {interval_width}"

    def test_wilson_score_single_trial(self):
        """Test Wilson score with single trial."""
        # Single failure
        lower, upper = wilson_score_interval(successes=0, trials=1, confidence=0.95)
        assert lower == 0.0
        assert 0 < upper < 1.0

        # Single success
        lower, upper = wilson_score_interval(successes=1, trials=1, confidence=0.95)
        assert 0 < lower < 1.0
        assert upper == 1.0


class TestClopperPearsonInterval:
    """Tests for Clopper-Pearson exact confidence interval calculation."""

    def test_clopper_pearson_basic(self):
        """Test Clopper-Pearson with typical values."""
        lower, upper = clopper_pearson_interval(successes=10, trials=100, confidence=0.95)

        # Should be around 10% with reasonable margin (wider than Wilson)
        assert 0.04 < lower < 0.07, f"Lower bound {lower} outside expected range"
        assert 0.16 < upper < 0.20, f"Upper bound {upper} outside expected range"
        assert lower < 0.10 < upper, "CI should contain point estimate"

    def test_clopper_pearson_zero_successes(self):
        """Test Clopper-Pearson with zero successes."""
        lower, upper = clopper_pearson_interval(successes=0, trials=100, confidence=0.95)

        assert lower == 0.0, "Lower bound should be exactly 0"
        assert 0 < upper < 0.04, "Upper bound should be small"

    def test_clopper_pearson_all_successes(self):
        """Test Clopper-Pearson with all successes."""
        lower, upper = clopper_pearson_interval(successes=100, trials=100, confidence=0.95)

        assert 0.96 < lower < 1.0, "Lower bound should be high"
        assert upper == 1.0, "Upper bound should be exactly 1"

    def test_clopper_pearson_zero_trials(self):
        """Test Clopper-Pearson with zero trials."""
        lower, upper = clopper_pearson_interval(successes=0, trials=0, confidence=0.95)

        assert lower == 0.0
        assert upper == 0.0

    def test_clopper_pearson_99_confidence(self):
        """Test Clopper-Pearson with 99% confidence level."""
        lower_95, upper_95 = clopper_pearson_interval(successes=10, trials=100, confidence=0.95)
        lower_99, upper_99 = clopper_pearson_interval(successes=10, trials=100, confidence=0.99)

        # 99% CI should be wider than 95% CI
        assert lower_99 < lower_95
        assert upper_99 > upper_95

    def test_clopper_pearson_single_success_small_n(self):
        """Test Clopper-Pearson with 1 success in 15 trials (real-world example)."""
        lower, upper = clopper_pearson_interval(successes=1, trials=15, confidence=0.95)

        # Should produce very wide interval
        assert lower < 0.02, "Lower bound should be near 0"
        assert upper > 0.25, "Upper bound should be high due to uncertainty"
        assert upper - lower > 0.20, "Interval should be very wide"


class TestAutomaticMethodSelection:
    """Tests for automatic CI method selection logic."""

    def test_auto_selects_clopper_pearson_small_n(self):
        """Test that auto selects Clopper-Pearson for n<20."""
        result = calculate_asr_confidence_interval(
            successes=5, trials=15, method="auto", confidence=0.95
        )

        assert result.method_used == "clopper-pearson"
        assert result.warning_message is not None
        assert "small sample" in result.warning_message.lower()

    def test_auto_selects_wilson_large_n(self):
        """Test that auto selects Wilson for n≥20."""
        result = calculate_asr_confidence_interval(
            successes=10, trials=100, method="auto", confidence=0.95
        )

        assert result.method_used == "wilson"
        assert result.warning_message is None

    def test_auto_selects_clopper_pearson_zero_successes(self):
        """Test that auto selects Clopper-Pearson for zero successes."""
        result = calculate_asr_confidence_interval(
            successes=0, trials=50, method="auto", confidence=0.95
        )

        assert result.method_used == "clopper-pearson"
        assert "zero successes" in result.warning_message.lower()

    def test_auto_selects_clopper_pearson_all_successes(self):
        """Test that auto selects Clopper-Pearson for all successes."""
        result = calculate_asr_confidence_interval(
            successes=50, trials=50, method="auto", confidence=0.95
        )

        assert result.method_used == "clopper-pearson"
        assert "all successes" in result.warning_message.lower()

    def test_forced_wilson(self):
        """Test forcing Wilson method even for small n."""
        result = calculate_asr_confidence_interval(
            successes=5, trials=15, method="wilson", confidence=0.95
        )

        assert result.method_used == "wilson"
        # Should still warn about small sample
        assert result.warning_message is not None
        assert "small sample" in result.warning_message.lower()

    def test_forced_clopper_pearson(self):
        """Test forcing Clopper-Pearson for large n."""
        result = calculate_asr_confidence_interval(
            successes=10, trials=100, method="clopper-pearson", confidence=0.95
        )

        assert result.method_used == "clopper-pearson"

    def test_invalid_method_raises_error(self):
        """Test that invalid method raises ValueError."""
        with pytest.raises(ValueError, match="Unknown method"):
            calculate_asr_confidence_interval(
                successes=10, trials=100, method="invalid", confidence=0.95
            )


class TestConfidenceIntervalEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_single_trial_success(self):
        """Test with single trial and success."""
        result = calculate_asr_confidence_interval(
            successes=1, trials=1, method="auto", confidence=0.95
        )

        assert result.point_estimate == 1.0
        assert result.method_used == "clopper-pearson"
        assert 0 < result.lower < 1.0
        assert result.upper == 1.0

    def test_single_trial_failure(self):
        """Test with single trial and failure."""
        result = calculate_asr_confidence_interval(
            successes=0, trials=1, method="auto", confidence=0.95
        )

        assert result.point_estimate == 0.0
        assert result.method_used == "clopper-pearson"
        assert result.lower == 0.0
        assert 0 < result.upper < 1.0

    def test_invalid_inputs_raise_error(self):
        """Test that invalid inputs raise ValueError."""
        # Negative trials
        with pytest.raises(ValueError):
            calculate_asr_confidence_interval(successes=5, trials=-10)

        # Negative successes
        with pytest.raises(ValueError):
            calculate_asr_confidence_interval(successes=-5, trials=10)

        # Successes > trials
        with pytest.raises(ValueError):
            calculate_asr_confidence_interval(successes=15, trials=10)

    def test_zero_trials(self):
        """Test with zero trials."""
        result = calculate_asr_confidence_interval(
            successes=0, trials=0, method="auto", confidence=0.95
        )

        assert result.point_estimate == 0.0
        assert result.lower == 0.0
        assert result.upper == 0.0

    def test_warning_for_very_small_n(self):
        """Test that warning is generated for n<30 with Wilson."""
        result = calculate_asr_confidence_interval(
            successes=10, trials=25, method="wilson", confidence=0.95
        )

        assert result.warning_message is not None


class TestConfidenceIntervalWidth:
    """Tests comparing CI widths between methods."""

    def test_clopper_pearson_wider_than_wilson(self):
        """Test that Clopper-Pearson produces wider intervals than Wilson."""
        # For same data, Clopper-Pearson should be wider (more conservative)
        successes, trials = 10, 100

        wilson_lower, wilson_upper = wilson_score_interval(successes, trials)
        cp_lower, cp_upper = clopper_pearson_interval(successes, trials)

        wilson_width = wilson_upper - wilson_lower
        cp_width = cp_upper - cp_lower

        assert cp_width >= wilson_width, "Clopper-Pearson should be wider or equal"

    def test_interval_width_decreases_with_n(self):
        """Test that interval width decreases as sample size increases."""
        # Fix proportion at 50%, increase n
        proportions = [(5, 10), (25, 50), (50, 100), (100, 200)]
        widths = []

        for successes, trials in proportions:
            result = calculate_asr_confidence_interval(successes, trials, method="wilson")
            width = result.upper - result.lower
            widths.append(width)

        # Each width should be smaller than the previous
        for i in range(len(widths) - 1):
            assert widths[i] > widths[i + 1], f"Width should decrease with n: {widths}"


class TestMonteCarloCoverage:
    """Monte Carlo simulation to verify coverage probability.

    These tests are slower but provide strong evidence that our CI
    methods achieve the claimed coverage probability.
    """

    @pytest.mark.slow
    def test_wilson_coverage_monte_carlo(self):
        """Verify Wilson score achieves ~95% coverage via Monte Carlo simulation."""
        import random

        import numpy as np

        # Set seeds for reproducibility
        random.seed(42)
        np.random.seed(42)

        # Simulation parameters
        true_p = 0.15  # True success rate
        n = 50  # Sample size
        num_simulations = 1000  # Run 1000 trials
        confidence = 0.95

        # Count how many CIs contain true_p
        contains_true_p = 0

        for _ in range(num_simulations):
            # Simulate binomial data
            k = binom.rvs(n, true_p)

            # Calculate CI
            lower, upper = wilson_score_interval(k, n, confidence)

            # Check if CI contains true_p
            if lower <= true_p <= upper:
                contains_true_p += 1

        coverage = contains_true_p / num_simulations

        # Allow ±3% deviation from 95% (93-97% is acceptable)
        assert 0.92 < coverage < 0.98, f"Wilson coverage {coverage:.1%} outside acceptable range"

    @pytest.mark.slow
    def test_clopper_pearson_coverage_monte_carlo(self):
        """Verify Clopper-Pearson achieves ≥95% coverage via Monte Carlo simulation."""
        import random

        import numpy as np

        # Set seeds for reproducibility
        random.seed(43)  # Different seed for independence
        np.random.seed(43)

        # Simulation parameters
        true_p = 0.15
        n = 50
        num_simulations = 1000
        confidence = 0.95

        contains_true_p = 0

        for _ in range(num_simulations):
            k = binom.rvs(n, true_p)
            lower, upper = clopper_pearson_interval(k, n, confidence)

            if lower <= true_p <= upper:
                contains_true_p += 1

        coverage = contains_true_p / num_simulations

        # Clopper-Pearson should be ≥95% (conservative)
        assert coverage >= 0.93, f"Clopper-Pearson coverage {coverage:.1%} below acceptable range"

    @pytest.mark.slow
    def test_coverage_for_small_n(self):
        """Test coverage for small sample sizes where Wilson may under-cover."""
        import random

        import numpy as np

        # Set seeds for reproducibility
        random.seed(44)  # Different seed for independence
        np.random.seed(44)

        true_p = 0.10
        n = 15  # Small sample
        num_simulations = 1000
        confidence = 0.95

        wilson_contains = 0
        cp_contains = 0

        for _ in range(num_simulations):
            k = binom.rvs(n, true_p)

            # Wilson
            w_lower, w_upper = wilson_score_interval(k, n, confidence)
            if w_lower <= true_p <= w_upper:
                wilson_contains += 1

            # Clopper-Pearson
            cp_lower, cp_upper = clopper_pearson_interval(k, n, confidence)
            if cp_lower <= true_p <= cp_upper:
                cp_contains += 1

        wilson_coverage = wilson_contains / num_simulations
        cp_coverage = cp_contains / num_simulations

        # For small n, Clopper-Pearson should have better coverage
        assert cp_coverage >= wilson_coverage, "CP should cover better than Wilson for small n"
        assert cp_coverage >= 0.93, f"CP coverage {cp_coverage:.1%} too low"


class TestConfidenceIntervalFormatting:
    """Tests for formatting CI results for display."""

    def test_format_confidence_interval_basic(self):
        """Test basic formatting of CI result."""
        result = ConfidenceIntervalResult(
            lower=0.05,
            upper=0.15,
            point_estimate=0.10,
            method_used="wilson",
            confidence_level=0.95,
        )

        formatted = format_confidence_interval(result, include_method=True)

        assert "10.0%" in formatted
        assert "5.0%" in formatted
        assert "15.0%" in formatted
        assert "95% CI" in formatted
        assert "Wilson" in formatted

    def test_format_confidence_interval_without_method(self):
        """Test formatting without method name."""
        result = ConfidenceIntervalResult(
            lower=0.05,
            upper=0.15,
            point_estimate=0.10,
            method_used="wilson",
            confidence_level=0.95,
        )

        formatted = format_confidence_interval(result, include_method=False)

        assert "Wilson" not in formatted
        assert "10.0%" in formatted

    def test_format_clopper_pearson(self):
        """Test formatting shows 'exact' for Clopper-Pearson."""
        result = ConfidenceIntervalResult(
            lower=0.012,
            upper=0.298,
            point_estimate=0.067,
            method_used="clopper-pearson",
            confidence_level=0.95,
        )

        formatted = format_confidence_interval(result, include_method=True)

        assert "Clopper-Pearson exact" in formatted


class TestRealWorldScenarios:
    """Tests based on real-world ASR measurement scenarios."""

    def test_typical_jailbreak_test_suite(self):
        """Test with typical test suite results (30 tests, 15% ASR)."""
        result = calculate_asr_confidence_interval(
            successes=5, trials=30, method="auto", confidence=0.95
        )

        # Should use Wilson (n≥20)
        assert result.method_used == "wilson"

        # Point estimate should be ~16.7%
        assert 0.15 < result.point_estimate < 0.18

        # CI should be reasonably narrow (for small n=30, width ~0.26 is expected)
        width = result.upper - result.lower
        assert width < 0.30, "CI should be reasonably narrow for n=30"

    def test_high_asr_scenario(self):
        """Test with high ASR (80% jailbreak success)."""
        result = calculate_asr_confidence_interval(
            successes=80, trials=100, method="auto", confidence=0.95
        )

        assert result.method_used == "wilson"
        assert 0.70 < result.lower < 0.75
        assert 0.85 < result.upper < 0.90

    def test_low_asr_scenario(self):
        """Test with low ASR (2% jailbreak success)."""
        result = calculate_asr_confidence_interval(
            successes=2, trials=100, method="auto", confidence=0.95
        )

        assert result.method_used == "wilson"
        assert result.lower < 0.01
        assert result.upper < 0.08

    def test_perfect_defense_scenario(self):
        """Test when model successfully defends all attacks."""
        result = calculate_asr_confidence_interval(
            successes=0, trials=50, method="auto", confidence=0.95
        )

        # Should use Clopper-Pearson for zero successes
        assert result.method_used == "clopper-pearson"
        assert result.lower == 0.0
        assert 0 < result.upper < 0.10, "Upper bound should indicate possible vulnerability"

    def test_completely_vulnerable_scenario(self):
        """Test when model fails all defenses."""
        result = calculate_asr_confidence_interval(
            successes=50, trials=50, method="auto", confidence=0.95
        )

        # Should use Clopper-Pearson for all successes
        assert result.method_used == "clopper-pearson"
        assert 0.90 < result.lower < 1.0
        assert result.upper == 1.0
