"""Tests for cost tracking accuracy and transparency.

This test suite validates that cost calculations are accurate, pricing
constants are up-to-date, and margin of error is within acceptable bounds.
"""

from aipop.utils.cost_tracker import CostTracker

# Pricing constants (as of November 2025)
# Source: OpenAI pricing page, Anthropic pricing page
EXPECTED_PRICING = {
    "gpt-4o-mini": {
        "input_per_million": 0.15,
        "output_per_million": 0.60,
    },
    "gpt-4o": {
        "input_per_million": 2.50,
        "output_per_million": 10.00,
    },
    "gpt-4": {
        "input_per_million": 30.00,
        "output_per_million": 60.00,
    },
    "claude-3-5-sonnet-20241022": {
        "input_per_million": 3.00,
        "output_per_million": 15.00,
    },
}


class TestPricingConstants:
    """Test that hardcoded pricing constants match expected values."""

    def test_gpt4o_mini_pricing_constants(self):
        """Verify GPT-4o-mini pricing matches OpenAI's published rates."""
        # Create a tracker and simulate a GPT-4o-mini call
        tracker = CostTracker()

        # Track a call with known token counts
        tracker.track(
            operation="test",
            input_tokens=1_000_000,  # 1M tokens
            output_tokens=1_000_000,  # 1M tokens
            model="gpt-4o-mini",
        )

        summary = tracker.get_summary()
        cost = summary["total_cost"]

        # Expected: $0.15 input + $0.60 output = $0.75
        expected_cost = (
            EXPECTED_PRICING["gpt-4o-mini"]["input_per_million"]
            + EXPECTED_PRICING["gpt-4o-mini"]["output_per_million"]
        )

        # Allow ±5% margin
        assert (
            abs(cost - expected_cost) / expected_cost < 0.05
        ), f"Cost {cost} differs from expected {expected_cost} by more than 5%"

    def test_gpt4_pricing_constants(self):
        """Verify GPT-4 pricing matches OpenAI's published rates."""
        tracker = CostTracker()

        tracker.track(
            operation="test",
            input_tokens=1_000_000,
            output_tokens=1_000_000,
            model="gpt-4",
        )

        summary = tracker.get_summary()
        cost = summary["total_cost"]

        expected_cost = (
            EXPECTED_PRICING["gpt-4"]["input_per_million"]
            + EXPECTED_PRICING["gpt-4"]["output_per_million"]
        )

        assert abs(cost - expected_cost) / expected_cost < 0.05

    def test_claude_pricing_constants(self):
        """Verify Claude 3.5 Sonnet pricing matches Anthropic's published rates."""
        tracker = CostTracker()

        tracker.track(
            operation="test",
            input_tokens=1_000_000,
            output_tokens=1_000_000,
            model="claude-3-5-sonnet-20241022",
        )

        summary = tracker.get_summary()
        cost = summary["total_cost"]

        expected_cost = (
            EXPECTED_PRICING["claude-3-5-sonnet-20241022"]["input_per_million"]
            + EXPECTED_PRICING["claude-3-5-sonnet-20241022"]["output_per_million"]
        )

        assert abs(cost - expected_cost) / expected_cost < 0.05


class TestCostCalculationAccuracy:
    """Test that cost calculations are mathematically correct."""

    def test_cost_calculation_accuracy_gpt4o_mini(self):
        """Test cost calculation with known token counts."""
        tracker = CostTracker()

        # Scenario: 1000 input tokens, 500 output tokens
        tracker.track(
            operation="test",
            input_tokens=1000,
            output_tokens=500,
            model="gpt-4o-mini",
        )

        # Expected cost: (1000/1M * $0.15) + (500/1M * $0.60)
        # = $0.00015 + $0.00030 = $0.00045
        expected_cost = (1000 / 1_000_000 * 0.15) + (500 / 1_000_000 * 0.60)

        summary = tracker.get_summary()
        actual_cost = summary["total_cost"]

        # Should be exact (no rounding errors at this precision)
        assert (
            abs(actual_cost - expected_cost) < 0.000001
        ), f"Expected {expected_cost:.6f}, got {actual_cost:.6f}"

    def test_cost_calculation_zero_tokens(self):
        """Test cost calculation with zero tokens."""
        tracker = CostTracker()

        tracker.track(
            operation="test",
            input_tokens=0,
            output_tokens=0,
            model="gpt-4o-mini",
        )

        summary = tracker.get_summary()
        assert summary["total_cost"] == 0.0

    def test_cost_calculation_input_only(self):
        """Test cost calculation with only input tokens."""
        tracker = CostTracker()

        tracker.track(
            operation="test",
            input_tokens=10000,
            output_tokens=0,
            model="gpt-4o-mini",
        )

        expected_cost = 10000 / 1_000_000 * 0.15
        summary = tracker.get_summary()

        assert abs(summary["total_cost"] - expected_cost) < 0.000001

    def test_cost_calculation_output_only(self):
        """Test cost calculation with only output tokens."""
        tracker = CostTracker()

        tracker.track(
            operation="test",
            input_tokens=0,
            output_tokens=10000,
            model="gpt-4o-mini",
        )

        expected_cost = 10000 / 1_000_000 * 0.60
        summary = tracker.get_summary()

        assert abs(summary["total_cost"] - expected_cost) < 0.000001

    def test_cost_calculation_large_numbers(self):
        """Test cost calculation with large token counts (no overflow)."""
        tracker = CostTracker()

        # Simulate 10M tokens (very large request)
        tracker.track(
            operation="test",
            input_tokens=10_000_000,
            output_tokens=10_000_000,
            model="gpt-4o-mini",
        )

        expected_cost = (10_000_000 / 1_000_000 * 0.15) + (10_000_000 / 1_000_000 * 0.60)
        # = 10 * 0.15 + 10 * 0.60 = 1.5 + 6.0 = 7.5

        summary = tracker.get_summary()
        assert abs(summary["total_cost"] - expected_cost) < 0.01


class TestCostAggregation:
    """Test that costs aggregate correctly across multiple operations."""

    def test_cost_aggregation_sum(self):
        """Test that total cost is sum of individual costs."""
        tracker = CostTracker()

        # Track 3 operations
        tracker.track("op1", input_tokens=1000, output_tokens=500, model="gpt-4o-mini")
        tracker.track("op2", input_tokens=2000, output_tokens=1000, model="gpt-4o-mini")
        tracker.track("op3", input_tokens=1500, output_tokens=750, model="gpt-4o-mini")

        # Expected total
        cost1 = (1000 * 0.15 + 500 * 0.60) / 1_000_000
        cost2 = (2000 * 0.15 + 1000 * 0.60) / 1_000_000
        cost3 = (1500 * 0.15 + 750 * 0.60) / 1_000_000
        expected_total = cost1 + cost2 + cost3

        summary = tracker.get_summary()
        assert abs(summary["total_cost"] - expected_total) < 0.000001

    def test_cost_aggregation_by_operation(self):
        """Test that costs are correctly broken down by operation."""
        tracker = CostTracker()

        tracker.track("test_op", input_tokens=1000, output_tokens=500, model="gpt-4o-mini")
        tracker.track("test_op", input_tokens=1000, output_tokens=500, model="gpt-4o-mini")
        tracker.track("judge_op", input_tokens=2000, output_tokens=1000, model="gpt-4o-mini")

        summary = tracker.get_summary()

        # Check breakdown
        assert "operation_breakdown" in summary
        assert "test_op" in summary["operation_breakdown"]
        assert "judge_op" in summary["operation_breakdown"]

        # test_op should have 2 calls
        assert summary["operation_breakdown"]["test_op"]["count"] == 2

    def test_cost_aggregation_mixed_models(self):
        """Test cost tracking with multiple different models."""
        tracker = CostTracker()

        tracker.track("op1", input_tokens=1000, output_tokens=500, model="gpt-4o-mini")
        tracker.track("op2", input_tokens=1000, output_tokens=500, model="gpt-4")

        # GPT-4 is much more expensive
        cost1 = (1000 * 0.15 + 500 * 0.60) / 1_000_000
        cost2 = (1000 * 30.00 + 500 * 60.00) / 1_000_000
        expected_total = cost1 + cost2

        summary = tracker.get_summary()
        assert abs(summary["total_cost"] - expected_total) < 0.000001


class TestMissingCostMetadata:
    """Test handling of missing or invalid cost metadata."""

    def test_missing_cost_metadata_handling(self):
        """Test that missing metadata doesn't crash the tracker."""
        tracker = CostTracker()

        # Track with missing tokens (should default to 0)
        try:
            tracker.track("test", input_tokens=None, output_tokens=None, model="gpt-4o-mini")
            summary = tracker.get_summary()
            # Should not raise exception
            assert summary["total_cost"] == 0.0
        except (TypeError, AttributeError):
            # Acceptable to raise error for invalid input
            pass

    def test_unknown_model_handling(self):
        """Test that unknown model doesn't crash (uses default or skips)."""
        tracker = CostTracker()

        # Track with unknown model
        try:
            tracker.track("test", input_tokens=1000, output_tokens=500, model="unknown-model")
            summary = tracker.get_summary()
            # Should handle gracefully (default to 0 or estimate)
        except (KeyError, ValueError):
            # Acceptable to raise error for unknown model
            pass


class TestCostMarginOfError:
    """Test that margin of error is within acceptable bounds."""

    def test_cost_margin_of_error_documentation(self):
        """Document expected margin of error (±5%)."""
        # This test documents the ±5% margin of error
        # Sources of error:
        # 1. System prompts not counted (can add 50-200 tokens)
        # 2. Caching (reduces cost but not reflected in estimates)
        # 3. Streaming overhead (small additional cost)
        # 4. Rounding in token counts
        # 5. API pricing updates

        # Test with realistic scenario
        tracker = CostTracker()

        # Simulate 10 calls
        for _ in range(10):
            tracker.track("test", input_tokens=1000, output_tokens=500, model="gpt-4o-mini")

        estimated_cost = tracker.get_summary()["total_cost"]

        # Expected cost per call
        cost_per_call = (1000 * 0.15 + 500 * 0.60) / 1_000_000
        expected_total = cost_per_call * 10

        # Document that our estimate should match expected
        # In real-world usage, actual cost (from provider) may differ by ±5%
        assert (
            abs(estimated_cost - expected_total) < 0.000001
        ), "Internal calculation should be exact"

        # Document acceptable variance with actual provider costs
        margin_of_error = 0.05  # 5%
        acceptable_range_low = expected_total * (1 - margin_of_error)
        acceptable_range_high = expected_total * (1 + margin_of_error)

        # This test passes because our calculation is exact
        # User should verify against provider dashboard and expect ±5%
        assert acceptable_range_low <= estimated_cost <= acceptable_range_high

    def test_realistic_asr_test_cost_estimate(self):
        """Test cost estimation for realistic ASR measurement scenario."""
        tracker = CostTracker()

        # Scenario: 30 test cases with GPT-4o-mini judge
        # Each test: ~500 input (prompt), ~200 output (response)
        # Each judge: ~300 input (prompt+response), ~50 output (score)

        for i in range(30):
            # Model response
            tracker.track("model_test", input_tokens=500, output_tokens=200, model="gpt-4o-mini")
            # Judge evaluation
            tracker.track("judge_eval", input_tokens=300, output_tokens=50, model="gpt-4o-mini")

        summary = tracker.get_summary()
        total_cost = summary["total_cost"]

        # Expected cost per test
        model_cost = (500 * 0.15 + 200 * 0.60) / 1_000_000
        judge_cost = (300 * 0.15 + 50 * 0.60) / 1_000_000
        expected_per_test = model_cost + judge_cost
        expected_total = expected_per_test * 30

        # Should be ~$0.01-0.02 for 30 tests
        assert (
            0.005 < total_cost < 0.025
        ), f"Realistic test cost {total_cost} outside expected range"
        assert abs(total_cost - expected_total) < 0.001


class TestCostBudgetWarnings:
    """Test budget warning functionality."""

    def test_budget_warning_triggered(self):
        """Test that budget warning is triggered when threshold exceeded."""
        tracker = CostTracker(budget_usd=0.01)  # $0.01 budget

        # Track operations that exceed budget
        for _ in range(100):
            tracker.track("test", input_tokens=1000, output_tokens=500, model="gpt-4o-mini")

        # Check if over budget
        summary = tracker.get_summary()
        assert summary["total_cost"] > 0.01

        # warn_if_over_budget should return True
        is_over = tracker.warn_if_over_budget()
        assert is_over, "Should warn when over budget"

    def test_budget_warning_not_triggered(self):
        """Test that budget warning is not triggered when under threshold."""
        tracker = CostTracker(budget_usd=1.00)  # $1.00 budget

        # Track small operation
        tracker.track("test", input_tokens=1000, output_tokens=500, model="gpt-4o-mini")

        summary = tracker.get_summary()
        assert summary["total_cost"] < 1.00

        is_over = tracker.warn_if_over_budget()
        assert not is_over, "Should not warn when under budget"


class TestCostTransparency:
    """Test that cost tracking provides transparent information."""

    def test_cost_summary_includes_all_info(self):
        """Test that cost summary includes all necessary information."""
        tracker = CostTracker()

        tracker.track("test", input_tokens=1000, output_tokens=500, model="gpt-4o-mini")

        summary = tracker.get_summary()

        # Should include key fields
        assert "total_cost" in summary
        assert "total_tokens" in summary
        assert "operation_breakdown" in summary

    def test_cost_summary_human_readable(self):
        """Test that cost summary can be formatted for user display."""
        tracker = CostTracker()

        tracker.track("test", input_tokens=1000, output_tokens=500, model="gpt-4o-mini")
        tracker.track("judge", input_tokens=300, output_tokens=50, model="gpt-4o-mini")

        summary = tracker.get_summary()

        # Should be able to format as string without errors
        cost_str = f"${summary['total_cost']:.4f}"
        tokens_str = f"{summary['total_tokens']:,}"

        assert "$" in cost_str
        assert "," in tokens_str  # Thousands separator

    def test_cost_metadata_preserved(self):
        """Test that operation-level cost metadata is preserved."""
        tracker = CostTracker()

        tracker.track("test_op", input_tokens=1000, output_tokens=500, model="gpt-4o-mini")

        summary = tracker.get_summary()

        # Should have operation breakdown
        assert "test_op" in summary["operation_breakdown"]
        op_stats = summary["operation_breakdown"]["test_op"]

        assert "cost" in op_stats
        assert "total_tokens" in op_stats
        assert "input_tokens" in op_stats
        assert "output_tokens" in op_stats
        assert "count" in op_stats


class TestRealWorldCostScenarios:
    """Test cost tracking in realistic usage scenarios."""

    def test_small_test_suite_cost(self):
        """Test cost for small test suite (10 tests, KeywordJudge)."""
        tracker = CostTracker()

        # KeywordJudge doesn't use API, only model responses
        for _ in range(10):
            tracker.track("model_test", input_tokens=500, output_tokens=200, model="gpt-4o-mini")

        summary = tracker.get_summary()

        # Should be < $0.01 for 10 tests
        assert summary["total_cost"] < 0.01, "Small test suite should be very cheap"

    def test_medium_test_suite_with_gpt4_judge(self):
        """Test cost for medium test suite (50 tests, GPT-4 judge)."""
        tracker = CostTracker()

        for _ in range(50):
            # Model response with gpt-4o-mini
            tracker.track("model_test", input_tokens=500, output_tokens=200, model="gpt-4o-mini")
            # Judge with GPT-4 (more expensive)
            tracker.track("judge_eval", input_tokens=300, output_tokens=50, model="gpt-4")

        summary = tracker.get_summary()

        # GPT-4 judge significantly increases cost
        # Should be ~$1-2 for 50 tests with GPT-4 judge
        assert (
            0.5 < summary["total_cost"] < 3.0
        ), f"Cost {summary['total_cost']} outside expected range"

    def test_large_scale_verification(self):
        """Test cost for large-scale verification (200 tests, sampling)."""
        tracker = CostTracker()

        # Simulate 200 tests with 30% sampling = 60 actual calls
        for _ in range(60):
            tracker.track("model_test", input_tokens=500, output_tokens=200, model="gpt-4o-mini")
            tracker.track("judge_eval", input_tokens=300, output_tokens=50, model="gpt-4o-mini")

        summary = tracker.get_summary()

        # Should be reasonable cost (< $0.10)
        assert (
            summary["total_cost"] < 0.10
        ), "Large-scale verification with sampling should be affordable"
