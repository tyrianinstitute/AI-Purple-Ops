"""Unit tests for CostTracker utility."""

from aipop.utils.cost_tracker import CostTracker


def test_cost_tracker_initialization():
    """Test CostTracker initialization."""
    tracker = CostTracker()
    assert len(tracker.operations) == 0


def test_track_operation():
    """Test tracking a cost operation."""
    tracker = CostTracker()
    tracker.track(
        operation="run",
        model="gpt-4",
        input_tokens=400,
        output_tokens=600,
        cost=0.03,
    )

    assert len(tracker.operations) == 1
    assert tracker.operations[0].operation == "run"
    assert tracker.operations[0].total_tokens == 1000
    assert tracker.operations[0].input_tokens == 400
    assert tracker.operations[0].output_tokens == 600
    assert tracker.operations[0].model == "gpt-4"
    assert tracker.operations[0].cost == 0.03


def test_get_summary_empty():
    """Test summary with no operations."""
    tracker = CostTracker()
    summary = tracker.get_summary()

    assert summary["total_cost"] == 0.0
    assert summary["total_tokens"] == 0
    assert summary["operation_count"] == 0


def test_get_summary_with_operations():
    """Test summary with multiple operations."""
    tracker = CostTracker()
    tracker.track(operation="run", model="gpt-4", tokens=1000, cost=0.03)
    tracker.track(operation="run", model="gpt-4", tokens=500, cost=0.015)
    tracker.track(operation="verify-suite", model="gpt-4", tokens=2000, cost=0.06)

    summary = tracker.get_summary()

    assert summary["total_cost"] == 0.105
    assert summary["total_tokens"] == 3500
    assert summary["operation_count"] == 3
    assert summary["operation_breakdown"]["run"]["cost"] == 0.045
    assert summary["operation_breakdown"]["run"]["count"] == 2
    assert summary["model_breakdown"]["gpt-4"]["cost"] == 0.105


def test_warn_if_over_budget():
    """Test budget warning."""
    # Tracker with budget set to $0.03
    tracker = CostTracker(budget_usd=0.03)
    tracker.track(operation="run", model="gpt-4", tokens=1000, cost=0.05)

    # Should warn if over budget
    assert tracker.warn_if_over_budget() is True

    # Should not warn if under budget
    tracker2 = CostTracker(budget_usd=0.03)
    tracker2.track(operation="run", model="gpt-4", tokens=1000, cost=0.01)
    assert tracker2.warn_if_over_budget() is False


def test_reset():
    """Test resetting tracker."""
    tracker = CostTracker()
    tracker.track(operation="run", model="gpt-4", tokens=1000, cost=0.03)
    assert len(tracker.operations) == 1

    tracker.reset()
    assert len(tracker.operations) == 0


def test_get_operation_cost():
    """Test getting cost for specific operation."""
    tracker = CostTracker()
    tracker.track(operation="run", model="gpt-4", tokens=1000, cost=0.03)
    tracker.track(operation="verify-suite", model="gpt-4", tokens=2000, cost=0.06)
    tracker.track(operation="run", model="gpt-4", tokens=500, cost=0.015)

    assert tracker.get_operation_cost("run") == 0.045
    assert tracker.get_operation_cost("verify-suite") == 0.06


def test_get_model_cost():
    """Test getting cost for specific model."""
    tracker = CostTracker()
    tracker.track(operation="run", model="gpt-4", tokens=1000, cost=0.03)
    tracker.track(operation="run", model="claude-3-5-sonnet", tokens=500, cost=0.02)
    tracker.track(operation="verify-suite", model="gpt-4", tokens=2000, cost=0.06)

    assert tracker.get_model_cost("gpt-4") == 0.09
    assert tracker.get_model_cost("claude-3-5-sonnet") == 0.02
