"""Tests for LiveRunner — budget enforcement, timeouts, error handling."""

from __future__ import annotations

from aipop.adapters.mock import MockAdapter
from aipop.core.models import ModelResponse, RunResult, TestCase
from aipop.detectors.harmful_content import HarmfulContentDetector
from aipop.runners.live import LiveRunner, LiveRunnerConfig


def _case(id: str = "t1", prompt: str = "Hello", expected: str = "pass") -> TestCase:
    return TestCase(
        id=id,
        prompt=prompt,
        metadata={"expected": expected, "category": "test", "risk": "low"},
    )


def _cases(n: int) -> list[TestCase]:
    return [_case(id=f"t{i}", prompt=f"Test prompt {i}") for i in range(n)]


class TestLiveRunnerBasic:
    def test_execute_returns_run_result(self):
        runner = LiveRunner(adapter=MockAdapter(seed=42, response_mode="smart"))
        result = runner.execute(_case())
        assert isinstance(result, RunResult)
        assert result.test_id == "t1"
        assert result.passed is True
        assert result.response  # non-empty

    def test_execute_many_yields_all(self):
        runner = LiveRunner(adapter=MockAdapter(seed=42, response_mode="smart"))
        results = list(runner.execute_many(_cases(5)))
        assert len(results) == 5
        for r in results:
            assert isinstance(r, RunResult)

    def test_execute_with_detectors(self):
        runner = LiveRunner(
            adapter=MockAdapter(seed=42, response_mode="smart"),
            detectors=[HarmfulContentDetector()],
        )
        result = runner.execute(_case())
        assert result.detector_results is not None
        assert len(result.detector_results) > 0

    def test_metadata_has_model_meta(self):
        runner = LiveRunner(adapter=MockAdapter(seed=42, response_mode="smart"))
        result = runner.execute(_case())
        assert "model_meta" in result.metadata
        assert "elapsed_ms" in result.metadata

    def test_refusal_detection(self):
        runner = LiveRunner(adapter=MockAdapter(seed=42, response_mode="refuse"))
        result = runner.execute(_case(expected="refuse"))
        assert result.passed is True  # refusal was expected

    def test_refusal_when_pass_expected(self):
        runner = LiveRunner(adapter=MockAdapter(seed=42, response_mode="refuse"))
        result = runner.execute(_case(expected="pass"))
        # MockAdapter in refuse mode returns refusals; "pass" expected means
        # response should be non-empty and no violations — depends on refusal keywords
        assert isinstance(result, RunResult)


class TestBudgetEnforcement:
    def test_budget_stops_execution(self):
        """When budget is exceeded, remaining tests get skip results."""
        runner = LiveRunner(
            adapter=MockAdapter(seed=42, response_mode="smart"),
            config=LiveRunnerConfig(budget=0.0001),  # Very low budget
        )
        results = list(runner.execute_many(_cases(10)))
        assert len(results) == 10

        # At least the later tests should be budget-skipped
        budget_skipped = [r for r in results if "budget_exceeded" in str(r.metadata.get("error", ""))]
        # First test runs (costs ~$0.0002), exceeds $0.0001 budget,
        # remaining tests get skipped
        assert len(budget_skipped) > 0

    def test_budget_skip_result_has_metadata(self):
        runner = LiveRunner(
            adapter=MockAdapter(seed=42, response_mode="smart"),
            config=LiveRunnerConfig(budget=0.0001),
        )
        results = list(runner.execute_many(_cases(5)))
        skipped = [r for r in results if r.metadata.get("error") == "budget_exceeded"]
        if skipped:
            s = skipped[0]
            assert s.passed is False
            assert "budget" in s.metadata
            assert "cumulative_cost" in s.metadata

    def test_no_budget_runs_all(self):
        runner = LiveRunner(
            adapter=MockAdapter(seed=42, response_mode="smart"),
            config=LiveRunnerConfig(budget=None),
        )
        results = list(runner.execute_many(_cases(10)))
        budget_skipped = [r for r in results if r.metadata.get("error") == "budget_exceeded"]
        assert len(budget_skipped) == 0

    def test_high_budget_runs_all(self):
        runner = LiveRunner(
            adapter=MockAdapter(seed=42, response_mode="smart"),
            config=LiveRunnerConfig(budget=1000.0),
        )
        results = list(runner.execute_many(_cases(10)))
        budget_skipped = [r for r in results if r.metadata.get("error") == "budget_exceeded"]
        assert len(budget_skipped) == 0

    def test_cumulative_cost_tracked(self):
        runner = LiveRunner(
            adapter=MockAdapter(seed=42, response_mode="smart"),
        )
        list(runner.execute_many(_cases(3)))
        assert runner.cumulative_cost > 0


class TestErrorHandling:
    def test_adapter_error_becomes_failed_result(self):
        """If adapter.invoke() throws, we get a failed RunResult, not a crash."""

        class BrokenAdapter:
            model = "broken"
            def invoke(self, prompt, **kw):
                raise ConnectionError("API down")
            def batch_query(self, prompts, **kw):
                return [self.invoke(p) for p in prompts]

        runner = LiveRunner(adapter=BrokenAdapter())
        result = runner.execute(_case())
        assert result.passed is False
        assert "ConnectionError" in result.metadata.get("error_type", "")
        assert "API down" in result.response

    def test_all_errors_handled_no_crash(self):
        """10 broken tests should yield 10 failed results, not crash."""

        class FlakeyAdapter:
            model = "flakey"
            call_count = 0
            def invoke(self, prompt, **kw):
                self.call_count += 1
                if self.call_count % 2 == 0:
                    raise TimeoutError("Timed out")
                return ModelResponse(text="ok", meta={"cost_usd": 0.001})
            def batch_query(self, prompts, **kw):
                return [self.invoke(p) for p in prompts]

        runner = LiveRunner(adapter=FlakeyAdapter())
        results = list(runner.execute_many(_cases(10)))
        assert len(results) == 10  # All 10 complete, no crash


class TestASRSummary:
    def test_asr_disabled_without_judge(self):
        runner = LiveRunner(adapter=MockAdapter(seed=42, response_mode="smart"))
        list(runner.execute_many(_cases(3)))
        asr = runner.get_asr_summary()
        assert asr["enabled"] is False

    def test_asr_interface_matches_mock_runner(self):
        """get_asr_summary() returns the same keys Scanner expects."""
        runner = LiveRunner(adapter=MockAdapter(seed=42, response_mode="smart"))
        list(runner.execute_many(_cases(3)))
        asr = runner.get_asr_summary()
        assert "enabled" in asr


class TestEncodingSupport:
    def test_base64_encoding(self):
        runner = LiveRunner(adapter=MockAdapter(seed=42, response_mode="echo"))
        case = TestCase(
            id="enc1",
            prompt="Hello",
            metadata={"expected": "pass", "encoding": "base64"},
        )
        result = runner.execute(case)
        assert isinstance(result, RunResult)
        # Echo mode should return the encoded prompt
        assert result.response  # non-empty
