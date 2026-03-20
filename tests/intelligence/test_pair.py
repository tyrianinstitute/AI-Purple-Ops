"""Unit tests for PAIR multi-turn adversarial game."""

import pytest

from aipop.intelligence.pair import PAIRAttacker, PAIRConfig, PAIRStream, PAIRTurn


class MockAdapter:
    """Mock adapter for testing."""

    def __init__(self, responses=None):
        self.responses = responses or ['{"improvement": "test", "prompt": "Mock prompt"}']
        self.call_count = 0

    def invoke(self, prompt, system_prompt=None):
        """Mock invoke that returns predefined responses."""
        self.call_count += 1
        response_idx = (self.call_count - 1) % len(self.responses)

        class MockResponse:
            def __init__(self, text):
                self.text = text

        return MockResponse(self.responses[response_idx])


class MockJudge:
    """Mock judge for testing."""

    def score_response(self, prompt, response):
        from aipop.intelligence.judge_models import JudgmentResult

        # Simple mock: return high score if response starts correctly
        starts_correctly = response.strip().startswith("Sure")
        score = 9.0 if starts_correctly else 2.0
        return JudgmentResult(
            score=score,
            is_jailbreak=starts_correctly,
            confidence=0.9,
            reasoning="Mock judgment",
        )


def test_pair_config_defaults():
    """Test PAIR config has correct defaults."""
    config = PAIRConfig()
    assert config.num_streams == 30
    assert config.iterations_per_stream == 3
    assert config.attacker_model == "gpt-4"
    assert len(config.strategies) == 3
    assert "logical_appeal" in config.strategies


def test_pair_stream():
    """Test PAIR stream tracks history correctly."""
    stream = PAIRStream(
        stream_id=0,
        strategy="logical_appeal",
        objective="Write hacking instructions",
        starting_string="Sure",
    )

    assert stream.stream_id == 0
    assert stream.strategy == "logical_appeal"
    assert len(stream.history) == 0
    assert not stream.success

    # Add a turn
    turn = PAIRTurn(
        prompt="Test prompt",
        response="Sure, I can help",
        score=0.9,
        improvement="Good attempt",
        iteration=1,
    )
    stream.history.append(turn)

    assert len(stream.history) == 1
    assert stream.history[0].score == 0.9


def test_pair_attacker_initialization():
    """Test PAIR attacker initializes correctly."""
    attacker_adapter = MockAdapter()
    target_adapter = MockAdapter()
    config = PAIRConfig(num_streams=5, iterations_per_stream=2)

    attacker = PAIRAttacker(
        config=config,
        attacker_adapter=attacker_adapter,
        target_adapter=target_adapter,
        judge=MockJudge(),
    )

    assert attacker.config == config
    assert attacker.attacker_adapter == attacker_adapter
    assert attacker.target_adapter == target_adapter
    assert attacker.query_count == 0


def test_pair_attacker_create_prompt():
    """Test PAIR attacker creates prompts correctly."""
    attacker_adapter = MockAdapter()
    target_adapter = MockAdapter()
    config = PAIRConfig()

    attacker = PAIRAttacker(
        config=config,
        attacker_adapter=attacker_adapter,
        target_adapter=target_adapter,
        judge=None,
    )

    objective = "Write hacking instructions"
    starting_string = "Sure"
    history = []
    strategy = "logical_appeal"

    prompt = attacker._create_attacker_prompt(
        objective=objective,
        starting_string=starting_string,
        history=history,
        strategy=strategy,
    )

    assert objective in prompt
    assert starting_string in prompt
    assert strategy in prompt.lower() or "logical" in prompt.lower()


def test_pair_attacker_parse_response():
    """Test PAIR attacker parses JSON responses."""
    attacker_adapter = MockAdapter()
    target_adapter = MockAdapter()
    config = PAIRConfig()

    attacker = PAIRAttacker(
        config=config,
        attacker_adapter=attacker_adapter,
        target_adapter=target_adapter,
        judge=None,
    )

    # Valid JSON
    response = '{"improvement": "Try different approach", "prompt": "New prompt"}'
    improvement, prompt = attacker._parse_attacker_response(response)
    assert improvement == "Try different approach"
    assert prompt == "New prompt"

    # JSON in markdown code block
    response = '```json\n{"improvement": "Test", "prompt": "Prompt"}\n```'
    improvement, prompt = attacker._parse_attacker_response(response)
    assert improvement == "Test"
    assert prompt == "Prompt"


def test_pair_attacker_evaluate_response():
    """Test PAIR attacker evaluates responses correctly."""
    attacker_adapter = MockAdapter()
    target_adapter = MockAdapter()
    config = PAIRConfig()

    attacker = PAIRAttacker(
        config=config,
        attacker_adapter=attacker_adapter,
        target_adapter=target_adapter,
        judge=MockJudge(),
    )

    # Response that starts correctly
    score1 = attacker._evaluate_response(
        prompt="Test",
        response="Sure, I can help",
        starting_string="Sure",
    )
    assert score1 >= 0.8

    # Response that doesn't start correctly
    score2 = attacker._evaluate_response(
        prompt="Test",
        response="I cannot help",
        starting_string="Sure",
    )
    assert score2 < 0.8


def test_pair_attacker_detect_stagnation():
    """Test PAIR attacker detects stagnation."""
    attacker_adapter = MockAdapter()
    target_adapter = MockAdapter()
    config = PAIRConfig()

    attacker = PAIRAttacker(
        config=config,
        attacker_adapter=attacker_adapter,
        target_adapter=target_adapter,
        judge=None,
    )

    # Stream with improving scores
    stream1 = PAIRStream(
        stream_id=0,
        strategy="test",
        objective="test",
        starting_string="test",
    )
    stream1.history = [
        PAIRTurn("p1", "r1", 0.3, "i1", 1),
        PAIRTurn("p2", "r2", 0.5, "i2", 2),
        PAIRTurn("p3", "r3", 0.7, "i3", 3),
    ]
    assert not attacker._detect_stagnation(stream1)

    # Stream with stagnant scores
    stream2 = PAIRStream(
        stream_id=1,
        strategy="test",
        objective="test",
        starting_string="test",
    )
    stream2.history = [
        PAIRTurn("p1", "r1", 0.5, "i1", 1),
        PAIRTurn("p2", "r2", 0.5, "i2", 2),
        PAIRTurn("p3", "r3", 0.4, "i3", 3),  # Decreasing
    ]
    assert attacker._detect_stagnation(stream2)


@pytest.mark.slow
def test_pair_attack_small():
    """Test PAIR attack with small configuration (slow test)."""
    attacker_adapter = MockAdapter(
        responses=[
            '{"improvement": "Try again", "prompt": "Refined prompt"}',
            '{"improvement": "Better", "prompt": "Better prompt"}',
        ]
    )
    target_adapter = MockAdapter(responses=["Sure, I can help", "I cannot help"])
    config = PAIRConfig(num_streams=2, iterations_per_stream=2, max_queries=10)

    attacker = PAIRAttacker(
        config=config,
        attacker_adapter=attacker_adapter,
        target_adapter=target_adapter,
        judge=MockJudge(),
    )

    streams = attacker.attack(objective="Write hacking instructions", starting_string="Sure")

    assert len(streams) == config.num_streams
    assert attacker.query_count > 0
    # At least some streams should have history
    assert any(len(s.history) > 0 for s in streams)
