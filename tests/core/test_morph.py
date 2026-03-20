"""Tests for the morph engine."""

import pytest
from aipop.core.morph import MorphEngine, MorphStrategy


class TestMorphEngine:
    def test_list_strategies(self):
        engine = MorphEngine()
        strategies = engine.list_strategies()
        assert len(strategies) >= 7
        names = {s.name for s in strategies}
        assert "base64" in names
        assert "rot13" in names
        assert "zero_width" in names

    def test_base64_morph(self):
        engine = MorphEngine()
        result = engine.morph("hello", "base64")
        import base64
        assert base64.b64decode(result).decode() == "hello"

    def test_rot13_morph(self):
        engine = MorphEngine()
        result = engine.morph("hello", "rot13")
        assert result != "hello"
        assert engine.morph(result, "rot13") == "hello"  # reversible

    def test_hex_morph(self):
        engine = MorphEngine()
        result = engine.morph("hello", "hex")
        assert bytes.fromhex(result).decode() == "hello"

    def test_unknown_strategy_raises(self):
        engine = MorphEngine()
        with pytest.raises(ValueError, match="Unknown strategy"):
            engine.morph("test", "nonexistent")

    def test_register_custom_strategy(self):
        engine = MorphEngine()
        engine.register(MorphStrategy(
            name="shout",
            description="UPPERCASE everything",
            category="custom",
            transform=lambda p: p.upper(),
        ))
        assert engine.morph("hello", "shout") == "HELLO"

    def test_leetspeak(self):
        engine = MorphEngine()
        result = engine.morph("test", "leetspeak")
        assert "7" in result or "3" in result

    def test_zero_width(self):
        engine = MorphEngine()
        result = engine.morph("hello world", "zero_width")
        assert "\u200b" in result

    def test_semantic_strategies_have_sources(self):
        engine = MorphEngine()
        authority = engine.get_strategy("authority_frame")
        assert authority is not None
        assert authority.category == "semantic"
        assert authority.source  # has a research source citation

    def test_evaluation_reframe_has_effectiveness(self):
        engine = MorphEngine()
        eval_strat = engine.get_strategy("evaluation_reframe")
        assert eval_strat is not None
        assert "71.6%" in eval_strat.effectiveness  # Bad Likert Judge data
