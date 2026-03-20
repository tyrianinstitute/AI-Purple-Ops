"""Unit tests for UnicodeMutator."""

from aipop.mutators.unicode_mutator import UnicodeMutator


def test_unicode_mutator_homoglyph():
    """Test homoglyph substitution."""
    mutator = UnicodeMutator()
    prompt = "Hello"
    mutations = mutator.mutate(prompt)

    homoglyph_mutation = next((m for m in mutations if m.mutation_type == "homoglyph"), None)
    assert homoglyph_mutation is not None
    assert homoglyph_mutation.original == prompt
    assert homoglyph_mutation.mutated != prompt  # Should be different


def test_unicode_mutator_zero_width():
    """Test zero-width character insertion."""
    mutator = UnicodeMutator()
    prompt = "Hello World"
    mutations = mutator.mutate(prompt)

    zw_mutation = next((m for m in mutations if m.mutation_type == "zero_width"), None)
    assert zw_mutation is not None
    assert zw_mutation.original == prompt
    assert "\u200b" in zw_mutation.mutated  # Zero-width space


def test_unicode_mutator_all_types():
    """Test that all unicode mutation types are generated."""
    mutator = UnicodeMutator()
    prompt = "Test"
    mutations = mutator.mutate(prompt)

    assert len(mutations) == 2
    types = {m.mutation_type for m in mutations}
    assert types == {"homoglyph", "zero_width"}


def test_unicode_mutator_stats():
    """Test mutation statistics tracking."""
    mutator = UnicodeMutator()
    mutator.mutate("test")
    stats = mutator.get_stats()

    assert stats["total"] >= 2
    assert stats["success"] >= 1


def test_unicode_mutator_metadata():
    """Test mutation metadata."""
    mutator = UnicodeMutator()
    mutations = mutator.mutate("test")

    homoglyph = next((m for m in mutations if m.mutation_type == "homoglyph"), None)
    assert homoglyph is not None
    assert "technique" in homoglyph.metadata

    zw = next((m for m in mutations if m.mutation_type == "zero_width"), None)
    assert zw is not None
    assert "chars_inserted" in zw.metadata


def test_unicode_mutator_empty_prompt():
    """Test unicode mutator with empty prompt."""
    mutator = UnicodeMutator()
    mutations = mutator.mutate("")

    assert len(mutations) == 2


def test_unicode_mutator_special_chars():
    """Test unicode mutator with special characters."""
    mutator = UnicodeMutator()
    prompt = "Hello! @#$%"
    mutations = mutator.mutate(prompt)

    assert len(mutations) == 2


def test_unicode_mutator_zero_width_count():
    """Test zero-width character count in metadata."""
    mutator = UnicodeMutator()
    prompt = "Hello"
    mutations = mutator.mutate(prompt)

    zw_mutation = next((m for m in mutations if m.mutation_type == "zero_width"), None)
    assert zw_mutation is not None
    assert zw_mutation.metadata["chars_inserted"] > 0


def test_unicode_mutator_homoglyph_substitution():
    """Test that homoglyphs are actually substituted."""
    mutator = UnicodeMutator()
    prompt = "attack"
    mutations = mutator.mutate(prompt)

    homoglyph = next((m for m in mutations if m.mutation_type == "homoglyph"), None)
    assert homoglyph is not None
    # Should contain Cyrillic or other homoglyphs
    assert any(ord(c) > 127 for c in homoglyph.mutated) or homoglyph.mutated != prompt
