"""Unit tests for EncodingMutator."""

import base64
import urllib.parse

from aipop.mutators.encoding import EncodingMutator


def test_encoding_mutator_base64():
    """Test Base64 encoding mutation."""
    mutator = EncodingMutator()
    prompt = "Hello World"
    mutations = mutator.mutate(prompt)

    base64_mutation = next((m for m in mutations if m.mutation_type == "base64"), None)
    assert base64_mutation is not None
    assert base64_mutation.original == prompt
    assert "Decode this Base64:" in base64_mutation.mutated
    assert base64.b64encode(prompt.encode()).decode() in base64_mutation.mutated


def test_encoding_mutator_url():
    """Test URL encoding mutation."""
    mutator = EncodingMutator()
    prompt = "Hello World"
    mutations = mutator.mutate(prompt)

    url_mutation = next((m for m in mutations if m.mutation_type == "url_encoding"), None)
    assert url_mutation is not None
    assert url_mutation.original == prompt
    assert "URL decode:" in url_mutation.mutated
    assert urllib.parse.quote(prompt) in url_mutation.mutated


def test_encoding_mutator_rot13():
    """Test ROT13 encoding mutation."""
    mutator = EncodingMutator()
    prompt = "Hello"
    mutations = mutator.mutate(prompt)

    rot13_mutation = next((m for m in mutations if m.mutation_type == "rot13"), None)
    assert rot13_mutation is not None
    assert rot13_mutation.original == prompt
    assert "ROT13:" in rot13_mutation.mutated


def test_encoding_mutator_hex():
    """Test hex encoding mutation."""
    mutator = EncodingMutator()
    prompt = "Hello"
    mutations = mutator.mutate(prompt)

    hex_mutation = next((m for m in mutations if m.mutation_type == "hex"), None)
    assert hex_mutation is not None
    assert hex_mutation.original == prompt
    assert "Hex decode:" in hex_mutation.mutated
    assert prompt.encode().hex() in hex_mutation.mutated


def test_encoding_mutator_all_types():
    """Test that all encoding types are generated."""
    mutator = EncodingMutator()
    prompt = "Test prompt"
    mutations = mutator.mutate(prompt)

    assert len(mutations) == 4
    types = {m.mutation_type for m in mutations}
    assert types == {"base64", "url_encoding", "rot13", "hex"}


def test_encoding_mutator_stats():
    """Test mutation statistics tracking."""
    mutator = EncodingMutator()
    mutator.mutate("test")
    stats = mutator.get_stats()

    assert stats["total"] >= 4
    assert stats["success"] >= 1


def test_encoding_mutator_metadata():
    """Test mutation metadata."""
    mutator = EncodingMutator()
    mutations = mutator.mutate("test")

    for mutation in mutations:
        assert "encoding" in mutation.metadata
        assert mutation.metadata["encoding"] in ["base64", "url", "rot13", "hex"]


def test_encoding_mutator_empty_prompt():
    """Test encoding mutator with empty prompt."""
    mutator = EncodingMutator()
    mutations = mutator.mutate("")

    # Should still generate mutations (empty strings are valid)
    assert len(mutations) == 4


def test_encoding_mutator_special_chars():
    """Test encoding mutator with special characters."""
    mutator = EncodingMutator()
    prompt = "Hello! @#$%"
    mutations = mutator.mutate(prompt)

    assert len(mutations) == 4
    for mutation in mutations:
        assert mutation.original == prompt


def test_encoding_mutator_unicode():
    """Test encoding mutator with unicode characters."""
    mutator = EncodingMutator()
    prompt = "Hello 世界"
    mutations = mutator.mutate(prompt)

    assert len(mutations) == 4
    for mutation in mutations:
        assert mutation.original == prompt
