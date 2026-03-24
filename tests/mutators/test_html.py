"""Unit tests for HTMLMutator."""

from aipop.mutators.html import HTMLMutator


def test_html_mutator_comment():
    """Test HTML comment mutation."""
    mutator = HTMLMutator()
    prompt = "Hello World"
    mutations = mutator.mutate(prompt)

    comment_mutation = next((m for m in mutations if m.mutation_type == "html_comment"), None)
    assert comment_mutation is not None
    assert comment_mutation.original == prompt
    assert comment_mutation.mutated == f"<!-- {prompt} -->"


def test_html_mutator_script_tag():
    """Test script tag mutation."""
    mutator = HTMLMutator()
    prompt = "Hello World"
    mutations = mutator.mutate(prompt)

    script_mutation = next((m for m in mutations if m.mutation_type == "script_tag"), None)
    assert script_mutation is not None
    assert script_mutation.original == prompt
    assert script_mutation.mutated == f"<script>{prompt}</script>"


def test_html_mutator_cdata():
    """Test CDATA mutation."""
    mutator = HTMLMutator()
    prompt = "Hello World"
    mutations = mutator.mutate(prompt)

    cdata_mutation = next((m for m in mutations if m.mutation_type == "cdata"), None)
    assert cdata_mutation is not None
    assert cdata_mutation.original == prompt
    assert cdata_mutation.mutated == f"<![CDATA[{prompt}]]>"


def test_html_mutator_all_types():
    """Test that all HTML mutation types are generated."""
    mutator = HTMLMutator()
    prompt = "Test"
    mutations = mutator.mutate(prompt)

    assert len(mutations) == 3
    types = {m.mutation_type for m in mutations}
    assert types == {"html_comment", "script_tag", "cdata"}


def test_html_mutator_stats():
    """Test mutation statistics tracking."""
    mutator = HTMLMutator()
    mutator.mutate("test")
    stats = mutator.get_stats()

    assert stats["total"] == 3
    assert stats["success"] == 1


def test_html_mutator_metadata():
    """Test mutation metadata."""
    mutator = HTMLMutator()
    mutations = mutator.mutate("test")

    for mutation in mutations:
        assert "container" in mutation.metadata
        assert mutation.metadata["container"] in ["comment", "script", "cdata"]


def test_html_mutator_empty_prompt():
    """Test HTML mutator with empty prompt."""
    mutator = HTMLMutator()
    mutations = mutator.mutate("")

    assert len(mutations) == 3
    assert any(m.mutated == "<!--  -->" for m in mutations)
    assert any(m.mutated == "<script></script>" for m in mutations)
    assert any(m.mutated == "<![CDATA[]]>" for m in mutations)


def test_html_mutator_special_chars():
    """Test HTML mutator with special characters."""
    mutator = HTMLMutator()
    prompt = "Hello <>&\"'"
    mutations = mutator.mutate(prompt)

    assert len(mutations) == 3
    for mutation in mutations:
        assert mutation.original == prompt


def test_html_mutator_multiline():
    """Test HTML mutator with multiline prompt."""
    mutator = HTMLMutator()
    prompt = "Line 1\nLine 2\nLine 3"
    mutations = mutator.mutate(prompt)

    assert len(mutations) == 3
    for mutation in mutations:
        assert mutation.original == prompt


def test_html_mutator_xss_payload():
    """Test HTML mutator with XSS-like payload."""
    mutator = HTMLMutator()
    prompt = "<script>alert('XSS')</script>"
    mutations = mutator.mutate(prompt)

    assert len(mutations) == 3
    # Should wrap the entire payload
    script_mutation = next((m for m in mutations if m.mutation_type == "script_tag"), None)
    assert script_mutation is not None
    assert prompt in script_mutation.mutated
