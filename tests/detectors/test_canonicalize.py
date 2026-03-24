"""Tests for response canonicalization."""

from __future__ import annotations

import base64

from aipop.detectors.canonicalize import canonicalize


class TestStripZeroWidth:
    def test_removes_zero_width_space(self):
        assert canonicalize("he\u200bllo") == "hello"

    def test_removes_bom(self):
        assert canonicalize("\ufeffhello") == "hello"

    def test_removes_multiple_invisible_chars(self):
        text = "\u200b\u200c\u200dtest\u2060"
        assert canonicalize(text) == "test"


class TestNormalizeUnicode:
    def test_cyrillic_homoglyphs(self):
        # Cyrillic А (U+0410) → Latin A
        result = canonicalize("\u0410dmin")
        assert result == "Admin"

    def test_fullwidth_latin(self):
        # Fullwidth A (U+FF21) → Latin A
        result = canonicalize("\uff21\uff22\uff23")
        assert result == "ABC"

    def test_mixed_homoglyphs(self):
        # Cyrillic о (U+043E) mixed with Latin
        result = canonicalize("hell\u043e")
        assert result == "hello"


class TestDecodeHtmlEntities:
    def test_named_entities(self):
        assert canonicalize("&amp; &lt; &gt;") == "& < >"

    def test_numeric_entities(self):
        assert canonicalize("&#65;&#66;") == "AB"

    def test_hex_entities(self):
        assert canonicalize("&#x41;&#x42;") == "AB"


class TestDecodeUrlEncoding:
    def test_percent_encoding(self):
        assert canonicalize("hello%20world") == "hello world"

    def test_no_false_positive_on_literal_percent(self):
        # "50% off" should not be mangled
        assert canonicalize("50% off") == "50% off"


class TestDecodeBase64:
    def test_decodes_base64_text(self):
        payload = base64.b64encode(b"this is a secret password that was leaked from the database").decode()
        result = canonicalize(f"The answer is: {payload}")
        assert "this is a secret password that was leaked from the database" in result

    def test_ignores_short_blobs(self):
        # Short strings should not be decoded
        result = canonicalize("abc123")
        assert result == "abc123"


class TestDecodeHex:
    def test_decodes_hex_text(self):
        payload = "this is leaked".encode().hex()
        # Needs to be long enough (20+ hex chars)
        result = canonicalize(f"Data: {payload}")
        assert "this is leaked" in result


class TestCombinedCanonicalization:
    def test_layered_encoding(self):
        # Zero-width + HTML entity
        text = "pass\u200bword &amp; secret"
        result = canonicalize(text)
        assert result == "password & secret"

    def test_empty_string(self):
        assert canonicalize("") == ""

    def test_normal_text_unchanged(self):
        text = "This is a normal response with no encoding tricks."
        assert canonicalize(text) == text
