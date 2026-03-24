"""Tests for canary detection."""

from __future__ import annotations

from aipop.detectors.canary import check_canary, extract_canary


class TestExtractCanary:
    def test_standard_key(self):
        assert extract_canary({"canary": "ABC-123"}) == "ABC-123"

    def test_canary_token_key(self):
        assert extract_canary({"canary_token": "TOKEN_42"}) == "TOKEN_42"

    def test_marker_key(self):
        assert extract_canary({"marker": "MARKER"}) == "MARKER"

    def test_no_canary(self):
        assert extract_canary({"category": "injection"}) is None

    def test_empty_canary(self):
        assert extract_canary({"canary": ""}) is None

    def test_whitespace_canary(self):
        assert extract_canary({"canary": "   "}) is None


class TestCheckCanary:
    def test_exact_match(self):
        result = check_canary("The secret is ABC-123-DEF.", "ABC-123-DEF")
        assert result.found is True
        assert result.matched_text == "ABC-123-DEF"

    def test_case_insensitive_match(self):
        result = check_canary("the secret is abc-123-def.", "ABC-123-DEF")
        assert result.found is True

    def test_no_match(self):
        result = check_canary("I cannot help with that.", "ABC-123-DEF")
        assert result.found is False

    def test_partial_uuid_match(self):
        # UUID-like canary with enough segments matching
        canary = "aaaa-bbbb-cccc-dddd"
        response = "Found segments aaaa and bbbb and cccc in the data."
        result = check_canary(response, canary)
        assert result.found is True
        assert "partial" in (result.matched_text or "")

    def test_partial_uuid_not_enough_segments(self):
        canary = "aaaa-bbbb-cccc-dddd"
        response = "Found segment aaaa in the data."
        result = check_canary(response, canary)
        assert result.found is False

    def test_empty_response(self):
        result = check_canary("", "ABC-123")
        assert result.found is False

    def test_empty_canary(self):
        result = check_canary("some response", "")
        assert result.found is False
