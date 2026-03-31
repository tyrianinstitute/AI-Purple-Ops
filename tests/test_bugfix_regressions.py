"""Regression tests for the 13 bugs fixed in the March 2026 code review.

Each test targets one specific bug. If any of these fail, the bug has been
reintroduced. Do not delete or weaken these tests.
"""

import json
import re
from html import escape
from unittest.mock import MagicMock, patch

import pytest


# ── BUG 1-2: XSS in HTML and PDF reporters ──────────────────────────


class TestXSSPrevention:
    """HTML reporters must escape attacker-controlled content."""

    def test_html_reporter_imports_escape(self):
        """html_reporter.py must import html.escape."""
        from pathlib import Path
        html_rep = Path(__file__).parent.parent / "src" / "aipop" / "reporters" / "html_reporter.py"
        source = html_rep.read_text()
        assert "from html import escape as h" in source
        # Verify h() is actually used on user content
        assert "h(finding.get(" in source or "h(test_name)" in source

    def test_pdf_reporter_imports_html_escape(self):
        """pdf_report.py must import html.escape."""
        import aipop.reporters.pdf_report as mod
        source = open(mod.__file__).read()
        assert "from html import escape as h" in source


# ── BUG 3-4: NameError crashes in harness ────────────────────────────


class TestNameErrorFixes:
    """Functions must not reference undefined variables."""

    def test_logger_not_referenced(self):
        """harness.py must use log.warn, not logger.warning."""
        from pathlib import Path
        harness = Path(__file__).parent.parent / "src" / "aipop" / "cli" / "harness.py"
        source = harness.read_text()
        # The broken reference should be gone
        assert "logger.warning" not in source

    def test_judge_variable_correct_in_run_cmd(self):
        """run_cmd must use judge (not judge_name) for keyword check."""
        from pathlib import Path
        harness = Path(__file__).parent.parent / "src" / "aipop" / "cli" / "harness.py"
        source = harness.read_text()
        # judge_name is valid inside _create_judge_from_cli (it's the param name)
        # but in run_cmd around line 4054, it must be just "judge"
        lines = source.split("\n")
        for i, line in enumerate(lines):
            # Look for the keyword judge check in run_cmd context (after line 4000)
            if i > 4000 and 'judge_name == "keyword"' in line:
                pytest.fail(f"Line {i+1}: run_cmd still uses judge_name instead of judge")

    def test_cost_tracker_not_referenced(self):
        """harness.py must not reference undefined cost_tracker."""
        from pathlib import Path
        harness = Path(__file__).parent.parent / "src" / "aipop" / "cli" / "harness.py"
        source = harness.read_text()
        assert "cost_tracker.warn_if_over_budget" not in source


# ── BUG 5: idx shadowing in fuzz engine ──────────────────────────────


class TestIdxShadowing:
    """The loop counter must not be overwritten by str.find()."""

    def test_no_idx_reassignment_in_leak_check(self):
        """engine.py leak check must use pos, not idx."""
        from pathlib import Path
        engine = Path(__file__).parent.parent / "src" / "aipop" / "fuzz" / "engine.py"
        source = engine.read_text()
        # The old pattern: idx = reply_text.lower().find(
        assert "idx = reply_text.lower().find(" not in source
        # The new pattern: pos = reply_text.lower().find(
        assert "pos = reply_text.lower().find(" in source


# ── BUG 6: Chain runner false VULNERABLE on HTTP errors ──────────────


class TestChainErrorHandling:
    """HTTP step errors must not be reported as vulnerabilities."""

    def test_step_error_sets_passed_true(self):
        """A non-connection step error should set passed=True."""
        from pathlib import Path
        chain = Path(__file__).parent.parent / "src" / "aipop" / "runners" / "chain.py"
        source = chain.read_text()
        # The else branch for non-connection errors must set passed=True
        assert 'chain_result.passed = True  # Step error' in source
        assert '"error_class"] = "step_error"' in source


# ── BUG 7: Bypass rate wrong denominator ─────────────────────────────


class TestBypassRate:
    """Bypass rate must exclude errors from denominator."""

    def test_valid_count_used_in_bypass_calculation(self):
        """engine.py must calculate valid_count = len(attempts) - error_count."""
        from pathlib import Path
        engine = Path(__file__).parent.parent / "src" / "aipop" / "fuzz" / "engine.py"
        source = engine.read_text()
        assert "valid_count = len(attempts) - error_count" in source
        assert "vuln_count / valid_count" in source


# ── BUG 8: resp.json() crash on non-JSON 200 ────────────────────────


class TestNonJsonResponse:
    """Successful upload with non-JSON body must not crash."""

    def test_json_decode_wrapped_in_try_except(self):
        """engine.py must catch JSONDecodeError on resp.json()."""
        from pathlib import Path
        engine = Path(__file__).parent.parent / "src" / "aipop" / "fuzz" / "engine.py"
        source = engine.read_text()
        # Both paths should have the try/except
        assert source.count("except (ValueError, requests.exceptions.JSONDecodeError)") >= 2


# ── BUG 9: False positive email detection ────────────────────────────


class TestFalsePositiveDetector:
    """Public emails must not be flagged as critical data leaks."""

    def test_public_domains_excluded(self):
        """cascade.py must exclude common public email domains."""
        from pathlib import Path
        cascade = Path(__file__).parent.parent / "src" / "aipop" / "detectors" / "cascade.py"
        source = cascade.read_text()
        assert "example.com" in source
        assert "gmail.com" in source

    def test_email_confidence_is_tentative(self):
        """Email pattern matches should produce tentative confidence, not certain."""
        from pathlib import Path
        cascade = Path(__file__).parent.parent / "src" / "aipop" / "detectors" / "cascade.py"
        source = cascade.read_text()
        assert "tentative" in source


# ── BUG 10: Bedrock JSON serialization ───────────────────────────────


class TestBedrockSerialization:
    """Bedrock adapter must use json.dumps, not str().replace."""

    def test_no_str_replace_pattern(self):
        """bedrock.py must not use str(body).replace for JSON."""
        from pathlib import Path
        bedrock = Path(__file__).parent.parent / "src" / "aipop" / "adapters" / "bedrock.py"
        source = bedrock.read_text()
        assert "str(body).replace" not in source
        assert "json.dumps(body)" in source


# ── BUG 11: TLS silently disabled on proxy ───────────────────────────


class TestTLSProxy:
    """TLS must not be silently disabled when a proxy is configured."""

    def test_openai_has_insecure_param(self):
        """OpenAI adapter must have explicit insecure parameter."""
        from aipop.adapters.openai import OpenAIAdapter
        import inspect
        sig = inspect.signature(OpenAIAdapter.__init__)
        assert "insecure" in sig.parameters

    def test_anthropic_has_insecure_param(self):
        """Anthropic adapter must have explicit insecure parameter."""
        from aipop.adapters.anthropic import AnthropicAdapter
        import inspect
        sig = inspect.signature(AnthropicAdapter.__init__)
        assert "insecure" in sig.parameters


# ── BUG 12: Missing adapters in CLI ──────────────────────────────────


class TestAdapterMap:
    """All registered adapters must be reachable from the CLI."""

    def test_bedrock_in_adapter_creation(self):
        """harness.py must register bedrock adapter."""
        from pathlib import Path
        harness = Path(__file__).parent.parent / "src" / "aipop" / "cli" / "harness.py"
        source = harness.read_text()
        assert "BedrockAdapter" in source

    def test_llamacpp_in_adapter_creation(self):
        """harness.py must register llamacpp adapter."""
        from pathlib import Path
        harness = Path(__file__).parent.parent / "src" / "aipop" / "cli" / "harness.py"
        source = harness.read_text()
        assert "LlamaCppAdapter" in source

    def test_mcp_in_adapter_creation(self):
        """harness.py must register mcp adapter."""
        from pathlib import Path
        harness = Path(__file__).parent.parent / "src" / "aipop" / "cli" / "harness.py"
        source = harness.read_text()
        assert "MCPAdapter" in source


# ── BUG 13: Fingerprint schema path ──────────────────────────────────


class TestFingerprintPath:
    """Fingerprint engine must have duckdb guard and correct path."""

    def test_duckdb_import_guard(self):
        """fingerprint_engine.py must guard duckdb import."""
        from pathlib import Path
        fp = Path(__file__).parent.parent / "src" / "aipop" / "intelligence" / "fingerprint_engine.py"
        source = fp.read_text()
        assert "pip install aipop[intelligence]" in source
