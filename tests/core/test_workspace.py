"""Tests for the options paradigm workspace."""

from __future__ import annotations

import pytest

from aipop.core.workspace import Workspace


class TestWorkspaceUse:
    def test_use_loads_template(self):
        ws = Workspace()
        info = ws.use("adversarial/rag_injection")
        assert ws.is_loaded
        assert info.case_count > 0
        assert info.path == "adversarial/rag_injection"

    def test_use_extracts_metadata(self):
        ws = Workspace()
        info = ws.use("adversarial/rag_injection")
        assert info.seam == "concatenation"
        assert "instructions" in info.axiom.lower()

    def test_use_resets_previous_options(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        ws.set("TARGET", "http://first.com")
        ws.use("adversarial/tool_misuse")
        assert ws.get("TARGET") is None  # reset

    def test_use_bad_template_raises(self):
        ws = Workspace()
        with pytest.raises(Exception):
            ws.use("nonexistent/fake_template_xyz")

    def test_use_loads_test_cases(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        assert len(ws.test_cases) > 0


class TestWorkspaceSet:
    def test_set_valid_option(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        ws.set("TARGET", "http://localhost:8080")
        assert ws.get("TARGET") == "http://localhost:8080"

    def test_set_unknown_option_raises(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        with pytest.raises(KeyError):
            ws.set("BOGUS_OPTION", "value")

    def test_set_case_insensitive(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        ws.set("target", "http://localhost")
        assert ws.get("TARGET") == "http://localhost"

    def test_set_bool_coercion(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        ws.set("DRY_RUN", "true")
        assert ws.get("DRY_RUN") is True
        ws.set("DRY_RUN", "false")
        assert ws.get("DRY_RUN") is False

    def test_set_int_coercion(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        ws.set("SEED", "123")
        assert ws.get("SEED") == 123
        assert isinstance(ws.get("SEED"), int)

    def test_set_tracks_source(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        ws.set("TARGET", "http://test.com", source="user")
        options = ws.get_options()
        target_opt = next(o for o in options if o.name == "TARGET")
        assert target_opt.source == "user"


class TestWorkspaceGet:
    def test_get_default_values(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        assert ws.get("ADAPTER") == "static"
        assert ws.get("SEED") == 42

    def test_get_unset_returns_none(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        assert ws.get("TARGET") is None

    def test_get_nonexistent_returns_none(self):
        ws = Workspace()
        assert ws.get("DOES_NOT_EXIST") is None


class TestWorkspaceValidation:
    def test_validate_no_template(self):
        ws = Workspace()
        errors = ws.validate()
        assert any("No template" in e for e in errors)

    def test_validate_required_fields(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        errors = ws.validate()
        # ADAPTER is required and has default, so no error
        assert not any("ADAPTER" in e for e in errors)

    def test_validate_passes_with_defaults(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        errors = ws.validate()
        # Should pass — ADAPTER has a default
        assert len(errors) == 0


class TestWorkspaceOptions:
    def test_get_options_core_only(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        core = ws.get_options(include_advanced=False)
        names = {o.name for o in core}
        assert "TARGET" in names
        assert "ADAPTER" in names
        assert "DRY_RUN" not in names  # advanced

    def test_get_options_with_advanced(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        all_opts = ws.get_options(include_advanced=True)
        names = {o.name for o in all_opts}
        assert "DRY_RUN" in names
        assert "PROXY" in names
        assert "TARGET" in names
