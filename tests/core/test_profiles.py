"""Tests for configuration profiles."""

from aipop.core.profiles import BUILTIN_PROFILES, Profile, apply_profile, load_profile, list_profiles
from aipop.core.workspace import Workspace
import pytest


class TestBuiltinProfiles:
    def test_four_builtins_exist(self):
        assert len(BUILTIN_PROFILES) == 4
        assert "pentest" in BUILTIN_PROFILES
        assert "bounty" in BUILTIN_PROFILES
        assert "lab" in BUILTIN_PROFILES
        assert "ci" in BUILTIN_PROFILES

    def test_pentest_has_proxy(self):
        p = BUILTIN_PROFILES["pentest"]
        assert "PROXY" in p.options
        assert "8080" in str(p.options["PROXY"])

    def test_bounty_has_budget(self):
        p = BUILTIN_PROFILES["bounty"]
        assert "BUDGET" in p.options

    def test_lab_uses_static(self):
        p = BUILTIN_PROFILES["lab"]
        assert p.options.get("ADAPTER") == "static"


class TestLoadProfile:
    def test_load_builtin(self):
        p = load_profile("pentest")
        assert p.name == "pentest"
        assert len(p.options) > 0

    def test_load_unknown_raises(self):
        with pytest.raises(KeyError, match="not found"):
            load_profile("nonexistent_profile_xyz")


class TestApplyProfile:
    def test_apply_to_workspace(self):
        ws = Workspace()
        ws.use("adversarial/rag_injection")
        profile = load_profile("bounty")
        applied = apply_profile(profile, ws)
        assert len(applied) > 0
        assert ws.get("BUDGET") == 2.0


class TestListProfiles:
    def test_list_includes_builtins(self):
        profiles = list_profiles()
        names = {p.name for p in profiles}
        assert "pentest" in names
        assert "lab" in names
