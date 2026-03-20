"""Tests for the verbosity ladder."""

from aipop.core.verbosity import (
    Verbosity,
    get_verbosity,
    is_quiet,
    is_trace,
    is_verbose,
    set_verbosity,
)


class TestVerbosityLevels:
    def test_default_is_default(self):
        set_verbosity(Verbosity.DEFAULT)
        assert get_verbosity() == Verbosity.DEFAULT

    def test_quiet_level(self):
        set_verbosity(Verbosity.QUIET)
        assert is_quiet()
        assert not is_verbose()
        assert not is_trace()

    def test_default_level(self):
        set_verbosity(Verbosity.DEFAULT)
        assert not is_quiet()
        assert not is_verbose()
        assert not is_trace()

    def test_verbose_level(self):
        set_verbosity(Verbosity.VERBOSE)
        assert not is_quiet()
        assert is_verbose()
        assert not is_trace()

    def test_trace_level(self):
        set_verbosity(Verbosity.TRACE)
        assert not is_quiet()
        assert is_verbose()  # trace includes verbose
        assert is_trace()


class TestVerbosityFromString:
    def test_string_quiet(self):
        set_verbosity("quiet")
        assert get_verbosity() == Verbosity.QUIET

    def test_string_verbose(self):
        set_verbosity("verbose")
        assert get_verbosity() == Verbosity.VERBOSE

    def test_string_trace(self):
        set_verbosity("trace")
        assert get_verbosity() == Verbosity.TRACE

    def test_string_alias_q(self):
        set_verbosity("q")
        assert get_verbosity() == Verbosity.QUIET

    def test_string_alias_v(self):
        set_verbosity("v")
        assert get_verbosity() == Verbosity.VERBOSE

    def test_string_alias_vv(self):
        set_verbosity("vv")
        assert get_verbosity() == Verbosity.TRACE

    def test_string_alias_debug(self):
        set_verbosity("debug")
        assert get_verbosity() == Verbosity.TRACE

    def test_unknown_string_defaults(self):
        set_verbosity("nonsense")
        assert get_verbosity() == Verbosity.DEFAULT


class TestVerbosityFromInt:
    def test_int_0(self):
        set_verbosity(0)
        assert get_verbosity() == Verbosity.QUIET

    def test_int_1(self):
        set_verbosity(1)
        assert get_verbosity() == Verbosity.DEFAULT

    def test_int_2(self):
        set_verbosity(2)
        assert get_verbosity() == Verbosity.VERBOSE

    def test_int_3(self):
        set_verbosity(3)
        assert get_verbosity() == Verbosity.TRACE

    def test_int_clamped_high(self):
        set_verbosity(99)
        assert get_verbosity() == Verbosity.TRACE

    def test_int_clamped_low(self):
        set_verbosity(-5)
        assert get_verbosity() == Verbosity.QUIET


class TestVerbosityIntComparison:
    def test_ordering(self):
        assert Verbosity.QUIET < Verbosity.DEFAULT
        assert Verbosity.DEFAULT < Verbosity.VERBOSE
        assert Verbosity.VERBOSE < Verbosity.TRACE

    def test_verbose_includes_default(self):
        set_verbosity(Verbosity.VERBOSE)
        assert get_verbosity() >= Verbosity.DEFAULT

    def test_trace_includes_verbose(self):
        set_verbosity(Verbosity.TRACE)
        assert get_verbosity() >= Verbosity.VERBOSE
