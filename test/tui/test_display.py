"""Tests for terminal compatibility profile selection."""

from tui.display import has_limited_color, resolve_display_profile


def test_auto_mode_uses_standard_profile_for_utf8_terminal():
    profile = resolve_display_profile("auto", environ={"TERM": "xterm-256color"}, encoding="UTF-8")

    assert profile.mode == "standard"
    assert not profile.limited_color
    assert (profile.ready, profile.warning, profile.vertical_separator) == ("✓", "⚠", "│")


def test_auto_mode_uses_ascii_for_dumb_or_non_utf8_terminal():
    dumb = resolve_display_profile("auto", environ={"TERM": "dumb"}, encoding="UTF-8")
    non_utf8 = resolve_display_profile("auto", environ={"TERM": "xterm"}, encoding="ANSI_X3.4-1968")

    assert dumb.mode == non_utf8.mode == "ascii"
    assert dumb.limited_color and non_utf8.limited_color
    assert (dumb.ready, dumb.missing, dumb.warning) == ("OK", "--", "!!")
    assert (dumb.vertical_separator, dumb.horizontal_separator) == ("|", "-")


def test_explicit_mode_overrides_unicode_detection_but_honors_no_color():
    ascii_profile = resolve_display_profile("ascii", environ={}, encoding="UTF-8")
    standard_profile = resolve_display_profile("standard", environ={"TERM": "dumb", "NO_COLOR": "1"}, encoding="ASCII")

    assert ascii_profile.mode == "ascii"
    assert standard_profile.mode == "standard"
    assert standard_profile.limited_color


def test_resolved_standard_color_system_uses_high_contrast_fallback():
    assert has_limited_color(None)
    assert has_limited_color("standard")
    assert not has_limited_color("256")
    assert not has_limited_color("truecolor")
