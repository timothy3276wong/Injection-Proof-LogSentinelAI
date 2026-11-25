"""Tests for the prompt-injection defense in core/sanitize.py (see docs/defense-1-decisions.md)."""

import re

MARKER = re.compile(r"^<<<LOG_DATA_([0-9a-f]{16}) (BEGIN|END)>>>$")


def test_lines_are_wrapped_in_matching_random_markers(configured_project) -> None:
    from logsentinelai.core.sanitize import wrap_untrusted_logs

    out = wrap_untrusted_logs(["line one", "line two"]).split("\n")

    begin, end = MARKER.match(out[0]), MARKER.match(out[-1])
    assert begin and begin.group(2) == "BEGIN"
    assert end and end.group(2) == "END"
    assert begin.group(1) == end.group(1)          # same code at both ends
    assert out[1:-1] == ["line one", "line two"]   # log lines unchanged, in order


def test_each_prompt_gets_a_new_code(configured_project) -> None:
    from logsentinelai.core.sanitize import new_marker_code

    codes = {new_marker_code() for _ in range(100)}
    assert len(codes) == 100                       # no repeats
    assert all(re.fullmatch(r"[0-9a-f]{16}", c) for c in codes)


def test_lines_are_stripped_and_empty_lines_dropped(configured_project) -> None:
    from logsentinelai.core.sanitize import wrap_untrusted_logs

    out = wrap_untrusted_logs(["  a  ", "", "   ", "b\n"]).split("\n")
    assert out[1:-1] == ["a", "b"]                 # same cleaning as the original code


def test_wrapped_logs_fill_every_template_once(configured_project) -> None:
    from logsentinelai.core import prompts
    from logsentinelai.core.sanitize import wrap_untrusted_logs

    log_line = 'GET /x?q={payload} HTTP/1.1'      # curly braces, as an attacker might send
    for template in (prompts.get_httpd_access_prompt(), prompts.get_httpd_server_error_prompt(),
                     prompts.get_linux_system_prompt(), prompts.get_general_log_prompt()):
        prompt = template.format(logs=wrap_untrusted_logs([log_line]),
                                 model_schema="{}", response_language="english")
        assert prompt.count(" BEGIN>>>") == 1 and prompt.count(" END>>>") == 1
        assert log_line in prompt                  # braces in log text survive .format()
