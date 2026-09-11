"""Unit tests for the XSS reflection analyser and echo stripping."""

from scanner.modules.base import strip_echo
from scanner.modules.xss import PROBE_SUFFIX, analyse_reflection


class TestAnalyseReflection:
    def test_full_survival(self):
        canary = "wvsdeadbeef"
        text = f"Results for {canary}{PROBE_SUFFIX} (10 items)"
        result = analyse_reflection(text, canary, PROBE_SUFFIX)
        assert set(result["survived"]) == set(PROBE_SUFFIX)

    def test_html_encoded_marks_safe(self):
        canary = "wvsdeadbeef"
        encoded = PROBE_SUFFIX.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        encoded = encoded.replace('"', "&quot;").replace("'", "&#x27;")
        text = f"Results for {canary}{encoded}"
        result = analyse_reflection(text, canary, PROBE_SUFFIX)
        assert "<" not in result["survived"]
        assert ">" not in result["survived"]
        assert '"' not in result["survived"]
        assert "'" not in result["survived"]

    def test_angle_brackets_only(self):
        canary = "wvsdeadbeef"
        # filter strips quotes but keeps <> — classic partial filter
        filtered = "".join(ch for ch in PROBE_SUFFIX if ch not in "'\"")
        text = f"<p>{canary}{filtered}</p>"
        result = analyse_reflection(text, canary, PROBE_SUFFIX)
        assert "<" in result["survived"] and ">" in result["survived"]

    def test_no_reflection(self):
        result = analyse_reflection("nothing here", "wvsdeadbeef", PROBE_SUFFIX)
        assert result["survived"] == ""

    def test_best_occurrence_wins(self):
        canary = "wvsdeadbeef"
        truncated = canary + "'"          # first occurrence cut short
        full = canary + PROBE_SUFFIX      # second occurrence complete
        text = f"a {truncated} ... b {full} c"
        result = analyse_reflection(text, canary, PROBE_SUFFIX)
        assert "<" in result["survived"]


class TestStripEcho:
    def test_removes_raw_echo(self):
        payload = "; echo wvsabc123:"
        assert "wvsabc123" not in strip_echo("input was ; echo wvsabc123: ok", payload)

    def test_removes_html_escaped_echo(self):
        payload = "`echo wvsabc123`"
        escaped = "`echo wvsabc123`".replace("`", "&#96;")
        text = f"value: {escaped}"
        # raw form also present in this construction; both must go
        cleaned = strip_echo(text, payload)
        assert "wvsabc123" not in cleaned.replace("&#96;", "`")

    def test_keeps_real_output(self):
        payload = "; echo wvsabc123:"
        text = "PING output\nwvsabc123:\n"
        assert "wvsabc123" in strip_echo(text, payload)
