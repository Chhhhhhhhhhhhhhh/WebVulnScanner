"""Unit tests for the calibration-based page equivalence used by the
boolean SQLi differential."""

from scanner.modules.sqli import pages_equivalent

B1 = "<html>sid=aaa111bbb222ccc <p>Item 5</p> ts=1693571234</html>"
B2 = "<html>sid=fff999eee888ddd <p>Item 5</p> ts=1693571300</html>"
CALIBRATION = (B1, B2)


class TestPagesEquivalent:
    def test_identical_pages(self):
        assert pages_equivalent(B1, B1)

    def test_calibration_masks_token_drift(self):
        drifted = "<html>sid=zzz777yyy666xxx <p>Item 5</p> ts=1693571500</html>"
        assert pages_equivalent(drifted, B1, CALIBRATION)

    def test_row_count_change_is_not_masked(self):
        true_page = "<html>sid=zzz777yyy666xxx <p>Item 5</p> ts=1693571500</html>"
        false_page = "<html>sid=zzz777yyy666xxx <p>0 results</p> ts=1693571500</html>"
        assert not pages_equivalent(false_page, true_page, CALIBRATION)

    def test_misaligned_pages_fall_back_to_ratio(self):
        # token counts differ → no positional comparison; single-token
        # drift in a realistically sized page must still count as "same"
        def page(nonce):
            words = " ".join(f"word{i}" for i in range(120))
            return f"<html><body><p>{words}</p><span>{nonce}</span></body></html>"

        assert pages_equivalent(page("nonce=abc"), page("nonce=xyz"))

    def test_fallback_ratio_detects_real_change(self):
        long_a = "<html>" + " ".join(f"w{i}" for i in range(40)) + " tail</html>"
        long_b = "<html>" + " ".join(f"w{i}" for i in range(30)) + " tail</html>"
        assert not pages_equivalent(long_a, long_b)

    def test_without_calibration_different_pages(self):
        assert not pages_equivalent("<p>a</p>", "<p>b</p>")
