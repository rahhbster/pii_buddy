"""The tokenizer-cost proxy against the real spaCy tokenizer.

Review finding: the old proxy charged every non-alphanumeric character of a
whitespace-free chunk, so long CJK paragraphs, link-heavy text and base64 blobs
were rejected although the real tokenizer takes ~0.02 s on them. The model now
charges only what the tokenizer is actually quadratic in (see the comment above
`detector.tokenizer_cost`); these tests pin both directions: realistic input is
accepted, and every shape that is slow in the real tokenizer is rejected or
finishes quickly.
"""

import re
import time

import pytest

from pii_buddy import core, detector

from . import _latency_docs
from .test_core import CANARY_TEXT, _assert_no_canary

REAL_DOCS = _latency_docs.realistic()
FAST_S = 1.5


@pytest.fixture
def stub(monkeypatch):
    detected = []
    monkeypatch.setattr(
        detector, "detect_pii",
        lambda text, doc_type="auto": detected.append(len(text)) or [],
    )
    return detected


def _rejected_or_fast(text):
    start = time.perf_counter()
    try:
        core.check_text(text)
        outcome = "accepted"
    except core.CoreError as e:
        assert e.code == "payload_too_large"
        assert e.message == core.TOO_COMPLEX_MESSAGE
        outcome = "rejected"
    elapsed = time.perf_counter() - start
    assert elapsed < FAST_S, f"{outcome} after {elapsed:.2f}s"
    return outcome


class TestRealisticDocumentsAreAccepted:
    def test_there_are_at_least_forty(self):
        assert len(REAL_DOCS) >= 40

    @pytest.mark.parametrize("name", sorted(REAL_DOCS))
    def test_accepted(self, name, stub):
        text = REAL_DOCS[name]
        assert len(text) <= core.MAX_TEXT_CHARS
        core.check_text(text)
        assert stub == [len(text)]

    @pytest.mark.parametrize("name", [
        "zh_para_30000", "ja_para_30000", "linkheavy_30000_300", "linkheavy_50000_330",
        "b64_11000", "b64_50000", "json_min_50000", "urllist_30000",
    ])
    def test_the_reviewed_false_rejections_are_cheap_now(self, name):
        assert detector.tokenizer_cost(REAL_DOCS[name]) < core.MAX_TOKENIZER_COST // 4


# Every one of these takes seconds-to-minutes in the real tokenizer if it gets there.
SLOW_IN_THE_TOKENIZER = {
    "emoji_run": lambda: "\U0001F600" * 25_000,
    "bangs": lambda: "!" * 50_000,
    "dollars": lambda: "$" * 50_000,
    "parens_pairs": lambda: "((" * 25_000,
    "a_dollar_pairs": lambda: "A$" * 25_000,
    "us_dollar_pairs": lambda: "US$" * 16_000,
    "apostrophe_s": lambda: "a" + "'s" * 20_000,
    "curly_apostrophe_s": lambda: "a" + "\u2019s" * 20_000,
    "fullwidth_trail": lambda: "z" + "\uff01" * 49_000,
    "fullwidth_lead": lambda: "\uff08" * 49_000 + "z",
    "digits_then_commas": lambda: "1" * 20_000 + "," * 20_000,
    "colons_1": lambda: "1:" * 25_000,
    "colons_a": lambda: "a:" * 25_000,
    "colons_at": lambda: "@:" * 25_000,
    "colons_digit_body": lambda: "a" + ":a" * 4_000 + "@" * 20_000,
    "quote_run": lambda: '"' * 50_000,
    "mixed_edges": lambda: "(" * 20_000 + "1" * 5_000 + "." * 20_000,
}


class TestSlowShapesAreRejected:
    @pytest.mark.parametrize("name", sorted(SLOW_IN_THE_TOKENIZER))
    def test_rejected_before_the_tokenizer_runs(self, name, stub, monkeypatch):
        text = SLOW_IN_THE_TOKENIZER[name]()
        assert len(text) <= core.MAX_TEXT_CHARS
        monkeypatch.setattr(
            detector, "count_tokens", lambda t: pytest.fail("tokenizer ran on a slow shape")
        )
        start = time.perf_counter()
        with pytest.raises(core.CoreError) as e:
            core.check_text(text)
        assert time.perf_counter() - start < 1.0
        assert e.value.code == "payload_too_large"
        assert e.value.message == core.TOO_COMPLEX_MESSAGE
        assert stub == []

    @pytest.mark.parametrize("make", [
        lambda: "a " * 25_000, lambda: ". " * 25_000, lambda: "! " * 20_000,
        lambda: "\U0001F600 " * 20_000, lambda: "\n," * 25_000, lambda: "a  " * 16_000,
        lambda: "\U0001F600\u200d" * 20_000, lambda: "\U0001F600a" * 20_000,
    ], ids=["a_sp", "dot_sp", "bang_sp", "emoji_sp", "nl_comma", "a_2sp", "zwj_emoji", "emoji_a"])
    def test_token_dense_text_is_rejected_by_the_token_cap(self, make, stub):
        with pytest.raises(core.CoreError) as e:
            core.check_text(make())
        assert e.value.message == core.TOO_COMPLEX_MESSAGE
        assert stub == []

    def test_message_echoes_no_counts_or_input(self, stub):
        for text in ("$" * 40_000, "a " * 20_000):
            with pytest.raises(core.CoreError) as e:
                core.check_text(CANARY_TEXT + " " + text)
            assert not re.search(r"\d", e.value.message)
            _assert_no_canary(repr(e.value))


def _family_grid():
    units = ["(", "$", "!", "'", "\u2014", "\u2026", "\U0001F600", "\u3002", "A$", "US$", "C$", "'s",
             "\u2019s", ":", "1:", "a:", "a:@", "\U0001F600\u200d", "1m", "1km", "5%", "a.", "A.", ".a",
             "1,", "a,", "a-", "a/", "\u0301", "\u200d", "\uff0c", "\u4f60\u3002", "=", "%", "_"]
    bodies = {"": "", "digits": "1" * 4_000, "alpha": "a" * 4_000, "cjk": "\u4f60" * 4_000}
    grid = {}
    for u in units:
        k = 50_000 // len(u) - 4_100 // len(u)
        for bn, b in bodies.items():
            grid[f"lead[{u!r}]+{bn}"] = (u * k + b + "z")[:50_000]
            grid[f"trail[{u!r}]+{bn}"] = ("z" + b + u * k)[:50_000]
        grid[f"only[{u!r}]"] = (u * (50_000 // len(u)))[:50_000]
        grid[f"a-in-a[{u!r}]"] = ("a" + u) * (25_000 // (len(u) + 1)) + "z"
    return grid


FAMILY_GRID = _family_grid()


class TestEveryFamilyIsRejectedOrFast:
    def test_the_grid_is_big_enough(self):
        assert len(FAMILY_GRID) >= 200

    @pytest.mark.parametrize("name", sorted(FAMILY_GRID))
    def test_rejected_or_under_the_deadline(self, name, stub):
        _rejected_or_fast(FAMILY_GRID[name])


class TestCostModel:
    @pytest.mark.parametrize("text,strips", [
        ("hello", 0), ("hello.", 1), ("(hello)", 2), ("((hello))", 4), ("A$A$A$x", 3), ("US$5", 1),
        ("C$C$", 2), ("a's", 1), ("a'sss", 0), ("a\u2019s\u2019S", 2), ("\u4f60\u597d\uff0c\u4e16\u754c\u3002", 1),
        ("a:b@c", 0), ("1m1m1m", 0), ("$$$$", 4), ("", 0),
    ])
    def test_affix_strips(self, text, strips):
        assert detector._affix_strips(text) == strips

    def test_middle_punctuation_is_free(self):
        zh = "\u4f60\u597d\uff0c" * 10_000
        url = "https://example.test/a-b_c/d.e?f=g&h=i#j" * 700
        b64 = "AbC+/0123456789" * 3_000
        for text in (zh, url, b64):
            assert detector.tokenizer_cost(text) < 20 * len(text)

    def test_cost_grows_quadratically_only_for_edge_chains(self):
        small = detector.tokenizer_cost("(" * 1_000)
        large = detector.tokenizer_cost("(" * 2_000)
        assert 3.5 < large / small < 4.5
        small = detector.tokenizer_cost("\u4f60\uff0c" * 1_000)
        large = detector.tokenizer_cost("\u4f60\uff0c" * 2_000)
        assert 1.8 < large / small < 2.2

    def test_colons_are_charged_by_length(self):
        small = detector.tokenizer_cost("a:" * 5_000)
        large = detector.tokenizer_cost("a:" * 10_000)
        assert large / small > 3

    def test_whitespace_still_costs_something(self):
        assert detector.tokenizer_cost(" " * 50_000) > 0
        assert detector.tokenizer_cost("") == 0

    def test_splits_like_the_tokenizer_on_unicode_whitespace(self):
        text = "(((" + "\u3000" + "))" + "\u2003" + "x"
        assert detector.tokenizer_cost(text) == detector.tokenizer_cost("((( )) x")

    def test_letter_bearing_literals_match_the_installed_spacy(self):
        nlp = detector.get_nlp(allow_download=False)
        letters = re.compile(r"[A-Za-z]")
        stripped = lambda p: re.sub(r"\[[^\]]*\]|\\.|\(\?[^)]*\)", "", p)
        prefixes = {p.replace("\\", "") for p in nlp.Defaults.prefixes
                    if not p.startswith("(?") and letters.search(stripped(p))}
        suffixes = {p for p in nlp.Defaults.suffixes
                    if not p.startswith("(?") and letters.search(stripped(p))}
        assert prefixes == set(detector._PREFIX_LITERALS)
        assert suffixes == set(detector._SUFFIX_LITERALS)

    def test_every_codepoint_that_splits_at_a_chunk_edge_is_an_affix_char(self):
        tokenizer = detector.get_nlp(allow_download=False).tokenizer
        missed = []
        for cp in range(0x21, 0x20000):
            if 0xD800 <= cp <= 0xDFFF:
                continue
            c = chr(cp)
            if c.isspace() or detector._is_affix_char(c):
                continue
            if len(tokenizer("a" + c * 6)) > 1 or len(tokenizer(c * 6 + "a")) > 1 or len(tokenizer(c * 6)) > 1:
                missed.append(hex(cp))
        assert missed == []


CALIBRATION = {
    "parens": "(" * 1_500, "dollars": "$" * 1_500, "emoji": "\U0001F600" * 1_200, "fw_trail": "z" + "\uff01" * 1_500,
    "a_dollar": "A$" * 1_200, "us_dollar": "US$" * 800, "apos_s": "a" + "'s" * 1_200, "mixed": "(" * 700 + "1" * 1_500 + "." * 700,
    "digit_body": "(" * 700 + "1" * 1_500 + "z", "colons": "a:" * 4_000, "colons_at": "@:" * 3_000, "colons_digits": "1:" * 4_000,
    "json_nospace": _latency_docs.json_nospace(20_000), "prose": _latency_docs.prose(50_000),
    "zh": _latency_docs.cjk(30_000, "zh"), "b64": _latency_docs.b64(50_000),
}


class TestProxyUpperBoundsTheRealTokenizer:
    @pytest.mark.parametrize("name", sorted(CALIBRATION))
    def test_estimate_covers_measured_time(self, name):
        nlp = detector.get_nlp(allow_download=False)
        text = CALIBRATION[name]
        estimate_s = detector.tokenizer_cost(text) / 1e6
        start = time.perf_counter()
        nlp.make_doc(text)
        elapsed = time.perf_counter() - start
        assert elapsed <= estimate_s + 0.05, (estimate_s, elapsed)
