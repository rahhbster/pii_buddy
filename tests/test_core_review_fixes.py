"""Review-round fixes for pii_buddy.core: error chains must not carry the input,
and absolute-limit / bounded-regex tests that kill the constant and TAG_RE mutants
(the existing tests only compared against the constants themselves)."""

import pytest

from pii_buddy import core, detector

from .test_core import CANARY_TEXT, CANARY_WINDOWS


def _chain(exc):
    seen, stack = [], [exc]
    ids = set()
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in ids:
            continue
        ids.add(id(cur))
        seen.append(cur)
        stack.append(cur.__cause__)
        stack.append(cur.__context__)
    return seen


def _strings_in(obj, depth=0):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, (bytes, bytearray)):
        yield obj.decode("utf-8", "replace")
    elif isinstance(obj, (tuple, list, set, frozenset)) and depth < 4:
        for item in obj:
            yield from _strings_in(item, depth + 1)
    elif isinstance(obj, dict) and depth < 4:
        for k, v in obj.items():
            yield from _strings_in(k, depth + 1)
            yield from _strings_in(v, depth + 1)


def _assert_chain_clean(exc):
    for link in _chain(exc):
        carried = [link.args, getattr(link, "object", None), repr(link), str(link),
                   getattr(link, "__dict__", {})]
        for blob in carried:
            for s in _strings_in(blob):
                for w in CANARY_WINDOWS:
                    assert w not in s, f"{type(link).__name__} chain carries input: {w!r}"


class TestErrorChainsDoNotCarryInput:
    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    def test_lone_surrogate_error_has_no_cause_or_context(self, fn):
        with pytest.raises(core.CoreError) as e:
            fn("x \ud800 y " + CANARY_TEXT)
        assert e.value.code == "invalid_text"
        assert e.value.__cause__ is None
        assert e.value.__context__ is None
        _assert_chain_clean(e.value)

    @pytest.mark.parametrize("bad", ["\ud800", "\udfff", "a\udc00b", "\ud83d", "\ud83dx\ude00"])
    def test_every_lone_surrogate_shape_is_rejected_cleanly(self, bad):
        with pytest.raises(core.CoreError) as e:
            core.check_text(CANARY_TEXT + bad)
        assert e.value.code == "invalid_text"
        assert e.value.__context__ is None
        _assert_chain_clean(e.value)

    def test_chain_walker_would_see_an_unicode_error_context(self):
        try:
            ("x" + CANARY_TEXT + "\ud800").encode("utf-8")
        except UnicodeEncodeError as inner:
            try:
                raise core.CoreError("invalid_text", "x") from None
            except core.CoreError as outer:
                assert outer.__suppress_context__ is True
                assert outer.__context__ is inner
                with pytest.raises(AssertionError):
                    _assert_chain_clean(outer)

    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    def test_model_unavailable_error_has_no_cause_or_context(self, fn, monkeypatch):
        def boom(allow_download=True):
            raise detector.ModelNotInstalledError(CANARY_TEXT)

        monkeypatch.setattr(detector, "get_nlp", boom)
        with pytest.raises(core.CoreError) as e:
            fn(CANARY_TEXT)
        assert e.value.code == "model_unavailable"
        assert e.value.__cause__ is None
        assert e.value.__context__ is None
        _assert_chain_clean(e.value)

    def test_no_raise_inside_an_except_block_in_core_sources(self):
        import ast
        import inspect

        from pii_buddy import restorer

        for module in (core, detector, restorer):
            tree = ast.parse(inspect.getsource(module))
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler):
                    raises = [n for n in ast.walk(node) if isinstance(n, ast.Raise)]
                    assert not raises, f"{module.__name__}:{node.lineno} raises inside except"


class TestAbsoluteLimits:
    """Literal numbers on purpose: a limit raised 100x must fail here."""

    def test_constant_values(self):
        assert core.MAX_TEXT_CHARS == 50_000
        assert core.MAX_RESTORE_TEXT_CHARS == 200_000
        assert core.MAX_MAPPING_ENTRIES == 10_000
        assert core.MAX_VALUE_CHARS == 50_000
        assert core.MAX_TAG_CHARS == 128

    def test_mapping_entry_limit_is_ten_thousand(self):
        ok = {f"<<T_{i}>>": "v" for i in range(10_000)}
        assert core.restore_text("none", ok) == "none"
        over = {f"<<T_{i}>>": "v" for i in range(10_001)}
        with pytest.raises(core.CoreError) as e:
            core.restore_text("none", over)
        assert e.value.code == "invalid_mapping"

    def test_restore_text_limit_is_two_hundred_thousand(self):
        mapping = {"<<T_1>>": "v"}
        assert core.restore_text("a" * 200_000, mapping) == "a" * 200_000
        with pytest.raises(core.CoreError) as e:
            core.restore_text("a" * 200_001, mapping)
        assert e.value.code == "payload_too_large"

    def test_value_limit_is_fifty_thousand(self):
        assert core.restore_text("<<T_1>>", {"<<T_1>>": "v" * 50_000}) == "v" * 50_000
        with pytest.raises(core.CoreError) as e:
            core.restore_text("<<T_1>>", {"<<T_1>>": "v" * 50_001})
        assert e.value.code == "invalid_mapping"


class TestTagRegexIsBounded:
    @pytest.mark.parametrize("key", [
        "<<" + "A" * 101 + "_1>>",
        "<<A_" + "1" * 10 + ">>",
        "<NAME " + "x" * 101 + ">",
        "<<A_1>>x",
    ])
    def test_over_long_or_malformed_keys_are_not_tags(self, key):
        assert len(key) <= core.MAX_TAG_CHARS
        with pytest.raises(core.CoreError) as e:
            core.restore_text("anything", {key: "v"})
        assert e.value.code == "invalid_mapping"

    @pytest.mark.parametrize("key", [
        "<<" + "A" * 100 + "_1>>", "<<A_123456789>>", "<NAME " + "x" * 100 + ">",
    ])
    def test_limits_are_inclusive(self, key):
        assert core.TAG_RE.fullmatch(key)
