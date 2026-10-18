"""core: internal errors never carry input, document_type / surrogate validation
on every entry point, the restorer's longest-first ordering, and the functional
contract for realistic text (core itself has no latency bound)."""

import json

import pytest

from pii_buddy import audit as audit_mod
from pii_buddy import core, detector, restorer

from .test_core import CANARY, CANARY_TEXT
from .test_core_review_fixes import _assert_chain_clean, _chain


@pytest.fixture
def no_model(monkeypatch):
    monkeypatch.setattr(detector, "get_nlp", lambda allow_download=True: None)


ERRORS = [
    ("ValueError", lambda: ValueError(CANARY_TEXT)),
    ("UnicodeEncodeError",
     lambda: UnicodeEncodeError("utf-8", CANARY_TEXT + "\ud800", 0, 1, CANARY_TEXT)),
    ("MemoryError", lambda: MemoryError(CANARY_TEXT)),
    ("RecursionError", lambda: RecursionError(CANARY_TEXT)),
]
ERROR_IDS = [n for n, _ in ERRORS]


class TestInternalErrorWrapping:
    @pytest.fixture(params=["detect", "redact", "audit", "load"])
    def inject(self, request, monkeypatch, no_model):
        def arm(make):
            def boom(*a, **k):
                raise make()

            if request.param == "detect":
                monkeypatch.setattr(detector, "detect_pii", boom)
            elif request.param == "redact":
                monkeypatch.setattr(detector, "detect_pii", lambda t, d="auto": [])
                monkeypatch.setattr(core, "redact", boom)
            elif request.param == "audit":
                monkeypatch.setattr(detector, "detect_pii", lambda t, d="auto": [])
                monkeypatch.setattr(audit_mod, "audit_redacted", boom)
            else:
                monkeypatch.setattr(detector, "get_nlp", boom)

        arm.stage = request.param
        return arm

    @staticmethod
    def _fn(inject):
        return core.check_text if inject.stage in ("detect", "load") else core.redact_text

    @pytest.mark.parametrize("make", [m for _, m in ERRORS], ids=ERROR_IDS)
    def test_wrapped_with_a_fixed_message_and_a_clean_chain(self, inject, make):
        inject(make)
        with pytest.raises(core.CoreError) as e:
            self._fn(inject)(CANARY_TEXT)
        err = e.value
        assert err.code == "internal_error"
        assert err.message == "internal error"
        assert err.__cause__ is None and err.__context__ is None
        assert len(_chain(err)) == 1
        _assert_chain_clean(err)
        assert CANARY not in repr(err) + str(err) + repr(err.to_dict()) + repr(err.args)

    def test_exception_type_name_is_recorded_without_the_message(self, inject):
        inject(lambda: ValueError(CANARY_TEXT))
        with pytest.raises(core.CoreError) as e:
            self._fn(inject)(CANARY_TEXT)
        assert e.value.exc_type == "ValueError"

    @pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit])
    def test_base_exceptions_are_not_swallowed(self, monkeypatch, no_model, exc):
        def boom(*a, **k):
            raise exc()

        monkeypatch.setattr(detector, "detect_pii", boom)
        with pytest.raises(exc):
            core.check_text("hello")

    def test_core_errors_keep_their_own_code(self, monkeypatch, no_model):
        monkeypatch.setattr(detector, "detect_pii", lambda t, d="auto": [])
        monkeypatch.setattr(core, "redact", lambda t, e: (t, {"tags": {"<NAME <>": "x"}}))
        with pytest.raises(core.CoreError) as e:
            core.redact_text("hello", audit=False)
        assert e.value.code == "invalid_mapping"

    def test_model_unavailable_is_not_reported_as_internal(self, monkeypatch):
        def missing(allow_download=True):
            raise detector.ModelNotInstalledError("x")

        monkeypatch.setattr(detector, "get_nlp", missing)
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello")
        assert e.value.code == "model_unavailable"


class TestNoDownloadPath:
    def test_missing_model_never_downloads_through_core(self, monkeypatch):
        import spacy
        import spacy.cli

        def no_load(name, *a, **k):
            raise OSError("no model")

        monkeypatch.setattr(detector, "_nlp", None)
        monkeypatch.setattr(spacy, "load", no_load)
        monkeypatch.setattr(
            spacy.cli, "download", lambda *a, **k: pytest.fail("download attempted")
        )
        for fn in (core.check_text, core.redact_text):
            with pytest.raises(core.CoreError) as e:
                fn("hello world")
            assert e.value.code == "model_unavailable"

    def test_core_only_asks_for_the_model_without_download(self, monkeypatch):
        seen = []
        monkeypatch.setattr(
            detector, "get_nlp", lambda allow_download=True: seen.append(allow_download)
        )
        monkeypatch.setattr(detector, "detect_pii", lambda t, d="auto": [])
        core.check_text("hi")
        core.redact_text("hi")
        assert seen and set(seen) == {False}

    def test_token_cost_machinery_is_gone(self):
        for name in ("count_tokens", "tokenizer_cost"):
            assert not hasattr(detector, name)
        for name in ("MAX_TOKENS", "MAX_TOKENIZER_COST", "TOO_COMPLEX_MESSAGE"):
            assert not hasattr(core, name)


class TestDocumentTypeMustBeAString:
    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    @pytest.mark.parametrize("bad", [["auto"], None, 1, b"auto", {"a": 1}, ("auto",), {"auto"}])
    def test_non_str_is_invalid_request(self, fn, bad, no_model):
        with pytest.raises(core.CoreError) as e:
            fn("hello", document_type=bad)
        assert e.value.code == "invalid_request"
        assert e.value.__context__ is None

    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    def test_unknown_string_keeps_its_code(self, fn, no_model):
        with pytest.raises(core.CoreError) as e:
            fn("hello", document_type="spreadsheet")
        assert e.value.code == "invalid_document_type"


class TestRestoreRejectsLoneSurrogates:
    @pytest.mark.parametrize("bad", ["\ud800", "a\udfffb", "\ud83d"])
    def test_in_redacted_text(self, bad):
        with pytest.raises(core.CoreError) as e:
            core.restore_text("<<EMAIL_1>> " + CANARY + bad, {"<<EMAIL_1>>": "a@example.test"})
        assert e.value.code == "invalid_text"
        assert e.value.__context__ is None
        _assert_chain_clean(e.value)

    @pytest.mark.parametrize("bad", ["\ud800", "x\udc00y"])
    def test_in_mapping_value(self, bad):
        with pytest.raises(core.CoreError) as e:
            core.restore_text("<<EMAIL_1>>", {"<<EMAIL_1>>": CANARY + bad})
        assert e.value.code == "invalid_text"
        assert e.value.__context__ is None
        _assert_chain_clean(e.value)

    def test_in_mapping_key(self):
        with pytest.raises(core.CoreError) as e:
            core.restore_text("x", {"<NAME A\ud800>": CANARY})
        assert e.value.code == "invalid_text"
        _assert_chain_clean(e.value)

    def test_output_is_always_encodable(self):
        out = core.restore_text("<<EMAIL_1>> \U0001F600", {"<<EMAIL_1>>": "a@example.test"})
        out.encode("utf-8")

    def test_real_astral_characters_are_fine(self):
        assert core.restore_text("\U0001F600", {}) == "\U0001F600"


class TestRestoreUncheckedPrefersTheLongestKey:
    def test_prefix_overlapping_tags(self):
        mapping = {"<<A>>": "short", "<<A>>B": "long", "<<A>>BC": "longest"}
        assert core._restore_unchecked("<<A>>BC <<A>>B <<A>>", mapping) == "longest long short"

    def test_order_does_not_depend_on_dict_insertion(self):
        forward = {"<<A>>": "s", "<<A>>B": "l"}
        backward = {"<<A>>B": "l", "<<A>>": "s"}
        text = "<<A>>B and <<A>>"
        assert core._restore_unchecked(text, forward) == "l and s"
        assert core._restore_unchecked(text, backward) == "l and s"

    def test_through_the_restorer_file_api(self, tmp_path):
        path = tmp_path / "m.json"
        path.write_text(json.dumps({"tags": {"<<A>>": "short", "<<A>>B": "long"}}))
        assert restorer.restore("<<A>>B <<A>>", path) == "long short"


class TestFunctionalContract:
    def test_realistic_20000_character_text_redacts_correctly(self):
        block = (
            "Alex Sample wrote to alex.sample@example.test and called (555) 010-0142 "
            "about the quarterly review. "
        )
        text = (block * (20_000 // len(block) + 1))[:20_000]
        assert len(text) == 20_000
        result = core.redact_text(text, audit=False)
        assert "alex.sample@example.test" not in result.redacted_text
        assert "(555) 010-0142" not in result.redacted_text
        assert result.entity_counts["EMAIL"] >= 100
        assert result.entity_counts["PHONE"] >= 100
        assert core.restore_text(result.redacted_text, result.mapping) == text
