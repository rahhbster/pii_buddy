"""Review follow-ups for pii_buddy.core: error location, strict parameter
types, hostile subclasses, and the Finding wire format."""

import dataclasses
import inspect
import json
import operator
import re

import pytest

from pii_buddy import core, detector

from .test_core import CANARY_TEXT, CANARY_WINDOWS
from .test_core_review3 import assert_where_real
from .test_core_review_fixes import _assert_chain_clean

WHERE_RE = re.compile(r"[A-Za-z0-9_.:]+")


class _BadEntity:
    """.label raises AttributeError naming 'canary_attr' from C code, so the
    innermost Python frame is redactor.py, not this file."""

    label = property(operator.attrgetter("canary_attr"))


@pytest.fixture
def broken_redact(monkeypatch):
    monkeypatch.setattr(detector, "get_nlp", lambda allow_download=True: None)
    monkeypatch.setattr(detector, "detect_pii", lambda t, d="auto": [_BadEntity()])


class TestErrorLocation:
    def test_where_names_innermost_frame(self, broken_redact):
        with pytest.raises(core.CoreError) as e:
            core.redact_text(CANARY_TEXT)
        err = e.value
        assert err.code == "internal_error"
        assert err.exc_type == "AttributeError"
        assert_where_real(err.where, "redact", "redactor.py")
        assert err.to_dict()["where"] == err.where

    def test_where_is_fixed_format_and_leaks_nothing(self, broken_redact):
        with pytest.raises(core.CoreError) as e:
            core.redact_text(CANARY_TEXT)
        err = e.value
        assert WHERE_RE.fullmatch(err.where)
        blob = json.dumps(err.to_dict()) + str(err) + repr(err) + err.where
        assert "canary_attr" not in blob
        for w in CANARY_WINDOWS:
            assert w not in blob
        assert err.__cause__ is None and err.__context__ is None
        _assert_chain_clean(err)

    def test_message_and_str_unchanged(self, broken_redact):
        with pytest.raises(core.CoreError) as e:
            core.redact_text(CANARY_TEXT)
        assert str(e.value) == "internal error"
        assert e.value.message == "internal error"

    def test_unsafe_where_is_omitted(self, monkeypatch):
        monkeypatch.setattr(detector, "get_nlp", lambda allow_download=True: None)

        def boom(t, d="auto"):
            raise RuntimeError("x")

        boom.__code__ = boom.__code__.replace(co_name="<weird>")
        monkeypatch.setattr(detector, "detect_pii", boom)
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello")
        assert e.value.code == "internal_error"
        assert e.value.where is None
        assert "where" not in e.value.to_dict()

    @pytest.mark.parametrize("bad", ["a b", "x<y>:f:1", "f.py:g:1\n", "f.py:g:1 (secret)"])
    def test_to_dict_omits_where_with_unsafe_characters(self, bad):
        err = core.CoreError("internal_error", "internal error", "X", bad)
        assert "where" not in err.to_dict()
        assert core.CoreError("internal_error", "m", "X", "a.py:f:3").to_dict()["where"] == "a.py:f:3"

    def test_validation_errors_have_no_where(self):
        with pytest.raises(core.CoreError) as e:
            core.check_text(5)
        assert e.value.where is None
        assert e.value.to_dict() == {"error": "invalid_text", "message": e.value.message}

    def test_model_unavailable_has_no_where(self, monkeypatch):
        def boom(allow_download=True):
            raise detector.ModelNotInstalledError("x")

        monkeypatch.setattr(detector, "get_nlp", boom)
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello")
        assert e.value.where is None


class TestBoolParametersAreStrict:
    @pytest.mark.parametrize("bad", [0, 1, "", "yes", None, [], [1], 1.0])
    def test_audit_must_be_exactly_bool(self, bad):
        with pytest.raises(core.CoreError) as e:
            core.redact_text("hello there", audit=bad)
        assert e.value.code == "invalid_request"

    def test_audit_with_raising_bool_is_core_error(self):
        class Boom:
            def __bool__(self):
                raise RuntimeError("canary")

        with pytest.raises(core.CoreError) as e:
            core.redact_text("hello there", audit=Boom())
        assert e.value.code == "invalid_request"

    @pytest.mark.parametrize("ok", [True, False])
    def test_real_bools_accepted(self, ok):
        core.redact_text("hello there", audit=ok)

    def test_audit_checked_before_detection(self, monkeypatch):
        def never(*a, **k):
            raise AssertionError("detector ran")

        monkeypatch.setattr(detector, "get_nlp", never)
        with pytest.raises(core.CoreError):
            core.redact_text("x", audit=0)

    def test_no_other_bool_like_parameters(self):
        for fn in (core.check_text, core.redact_text, core.restore_text):
            for name, p in inspect.signature(fn).parameters.items():
                if name != "audit" and p.default is not inspect.Parameter.empty:
                    assert not isinstance(p.default, (bool, int)), (fn.__name__, name)


class _RaisingLen(str):
    def __len__(self):
        raise RuntimeError("len")


class _LyingLen(str):
    def __len__(self):
        return 1


class _RaisingHash(str):
    def __hash__(self):
        raise RuntimeError("hash")


class _AlwaysEq(str):
    def __eq__(self, other):
        return True

    __hash__ = str.__hash__


class _RaisingDict(dict):
    def items(self):
        raise RuntimeError("items")

    def get(self, *a):
        raise RuntimeError("get")

    def __len__(self):
        raise RuntimeError("len")

    def __iter__(self):
        raise RuntimeError("iter")


class _EvilStrKey(str):
    def __eq__(self, other):
        raise RuntimeError("eq")

    __hash__ = str.__hash__


class TestHostileSubclassesRejected:
    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    @pytest.mark.parametrize("cls", [_RaisingLen, _LyingLen, _RaisingHash, _AlwaysEq])
    def test_text_subclass(self, fn, cls):
        with pytest.raises(core.CoreError) as e:
            fn(cls("hello"))
        assert e.value.code == "invalid_request"

    def test_lying_len_cannot_bypass_cap(self):
        with pytest.raises(core.CoreError) as e:
            core.check_text(_LyingLen("x" * 60000))
        assert e.value.code == "invalid_request"

    @pytest.mark.parametrize("cls", [_RaisingHash, _AlwaysEq, _RaisingLen])
    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    def test_document_type_subclass(self, fn, cls):
        with pytest.raises(core.CoreError) as e:
            fn("hello", document_type=cls("auto"))
        assert e.value.code == "invalid_request"

    def test_always_eq_not_accepted_as_document_type(self):
        with pytest.raises(core.CoreError):
            core.check_text("hello", document_type=_AlwaysEq("bogus"))

    @pytest.mark.parametrize("cls", [_RaisingLen, _LyingLen, _AlwaysEq])
    def test_restore_text_subclass_text(self, cls):
        with pytest.raises(core.CoreError) as e:
            core.restore_text(cls("hi <<EMAIL_1>>"), {"<<EMAIL_1>>": "a"})
        assert e.value.code == "invalid_request"

    def test_restore_dict_subclass(self):
        with pytest.raises(core.CoreError) as e:
            core.restore_text("hi", _RaisingDict({"<<EMAIL_1>>": "a"}))
        assert e.value.code == "invalid_request"

    def test_restore_ordered_dict_rejected(self):
        from collections import OrderedDict

        with pytest.raises(core.CoreError) as e:
            core.restore_text("hi", OrderedDict({"<<EMAIL_1>>": "a"}))
        assert e.value.code == "invalid_request"

    @pytest.mark.parametrize("cls", [_RaisingLen, _LyingLen, _EvilStrKey])
    def test_restore_mapping_str_subclass_entries(self, cls):
        with pytest.raises(core.CoreError) as e:
            core.restore_text("hi", {cls("<<EMAIL_1>>"): "a"})
        assert e.value.code == "invalid_request"
        with pytest.raises(core.CoreError) as e:
            core.restore_text("hi", {"<<EMAIL_1>>": cls("a")})
        assert e.value.code == "invalid_request"

    def test_unchecked_rejects_subclasses_too(self):
        with pytest.raises(core.CoreError):
            core._restore_unchecked(_RaisingLen("x"), {"a": "b"})
        with pytest.raises(core.CoreError):
            core._restore_unchecked("x", _RaisingDict({"a": "b"}))
        with pytest.raises(core.CoreError):
            core._restore_unchecked("x", {_RaisingLen("a"): "b"})

    def test_plain_types_still_work(self):
        assert core.restore_text("a <<EMAIL_1>>", {"<<EMAIL_1>>": "b"}) == "a b"
        core.check_text("hello", document_type="general")

    def test_json_load_results_work_with_restorer(self, tmp_path):
        from pii_buddy import restorer

        p = tmp_path / "m.json"
        p.write_text(json.dumps({"tags": {"<<EMAIL_1>>": "a@example.test"}}))
        assert restorer.restore("x <<EMAIL_1>>", p) == "x a@example.test"

    def test_exact_valid_call_that_still_raises_is_internal_error(self, monkeypatch):
        monkeypatch.setattr(detector, "get_nlp", lambda allow_download=True: None)

        def boom(t, d="auto"):
            raise RuntimeError("canary")

        monkeypatch.setattr(detector, "detect_pii", boom)
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello")
        assert e.value.code == "internal_error"


class TestWireFormat:
    def test_finding_fields_are_pinned(self):
        assert [f.name for f in dataclasses.fields(core.Finding)] == [
            "type", "start_offset", "end_offset", "confidence",
        ]
        d = core.Finding("EMAIL", 1, 2, 0.5).to_dict()
        assert set(d) == {"type", "start_offset", "end_offset", "confidence"}

    def test_result_dict_keys_pinned(self):
        assert set(core.CheckResult((), {}).to_dict()) == {"findings", "entity_counts"}
        assert set(core.RedactResult("", {}, (), {}, 0).to_dict()) == {
            "redacted_text", "mapping", "findings", "entity_counts", "audit_additions",
        }
