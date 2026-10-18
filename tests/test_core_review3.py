"""Third review round for pii_buddy.core: Python-version-robust error
location, picklable errors, hostile __class__ / __getattribute__ / __traceback__,
and bounds on `where`."""

import concurrent.futures
import copy
import json
import multiprocessing
import operator
import pickle
import re
import types

import pytest

from pii_buddy import core, detector

from .test_core import CANARY_TEXT
from .test_core_review_fixes import _assert_chain_clean

WHERE_FORMAT = re.compile(r"[A-Za-z0-9_.]+\.py:[A-Za-z0-9_]+:[0-9]+")


def _raiser(co_name="boom", co_filename=None, message="x"):
    """A function whose code object carries a chosen name / filename."""

    def boom(*_a, **_k):
        raise RuntimeError(message)

    repl = {"co_name": co_name}
    if co_filename is not None:
        repl["co_filename"] = co_filename
    boom.__code__ = boom.__code__.replace(**repl)
    return boom


def _where_of(fn):
    try:
        fn()
    except Exception as exc:
        return core._capture_where(exc)


class _BadEntity:
    label = property(operator.attrgetter("canary_attr"))


@pytest.fixture
def stub_detect(monkeypatch):
    monkeypatch.setattr(detector, "get_nlp", lambda allow_download=True: None)

    def install(fn):
        monkeypatch.setattr(detector, "detect_pii", fn)

    return install


class TestWhereVersionNames:
    @pytest.mark.parametrize(
        "co_name, bare",
        [
            ("<listcomp>", "listcomp"),
            ("<genexpr>", "genexpr"),
            ("<lambda>", "lambda"),
            ("<dictcomp>", "dictcomp"),
            ("<setcomp>", "setcomp"),
            ("<module>", "module"),
        ],
    )
    def test_angle_bracket_names_map_to_bare_name(self, co_name, bare):
        where = _where_of(_raiser(co_name, "/x/redactor.py"))
        assert re.fullmatch(rf"redactor\.py:{bare}:[0-9]+", where), where

    @pytest.mark.parametrize("co_name", ["<weird>", "<listcomp", "listcomp>", "<>", "<<listcomp>>", "<LISTCOMP>"])
    def test_other_angle_names_are_dropped(self, co_name):
        assert _where_of(_raiser(co_name, "/x/redactor.py")) is None

    def test_plain_function_name_kept(self):
        where = _where_of(_raiser("redact", "/x/redactor.py"))
        assert re.fullmatch(r"redactor\.py:redact:[0-9]+", where)

    def test_injected_failure_is_version_robust(self, stub_detect):
        stub_detect(lambda t, d="auto": [_BadEntity()])
        with pytest.raises(core.CoreError) as e:
            core.redact_text(CANARY_TEXT)
        err = e.value
        assert err.exc_type == "AttributeError"
        assert WHERE_FORMAT.fullmatch(err.where), err.where
        assert err.where.startswith("redactor.py:")
        assert err.to_dict()["where"] == err.where
        assert "canary_attr" not in json.dumps(err.to_dict())
        _assert_chain_clean(err)

    def test_comprehension_frame_surfaces_through_guarded(self, stub_detect):
        def detect(t, d="auto"):
            return [x.label for x in [_BadEntity()]]

        detect.__code__ = detect.__code__.replace(co_filename="/p/detector.py")
        stub_detect(detect)
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello")
        # innermost frame is the C-level property getter's caller: the
        # comprehension on 3.10-3.11, the function itself on 3.12+.
        assert WHERE_FORMAT.fullmatch(e.value.where), e.value.where
        assert re.fullmatch(r"detector\.py:(listcomp|detect):[0-9]+", e.value.where)


class TestWhereBuilder:
    def test_windows_path_is_reduced_to_basename(self):
        where = _where_of(_raiser("f", "C:\\Users\\someone\\proj\\redactor.py"))
        assert re.fullmatch(r"redactor\.py:f:[0-9]+", where), where

    def test_mixed_separators(self):
        where = _where_of(_raiser("f", "C:\\a/b\\c/redactor.py"))
        assert re.fullmatch(r"redactor\.py:f:[0-9]+", where), where

    def test_line_number_is_the_real_one(self):
        def boom():
            raise RuntimeError("x")  # marker

        line = boom.__code__.co_firstlineno + 1
        where = _where_of(boom)
        assert where.endswith(f":boom:{line}"), (where, line)
        assert int(where.rsplit(":", 1)[1]) > 0

    def test_huge_alphanumeric_function_name_dropped(self):
        assert _where_of(_raiser("a" * 100_000, "/x/redactor.py")) is None

    def test_huge_filename_dropped(self):
        assert _where_of(_raiser("f", "/x/" + "a" * 100_000 + ".py")) is None

    def test_synthetic_alphanumeric_name_accepted(self):
        where = _where_of(_raiser("Fn9", "/x/mod_1.py"))
        assert re.fullmatch(r"mod_1\.py:Fn9:[0-9]+", where)

    @pytest.mark.parametrize("fname", ["/x/redactor", "/x/redactor.pyc", "/x/redactor.txt", "/x/.py", "/x/", ""])
    def test_file_part_must_be_a_py_file(self, fname):
        assert _where_of(_raiser("f", fname)) is None

    def test_length_cap_boundary(self):
        base = "m.py:f:"
        # lineno is whatever the raise line is; measure it, then pad the name.
        probe = _where_of(_raiser("f", "/x/m.py"))
        lineno = probe.rsplit(":", 1)[1]
        fixed = len("m.py::") + len(lineno)
        ok = _where_of(_raiser("n" * (160 - fixed), "/x/m.py"))
        assert ok is not None and len(ok) == 160
        assert _where_of(_raiser("n" * (161 - fixed), "/x/m.py")) is None
        assert base  # keep the shape documented

    def test_unicode_digits_and_letters_rejected(self):
        assert _where_of(_raiser("f\u00e9", "/x/m.py")) is None
        assert not core._where_ok("m.py:f:\u0661\u0662")
        assert not core._where_ok("m\u00e9.py:f:1")

    def test_to_dict_applies_the_same_bounds(self):
        long = "m.py:" + "n" * 200 + ":1"
        assert "where" not in core.CoreError("internal_error", "m", "X", long).to_dict()
        assert "where" not in core.CoreError("internal_error", "m", "X", "a/b.py:f:1").to_dict()
        assert "where" not in core.CoreError("internal_error", "m", "X", "a\\b.py:f:1").to_dict()
        assert "where" not in core.CoreError("internal_error", "m", "X", "ab:f:1").to_dict()
        assert core.CoreError("internal_error", "m", "X", "ab.py:f:1").to_dict()["where"] == "ab.py:f:1"

    @pytest.mark.parametrize("bad", [123, b"a.py:f:1", ["a.py:f:1"], object(), True])
    def test_to_dict_tolerates_non_str_where(self, bad):
        d = core.CoreError("internal_error", "m", "X", bad).to_dict()
        assert "where" not in d
        assert d == {"error": "internal_error", "message": "m"}

    def test_to_dict_tolerates_hostile_str_subclass_where(self):
        class S(str):
            def __len__(self):
                raise RuntimeError("boom")

        d = core.CoreError("internal_error", "m", "X", S("a.py:f:1")).to_dict()
        assert "where" not in d


class TestHostileTraceback:
    def test_traceback_property_that_raises(self, stub_detect):
        class Evil(Exception):
            @property
            def __traceback__(self):
                raise RuntimeError("canary traceback")

        def detect(t, d="auto"):
            raise Evil()

        stub_detect(detect)
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello")
        assert e.value.code == "internal_error"
        assert e.value.exc_type == "Evil"
        assert e.value.where is None
        assert "where" not in e.value.to_dict()
        assert e.value.__cause__ is None and e.value.__context__ is None

    def test_traceback_returning_non_traceback(self, stub_detect):
        class Evil(Exception):
            @property
            def __traceback__(self):
                return object()

        def detect(t, d="auto"):
            raise Evil()

        stub_detect(detect)
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello")
        assert e.value.where is None

    def test_capture_where_never_raises(self):
        class Evil(Exception):
            @property
            def __traceback__(self):
                raise RuntimeError("x")

        assert core._capture_where(Evil()) is None
        assert core._capture_where(None) is None
        assert core._capture_where(object()) is None

    def test_hostile_exception_class_name(self, stub_detect):
        class Meta(type):
            @property
            def __name__(cls):
                raise RuntimeError("canary name")

        class Evil(Exception, metaclass=Meta):
            pass

        def detect(t, d="auto"):
            raise Evil()

        stub_detect(detect)
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello")
        assert e.value.code == "internal_error"
        assert e.value.exc_type is None


class _PropClass:
    @property
    def __class__(self):
        raise RuntimeError("canary __class__")


class _GetAttr:
    def __getattribute__(self, name):
        raise RuntimeError("canary __getattribute__")


class _SpoofStr:
    __class__ = str


class _SpoofDict:
    __class__ = dict


class _SpoofBool:
    __class__ = bool


HOSTILE = [_PropClass, _GetAttr]
OK_CODES = {"invalid_text", "invalid_request", "invalid_mapping", "invalid_document_type"}


def _expect_core_error(fn, *args, **kwargs):
    with pytest.raises(core.CoreError) as e:
        fn(*args, **kwargs)
    assert e.value.code in OK_CODES, e.value.code
    assert e.value.__cause__ is None and e.value.__context__ is None
    assert "canary" not in json.dumps(e.value.to_dict()) + repr(e.value)
    return e.value


class TestHostileObjects:
    @pytest.mark.parametrize("cls", HOSTILE)
    def test_check_text_text(self, cls):
        _expect_core_error(core.check_text, cls())

    @pytest.mark.parametrize("cls", HOSTILE)
    def test_check_text_document_type(self, cls):
        _expect_core_error(core.check_text, "hello", document_type=cls())

    @pytest.mark.parametrize("cls", HOSTILE)
    def test_redact_text_text(self, cls):
        _expect_core_error(core.redact_text, cls())

    @pytest.mark.parametrize("cls", HOSTILE)
    def test_redact_text_document_type(self, cls):
        _expect_core_error(core.redact_text, "hello", document_type=cls())

    @pytest.mark.parametrize("cls", HOSTILE)
    def test_redact_text_audit(self, cls):
        _expect_core_error(core.redact_text, "hello", audit=cls())

    @pytest.mark.parametrize("cls", HOSTILE)
    def test_restore_text_text(self, cls):
        _expect_core_error(core.restore_text, cls(), {})

    @pytest.mark.parametrize("cls", HOSTILE)
    def test_restore_text_mapping(self, cls):
        _expect_core_error(core.restore_text, "hello", cls())

    @pytest.mark.parametrize("cls", HOSTILE)
    def test_restore_text_mapping_value(self, cls):
        _expect_core_error(core.restore_text, "hello", {"<<EMAIL_1>>": cls()})

    @pytest.mark.parametrize("cls", HOSTILE)
    def test_restore_text_mapping_key(self, cls):
        _expect_core_error(core.restore_text, "hello", {cls(): "v"})

    @pytest.mark.parametrize("cls", HOSTILE)
    def test_restore_unchecked_text(self, cls):
        _expect_core_error(core._restore_unchecked, cls(), {})

    @pytest.mark.parametrize("cls", HOSTILE)
    def test_restore_unchecked_mapping(self, cls):
        _expect_core_error(core._restore_unchecked, "hello", cls())

    @pytest.mark.parametrize("cls", HOSTILE)
    def test_restore_unchecked_value_and_key(self, cls):
        _expect_core_error(core._restore_unchecked, "hello", {"<<EMAIL_1>>": cls()})
        _expect_core_error(core._restore_unchecked, "hello", {cls(): "v"})

    def test_spoofed_class_is_not_the_real_type(self):
        _expect_core_error(core.check_text, _SpoofStr())
        _expect_core_error(core.check_text, "hello", document_type=_SpoofStr())
        _expect_core_error(core.restore_text, _SpoofStr(), {})
        _expect_core_error(core.restore_text, "hello", _SpoofDict())
        _expect_core_error(core.restore_text, "hello", {"<<EMAIL_1>>": _SpoofStr()})
        _expect_core_error(core._restore_unchecked, "hello", _SpoofDict())

    @pytest.mark.parametrize("spoof", [_SpoofBool(), 1, 0, "", None])
    def test_audit_requires_exact_bool_even_when_class_is_spoofed(self, spoof):
        err = _expect_core_error(core.redact_text, "hello", audit=spoof)
        assert err.code == "invalid_request"

    def test_require_helpers_wrap_residual_exceptions(self, monkeypatch):
        def explode(*_a, **_k):
            raise RuntimeError("canary residual")

        monkeypatch.setattr(core, "issubclass", explode, raising=False)
        with pytest.raises(core.CoreError) as e:
            core._require_str(5, "text")
        assert e.value.code == "invalid_request"
        assert e.value.__cause__ is None and e.value.__context__ is None
        with pytest.raises(core.CoreError) as e:
            core._check_mapping_types(5)
        assert e.value.code == "invalid_request"

    def test_annotation_says_dict(self):
        import inspect

        ann = inspect.signature(core.restore_text).parameters["mapping"].annotation
        assert str(ann).replace(" ", "") in {"dict[str,str]", "Dict[str,str]"}, ann


class _SubError(core.CoreError):
    pass


def _fields(err):
    return (type(err), err.code, err.message, err.exc_type, err.where, str(err), err.args)


def _sample_errors():
    return [
        core.CoreError("internal_error", "internal error", "AttributeError", "redactor.py:redact:87"),
        core.CoreError("invalid_text", "text must be a string"),
        core.CoreError("model_unavailable", "no spaCy model is installed"),
    ]


class TestCoreErrorPickles:
    @pytest.mark.parametrize("proto", range(pickle.HIGHEST_PROTOCOL + 1))
    def test_roundtrip_all_protocols(self, proto):
        for err in _sample_errors():
            back = pickle.loads(pickle.dumps(err, protocol=proto))
            assert _fields(back) == _fields(err)
            assert back.to_dict() == err.to_dict()

    def test_copy_and_deepcopy(self):
        for err in _sample_errors():
            assert _fields(copy.copy(err)) == _fields(err)
            assert _fields(copy.deepcopy(err)) == _fields(err)

    def test_pickle_carries_no_chain_or_input(self, stub_detect):
        stub_detect(lambda t, d="auto": [_BadEntity()])
        with pytest.raises(core.CoreError) as e:
            core.redact_text(CANARY_TEXT)
        blob = pickle.dumps(e.value)
        assert b"canary_attr" not in blob
        assert CANARY_TEXT.encode() not in blob
        assert b"Zq7f3a9c" not in blob
        back = pickle.loads(blob)
        assert back.__cause__ is None and back.__context__ is None
        assert _fields(back) == _fields(e.value)

    def test_subclass_survives(self):
        back = pickle.loads(pickle.dumps(_SubError("internal_error", "m", "X", "a.py:f:1")))
        assert type(back) is _SubError and back.where == "a.py:f:1"

    def test_still_a_value_error(self):
        back = pickle.loads(pickle.dumps(_sample_errors()[0]))
        assert isinstance(back, ValueError)

    def test_model_not_installed_error_pickles(self):
        err = detector.ModelNotInstalledError("need a model")
        back = pickle.loads(pickle.dumps(err))
        assert type(back) is detector.ModelNotInstalledError and back.args == err.args
        assert type(copy.deepcopy(err)) is detector.ModelNotInstalledError


def _worker_raise():
    raise core.CoreError("internal_error", "internal error", "AttributeError", "redactor.py:redact:87")


def _worker_core_validation():
    core.check_text(5)


class TestCoreErrorCrossesProcessBoundary:
    def _run(self, fn):
        ctx = multiprocessing.get_context("spawn")
        with concurrent.futures.ProcessPoolExecutor(max_workers=1, mp_context=ctx) as pool:
            return pool.submit(fn).exception(timeout=60)

    def test_worker_error_reaches_parent_with_same_fields(self):
        exc = self._run(_worker_raise)
        assert type(exc) is core.CoreError
        assert (exc.code, exc.message, exc.exc_type, exc.where) == (
            "internal_error", "internal error", "AttributeError", "redactor.py:redact:87",
        )

    def test_worker_validation_error(self):
        exc = self._run(_worker_core_validation)
        assert type(exc) is core.CoreError
        assert exc.code == "invalid_text" and exc.where is None
