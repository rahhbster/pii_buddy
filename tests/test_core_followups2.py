"""Second follow-up round for pii_buddy.core / restorer: exc_type bounds,
no retention of the wrapped exception or its input, the restore-output
boundary, and restorer errors for malformed mapping files."""

import gc
import json
import operator
import pickle
import weakref

import pytest

from pii_buddy import core, detector, restorer

from .test_core import CANARY_TEXT


@pytest.fixture
def stub_detect(monkeypatch):
    monkeypatch.setattr(detector, "get_nlp", lambda allow_download=True: None)

    def install(fn):
        monkeypatch.setattr(detector, "detect_pii", fn)

    return install


def _exc_class_named(value):
    class Meta(type):
        @property
        def __name__(cls):
            return value

    class Evil(Exception, metaclass=Meta):
        pass

    return Evil


class _StrSub(str):
    pass


class TestExcTypeIsBounded:
    @pytest.mark.parametrize(
        "name",
        [
            "",
            "x\ny",
            "Evil\n",
            "Fooé",
            "A٣",
            "A" * 100_000,
            "A" * 65,
            "a/b/c.py",
            "/etc/passwd",
            "has space",
            "1abc",
            "a-b",
            123,
            None,
            b"Evil",
            _StrSub("Evil"),
        ],
        ids=lambda v: repr(v)[:30],
    )
    def test_hostile_name_becomes_fixed_string(self, stub_detect, name):
        evil = _exc_class_named(name)

        def detect(t, d="auto"):
            raise evil()

        stub_detect(detect)
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello")
        assert type(e.value.exc_type) is str
        assert e.value.exc_type == "Exception"

    @pytest.mark.parametrize("name", ["Evil", "_x1", "A", "A" * 64])
    def test_valid_name_is_kept(self, stub_detect, name):
        evil = _exc_class_named(name)

        def detect(t, d="auto"):
            raise evil()

        stub_detect(detect)
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello")
        assert e.value.exc_type == name

    def test_pickle_roundtrip_keeps_exc_type(self, stub_detect):
        stub_detect(lambda t, d="auto": 1 / 0)
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello")
        again = pickle.loads(pickle.dumps(e.value))
        assert again.exc_type == "ZeroDivisionError"


def _frame_locals(err):
    """Locals of the library's frames only; the caller's own frames hold its data."""
    tb = err.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code.co_filename.endswith("pii_buddy/core.py"):
            yield from tb.tb_frame.f_locals.values()
        tb = tb.tb_next


def _flatten(value):
    yield value
    if type(value) in (tuple, list, set, frozenset):
        yield from value
    elif type(value) is dict:
        yield from value.keys()
        yield from value.values()


class _Ent:
    label = property(operator.attrgetter("canary_attr"))


def _unique_text():
    return "".join(["Reach ", "me ", CANARY_TEXT])


class TestNoRetention:
    def test_wrapped_exception_is_not_kept_alive(self, stub_detect):
        class Lingering(Exception):
            pass

        def detect(t, d="auto"):
            raise Lingering(t)

        stub_detect(detect)
        try:
            core.check_text(_unique_text())
        except core.CoreError as e:
            err = e
        del err
        gc.collect()
        assert [o for o in gc.get_objects() if type(o) is Lingering] == []

    def test_traceback_frames_do_not_hold_the_input(self, stub_detect):
        ent = _Ent()
        ref = weakref.ref(ent)
        stub_detect(lambda t, d="auto": [ent])
        text = _unique_text()
        try:
            core.redact_text(text)
        except core.CoreError as e:
            err = e
        assert err.code == "internal_error"
        assert err.__traceback__ is not None
        for local in _frame_locals(err):
            for item in _flatten(local):
                assert item is not text
                assert item is not ent
        del ent
        stub_detect(lambda t, d="auto": [])
        del err
        gc.collect()
        assert ref() is None

    @pytest.mark.parametrize(
        "call",
        [
            lambda t: core.check_text(t + "\ud800"),
            lambda t: core.redact_text(t, document_type="nope"),
            lambda t: core.restore_text(t, {"bad key": "v"}),
        ],
        ids=["surrogate", "doc_type", "mapping"],
    )
    def test_validation_errors_do_not_hold_the_input(self, call):
        text = _unique_text()
        try:
            call(text)
        except core.CoreError as e:
            err = e
        for local in _frame_locals(err):
            for item in _flatten(local):
                assert item is not text

    def test_error_still_raises_with_fixed_fields(self, stub_detect):
        stub_detect(lambda t, d="auto": [_Ent()])
        with pytest.raises(core.CoreError) as e:
            core.redact_text(_unique_text())
        assert (e.value.code, e.value.message) == ("internal_error", "internal error")
        assert e.value.exc_type == "AttributeError"
        assert e.value.where is not None
        assert e.value.__cause__ is None and e.value.__context__ is None


class TestRestoreOutputBoundary:
    TAG = "<<EMAIL_1>>"

    def test_exactly_the_limit_is_allowed(self):
        mapping = {self.TAG: "a" * core.MAX_VALUE_CHARS}
        n = core.MAX_RESTORE_OUTPUT_CHARS // core.MAX_VALUE_CHARS
        out = core.restore_text(self.TAG * n, mapping)
        assert len(out) == core.MAX_RESTORE_OUTPUT_CHARS

    def test_one_over_the_limit_before_a_tag_is_refused(self):
        mapping = {self.TAG: "a" * core.MAX_VALUE_CHARS}
        n = core.MAX_RESTORE_OUTPUT_CHARS // core.MAX_VALUE_CHARS
        with pytest.raises(core.CoreError) as e:
            core.restore_text("x" + self.TAG * n, mapping)
        assert e.value.code == "payload_too_large"

    def test_exactly_the_limit_with_a_plain_tail(self):
        mapping = {self.TAG: "a" * core.MAX_VALUE_CHARS}
        n = core.MAX_RESTORE_OUTPUT_CHARS // core.MAX_VALUE_CHARS - 1
        tail = "t" * core.MAX_VALUE_CHARS
        out = core.restore_text(self.TAG * n + tail, mapping)
        assert len(out) == core.MAX_RESTORE_OUTPUT_CHARS

    def test_plain_tail_one_over_the_limit_is_refused(self):
        mapping = {self.TAG: "a" * core.MAX_VALUE_CHARS}
        n = core.MAX_RESTORE_OUTPUT_CHARS // core.MAX_VALUE_CHARS
        with pytest.raises(core.CoreError) as e:
            core.restore_text(self.TAG * n + "t", mapping)
        assert e.value.code == "payload_too_large"

    def test_head_text_exactly_at_the_limit(self):
        mapping = {self.TAG: "a" * core.MAX_VALUE_CHARS}
        n = core.MAX_RESTORE_OUTPUT_CHARS // core.MAX_VALUE_CHARS - 1
        head = "h" * core.MAX_VALUE_CHARS
        out = core.restore_text(head + self.TAG * n, mapping)
        assert len(out) == core.MAX_RESTORE_OUTPUT_CHARS
        with pytest.raises(core.CoreError):
            core.restore_text("h" + head + self.TAG * n, mapping)


class TestRestorerMalformedMapping:
    def _write(self, tmp_path, raw):
        p = tmp_path / "m.json"
        p.write_text(raw, encoding="utf-8")
        return p

    @pytest.mark.parametrize("raw", ["[]", '"x"', "null", "1", "true", "[1, 2]"])
    def test_non_object_json_is_invalid_mapping(self, tmp_path, raw):
        with pytest.raises(core.CoreError) as e:
            restorer.restore("hi", self._write(tmp_path, raw))
        assert e.value.code == "invalid_mapping"
        assert isinstance(e.value, ValueError)

    @pytest.mark.parametrize("raw", ["", "{", "not json", "{'a': 1}", '{"tags": '])
    def test_invalid_json_is_invalid_json(self, tmp_path, raw):
        with pytest.raises(core.CoreError) as e:
            restorer.restore("hi", self._write(tmp_path, raw))
        assert e.value.code == "invalid_json"
        assert isinstance(e.value, ValueError)
        assert e.value.__cause__ is None and e.value.__context__ is None

    def test_deeply_nested_json_is_invalid_json(self, tmp_path):
        raw = "[" * 100_000
        with pytest.raises(core.CoreError) as e:
            restorer.restore("hi", self._write(tmp_path, raw))
        assert e.value.code == "invalid_json"

    def test_invalid_utf8_is_invalid_json(self, tmp_path):
        p = tmp_path / "m.json"
        p.write_bytes(b"\xff\xfe{")
        with pytest.raises(core.CoreError) as e:
            restorer.restore("hi", p)
        assert e.value.code == "invalid_json"

    def test_error_text_carries_no_file_content(self, tmp_path):
        raw = '{"tags": {"<<EMAIL_1>>": "%s"' % CANARY_TEXT
        with pytest.raises(core.CoreError) as e:
            restorer.restore("hi", self._write(tmp_path, raw))
        assert CANARY_TEXT not in json.dumps(e.value.to_dict()) + repr(e.value)

    def test_missing_file_still_raises_oserror(self, tmp_path):
        with pytest.raises(OSError):
            restorer.restore("hi", tmp_path / "nope.json")

    def test_valid_and_lenient_shapes_unchanged(self, tmp_path):
        assert restorer.restore("hi", self._write(tmp_path, "{}")) == "hi"
        assert restorer.restore("hi", self._write(tmp_path, '{"tags": null}')) == "hi"
        assert restorer.restore("hi", self._write(tmp_path, '{"tags": {}}')) == "hi"
