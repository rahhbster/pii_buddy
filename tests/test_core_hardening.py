"""Hardening tests for pii_buddy.core / restorer: input edge cases, the removed
public `trusted` bypass, the restorer's unchecked path, repr safety, and
mutation-killers for locks and copies."""

import dataclasses
import inspect
import json
import threading
import time
from pathlib import Path

import pytest

from pii_buddy import core, detector

from .test_core import CANARY, CANARY_EMAIL, CANARY_TEXT, FakeNlp, _assert_no_canary


class TestInputEdgeCases:
    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    def test_lone_surrogate_is_a_typed_error(self, fn):
        with pytest.raises(core.CoreError) as e:
            fn("x \ud800 y " + CANARY)
        assert e.value.code == "invalid_text"
        _assert_no_canary(str(e.value))

    def test_surrogate_pair_emoji_is_fine(self):
        assert core.check_text("x \U0001F600 y").findings == ()

    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    def test_nul_bytes_do_not_crash(self, fn):
        fn("abc\x00def ghi\x00 jane.roe@example.test")

    def test_single_50000_char_token_is_accepted(self):
        core.check_text("a" * 50_000)

    @pytest.mark.parametrize("text", ["\n" * 50_000, " " * 50_000])
    def test_whitespace_only_has_no_findings(self, text):
        assert core.check_text(text).findings == ()


# ------------------------------------------------- restore: no public bypass

def _tags(n):
    return {f"<<EMAIL_{i}>>": f"user{i}@example.test" for i in range(n)}


class TestRestoreBypassRemoved:
    def test_restore_text_has_no_trusted_parameter(self):
        params = inspect.signature(core.restore_text).parameters
        assert "trusted" not in params
        assert not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
        assert list(params) == ["redacted_text", "mapping"]

    def test_passing_trusted_is_a_type_error(self):
        with pytest.raises(TypeError):
            core.restore_text("abc", {"": "X"}, trusted=True)

    def test_empty_key_bypass_is_closed(self):
        with pytest.raises(core.CoreError) as e:
            core.restore_text("abc", {"": "X"})
        assert e.value.code == "invalid_mapping"

    def test_amplification_bypass_is_closed(self):
        value = "a" * core.MAX_VALUE_CHARS
        too_many = {f"<<T_{i}>>": value for i in range(core.MAX_MAPPING_ENTRIES + 1)}
        with pytest.raises(core.CoreError) as e:
            core.restore_text("<<T_1>>", too_many)
        assert e.value.code == "invalid_mapping"
        at_limit = {f"<<T_{i}>>": value for i in range(core.MAX_MAPPING_ENTRIES)}
        with pytest.raises(core.CoreError) as e:
            core.restore_text("<<T_1>>" * 30, at_limit)
        assert e.value.code == "payload_too_large"

    def test_only_restorer_references_the_unchecked_path(self):
        root = Path(core.__file__).parent
        users = sorted(
            p.name for p in root.rglob("*.py") if "_restore_unchecked" in p.read_text("utf-8")
        )
        assert users == ["core.py", "restorer.py"]

    def test_unchecked_ignores_empty_key(self):
        assert core._restore_unchecked("abc", {"": "X"}) == "abc"

    def test_unchecked_accepts_hand_edited_and_large_mappings(self):
        assert core._restore_unchecked("hi <<SJ>>", {"<<SJ>>": "Jane Fake"}) == "hi Jane Fake"
        big = _tags(12_000)
        assert core._restore_unchecked("<<EMAIL_11999>>", big) == "user11999@example.test"
        assert core._restore_unchecked("same", {}) == "same"

    def test_unchecked_longest_key_wins(self):
        out = core._restore_unchecked("<<A_1>><<A_10>>", {"<<A_1>>": "x", "<<A_10>>": "y"})
        assert out == "xy"

    @pytest.mark.parametrize("position", [0, 1, 2])
    @pytest.mark.parametrize("bad", [1, None, ["a"], b"b"])
    @pytest.mark.parametrize("path", ["public", "unchecked"])
    def test_type_check_covers_every_item(self, position, bad, path):
        items = [(f"<<EMAIL_{i}>>", "ok") for i in range(3)]
        items[position] = (items[position][0], bad)
        fn = core.restore_text if path == "public" else core._restore_unchecked
        with pytest.raises(core.CoreError) as e:
            fn("x", dict(items))
        assert e.value.code == "invalid_mapping"

    @pytest.mark.parametrize("position", [0, 2])
    @pytest.mark.parametrize("path", ["public", "unchecked"])
    def test_non_str_key_at_any_position(self, position, path):
        items = [(f"<<EMAIL_{i}>>", "ok") for i in range(3)]
        items[position] = (7, "ok")
        fn = core.restore_text if path == "public" else core._restore_unchecked
        with pytest.raises(core.CoreError):
            fn("x", dict(items))

    def test_unchecked_rejects_non_dict_and_non_str_text(self):
        with pytest.raises(core.CoreError):
            core._restore_unchecked("x", [("a", "b")])
        with pytest.raises(core.CoreError):
            core._restore_unchecked(None, {})


class TestRestorerFileApi:
    def _write(self, tmp_path, payload):
        path = tmp_path / "mapping.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_hand_edited_non_tag_key(self, tmp_path):
        from pii_buddy import restorer

        path = self._write(tmp_path, {"tags": {"<<SJ>>": "Jane Fake", "plain": "word"}})
        assert restorer.restore("Hi <<SJ>>, plain", path) == "Hi Jane Fake, word"

    def test_more_than_the_public_entry_limit(self, tmp_path):
        from pii_buddy import restorer

        tags = _tags(core.MAX_MAPPING_ENTRIES + 2_000)
        path = self._write(tmp_path, {"tags": tags})
        assert restorer.restore("<<EMAIL_11999>>", path) == "user11999@example.test"

    def test_text_longer_than_the_public_limit(self, tmp_path):
        from pii_buddy import restorer

        path = self._write(tmp_path, {"tags": {"<<SJ>>": "Jane Fake"}})
        reps = core.MAX_RESTORE_TEXT_CHARS // 4
        text = "<<SJ>> " * reps
        assert len(text) > core.MAX_RESTORE_TEXT_CHARS
        assert restorer.restore(text, path) == "Jane Fake " * reps

    @pytest.mark.parametrize("payload", [{"tags": {}}, {}, {"tags": None}])
    def test_empty_mapping_returns_text(self, tmp_path, payload):
        from pii_buddy import restorer

        assert restorer.restore("keep <<SJ>>", self._write(tmp_path, payload)) == "keep <<SJ>>"

    def test_empty_key_does_not_shred_the_text(self, tmp_path):
        from pii_buddy import restorer

        path = self._write(tmp_path, {"tags": {"": "X", "<<SJ>>": "Jane"}})
        assert restorer.restore("abc <<SJ>>", path) == "abc Jane"

    @pytest.mark.parametrize(
        "tags", [["a"], "x", {"<<SJ>>": 5}, {"<<A_1>>": "ok", "<<SJ>>": None}]
    )
    def test_malformed_mapping_raises_core_error_which_is_a_value_error(self, tmp_path, tags):
        from pii_buddy import restorer

        with pytest.raises(core.CoreError) as e:
            restorer.restore("x", self._write(tmp_path, {"tags": tags}))
        assert isinstance(e.value, ValueError)

    def test_restorer_uses_the_unchecked_path_and_never_the_public_one(self, tmp_path, monkeypatch):
        from pii_buddy import restorer

        calls = []
        real = core._restore_unchecked
        monkeypatch.setattr(core, "_restore_unchecked", lambda t, m: calls.append(1) or real(t, m))
        monkeypatch.setattr(
            core, "restore_text", lambda *a, **k: pytest.fail("restorer used the validating path")
        )
        path = self._write(tmp_path, {"tags": {"<<SJ>>": "Jane"}})
        assert restorer.restore("<<SJ>>", path) == "Jane"
        assert calls == [1]


# ------------------------------------------------------------ no input in repr

@pytest.fixture(scope="module")
def result():
    return core.redact_text(CANARY_TEXT)


class TestResultRepr:
    def test_fixture_really_holds_the_canary(self, result):
        assert CANARY_EMAIL in result.mapping.values()
        assert CANARY in result.redacted_text

    @pytest.mark.parametrize("render", [
        repr, str, format, lambda r: f"{r}", lambda r: f"{r!r}", lambda r: "%s" % (r,),
        lambda r: "%r" % (r,), lambda r: "{}".format(r),
    ])
    def test_redact_result_never_renders_input(self, result, render):
        _assert_no_canary(render(result))

    def test_check_result_and_findings_never_render_input(self):
        res = core.check_text(CANARY_TEXT)
        _assert_no_canary(repr(res))
        for f in res.findings:
            _assert_no_canary(repr(f))

    def test_input_bearing_fields_are_excluded_from_repr(self):
        fields = {f.name: f for f in dataclasses.fields(core.RedactResult)}
        assert fields["mapping"].repr is False
        assert fields["redacted_text"].repr is False

    def test_to_dict_still_carries_everything(self, result):
        d = result.to_dict()
        assert d["mapping"] == result.mapping and d["redacted_text"] == result.redacted_text
        assert set(d) == {
            "redacted_text", "mapping", "findings", "entity_counts", "audit_additions",
        }


# ------------------------------------------------- concurrency / copy mutants

class TestLocksAndCopies:
    @pytest.fixture(autouse=True)
    def fresh(self, monkeypatch):
        monkeypatch.setattr(detector, "_nlp", None)
        monkeypatch.setattr(detector, "_warmed", False, raising=False)

    def test_preflight_warms_up_while_holding_the_spacy_lock(self, monkeypatch):
        import spacy

        fake = FakeNlp()
        monkeypatch.setattr(spacy, "load", lambda name, *a, **k: fake)
        detector.preflight()
        assert fake.lock_held == [True]
        assert not detector._nlp_lock.locked()

    def test_preflight_waits_for_a_request_holding_the_lock(self, monkeypatch):
        fake = FakeNlp()
        monkeypatch.setattr(detector, "_nlp", fake)
        done = threading.Event()
        t = threading.Thread(target=lambda: (detector.preflight(), done.set()), daemon=True)
        with detector._nlp_lock:
            t.start()
            assert not done.wait(0.3)
            assert fake.events == []
        t.join(5)
        assert done.is_set() and fake.events == ["enter", "exit"]

    def test_model_load_is_serialised_by_the_load_lock(self, monkeypatch):
        import spacy

        loads = []

        def slow_load(name, *a, **k):
            loads.append(name)
            time.sleep(0.3)
            return object()

        monkeypatch.setattr(spacy, "load", slow_load)
        start = threading.Barrier(4)
        got = []

        def worker():
            start.wait()
            got.append(detector.get_nlp(allow_download=False))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert len(loads) == 1
        assert len(got) == 4 and len({id(g) for g in got}) == 1

    def test_redact_result_mapping_is_a_copy(self, monkeypatch):
        shared = {"<<EMAIL_1>>": "a@example.test"}
        monkeypatch.setattr(
            core, "redact", lambda text, ents: ("<<EMAIL_1>>", {"tags": shared, "x": 1})
        )
        monkeypatch.setattr(detector, "detect_pii", lambda text, doc_type="auto": [])
        monkeypatch.setattr(detector, "get_nlp", lambda allow_download=True: None)
        result = core.redact_text("a@example.test", audit=False)
        assert result.mapping == shared and result.mapping is not shared
        result.mapping["<<EMAIL_2>>"] = "b@example.test"
        result.mapping["<<EMAIL_1>>"] = "tampered"
        assert shared == {"<<EMAIL_1>>": "a@example.test"}
        again = core.redact_text("a@example.test", audit=False)
        assert again.mapping == {"<<EMAIL_1>>": "a@example.test"}

    def test_to_dict_mapping_is_a_copy(self):
        result = core.redact_text("Mail jane.roe@example.test now.", audit=False)
        d = result.to_dict()
        d["mapping"]["<<EMAIL_9>>"] = "x"
        assert "<<EMAIL_9>>" not in result.mapping
