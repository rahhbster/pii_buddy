"""Hardening tests for pii_buddy.core / restorer: latency guards, the removed
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


def _synthetic_prose(n):
    words = ("the quick brown fox jumps over a lazy dog while several tired engineers "
             "review quarterly numbers and argue about nothing important today").split()
    out, i, size = [], 0, 0
    while size < n:
        sent = " ".join(words[(i + j) % len(words)] for j in range(11)).capitalize() + ". "
        out.append(sent)
        size += len(sent)
        i += 3
    return "".join(out)[:n]


def _synthetic_resume(n):
    block = (
        "Alex Sample\n12 Example Street, Testville\nalex.sample@example.test | (555) 010-0142\n"
        "EXPERIENCE\nSenior Engineer, Widget Corp, Jan 2010 - Mar 2020\n"
        + "- Led a team of five engineers shipping the billing platform.\n" * 8
        + "EDUCATION\nB.S. Computer Science, Example University, 2003\n\n"
    )
    return (block * (n // len(block) + 1))[:n]


def _synthetic_csv(n):
    out, size, i = ["id,first,last,email,phone,date,amount\n"], 0, 0
    while size < n:
        i += 1
        row = (f"{i},Alex,Sample,alex{i}@example.test,555-010-{i % 9000 + 1000},"
               f"2024-01-{i % 28 + 1:02d},{i}.50\n")
        out.append(row)
        size += len(row)
    return "".join(out)[:n]


# ------------------------------------------------------- latency guards

class TestTokenGuard:
    @pytest.fixture
    def stub(self, monkeypatch):
        self.detected = []
        monkeypatch.setattr(
            detector, "detect_pii",
            lambda text, doc_type="auto": self.detected.append(len(text)) or [],
        )

    def test_constants(self):
        assert isinstance(core.MAX_TOKENS, int) and 1_000 <= core.MAX_TOKENS <= 50_000
        assert isinstance(core.MAX_TOKENIZER_COST, int) and core.MAX_TOKENIZER_COST > 0

    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    def test_exactly_max_tokens_is_accepted(self, fn, stub, monkeypatch):
        monkeypatch.setattr(detector, "count_tokens", lambda text: core.MAX_TOKENS)
        fn("hello")
        assert self.detected == [5]

    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    def test_one_over_max_tokens_is_rejected_before_ner(self, fn, stub, monkeypatch):
        monkeypatch.setattr(detector, "count_tokens", lambda text: core.MAX_TOKENS + 1)
        with pytest.raises(core.CoreError) as e:
            fn(CANARY_TEXT)
        assert e.value.code == "payload_too_large"
        assert e.value.message == core.TOO_COMPLEX_MESSAGE
        _assert_no_canary(str(e.value))
        _assert_no_canary(repr(e.value))
        assert self.detected == []

    def test_token_count_is_taken_on_the_submitted_text(self, stub, monkeypatch):
        seen = []
        monkeypatch.setattr(detector, "count_tokens", lambda text: seen.append(text) or 1)
        core.check_text("some text")
        assert seen == ["some text"]

    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    def test_tokenizer_cost_over_budget_is_rejected_without_tokenizing(self, fn, stub, monkeypatch):
        monkeypatch.setattr(
            detector, "count_tokens", lambda text: pytest.fail("tokenizer ran on a hostile chunk")
        )
        text = "$" * 3_000
        assert detector.tokenizer_cost(text) > core.MAX_TOKENIZER_COST
        with pytest.raises(core.CoreError) as e:
            fn(text)
        assert e.value.code == "payload_too_large"
        assert self.detected == []

    def test_tokenizer_cost_boundary(self, stub, monkeypatch):
        monkeypatch.setattr(detector, "count_tokens", lambda text: 1)
        text = "$" * 100
        cost = detector.tokenizer_cost(text)
        monkeypatch.setattr(core, "MAX_TOKENIZER_COST", cost)
        core.check_text(text)
        monkeypatch.setattr(core, "MAX_TOKENIZER_COST", cost - 1)
        with pytest.raises(core.CoreError) as e:
            core.check_text(text)
        assert e.value.code == "payload_too_large"

    def test_character_cap_still_runs_first(self, stub, monkeypatch):
        monkeypatch.setattr(
            detector, "tokenizer_cost", lambda text: pytest.fail("cost computed past the cap")
        )
        with pytest.raises(core.CoreError) as e:
            core.check_text("a" * 50_001)
        assert e.value.message == "text exceeds 50000 characters"

    @pytest.mark.parametrize("make,n", [
        (_synthetic_prose, 50_000), (_synthetic_resume, 40_000), (_synthetic_csv, 50_000),
    ], ids=["prose", "resume", "csv"])
    def test_realistic_long_inputs_are_not_rejected(self, make, n, stub):
        text = make(n)
        assert len(text) == n
        core.check_text(text)
        assert self.detected == [n]

    @pytest.mark.parametrize("make", [
        lambda: "\U0001F600" * 16_000,
        lambda: "!" * 50_000,
        lambda: "a " * 25_000,
        lambda: ". " * 25_000,
        lambda: "1 " * 25_000,
        lambda: "! " * 20_000,
        lambda: "a  " * 16_000,
        lambda: "\n," * 25_000,
    ], ids=["emoji", "bangs", "a_sp", "dot_sp", "one_sp", "bang_sp", "a_2sp", "nl_comma"])
    def test_hostile_shapes_fail_fast_with_the_real_tokenizer(self, make, stub):
        text = make()
        start = time.perf_counter()
        with pytest.raises(core.CoreError) as e:
            core.check_text(text)
        assert time.perf_counter() - start < 3.0
        assert e.value.code == "payload_too_large"
        assert self.detected == []

    def test_count_tokens_matches_the_tokenizer_and_runs_under_the_lock(self, monkeypatch):
        fake = FakeNlp()
        monkeypatch.setattr(detector, "_nlp", fake)
        assert detector.count_tokens("Hello, world!") == 4
        assert fake.lock_held == [True]
        assert not detector._nlp_lock.locked()

    def test_count_tokens_releases_the_lock_on_error(self, monkeypatch):
        class Boom(FakeNlp):
            def make_doc(self, text):
                raise RuntimeError("boom")

        monkeypatch.setattr(detector, "_nlp", Boom())
        with pytest.raises(RuntimeError):
            detector.count_tokens("x")
        assert not detector._nlp_lock.locked()

    @pytest.mark.parametrize("text,cost", [
        ("", 0),
        ("hello world", 55),
        ("a,b", 15),
        ("a" * 50_000, 250_000),
        ("$" * 10, 150),
        ("$$ $$", 33),
        ("  a \n\t b  ", 50),
        ("x y", 15),
        ("a:b", 15),
        ("A$A$x", 35),
    ])
    def test_tokenizer_cost_values(self, text, cost):
        assert detector.tokenizer_cost(text) == cost

    def test_cost_bounds_real_tokenizer_time(self):
        nlp = detector.get_nlp(allow_download=False)
        shapes = [
            "$" * 1_500, "\U0001F600" * 1_200, "(" * 1_800, "=" * 1_000 + " " + "!?" * 600,
            "a" + "{" * 1_400 + "a", "(a." * 600,
        ]
        for i, text in enumerate(shapes):
            text = f"{i}{text}"
            cost = detector.tokenizer_cost(text)
            start = time.perf_counter()
            nlp.make_doc(text)
            elapsed = time.perf_counter() - start
            assert elapsed <= cost / 1e6 + 0.05, (i, cost, elapsed)


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

    def test_single_50000_char_token_is_bounded(self):
        start = time.perf_counter()
        core.check_text("a" * 50_000)
        assert time.perf_counter() - start < 5.0

    @pytest.mark.parametrize("text", ["\n" * 50_000, " " * 50_000])
    def test_whitespace_only_is_bounded(self, text):
        start = time.perf_counter()
        assert core.check_text(text).findings == ()
        assert time.perf_counter() - start < 5.0


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
        monkeypatch.setattr(detector, "count_tokens", lambda text: 1)
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
