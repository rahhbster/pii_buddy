"""pii_buddy.core: pure in-memory check / redact / restore, plus the detector
hooks it relies on (get_nlp(allow_download=...), preflight, the spaCy lock)."""

import builtins
import inspect
import io
import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path

import pytest

from pii_buddy import config as cfg
from pii_buddy import core, detector

CANARY = "Zq7f3a9cXk"
CANARY_EMAIL = f"{CANARY.lower()}@example.test"
CANARY_TEXT = f"Please write to {CANARY_EMAIL} about case {CANARY}."
FINDING_KEYS = {"type", "start_offset", "end_offset", "confidence"}


def _windows(s, n=6):
    return {s[i:i + n] for i in range(len(s) - n + 1)}


CANARY_WINDOWS = _windows(CANARY) | _windows(CANARY_EMAIL)


def _snapshot(*roots):
    snap = {}
    for root in roots:
        root = Path(root)
        snap[str(root)] = None
        if not root.exists():
            continue
        snap[str(root)] = "dir"
        for dirpath, dirnames, filenames in os.walk(root):
            for name in dirnames + filenames:
                p = Path(dirpath) / name
                st = p.lstat()
                snap[str(p)] = (st.st_size, st.st_mtime_ns, st.st_mode)
    return snap


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    scratch = tmp_path / "scratch"
    cwd = tmp_path / "cwd"
    scratch.mkdir()
    cwd.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    monkeypatch.chdir(cwd)
    return [cfg.BASE_DIR, scratch, cwd]


def _assert_no_canary(text):
    for w in CANARY_WINDOWS:
        assert w not in text, f"input substring leaked: {w!r}"


# ---------------------------------------------------------------- check_text

class TestCheckText:
    TEXT = "Reach me at jane.roe@example.test today."

    def test_email_found_with_correct_offsets(self):
        result = core.check_text(self.TEXT)
        emails = [f for f in result.findings if f.type == "EMAIL"]
        assert len(emails) == 1
        start = self.TEXT.index("jane.roe@example.test")
        assert emails[0].start_offset == start
        assert emails[0].end_offset == start + len("jane.roe@example.test")
        assert 0.0 <= emails[0].confidence <= 1.0
        assert result.entity_counts["EMAIL"] == 1

    def test_findings_carry_no_matched_text(self):
        d = core.check_text(self.TEXT).to_dict()
        assert d["findings"]
        for f in d["findings"]:
            assert set(f) == FINDING_KEYS
        assert "jane.roe" not in json.dumps(d)

    def test_result_is_frozen(self):
        result = core.check_text(self.TEXT)
        with pytest.raises(Exception):
            result.entity_counts = {}
        with pytest.raises(Exception):
            result.findings[0].type = "X"

    def test_to_dict_is_json_serialisable_and_detached(self):
        result = core.check_text(self.TEXT)
        d = result.to_dict()
        json.dumps(d)
        d["entity_counts"]["EMAIL"] = 99
        assert result.entity_counts["EMAIL"] == 1

    def test_empty_text(self):
        result = core.check_text("")
        assert result.findings == ()
        assert result.entity_counts == {}

    def test_rejects_non_str(self):
        for bad in (None, b"bytes", 12, ["a"]):
            with pytest.raises(core.CoreError) as e:
                core.check_text(bad)
            assert e.value.code == "invalid_text"

    def test_rejects_unknown_document_type(self):
        with pytest.raises(core.CoreError) as e:
            core.check_text("hello", document_type="spreadsheet")
        assert e.value.code == "invalid_document_type"

    @pytest.mark.parametrize("doc_type", ["auto", "general", "resume", "transcript"])
    def test_accepts_document_types(self, doc_type):
        core.check_text("hello there", document_type=doc_type)


# --------------------------------------------------------------- payload cap

class TestPayloadCap:
    def test_constant(self):
        assert core.MAX_TEXT_CHARS == 50_000

    @pytest.fixture(autouse=True)
    def fast_detector(self, monkeypatch):
        self.calls = []

        def fake(text, doc_type="auto"):
            self.calls.append(len(text))
            return []

        monkeypatch.setattr(detector, "detect_pii", fake)
        monkeypatch.setattr(detector, "get_nlp", lambda allow_download=True: None)
        monkeypatch.setattr(detector, "count_tokens", lambda text: 1)

    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    def test_exactly_at_cap_is_accepted(self, fn):
        fn("a" * 50_000)
        assert self.calls == [50_000]

    @pytest.mark.parametrize("fn", [core.check_text, core.redact_text])
    def test_one_over_cap_raises_typed_error_without_detecting(self, fn):
        text = CANARY * 5_001
        assert len(text) > 50_000
        with pytest.raises(core.CoreError) as e:
            fn(text)
        assert e.value.code == "payload_too_large"
        assert self.calls == []
        _assert_no_canary(str(e.value))

    def test_exact_boundary_plus_one(self):
        with pytest.raises(core.CoreError) as e:
            core.check_text("a" * 50_001)
        assert e.value.code == "payload_too_large"

    def test_cap_counts_characters_not_bytes(self):
        core.check_text("é" * 50_000)
        assert self.calls == [50_000]


# -------------------------------------------------------------- redact + restore

CANONICAL = [
    "Please email Alex Sample at alex.sample@example.test or call (555) 010-0142.",
    "Alex Sample met Rory Mockdata. Later Alex Sample wrote to rory.mockdata@example.test.",
    "SSN 078-05-1120 belongs to Alex Sample; card 4111 1111 1111 1111.",
    "Nothing sensitive in this sentence at all.",
    "",
]

HOSTILE = [
    "Alex Sample <<EMAIL_1>> wrote alex.sample@example.test and <<EMAIL_2>>.",
    "Literal <NAME AS> and Alex Sample plus <NAME AS2> sit together.",
    "<<PHONE_1>> call (555) 010-0142 <<PHONE_2>> <<PHONE_1>>",
    "<<EMAIL_1>><<EMAIL_1>> jane@example.test <<EMAIL_1>>",
    "Rory Mockdata says <NAME RM> and <NAME RM2> and <<EMAIL_1>> rory@example.test.",
]


class TestRedactRoundTrip:
    @pytest.mark.parametrize("audit", [True, False])
    @pytest.mark.parametrize("text", CANONICAL + HOSTILE)
    def test_round_trip(self, text, audit):
        result = core.redact_text(text, audit=audit)
        assert core.restore_text(result.redacted_text, result.mapping) == text

    def test_partial_name_mention_restores_as_full_name(self):
        # Pre-existing redactor behaviour: the mapping stores one canonical
        # name per person, so "Alex" alone cannot come back as "Alex".
        text = "Alex Sample met Rory Mockdata. Later Alex wrote."
        result = core.redact_text(text, audit=False)
        assert core.restore_text(result.redacted_text, result.mapping) == (
            "Alex Sample met Rory Mockdata. Later Alex Sample wrote."
        )

    def test_unrestorable_tag_fails_at_redact_time(self, monkeypatch):
        monkeypatch.setattr(
            core, "redact", lambda text, ents: (text, {"tags": {"<NAME <>": "x"}})
        )
        monkeypatch.setattr(detector, "detect_pii", lambda t, d="auto": [])
        monkeypatch.setattr(detector, "get_nlp", lambda allow_download=True: None)
        monkeypatch.setattr(detector, "count_tokens", lambda text: 1)
        with pytest.raises(core.CoreError) as e:
            core.redact_text("hello", audit=False)
        assert e.value.code == "invalid_mapping"

    def test_email_is_redacted(self):
        result = core.redact_text(CANONICAL[0])
        assert "alex.sample@example.test" not in result.redacted_text
        assert result.entity_counts["EMAIL"] == 1

    def test_mapping_is_flat_tag_to_str(self):
        result = core.redact_text(CANONICAL[1])
        assert result.mapping
        assert "persons" not in result.mapping
        assert "tags" not in result.mapping
        assert "metadata" not in result.mapping
        for tag, value in result.mapping.items():
            assert isinstance(tag, str) and isinstance(value, str)
            assert core.TAG_RE.fullmatch(tag)
            assert tag in result.redacted_text

    def test_findings_have_no_text(self):
        d = core.redact_text(CANONICAL[0]).to_dict()
        for f in d["findings"]:
            assert set(f) == FINDING_KEYS
        assert set(d) == {
            "redacted_text", "mapping", "findings", "entity_counts", "audit_additions",
        }

    def test_audit_additions_counts_audit_tags(self):
        text = "Mr Somebody and Dr Another were briefed. Alex Sample signed."
        on = core.redact_text(text, audit=True)
        off = core.redact_text(text, audit=False)
        assert off.audit_additions == 0
        assert on.audit_additions == len(on.mapping) - len(off.mapping)
        assert on.audit_additions >= 0

    def test_audit_is_explicit_parameter(self):
        sig = inspect.signature(core.redact_text)
        assert sig.parameters["audit"].default is True
        assert sig.parameters["audit"].kind is inspect.Parameter.KEYWORD_ONLY

    def test_audit_flag_controls_audit_call(self, monkeypatch):
        from pii_buddy import audit as audit_mod

        calls = []

        def spy(text, mapping):
            calls.append(1)
            return text, mapping

        monkeypatch.setattr(audit_mod, "audit_redacted", spy)
        core.redact_text("Alex Sample wrote.", audit=False)
        assert calls == []
        core.redact_text("Alex Sample wrote.", audit=True)
        assert calls == [1]

    def test_core_never_reads_settings(self, monkeypatch):
        import pii_buddy.settings as settings_mod

        src = inspect.getsource(core)
        assert "settings" not in src
        assert "cfg." not in src and "config" not in src
        monkeypatch.setattr(
            settings_mod.Settings, "load",
            classmethod(lambda cls, *a, **k: pytest.fail("core read settings")),
            raising=False,
        )
        core.redact_text("Alex Sample wrote.")

    def test_redacted_result_is_frozen(self):
        result = core.redact_text(CANONICAL[0])
        with pytest.raises(Exception):
            result.redacted_text = "x"


# ------------------------------------------------------------------ restore_text

class TestRestoreText:
    def test_basic_and_single_pass(self):
        mapping = {"<<EMAIL_1>>": "<<PHONE_1>>", "<<PHONE_1>>": "555-0100"}
        assert core.restore_text("<<EMAIL_1>> / <<PHONE_1>>", mapping) == "<<PHONE_1>> / 555-0100"

    def test_unknown_tags_left_alone(self):
        assert core.restore_text("a <<EMAIL_9>> b", {"<<EMAIL_1>>": "x"}) == "a <<EMAIL_9>> b"

    def test_empty_mapping_returns_text(self):
        assert core.restore_text("hello", {}) == "hello"

    @pytest.mark.parametrize("bad", [None, [], "mapping.json", 5, Path("/etc/hosts"), [("a", "b")]])
    def test_rejects_non_dict(self, bad):
        with pytest.raises(core.CoreError) as e:
            core.restore_text("x", bad)
        assert e.value.code == "invalid_mapping"

    def test_rejects_dict_subclass_free_mapping_types(self):
        from collections import UserDict

        with pytest.raises(core.CoreError):
            core.restore_text("x", UserDict({"<<EMAIL_1>>": "a"}))

    @pytest.mark.parametrize("value", [1, None, ["a"], {"a": "b"}, b"bytes", 1.5])
    def test_rejects_non_str_values(self, value):
        with pytest.raises(core.CoreError) as e:
            core.restore_text("<<EMAIL_1>>", {"<<EMAIL_1>>": value})
        assert e.value.code == "invalid_mapping"

    def test_rejects_non_str_keys(self):
        with pytest.raises(core.CoreError) as e:
            core.restore_text("x", {1: "a"})
        assert e.value.code == "invalid_mapping"

    @pytest.mark.parametrize("key", [
        "", "foo", "EMAIL_1", "<<EMAIL_1>", "<EMAIL_1>>", "<<email 1>>", "<<EMAIL_>>",
        "<NAME >", "<NAME AS", " <<EMAIL_1>>", "<<EMAIL_1>>x", "<<EMAIL_1>>\n",
        "<NAME A>B>", "../../etc/passwd",
    ])
    def test_rejects_non_tag_keys(self, key):
        with pytest.raises(core.CoreError) as e:
            core.restore_text("x", {key: "a"})
        assert e.value.code == "invalid_mapping"

    @pytest.mark.parametrize("key", [
        "<<EMAIL_1>>", "<<ID_12>>", "<<ADDR_3>>", "<NAME AS>", "<NAME AS2>", "<NAME J>",
    ])
    def test_accepts_tag_keys(self, key):
        assert core.restore_text(key, {key: "v"}) == "v"

    def test_rejects_oversize_mapping(self):
        big = {f"<<EMAIL_{i}>>": "a" for i in range(core.MAX_MAPPING_ENTRIES + 1)}
        with pytest.raises(core.CoreError) as e:
            core.restore_text("x", big)
        assert e.value.code == "invalid_mapping"

    def test_accepts_mapping_at_limit(self):
        ok = {f"<<EMAIL_{i}>>": "a" for i in range(core.MAX_MAPPING_ENTRIES)}
        assert core.restore_text("x", ok) == "x"

    def test_rejects_oversize_value_and_key(self):
        with pytest.raises(core.CoreError):
            core.restore_text("x", {"<<EMAIL_1>>": "a" * (core.MAX_VALUE_CHARS + 1)})
        with pytest.raises(core.CoreError):
            core.restore_text("x", {"<NAME " + "A" * core.MAX_TAG_CHARS + ">": "a"})

    def test_rejects_oversize_input_text(self):
        with pytest.raises(core.CoreError) as e:
            core.restore_text("a" * (core.MAX_RESTORE_TEXT_CHARS + 1), {})
        assert e.value.code == "payload_too_large"

    def test_rejects_non_str_text(self):
        with pytest.raises(core.CoreError) as e:
            core.restore_text(None, {})
        assert e.value.code == "invalid_text"

    def test_output_amplification_is_capped(self):
        value = "a" * core.MAX_VALUE_CHARS
        mapping = {"<<EMAIL_1>>": value}
        n = core.MAX_RESTORE_OUTPUT_CHARS // core.MAX_VALUE_CHARS + 1
        with pytest.raises(core.CoreError) as e:
            core.restore_text("<<EMAIL_1>>" * n, mapping)
        assert e.value.code == "payload_too_large"

    def test_never_opens_a_path(self, monkeypatch):
        def boom(*a, **k):
            raise AssertionError("restore_text touched the filesystem")

        monkeypatch.setattr(builtins, "open", boom)
        monkeypatch.setattr(io, "open", boom)
        monkeypatch.setattr(os, "open", boom)
        monkeypatch.setattr(Path, "open", boom)
        monkeypatch.setattr(Path, "read_text", boom)
        monkeypatch.setattr(Path, "read_bytes", boom)
        assert core.restore_text("<<EMAIL_1>>", {"<<EMAIL_1>>": "v"}) == "v"
        for bad in ("/etc/hosts", Path("/etc/hosts"), ["/etc/hosts"]):
            with pytest.raises(core.CoreError):
                core.restore_text("x", bad)

    def test_unchecked_skips_size_caps_but_not_types(self):
        big_text = "<<EMAIL_1>>" * 100_000
        out = core._restore_unchecked(big_text, {"<<EMAIL_1>>": "v"})
        assert out == "v" * 100_000
        with pytest.raises(core.CoreError):
            core._restore_unchecked("x", {"<<EMAIL_1>>": 1})


# --------------------------------------------------------- no I/O, no echo

class TestNoSideEffects:
    @pytest.fixture(autouse=True)
    def _setup(self, sandbox, caplog, monkeypatch):
        import logging

        self.roots = sandbox
        caplog.set_level(logging.DEBUG)
        logging.getLogger("pii_buddy").propagate = True
        self.caplog = caplog

    def _run_all(self):
        r = core.redact_text(CANARY_TEXT)
        core.check_text(CANARY_TEXT)
        core.restore_text(r.redacted_text, r.mapping)

    def _error_paths(self):
        for fn in (
            lambda: core.check_text(CANARY * 6_000),
            lambda: core.redact_text(CANARY * 6_000),
            lambda: core.restore_text(CANARY_TEXT, {"<<EMAIL_1>>": 1}),
            lambda: core.restore_text(CANARY_TEXT, {CANARY: "x"}),
            lambda: core.restore_text(CANARY_TEXT, [CANARY]),
            lambda: core.check_text(CANARY_TEXT, document_type=CANARY),
        ):
            with pytest.raises(core.CoreError) as e:
                fn()
            _assert_no_canary(str(e.value))
            _assert_no_canary(repr(e.value))
            _assert_no_canary(json.dumps(e.value.to_dict()))

    def test_writes_nothing(self):
        before = _snapshot(*self.roots)
        self._run_all()
        self._error_paths()
        assert _snapshot(*self.roots) == before

    def test_no_stdout_stderr_or_logs_contain_input(self, capsys):
        self._run_all()
        self._error_paths()
        out, err = capsys.readouterr()
        assert out == "" and err == ""
        for rec in self.caplog.records:
            _assert_no_canary(rec.getMessage())
            _assert_no_canary(str(rec.args))
            _assert_no_canary(str(rec.exc_text))

    def test_model_error_message_has_no_input(self, monkeypatch):
        def missing(allow_download=True):
            raise detector.ModelNotInstalledError("no model")

        monkeypatch.setattr(detector, "get_nlp", missing)
        with pytest.raises(core.CoreError) as e:
            core.check_text(CANARY_TEXT)
        assert e.value.code == "model_unavailable"
        _assert_no_canary(str(e.value))


# ----------------------------------------------------------- detector hooks

class FakeNlp:
    def __init__(self):
        import spacy

        self.inner = spacy.blank("en")
        self.inner.add_pipe("sentencizer")
        self.events = []
        self.active = 0
        self.max_active = 0
        self.delay = 0.0
        self.lock_held = []

    def make_doc(self, text):
        self.lock_held.append(detector._nlp_lock.locked())
        return self.inner.make_doc(text)

    def __call__(self, text):
        self.lock_held.append(detector._nlp_lock.locked())
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.events.append("enter")
        time.sleep(self.delay)
        doc = self.inner(text)
        self.events.append("exit")
        self.active -= 1
        return doc


class TestGetNlp:
    @pytest.fixture(autouse=True)
    def fresh(self, monkeypatch):
        monkeypatch.setattr(detector, "_nlp", None)
        monkeypatch.setattr(detector, "_warmed", False, raising=False)

    def test_no_model_raises_clear_error_without_download_or_print(self, monkeypatch, capsys):
        import spacy
        import spacy.cli

        def no_model(name, *a, **k):
            raise OSError(f"[E050] Can't find model '{name}'")

        def no_download(*a, **k):
            raise AssertionError("download attempted")

        monkeypatch.setattr(spacy, "load", no_model)
        monkeypatch.setattr(spacy.cli, "download", no_download)
        with pytest.raises(detector.ModelNotInstalledError) as e:
            detector.get_nlp(allow_download=False)
        assert "en_core_web" in str(e.value)
        assert detector._nlp is None
        out, err = capsys.readouterr()
        assert out == "" and err == ""

    def test_default_still_downloads_fallback(self, monkeypatch, capsys):
        import spacy
        import spacy.cli

        fake = object()
        state = {"downloaded": 0}

        def load(name, *a, **k):
            if state["downloaded"]:
                return fake
            raise OSError("missing")

        def download(name):
            state["downloaded"] += 1

        monkeypatch.setattr(spacy, "load", load)
        monkeypatch.setattr(spacy.cli, "download", download)
        assert detector.get_nlp() is fake
        assert state["downloaded"] == 1
        assert "Downloading" in capsys.readouterr().out

    def test_cached_model_returned_without_loading(self, monkeypatch):
        import spacy

        sentinel = object()
        monkeypatch.setattr(detector, "_nlp", sentinel)
        monkeypatch.setattr(
            spacy, "load", lambda *a, **k: pytest.fail("reloaded a cached model")
        )
        assert detector.get_nlp(allow_download=False) is sentinel

    def test_core_maps_missing_model_to_typed_error(self, monkeypatch):
        import spacy
        import spacy.cli

        monkeypatch.setattr(spacy, "load", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
        monkeypatch.setattr(
            spacy.cli, "download", lambda *a, **k: pytest.fail("download attempted")
        )
        for fn in (core.check_text, core.redact_text):
            with pytest.raises(core.CoreError) as e:
                fn("hello")
            assert e.value.code == "model_unavailable"


class TestPreflight:
    @pytest.fixture(autouse=True)
    def fresh(self, monkeypatch):
        monkeypatch.setattr(detector, "_nlp", None)
        monkeypatch.setattr(detector, "_warmed", False, raising=False)

    def test_loads_once_and_is_idempotent(self, monkeypatch):
        import spacy

        loads = []
        fake = FakeNlp()

        def load(name, *a, **k):
            loads.append(name)
            return fake

        monkeypatch.setattr(spacy, "load", load)
        detector.preflight()
        detector.preflight()
        detector.preflight()
        assert loads == [detector.SPACY_MODEL]
        assert fake.events == ["enter", "exit"]

    def test_never_downloads_and_raises_when_missing(self, monkeypatch, capsys):
        import spacy
        import spacy.cli

        monkeypatch.setattr(spacy, "load", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
        monkeypatch.setattr(
            spacy.cli, "download", lambda *a, **k: pytest.fail("download attempted")
        )
        with pytest.raises(detector.ModelNotInstalledError):
            detector.preflight()
        assert capsys.readouterr() == ("", "")

    def test_real_model_preflight(self):
        detector.preflight()
        assert detector._nlp is not None


class TestSpacyLock:
    def test_concurrent_calls_never_interleave(self, monkeypatch):
        fake = FakeNlp()
        fake.delay = 0.05
        monkeypatch.setattr(detector, "_nlp", fake)
        errors = []
        start = threading.Barrier(4)

        def worker():
            try:
                start.wait()
                core.check_text("Reach jane@example.test now.")
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert errors == []
        assert fake.max_active == 1
        assert fake.events == ["enter", "exit"] * 4
