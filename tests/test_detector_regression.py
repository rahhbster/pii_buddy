"""Regression tests: the regex-coverage PR must not redact less than main, and
must not redact ordinary technical text."""

import pytest

from pii_buddy.detector import detect_pii


def _ents(text):
    return [(e.text, e.label) for e in detect_pii(text, doc_type="general")]


def _labels_for(text, needle):
    return {lab for t, lab in _ents(text) if needle in t}


def _redacted(text, needle):
    """True if every character of ``needle`` falls inside some entity."""
    spans = [(e.start, e.end) for e in detect_pii(text, doc_type="general")]
    i = text.index(needle)
    return all(any(s <= k < e for s, e in spans) for k in range(i, i + len(needle)))


# --- SSN shapes that main redacted ----------------------------------------

@pytest.mark.parametrize("ssn", [
    "123\t45\t6789",
    "123\xa045\xa06789",
    "123 45 6789",
    "123 45 6789",
    "12345 6789",
    "12345-6789",
    "123 456789",
    "123-456789",
])
def test_ssn_shapes_main_redacted_stay_redacted(ssn):
    text = f"SSN {ssn} on file"
    assert _redacted(text, ssn), _ents(text)
    assert "SSN" in {l for t, l in _ents(text)}


def test_zip_plus_four_after_state_stays_address_not_ssn():
    text = "Austin, TX 78701-1234 ok"
    assert [t for t, l in _ents(text) if l == "SSN"] == []
    assert [t for t, l in _ents(text) if l == "ADDRESS"] == ["78701-1234"]


def test_zip_plus_four_without_state_fails_closed():
    assert _redacted("Ref 78701-1234 here", "78701-1234")


# --- international phone length -------------------------------------------

@pytest.mark.parametrize("number", [
    "+33 1 42 68 53 00",
    "+81 3 1234 5678 90 12",
])
def test_long_intl_phone_redacted_whole(number):
    hits = [t for t, l in _ents(f"Call {number} today") if l == "PHONE"]
    assert hits == [number]


# --- false positives -------------------------------------------------------

@pytest.mark.parametrize("text", [
    "@media (max-width: 600px) { }",
    "@pytest.fixture def f(): pass",
    "@staticmethod\ndef f(): pass",
    "@dataclass class A: pass",
])
def test_annotations_are_not_handles(text):
    assert [t for t, l in _ents(text) if l == "HANDLE"] == []


@pytest.mark.parametrize("text,expected", [
    ("Follow @janetest today", "@janetest"),
    ("(@janetest) wrote", "@janetest"),
    ("@janetest wrote", "@janetest"),
])
def test_real_handles_still_redacted(text, expected):
    assert [t for t, l in _ents(text) if l == "HANDLE"] == [expected]


@pytest.mark.parametrize("name", [
    "docker-compose.dev.yml", "settings.app", "tsconfig.dev",
    "index.ai", "model.io", "package.json", "main.py",
])
def test_filenames_are_not_urls(name):
    assert [t for t, l in _ents(f"Edit {name} now") if l == "URL"] == []


@pytest.mark.parametrize("url", [
    "janetest.com", "janetest.org", "janetest.co.uk",
    "janetest.dev/about", "janetest.io/me", "github.com/janetest",
    "linkedin.com/in/janetest", "janetest.ai/cv",
])
def test_real_bare_urls_still_redacted(url):
    assert [t for t, l in _ents(f"See {url} now") if l == "URL"] == [url]


@pytest.mark.parametrize("text", [
    "version 10.0.1.2", "build 4.5.6.7", "v10.20.30.40",
    "V10.1.2.3", "Version 10.0.1.2 shipped",
])
def test_version_strings_are_not_ips(text):
    assert [t for t, l in _ents(text) if l == "IP"] == []


@pytest.mark.parametrize("text,ip", [
    ("Host 10.0.1.2 is up", "10.0.1.2"),
    ("Server 1.2.3.4 is up", "1.2.3.4"),
    ("rev10.0.1.2 seen", "10.0.1.2"),
])
def test_bare_dotted_quads_still_redacted(text, ip):
    assert [t for t, l in _ents(text) if l == "IP"] == [ip]


def test_ordinal_day_of_month_year_is_redacted_as_full_date():
    assert _redacted("Met on 1st of March 2021 there", "1st of March 2021")


# --- round 2 red-team ------------------------------------------------------

@pytest.mark.parametrize("text,needle", [
    ("@jane@janetest.dev", "janetest.dev"),
    ("Find me @jane@fosstodon.org please", "fosstodon.org"),
    ("@jane@janetest.dev,", "janetest.dev"),
])
def test_fediverse_address_fully_redacted(text, needle):
    assert _redacted(text, needle), _ents(text)
    assert [t for t, l in _ents(text) if l == "EMAIL"]
    assert [t for t, l in _ents(text) if l == "HANDLE"] == []


@pytest.mark.parametrize("text,ip", [
    ("my ip is v 10.1.2.3", "10.1.2.3"),
    ("IP: v 8.8.8.8", "8.8.8.8"),
    ("build: 203.0.113.9", "203.0.113.9"),
    ("user v 203.0.113.9 connected", "203.0.113.9"),
    ("VERSION 203.0.113.9", "203.0.113.9"),
    ("v:203.0.113.9", "203.0.113.9"),
    ("V #203.0.113.9", "203.0.113.9"),
    ("server version 10.0.0.1", "10.0.0.1"),
    ("Version: 10.0.1.2", "10.0.1.2"),
    ("BUILD #4.5.6.7", "4.5.6.7"),
    ("from host v10.1.2.3", "10.1.2.3"),
])
def test_version_prefix_does_not_hide_ips(text, ip):
    assert [t for t, l in _ents(text) if l == "IP"] == [ip]


@pytest.mark.parametrize("name", [
    "author", "page", "container", "layer", "component", "entity", "type",
    "see", "todo", "wraps", "returns", "override", "property", "Author", "OVERRIDE",
])
def test_prose_handles_named_like_annotations_are_redacted(name):
    text = f"ask @{name} about it"
    assert [t for t, l in _ents(text) if l == "HANDLE"] == [f"@{name}"]


@pytest.mark.parametrize("text", [
    "@Override\npublic void run() {}",
    "    @Override\n    public void run() {}",
    "@media (min-width: 1px) { }",
    "@page\n@Component(selector)",
    "@Entity\nclass A {}",
    "@Entity class A {}",
    "x\n  @wraps(f)\ndef g(): pass",
])
def test_line_start_annotations_stay_unredacted(text):
    assert [t for t, l in _ents(text) if l == "HANDLE"] == []


@pytest.mark.parametrize("handle", ["@jane.doe", "@jane-doe", "@jane.doe_99"])
def test_compound_handles_redacted_whole(handle):
    text = f"ping {handle} now"
    assert [t for t, l in _ents(text) if l == "HANDLE"] == [handle]


def test_handle_trailing_punctuation_not_swallowed():
    assert [t for t, l in _ents("thanks @jane.") if l == "HANDLE"] == ["@jane"]
    assert [t for t, l in _ents("thanks @jane-, ok") if l == "HANDLE"] == ["@jane"]


@pytest.mark.parametrize("url", [
    "janetest.COM", "JANETEST.DEV/me", "janetest.co/me", "janetest.co",
    "janetest.me/x", "janetest.us", "janetest.ca", "janetest.de",
    "janetest.xyz", "janetest.tech", "janetest.page/x", "janetest.ly/x",
    "blog.janetest.dev/x", "t.me/janetest", "bit.ly/abc",
    "janetest.com?email=jane.doe@example.org", "janetest.com#jane",
    "janetest.com:8080", "janetest.com:8080/a?b=c#d",
])
def test_round2_bare_urls_redacted_whole(url):
    assert [t for t, l in _ents(f"See {url} now") if l == "URL"] == [url]


@pytest.mark.parametrize("name", [
    "janetest.dev", "blog.janetest.app", "x.ai", "y.io", "z.page", "q.me", "r.ly",
    "ASP.NET", "VB.NET", "Node.js",
])
def test_round2_ambiguous_pathless_stay_unredacted(name):
    assert [t for t, l in _ents(f"See {name} now") if l == "URL"] == []
