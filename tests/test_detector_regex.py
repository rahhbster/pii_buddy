"""Regex coverage and false-positive guards for the structured-PII detectors."""

import pytest

from pii_buddy import detector
from pii_buddy.detector import detect_pii
from tests._scaling import assert_scales_linearly


def _hits(text, label):
    return [e.text for e in detect_pii(text, doc_type="general") if e.label == label]


@pytest.mark.parametrize("number", [
    "+44 20 7946 0958",
    "+49 (0)30 12345678",
    "+91 98765 43210",
    "+442079460958",
])
def test_international_phone_numbers_are_redacted_whole(number):
    assert _hits(f"Call {number} today.", "PHONE") == [number]


def test_international_phone_not_mislabelled_as_date():
    assert _hits("Call +44 20 7946 0958 today.", "DOB") == []


@pytest.mark.parametrize("number", [
    "4111 1111 1111 1111",
    "4111-1111-1111-1111",
    "4111111111111111",
    "3782 822463 10005",
])
def test_valid_cards_are_labelled_card(number):
    assert _hits(f"Card {number} on file.", "CARD") == [number]


def test_card_shaped_number_failing_luhn_is_not_card():
    assert _hits("Card 4111 1111 1111 1112 on file.", "CARD") == []


@pytest.mark.parametrize("ssn", [
    "123-45-6789",
    "123 45 6789",
    "123.45.6789",
    "123–45–6789",
    "123—45—6789",
    "123456789",
])
def test_ssn_variants(ssn):
    assert _hits(f"SSN {ssn} here", "SSN") == [ssn]


def test_zip_plus_four_is_not_ssn():
    assert _hits("Austin, TX 78701-1234 ok", "SSN") == []


@pytest.mark.parametrize("date", [
    "04.03.1985",
    "3rd March 1985",
    "4 March 1985",
    "March 4th, 1985",
    "March 4, 1985",
    "1985-03-04",
    "04/03/1985",
])
def test_date_forms_are_redacted_whole(date):
    assert _hits(f"Born {date} in town", "DOB") == [date]


def test_iso_date_not_half_redacted():
    out = detect_pii("DOB: 1985-03-04\n", doc_type="general")
    assert [e.text for e in out] == ["1985-03-04"]


@pytest.mark.parametrize("text,expected", [
    ("Austin, TX 78701", "78701"),
    ("Austin, TX 78701-1234", "78701-1234"),
    ("Springfield IL 62704.", "62704"),
])
def test_zip_after_state_is_redacted(text, expected):
    assert _hits(text, "ADDRESS") == [expected]


@pytest.mark.parametrize("text", [
    "Ticket ID 12345 is closed",
    "We shipped 12345 units",
    "PO 12345 approved",
])
def test_bare_five_digits_are_not_zip(text):
    assert _hits(text, "ADDRESS") == []


@pytest.mark.parametrize("url", [
    "linkedin.com/in/janetest",
    "www.example.com/about",
    "janetest.com",
    "https://example.com/x",
])
def test_urls_with_and_without_scheme(url):
    assert _hits(f"See {url} now", "URL") == [url]


def test_url_trailing_punctuation_not_swallowed():
    assert _hits("Visit janetest.com.", "URL") == ["janetest.com"]


@pytest.mark.parametrize("text", [
    "We use ASP.NET and Node.js daily",
    "e.g. this",
    "file.pdf attached",
])
def test_tech_names_are_not_urls(text):
    assert _hits(text, "URL") == []


def test_email_domain_is_not_also_a_url():
    labels = [e.label for e in detect_pii("Mail jane@example.com now", doc_type="general")]
    assert labels == ["EMAIL"]


def test_handle_detected():
    assert _hits("Follow @janetest today", "HANDLE") == ["@janetest"]


def test_email_is_not_a_handle():
    assert _hits("Mail jane@example.invalid ok", "HANDLE") == []


def test_ipv4_detected():
    assert _hits("Server 192.168.1.10 is up.", "IP") == ["192.168.1.10"]


@pytest.mark.parametrize("text", [
    "Version 3.12.1 released",
    "Python 3.12.1 and 10.0.0.1.2 build",
    "Value 999.999.999.999 bogus",
])
def test_versions_and_bad_octets_are_not_ip(text):
    assert _hits(text, "IP") == []


@pytest.mark.parametrize("text", [
    "Released version 3.12.1 in 2024.",
    "Order 12345678 shipped in 2023.",
    "Order #20240615 shipped.",
    "Revenue was 1,234,567 dollars.",
    "Pi is 3.14159265358979.",
    "ISBN 978-3-16-148410-0",
    "Built in 1999 and 2024.",
])
def test_ordinary_numbers_not_phone_card_ssn(text):
    found = {e.label for e in detect_pii(text, doc_type="general")}
    assert not found & {"PHONE", "CARD", "SSN"}


def test_existing_us_phone_forms_still_work():
    for number in ("555-010-1234", "(555) 010-1234", "+1 555 010 1234"):
        assert _hits(f"Call {number} now", "PHONE") == [number]


_LINEAR_UNITS = [
    ("a-dot", "a."),
    ("a-dash", "a-"),
    ("dash-label", "a-a."),
    ("digit-space", "1 "),
    ("digit-run", "1"),
    ("a-at", "a@"),
    ("at-a", "@a"),
]


@pytest.mark.parametrize(
    "unit", [u for _, u in _LINEAR_UNITS], ids=[n for n, _ in _LINEAR_UNITS]
)
def test_regexes_are_linear_on_adversarial_input(unit):
    def run(text):
        for pattern, _label in detector.REGEX_PATTERNS:
            for _ in pattern.finditer(text):
                pass

    assert_scales_linearly(
        run, lambda size: unit * (size // len(unit)), repr(unit),
        backstop_size=200_000,
    )


def test_email_regex_linear_on_dotted_run():
    found = assert_scales_linearly(
        lambda text: detector.EMAIL_RE.search(text),
        lambda size: "a." * (size // 2), "email-dotted", backstop_size=200_000,
    )
    assert found is None
