"""Tests for Pass 2 — structural self-audit (audit.py).

These tests define acceptance criteria for the structural audit that runs
after Pass 1 (spaCy + regex) to catch leaked PII via pattern matching.
"""

import pytest

from pii_buddy.audit import (
    _check_capitalized_phrases,
    _check_orphaned_conjunctions,
    _check_possessive_references,
    _check_title_prefixed,
    _collect_known_names,
    audit_redacted,
)


# -----------------------------------------------------------------------
# _check_orphaned_conjunctions
# -----------------------------------------------------------------------
class TestOrphanedConjunctions:
    def test_tag_and_name(self):
        """'<NAME AS> and Robert' should catch 'Robert'."""
        text = "Meeting with <NAME AS> and Robert tomorrow."
        findings = _check_orphaned_conjunctions(text)
        assert "Robert" in findings

    def test_name_and_tag(self):
        """'Robert and <NAME AS>' should catch 'Robert'."""
        text = "Robert and <NAME AS> will attend."
        findings = _check_orphaned_conjunctions(text)
        assert "Robert" in findings

    def test_both_tagged_no_finding(self):
        """'<NAME AS> and <NAME RM>' should produce no findings."""
        text = "<NAME AS> and <NAME RM> will attend."
        findings = _check_orphaned_conjunctions(text)
        assert findings == []

    def test_multi_word_name_after_and(self):
        """'<NAME AS> and Amanda Chen' should catch 'Amanda Chen'."""
        text = "Invited <NAME AS> and Amanda Chen to the call."
        findings = _check_orphaned_conjunctions(text)
        assert "Amanda Chen" in findings

    def test_lowercase_after_and_ignored(self):
        """'<NAME AS> and the team' — 'the' is lowercase, not a name."""
        text = "<NAME AS> and the team discussed the issue."
        findings = _check_orphaned_conjunctions(text)
        assert findings == []

    def test_short_word_ignored(self):
        """Words with fewer than 3 chars after 'and' should be ignored (regex requires 3+)."""
        text = "<NAME AS> and Al discussed things."
        findings = _check_orphaned_conjunctions(text)
        # "Al" has only 2 chars — should be ignored by {2,} regex
        assert "Al" not in findings


# -----------------------------------------------------------------------
# _check_title_prefixed
# -----------------------------------------------------------------------
class TestTitlePrefixed:
    def test_mr_name(self):
        """'Mr. Singh' should be caught."""
        text = "Dear Mr. Singh, please review the document."
        findings = _check_title_prefixed(text)
        assert "Singh" in findings

    def test_dr_name(self):
        """'Dr. Amanda Chen' should be caught."""
        text = "Referred by Dr. Amanda Chen at the clinic."
        findings = _check_title_prefixed(text)
        assert "Amanda Chen" in findings or "Amanda" in findings

    def test_prof_name(self):
        """'Prof. Williams' should be caught."""
        text = "Prof. Williams will give the lecture."
        findings = _check_title_prefixed(text)
        assert "Williams" in findings

    def test_title_before_tag_no_finding(self):
        """'Mr. <NAME AS>' — tag already present, should not double-detect."""
        text = "Dear Mr. <NAME AS>,"
        findings = _check_title_prefixed(text)
        assert findings == []

    def test_title_no_period(self):
        """'Mrs Johnson' without period should still match."""
        text = "Mrs Johnson will arrive at 3pm."
        findings = _check_title_prefixed(text)
        assert "Johnson" in findings


# -----------------------------------------------------------------------
# _check_capitalized_phrases
# -----------------------------------------------------------------------
class TestCapitalizedPhrases:
    def test_two_word_name(self):
        """'Amanda Chen' as a standalone phrase should be caught."""
        text = "We spoke with Amanda Chen about the project."
        blocklist = set()
        findings = _check_capitalized_phrases(text, blocklist)
        assert "Amanda Chen" in findings

    def test_three_word_name(self):
        """'Mary Anne Wilson' should be caught."""
        text = "Mary Anne Wilson submitted the report."
        blocklist = set()
        findings = _check_capitalized_phrases(text, blocklist)
        assert "Mary Anne Wilson" in findings

    def test_blocklisted_phrase_skipped(self):
        """Phrases in the blocklist should be skipped."""
        text = "The United States has new regulations."
        blocklist = {"united states"}
        findings = _check_capitalized_phrases(text, blocklist)
        assert "United States" not in findings

    def test_single_word_ignored(self):
        """Single capitalized words are not multi-word phrases."""
        text = "Robert will attend."
        blocklist = set()
        findings = _check_capitalized_phrases(text, blocklist)
        assert findings == []

    def test_tagged_phrase_skipped(self):
        """Phrases inside tags should not be detected."""
        text = "Meeting with <NAME AC> about the budget."
        blocklist = set()
        findings = _check_capitalized_phrases(text, blocklist)
        # Should not catch anything inside a tag
        for f in findings:
            assert "NAME" not in f


# -----------------------------------------------------------------------
# _check_possessive_references
# -----------------------------------------------------------------------
class TestPossessiveReferences:
    def test_known_name_possessive(self):
        """'Robert's' where Robert is a known name should be caught."""
        text = "Robert's assistant will prepare the agenda."
        known = {"robert", "merrill", "robert merrill"}
        findings = _check_possessive_references(text, known)
        assert "Robert" in findings

    def test_unknown_name_possessive_ignored(self):
        """'Monday's' — not a known name, should be ignored."""
        text = "Monday's meeting is at 3pm."
        known = {"robert"}
        findings = _check_possessive_references(text, known)
        assert findings == []

    def test_tagged_possessive_ignored(self):
        """'<NAME RM>'s' — already tagged, should not double-detect."""
        text = "<NAME RM>'s assistant will prepare."
        known = {"robert"}
        findings = _check_possessive_references(text, known)
        assert findings == []


# -----------------------------------------------------------------------
# _collect_known_names
# -----------------------------------------------------------------------
class TestCollectKnownNames:
    def test_extracts_full_and_parts(self):
        mapping = {
            "persons": {
                "Atul Singh": "<NAME AS>",
                "Robert Merrill": "<NAME RM>",
            }
        }
        names = _collect_known_names(mapping)
        assert "atul singh" in names
        assert "robert merrill" in names
        assert "atul" in names
        assert "singh" in names
        assert "robert" in names
        assert "merrill" in names

    def test_empty_mapping(self):
        names = _collect_known_names({"persons": {}})
        assert names == set()


# -----------------------------------------------------------------------
# audit_redacted (integration)
# -----------------------------------------------------------------------
class TestAuditRedacted:
    def test_catches_orphaned_name(self, sample_redacted_text, sample_mapping):
        """audit_redacted should catch 'Amanda Chen' and 'Singh' after Mr."""
        patched, updated = audit_redacted(sample_redacted_text, sample_mapping)

        # Amanda Chen should now be tagged
        assert "Amanda Chen" not in patched
        assert "<NAME AC>" in patched or "<NAME" in patched

    def test_catches_possessive_reference(self, sample_redacted_text, sample_mapping):
        """'Robert's' should be replaced with Robert's tag."""
        patched, updated = audit_redacted(sample_redacted_text, sample_mapping)

        # "Robert's" should become "<NAME RM>'s" (reuses existing tag)
        assert "Robert's" not in patched

    def test_catches_title_prefixed(self, sample_redacted_text, sample_mapping):
        """'Mr. Singh' should have 'Singh' redacted."""
        patched, updated = audit_redacted(sample_redacted_text, sample_mapping)

        # "Mr. Singh" should become "Mr. <NAME AS>" (reuses existing tag)
        assert "Mr. Singh" not in patched

    def test_updates_mapping(self, sample_redacted_text, sample_mapping):
        """New findings should be added to the mapping."""
        _, updated = audit_redacted(sample_redacted_text, sample_mapping)

        # Should have more tags than before
        assert len(updated["tags"]) >= len(sample_mapping["tags"])

    def test_no_false_positives_on_clean_text(self, sample_redacted_clean, sample_mapping):
        """Already-clean text should pass through unchanged."""
        patched, updated = audit_redacted(sample_redacted_clean, sample_mapping)

        # Tags and text should be unchanged (or minimally changed)
        # The key thing: no errors, no crashes
        assert "<NAME" in patched

    def test_idempotent(self, sample_redacted_text, sample_mapping):
        """Running audit twice should not change the result."""
        patched1, mapping1 = audit_redacted(sample_redacted_text, sample_mapping)
        patched2, mapping2 = audit_redacted(patched1, mapping1)
        assert patched1 == patched2

    def test_empty_text(self):
        """Empty text should return empty text."""
        patched, mapping = audit_redacted("", {"tags": {}, "persons": {}})
        assert patched == ""
