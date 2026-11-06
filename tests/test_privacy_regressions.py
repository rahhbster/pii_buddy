"""Privacy regressions: audit-pass mapping corruption and missed names.

(A) The audit pass overwrote an existing tag's original and substituted inside
    existing tags, so restore produced "deLivered" or "<<Ip_1>>".
(B) An ALLCAPS name above an ALLCAPS title leaked: the candidate crossed the
    newline and was rejected as a whole.
(C) Accented and apostrophe names were invisible to the ALLCAPS and audit
    regexes.

Every name below is synthetic.
"""

import random
import re

import pytest

from pii_buddy import core, detector
from pii_buddy.audit import _check_capitalized_phrases, _covered_runs, audit_redacted


def _word_present(word, text):
    return re.search(rf"(?<!\w){re.escape(word)}(?!\w)", text) is not None


def _redact_round_trip(text):
    result = core.redact_text(text)
    assert core.restore_text(result.redacted_text, result.mapping) == text
    return result


class TestAuditKeepsMappingIntact:
    def test_short_surname_after_title_round_trips(self):
        text = "Wei Li delivered a reliable client platform. Ms. Li presented it."
        result = _redact_round_trip(text)
        assert not _word_present("Li", result.redacted_text)
        assert not _word_present("Wei", result.redacted_text)

    def test_audit_never_substitutes_inside_an_ip_tag(self):
        text = "Kin Ip applied from 10.1.2.3. Mr. Ip followed up."
        result = _redact_round_trip(text)
        assert "10.1.2.3" not in result.redacted_text
        assert not _word_present("Ip", result.redacted_text)
        assert "10.1.2.3" in result.mapping.values()

    def test_audit_never_substitutes_inside_an_email_tag(self):
        text = "Email and Jane Doe wrote to jane@example.com about the plan."
        result = _redact_round_trip(text)
        assert "jane@example.com" not in result.redacted_text
        assert not _word_present("Jane", result.redacted_text)
        assert "jane@example.com" in result.mapping.values()

    def test_existing_tag_original_is_never_reassigned(self):
        mapping = {
            "tags": {"<NAME WL>": "Wei Li"},
            "persons": {"Wei Li": "<NAME WL>"},
        }
        patched, updated = audit_redacted("<NAME WL> spoke. Ms. Li agreed.", mapping)
        assert updated["tags"]["<NAME WL>"] == "Wei Li"
        assert not _word_present("Li", patched)
        assert core.restore_text(patched, updated["tags"]) == (
            "Wei Li spoke. Ms. Li agreed."
        )

    def test_case_variants_each_restore_to_their_own_text(self):
        mapping = {"tags": {}, "persons": {}}
        text = "Dear Mr. Sample, the SAMPLE file and the sample size are ready."
        patched, updated = audit_redacted(text, mapping)
        assert "Sample" not in patched
        assert core.restore_text(patched, updated["tags"]) == text

    def test_literal_tag_text_in_redacted_input_is_not_reused(self):
        mapping = {"tags": {}, "persons": {}}
        text = "Legend <NAME S> is literal. Dear Mr. Sample, hello."
        patched, updated = audit_redacted(text, mapping)
        assert "<NAME S>" not in updated["tags"]
        assert core.restore_text(patched, updated["tags"]) == text


    def test_overlapping_occurrences_are_all_covered(self):
        mapping = {"tags": {}, "persons": {}}
        text = "Ann Testperson Ann Testperson Ann Testperson"
        patched, updated = audit_redacted(text, mapping)
        assert not _word_present("Testperson", patched)
        assert not _word_present("Ann", patched)
        assert core.restore_text(patched, updated["tags"]) == text

    def test_overlapping_occurrences_of_one_finding(self):
        assert _covered_runs("Ann Lee Ann Lee Ann", ["Ann Lee Ann"], []) == [(0, 19)]

    def test_every_phrase_window_not_one_tiling(self):
        findings = _check_capitalized_phrases("We met Wren Okafor Mina Lindqvist.", set())
        assert any("Lindqvist" in f for f in findings)

    def test_fragment_glued_to_a_name_tag_is_covered(self):
        mapping = {"tags": {"<NAME VDB>": "Van Der Berg"},
                   "persons": {"Van Der Berg": "<NAME VDB>", "Der": "<NAME VDB>"}}
        patched, updated = audit_redacted("See the Placehol<NAME VDB> file.", mapping)
        assert "Placehol" not in patched
        assert updated["tags"]["<NAME VDB>"] == "Van Der Berg"

    def test_neighbour_exposed_by_a_new_tag_is_caught_next_round(self):
        mapping = {"tags": {}, "persons": {}}
        text = "Ciarán Wu reviewed it. Later Mr. Wu approved."
        patched, updated = audit_redacted(text, mapping)
        assert "Ciarán" not in patched
        assert core.restore_text(patched, updated["tags"]) == text

    @pytest.mark.parametrize("text, word", [
        ("Notes from Uma <NAME KS> today.", "Uma"),
        ("Signed by <NAME LE> Ibáñez yesterday.", "Ibáñez"),
    ])
    def test_lone_capitalized_word_beside_a_name_tag(self, text, word):
        mapping = {"tags": {"<NAME KS>": "Kira Smith", "<NAME LE>": "Lucía Ek"},
                   "persons": {}}
        patched, updated = audit_redacted(text, mapping)
        assert word not in patched
        expected = core.restore_text(text, mapping["tags"])
        assert core.restore_text(patched, updated["tags"]) == expected

    def test_honorific_beside_a_name_tag_is_left_alone(self):
        mapping = {"tags": {"<NAME KS>": "Kira Smith"}, "persons": {}}
        patched, _ = audit_redacted("Thanks, Prof <NAME KS>.", mapping)
        assert "Prof <NAME KS>" in patched


class TestAllcapsHeaderAboveTitle:
    def test_allcaps_name_above_allcaps_title(self):
        text = "JAMES WHITFIELD\nSOFTWARE ENGINEER\nBuilt systems."
        result = _redact_round_trip(text)
        assert "JAMES" not in result.redacted_text
        assert "WHITFIELD" not in result.redacted_text

    def test_allcaps_name_with_crlf_lines(self):
        text = "JAMES WHITFIELD\r\nSOFTWARE ENGINEER\r\nBuilt systems."
        result = _redact_round_trip(text)
        assert "WHITFIELD" not in result.redacted_text

    def test_trailing_spaces_on_the_name_line_survive(self):
        text = "JAMES WHITFIELD   \nSOFTWARE ENGINEER\nBuilt systems."
        result = _redact_round_trip(text)
        assert "WHITFIELD" not in result.redacted_text
        assert "JAMES WHITFIELD" in result.mapping.values()

    @pytest.mark.parametrize("text, name", [
        ("Sam Roe\nScrum Master\n\nSkills\nLunch will be served.", "Sam Roe"),
        ("Wren Okafor\nData Analyst\nBuilt it.", "Wren Okafor"),
    ])
    def test_multi_line_spacy_entity_is_split_not_rejected(self, text, name):
        persons = [e.text for e in detector.detect_pii(text) if e.label == "PERSON"]
        assert name in persons


class TestDiacriticsAndApostrophes:
    def test_accented_allcaps_name(self):
        text = "JOSÉ GARCÍA\nSenior Engineer\nBuilt systems."
        result = _redact_round_trip(text)
        assert "JOSÉ" not in result.redacted_text
        assert "GARCÍA" not in result.redacted_text

    @pytest.mark.parametrize("name", ["SEÁN O'BRIEN", "AOIFE O’CONNOR",
                                      "BJØRN ØDEGÅRD", "ANNE-MARIE LEFÈVRE"])
    def test_apostrophe_and_nordic_allcaps_names(self, name):
        text = f"{name}\nDATA ANALYST\nBuilt systems."
        result = _redact_round_trip(text)
        for part in re.split(r"[ '’-]", name):
            assert len(part) < 2 or not _word_present(part, result.redacted_text)

    @pytest.mark.parametrize("surname", ["Núñez", "O'Brien", "O’Connor", "Lefèvre"])
    def test_audit_title_catches_accented_surnames(self, surname):
        mapping = {"tags": {}, "persons": {}}
        text = f"Thanks to Ms. {surname} for the review."
        patched, updated = audit_redacted(text, mapping)
        assert surname not in patched
        assert core.restore_text(patched, updated["tags"]) == text

    def test_audit_catches_accented_capitalized_phrase(self):
        mapping = {"tags": {}, "persons": {}}
        text = "We spoke with Jürgen Schröder about the project."
        patched, updated = audit_redacted(text, mapping)
        assert "Schröder" not in patched
        assert core.restore_text(patched, updated["tags"]) == text

    def test_audit_catches_curly_possessive_of_known_name(self):
        mapping = {
            "tags": {"<NAME RM>": "Rory Mockdata"},
            "persons": {"Rory Mockdata": "<NAME RM>", "Rory": "<NAME RM>"},
        }
        text = "<NAME RM> called. Rory’s notes are attached."
        patched, _ = audit_redacted(text, mapping)
        assert "Rory" not in patched


# -----------------------------------------------------------------------
# Seeded synthetic corpus
# -----------------------------------------------------------------------

_FIRST = {
    "anglo": ["James", "Emily", "Oliver", "Hannah", "Thomas", "Grace"],
    "hispanic": ["José", "María", "Iñigo", "Lucía", "Andrés", "Begoña"],
    "frde": ["François", "Jérôme", "Zoë", "Jürgen", "Anne-Marie", "Günther"],
    "nordslav": ["Bjørn", "Åsa", "Sven", "Agnieszka", "Miroslav", "Øystein"],
    "irish": ["Seán", "Siobhán", "Pádraig", "Aoife", "Niamh", "Ciarán"],
}
_LAST = {
    "anglo": ["Whitfield", "Hartwell", "Pembrook", "Ashcombe", "Thornbury"],
    "hispanic": ["García", "Núñez", "Ibáñez", "Peñalosa", "Gutiérrez"],
    "frde": ["Lefèvre", "Duchâteau", "Schröder", "Müllerson", "Brontëville"],
    "nordslav": ["Ødegård", "Lindström", "Wiśniewska", "Dvořák", "Kowalczyk"],
    "irish": ["O'Brien", "O’Connor", "Ó Súilleabháin", "Mac Giolla", "O'Dwyer"],
}
_SHORT = ["Li", "Ip", "Wu", "Ng", "Ho", "Xu", "Ek", "Oz", "Yu", "Lu"]
_TITLE_WORDS = ["Mr.", "Ms.", "Dr.", "Prof."]
_JOBS = ["Software Engineer", "Data Analyst", "Product Manager",
         "Senior Engineer", "Technical Lead", "Cloud Architect"]
_PROSE = ["Built reliable delivery pipelines for client platforms.",
          "Led a team of six across three time zones.",
          "Reduced build times by forty percent.",
          "Mentored new hires and wrote onboarding guides."]
_CORPUS_SEED = 20261104
_CORPUS_SIZE = 240

# Measured with en_core_web_md: main 172/300 (0.573), this branch 295/300
# (0.983). The margin absorbs model-version drift between machines.
_RECALL_FLOOR = 0.96


def _build_corpus():
    rng = random.Random(_CORPUS_SEED)
    groups = sorted(_FIRST)
    docs = []
    for i in range(_CORPUS_SIZE):
        g = groups[i % len(groups)]
        first, last = rng.choice(_FIRST[g]), rng.choice(_LAST[g])
        full = f"{first} {last}"
        job, prose = rng.choice(_JOBS), rng.choice(_PROSE)
        kind = i % 4
        if kind == 0:
            text = f"{full.upper()}\n{job.upper()}\n{prose}"
        elif kind == 1:
            text = f"{full.upper()}\n{job}\nPhone (555) 010-{1000 + i}\n{prose}"
        elif kind == 2:
            text = f"{full}\n{job}\n\n{prose}\nReferences: {full}."
        else:
            # A different first name: a shared one is a partial mention, which
            # restores as the full name by design (see test_core).
            short = rng.choice(_SHORT)
            sfirst = rng.choice([f for f in _FIRST[g] if f != first])
            title = rng.choice(_TITLE_WORDS)
            text = (f"{sfirst} {short} reviewed the proposal. {prose} "
                    f"Later {title} {short} approved it, and {full} agreed.")
            docs.append((text, [f"{sfirst} {short}", full]))
            continue
        docs.append((text, [full]))
    return docs


_CORPUS = _build_corpus()


def _name_hidden(name, redacted):
    parts = [p for p in re.split(r"[\s'’-]+", name) if len(p) >= 2]
    variants = set(parts) | {p.upper() for p in parts}
    return not any(_word_present(p, redacted) for p in variants)


def test_corpus_is_large_and_seeded():
    assert len(_CORPUS) >= 200
    assert _build_corpus() == _CORPUS


@pytest.mark.parametrize("index", range(len(_CORPUS)))
def test_corpus_round_trips_exactly(index):
    text, _ = _CORPUS[index]
    _redact_round_trip(text)


# Partial mentions restore as the full name (a redactor property), so these
# cannot round-trip exactly; the audit still must not make them worse.
_PARTIAL_MENTIONS = [
    "Steve Johnson met Steve later. Mr. Johnson left. Wei Li and Ms. Li agreed.",
    "Seán O'Brien led the team. Mr. O'Brien presented. Seán's notes followed.",
    "Ann Testperson wrote. ANN TESTPERSON signed. Mr. Testperson and Kin Ip met.",
    "Lucía Ek reviewed it. Later Prof. Ek approved it, and Lucía Ibáñez agreed.",
]


@pytest.mark.parametrize(
    "text", _PARTIAL_MENTIONS + [t for t, _ in _CORPUS[::6]])
def test_audit_is_restore_neutral(text):
    # Whatever the first pass restores to, the audit must not change it.
    before = core.redact_text(text, audit=False)
    after = core.redact_text(text)
    assert core.restore_text(after.redacted_text, after.mapping) == (
        core.restore_text(before.redacted_text, before.mapping)
    )


def test_corpus_recall_floor():
    total = hidden = 0
    for text, names in _CORPUS:
        redacted = core.redact_text(text).redacted_text
        for name in names:
            total += 1
            hidden += _name_hidden(name, redacted)
    recall = hidden / total
    assert recall >= _RECALL_FLOOR, f"recall {hidden}/{total} = {recall:.3f}"


# -----------------------------------------------------------------------
# Red-team round 1: common words, persons fragments, scaling
# -----------------------------------------------------------------------

@pytest.mark.parametrize("text, names, common", [
    ("When Sarah Collins joined the team, she shipped whenever possible.",
     ["Sarah", "Collins"], ["When", "whenever"]),
    ("Thanks Priya Sharma for the update, many thanks. Our Daniel Foster "
     "review is ours.", ["Priya", "Sharma", "Daniel", "Foster"],
     ["Thanks", "thanks", "Our", "ours"]),
    ("Manager Maya Patel led it; management matters.", ["Maya", "Patel"],
     ["Manager", "management"]),
    ("On Monday Liam Brooks called, as on most Mondays.", ["Liam", "Brooks"],
     ["Monday", "Mondays"]),
    # Not "Dear Ines Okafor": main's three-word phrase rule tags "Dear" too,
    # and coverage must not shrink below main.
    ("Hello Tomas Lindgren. See you in March, Ines Okafor.",
     ["Ines", "Okafor", "Tomas", "Lindgren"], ["March", "Hello"]),
])
def test_common_word_beside_a_name_stays_visible(text, names, common):
    result = _redact_round_trip(text)
    for word in names:
        assert not _word_present(word, result.redacted_text)
    for word in common:
        assert _word_present(word, result.redacted_text)


def test_beside_tag_still_catches_a_real_first_name():
    mapping = {"tags": {"<NAME KS>": "Kira Smith"}, "persons": {}}
    patched, _ = audit_redacted("Thanks, Manager <NAME KS> left; Uma <NAME KS> stayed.", mapping)
    assert "Uma" not in patched
    assert _word_present("Manager", patched)


def test_substring_fragments_do_not_enter_persons():
    # watcher._redact_filename rewrites filenames from "persons"; a fragment
    # such as "li" from "reliable" would rewrite unrelated filenames.
    mapping = {"tags": {}, "persons": {}}
    _, updated = audit_redacted("Thanks to Ms. Li for the reliable client work.", mapping)
    assert "Li" in updated["persons"]
    assert "li" not in updated["persons"]


def _audit_doc(n):
    tags, parts = {}, []
    for i in range(n):
        tag = f"<NAME A{i}>"
        tags[tag] = f"Person Number{i}"
        parts.append(f"{tag} met Mr. Ng and Bob Lee{i % 7} at noon.")
    return "\n".join(parts), {"tags": tags, "persons": {}}


def test_audit_scales_linearly_in_tags():
    from tests._scaling import BACKSTOP_S, assert_ratio_linear, best_of, cpu_time

    def run(args):
        return audit_redacted(*args)

    small = 1000
    t_small = best_of(run, _audit_doc(small))
    t_large = best_of(run, _audit_doc(small * 2))
    assert_ratio_linear(t_small, t_large, "audit_redacted", small, small * 2)
    elapsed, (patched, _) = cpu_time(run, _audit_doc(small * 4))
    assert elapsed < BACKSTOP_S
    assert "Mr. Ng" not in patched


# Red-team round 2: a stoplist word that is also a name must stay redacted.
_NAME_LIKE = ["April", "May", "June", "August", "Will", "Mark", "Grace", "Rose",
              "Frank", "Hope", "March", "Jan", "Jun", "Senior", "Junior", "Per",
              "Even", "Ask", "Sun", "Sat", "Best", "Chief", "Head", "Judge", "Lady",
              # round 3: Hmong, Vietnamese, Burmese, Cantonese, Chinese names
              "Her", "Thu", "Mon", "Than", "Hon", "Most", "Dear", "Hey", "Dame",
              "Tuesday", "Friday", "Sunday", "January", "You", "How", "She",
              "Call",
              # round 4: Hakka surname, rare given name
              "Then", "Wednesday"]


@pytest.mark.parametrize("word", _NAME_LIKE)
@pytest.mark.parametrize("shape", ["{w} <NAME KS> joined today.",
                                   "Notes: <NAME KS> {w} joined today."])
def test_name_like_word_beside_a_tag_is_redacted(word, shape):
    mapping = {"tags": {"<NAME KS>": "Kira Smith"}, "persons": {}}
    text = shape.format(w=word)
    patched, updated = audit_redacted(text, mapping)
    assert not _word_present(word, patched)
    assert core.restore_text(patched, updated["tags"]) == core.restore_text(text, mapping["tags"])


@pytest.mark.parametrize("word", ["When", "Thanks", "Our", "Monday", "Hello"])
def test_non_name_word_beside_a_tag_stays_visible(word):
    mapping = {"tags": {"<NAME KS>": "Kira Smith"}, "persons": {}}
    patched, _ = audit_redacted(f"Notes, {word} <NAME KS> joined.", mapping)
    assert _word_present(word, patched)


@pytest.mark.parametrize("text, surname", [
    ("Lisa <NAME LC> Her signed.", "Her"),
    ("Our analyst Mai <NAME ML> Her joined.", "Her"),
])
def test_hmong_surname_after_a_name_tag_is_redacted(text, surname):
    mapping = {"tags": {"<NAME LC>": "Chang", "<NAME ML>": "Lee"}, "persons": {}}
    patched, _ = audit_redacted(text, mapping)
    assert not _word_present(surname, patched)


@pytest.mark.parametrize("text, word", [
    ("Lisa Chang Her signed.", "Her"),
    ("Our analyst Mai Lee Her joined.", "Her"),
    ("Lucy Ann Then signed.", "Then"),
    ("Lucy Ann Wednesday signed.", "Wednesday"),
])
def test_name_like_surname_in_full_name_is_redacted(text, word):
    result = _redact_round_trip(text)
    assert not _word_present(word, result.redacted_text)
