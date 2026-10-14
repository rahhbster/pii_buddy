"""Differential test: the redactor must never redact less than `main` did.

Every row is (source text, [(entity substring, label)], output of main's
redactor, generated once from origin/main and frozen). Some of main's outputs
contain corrupted tags (the original defect); that only makes the check more
lenient on those rows, never stricter.
"""

import re

import pytest

from pii_buddy.redactor import redact
from tests.conftest import FakeEntity

MAIN_CASES = [
    ('Ann Testperson wrote. Ann_Testperson_resume.pdf',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. <NAME AT>_<NAME AT>_resume.pdf'),
    ('Ann Testperson wrote. ann_testperson',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. <NAME AT>_<NAME AT>'),
    ('Ann Testperson wrote. AnnTestperson2024',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. <NAME AT><NAME AT>2024'),
    ('Ann Testperson wrote. Ann2 is here',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. <NAME AT>2 is here'),
    ('Ann Testperson wrote. AnnAnnAnn',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. <NAME AT><NAME AT><NAME AT>'),
    ('Ann Testperson wrote. annlee',
     [('Ann Testperson', 'PERSON'), ('Ann Lee', 'PERSON')],
     '<NAME AT> wrote. <NAME AT>lee'),
    ('Ann Testperson wrote. ANNLEE',
     [('Ann Testperson', 'PERSON'), ('Ann Lee', 'PERSON')],
     '<NAME AT> wrote. <NAME AT>LEE'),
    ("Ann Lee met DrLee at Ann Lee's desk.",
     [('Ann Lee', 'PERSON')],
     "<NAME AL> met Dr<NAME AL> at <NAME AL>'s desk."),
    ('John Smith sent jsmith a note; jsmith replied.',
     [('John Smith', 'PERSON')],
     '<NAME JS> sent j<NAME JS> a note; j<NAME JS> replied.'),
    ("Mc Donald Trent and McDonald are Donald Trent's kin.",
     [('Donald Trent', 'PERSON')],
     "Mc <NAME DT> and Mc<NAME DT> are <NAME DT>'s kin."),
    ('McDonald was seen. Donald Trent left.',
     [('Donald Trent', 'PERSON')],
     'Mc<NAME DT> was seen. <NAME DT> left.'),
    ('\u738b\u5c0f\u660e wrote. \u738b\u5c0f\u660e\u5148\u751f',
     [('\u738b\u5c0f\u660e', 'PERSON')],
     '<NAME \u738b> wrote. <NAME \u738b>\u5148\u751f'),
    ('\u738b\u5c0f\u660e wrote. \u738b\u5c0f\u660e\u7684\u4e66',
     [('\u738b\u5c0f\u660e', 'PERSON')],
     '<NAME \u738b> wrote. <NAME \u738b>\u7684\u4e66'),
    ('\u738b\u5c0f\u660e wrote. \u89c1\u738b\u5c0f\u660e\u3002',
     [('\u738b\u5c0f\u660e', 'PERSON')],
     '<NAME \u738b> wrote. \u89c1<NAME \u738b>\u3002'),
    ('Ann Testperson wrote. Testpersons attended',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. <NAME AT>s attended'),
    ("Ann Testperson wrote. the Testpersons' house",
     [('Ann Testperson', 'PERSON')],
     "<NAME AT> wrote. the <NAME AT>s' house"),
    ("Ann Testperson wrote. Testperson's desk",
     [('Ann Testperson', 'PERSON')],
     "<NAME AT> wrote. <NAME AT>'s desk"),
    ('Ann Testperson wrote. Annual report',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. <NAME AT>ual report'),
    ('Ann Testperson wrote. JoAnn left',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. Jo<NAME AT> left'),
    ('Ann Testperson wrote. Annette left',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. <NAME AT>ette left'),
    ('Ann Testperson wrote. Maximus',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. Maximus'),
    ('Sam Rowe | \u017fam Sam',
     [('Sam Rowe', 'PERSON'), ('Sam', 'PERSON')],
     '<NAME SR>ME SR> | <NAME SR> <NAME SR>'),
    ('\u0130lker Aydin met \u0130lker \u0131lker ilker.',
     [('\u0130lker Aydin', 'PERSON')],
     '<NAME \u0130A> met <NAME \u0130A> <NAME \u0130A> <NAME \u0130A>.'),
    ('Sam | \u017fam Sam',
     [('Sam', 'PERSON')],
     '<NAME S> | <NAME S> <NAME S>'),
    ('Ema Lindgren met Erik Lund. Ema Lindgren emailed jane@example.invalid.',
     [('Ema Lindgren', 'PERSON'), ('Erik Lund', 'PERSON'), ('jane@example.invalid', 'EMAIL')],
     '<NAME EL> met <NAME EL2>. <NAME EL> <NAME EL>iled <<<NAME EL>IL_1>>.'),
    ('Ema Lindgren owns ema@example.invalid.',
     [('Ema Lindgren', 'PERSON')],
     '<NAME EL> owns <NAME EL>@example.invalid.'),
    ('Jane Testperson <jane.testperson@example.invalid> wrote.',
     [('Jane Testperson', 'PERSON'), ('jane.testperson@example.invalid', 'EMAIL')],
     '<NAME JT> <<<EMAIL_1>>> wrote.'),
    ('Call 555-867-5309 or 555-867-5309 and 555-000-1111.',
     [('555-867-5309', 'PHONE'), ('555-000-1111', 'PHONE')],
     'Call <<PHONE_1>> or <<PHONE_1>> and <<PHONE_2>>.'),
    ('(Ema Lindgren), <Erik Lund>; "Ema Lindgren" -- jane@example.invalid!',
     [('Ema Lindgren', 'PERSON'), ('Erik Lund', 'PERSON'), ('jane@example.invalid', 'EMAIL')],
     '(<NAME EL>), <<NAME EL2>>; "<NAME EL>" -- <<<NAME EL>IL_1>>!'),
    ('Annual review for Ann Testperson, not JoAnn Smith or Annabel Reed.',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT>ual review for <NAME AT>, not Jo<NAME AT> Smith or <NAME AT>abel Reed.'),
    ('Ann Testperson signed. ANN TESTPERSON agreed. ann testperson countersigned. Testperson done.',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> signed. <NAME AT> agreed. <NAME AT> countersigned. <NAME AT> done.'),
    ('Steve Johnson and Steve met Johnson. STEVE JOHNSON agreed.',
     [('Steve Johnson', 'PERSON')],
     '<NAME SJ> and <NAME SJ> met <NAME SJ>. <NAME SJ> agreed.'),
    ('Maria Garcia Lopez, Maria Garcia, Maria, Lopez.',
     [('Maria Garcia Lopez', 'PERSON')],
     '<NAME MGL>, <NAME MGL> <NAME MGL>, <NAME MGL>, <NAME MGL>.'),
    ('Zed Quill. Quill-Zed. zedquill. ZED_QUILL.',
     [('Zed Quill', 'PERSON')],
     '<NAME ZQ>. <NAME ZQ>-<NAME ZQ>. <NAME ZQ><NAME ZQ>. <NAME ZQ>_<NAME ZQ>.'),
    ('Bob Tan and Bo Tan: bobtan, BobTan, Bobby Tanner.',
     [('Bob Tan', 'PERSON'), ('Bo Tan', 'PERSON')],
     '<NAME BT2> and <NAME BT>: <NAME BT2><NAME BT2>, <NAME BT2><NAME BT2>, <NAME BT2>by <NAME BT2>ner.'),
    ("Dr. Lee Park saw Lee Park's parker. Park Lee too.",
     [('Lee Park', 'PERSON')],
     "Dr. <NAME LP> saw <NAME LP>'s <NAME LP>er. <NAME LP> <NAME LP> too."),
    ('Eve Moss/Eve-Moss/EveMoss/eve.moss/eve@moss.test',
     [('Eve Moss', 'PERSON')],
     '<NAME EM>/<NAME EM>-<NAME EM>/<NAME EM><NAME EM>/<NAME EM>.<NAME EM>/<NAME EM>@<NAME EM>.test'),
    ('Ivy Cole Cole Ivy Ivy Ivy Cole.',
     [('Ivy Cole', 'PERSON')],
     '<NAME IC> <NAME IC> <NAME IC> <NAME IC> <NAME IC>.'),
    ('Tom Ray\nTom Ray\tTom\xa0Ray TOM RAY',
     [('Tom Ray', 'PERSON')],
     '<NAME TR>\n<NAME TR>\t<NAME TR>\xa0<NAME TR> <NAME TR>'),
    ('Ann Testperson, Ann Testperson2, Ann Testperson3 and Anna Testpersona.',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT>, <NAME AT>2, <NAME AT>3 and <NAME AT>a <NAME AT>a.'),
    ('Joan Wu emailed joan.wu@example.invalid; JOAN WU also wrote joanwu@example.invalid.',
     [('Joan Wu', 'PERSON'), ('joan.wu@example.invalid', 'EMAIL')],
     '<NAME JW> emailed <<EMAIL_1>>; <NAME JW> also wrote <NAME JW>wu@example.invalid.'),
    ('Li Na and Na Li and Lina and Nali.',
     [('Li Na', 'PERSON')],
     '<NAME LN> and Na Li and Lina and Nali.'),
    ("Ed Cho edited Edwin Choi and Ed Cho's choir.",
     [('Ed Cho', 'PERSON')],
     "<NAME EC> edited Edwin <NAME EC>i and <NAME EC>'s <NAME EC>ir."),
    ('Ann Testperson Ann Testperson Ann Testperson',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> <NAME AT> <NAME AT>'),
    ('see 555-867-5309, jane@example.invalid, jane@example.invalid.',
     [('555-867-5309', 'PHONE'), ('jane@example.invalid', 'EMAIL')],
     'see <<PHONE_1>>, <<EMAIL_1>>, <<EMAIL_1>>.'),
    ('Ruth Vale; Ruthvale; ruth vale; RUTH   VALE.',
     [('Ruth Vale', 'PERSON')],
     '<NAME RV>; <NAME RV><NAME RV>; <NAME RV>; <NAME RV>   <NAME RV>.'),
    ('\xc9mile Zola met \xe9mile zola; \xc9MILE ZOLA.',
     [('\xc9mile Zola', 'PERSON')],
     '<NAME \xc9Z> met <NAME \xc9Z>; <NAME \xc9Z>.'),
    ('Ann Testperson wrote. AnnTestpersonAnnTestperson',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. <NAME AT><NAME AT><NAME AT><NAME AT>'),
    ('Ann Testperson wrote. Testperson_Ann, ann.testperson, ann-testperson',
     [('Ann Testperson', 'PERSON')],
     '<NAME AT> wrote. <NAME AT>_<NAME AT>, <NAME AT>.<NAME AT>, <NAME AT>-<NAME AT>'),
]

_TAG_RE = re.compile(r"<<[A-Z_]+_\d+>>|<<[A-Z_]+>>|<NAME [^<>]+>")


def _entities(text, spans):
    found = []
    for needle, label in spans:
        for m in re.finditer(re.escape(needle), text):
            found.append(FakeEntity(m.group(), label, m.start(), m.end()))
    return sorted(found, key=lambda e: e.start)


def _residue(redacted):
    """Original characters that survived redaction, tags removed."""
    return _TAG_RE.sub("", redacted)


def _is_subsequence(small, big):
    it = iter(big)
    return all(ch in it for ch in small)


def test_at_least_forty_cases():
    assert len(MAIN_CASES) >= 40


@pytest.mark.parametrize(
    "text,spans,main_output", MAIN_CASES, ids=[str(i) for i in range(len(MAIN_CASES))]
)
def test_redacts_everything_main_redacted(text, spans, main_output):
    redacted, _ = redact(text, _entities(text, spans))
    new_left = _residue(redacted)
    main_left = _residue(main_output)
    assert _is_subsequence(new_left, text), (redacted, text)
    assert _is_subsequence(new_left, main_left), (
        f"under-redacted vs main\n new : {redacted!r}\n main: {main_output!r}"
    )


def test_case_folding_surfaces_do_not_raise():
    # re.IGNORECASE matches characters whose .lower() differs from the surface.
    for text, name in [
        ("Sam | \u017fam Sam", "Sam"),
        ("\u0130lker \u0131lker ilker", "\u0130lker"),
    ]:
        redacted, _ = redact(text, _entities(text, [(name, "PERSON")]))
        assert name not in redacted
