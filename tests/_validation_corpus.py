"""Fake documents for the validation differential test, and the capture helper.

`python -m tests._validation_corpus` rewrites tests/data/validation_frozen.json
from the code currently checked out. The frozen file was generated once from
origin/main's validation.py; regenerate it only on purpose.
"""

import json
import random
import sys
from pathlib import Path

from pii_buddy import detector

FROZEN = Path(__file__).parent / "data" / "validation_frozen.json"

FIRST = ["Ann", "Bob", "Carla", "Dev", "Elena", "Farid", "Gwen", "Hiro", "Ines",
         "Jonas", "Kira", "Liam", "Mina", "Noor", "Omar", "Priya", "Quinn",
         "Rosa", "Sam", "Tara", "Uma", "Vik", "Wren", "Xavi", "Yara", "Zed"]
LAST = ["Testperson", "Roe", "Faker", "Placeholder", "Examplar", "Nobody",
        "Smith", "Okafor", "Lindqvist", "Marlowe", "Quillfeather", "Brightwater",
        "McDonald", "O'Neil", "Van Der Berg", "De La Cruz", "Smith-Jones"]
TITLES = ["Mr.", "Mrs.", "Ms.", "Dr.", "Prof.", "Sir"]
JOBS = ["Senior Software Engineer", "Product Manager", "Data Analyst",
        "Scrum Master", "Vice President", "Technical Lead", "Cloud Architect",
        "Lead Frontend Developer", "Managing Director", "Security Administrator"]
HEADERS = ["Education", "Skills", "Work Experience", "Professional Summary",
           "References", "Certifications", "Projects", "Languages"]
CERTS = ["AWS Certified Solutions Architect", "PMP", "Google Cloud", "Six Sigma"]
ORGS = ["Acme Widgets Inc.", "Globex Corporation", "Initech", "Umbrella Labs",
        "Paris", "Berlin", "Springfield", "Mount Testmore"]
VERBS = ["met", "called", "emailed", "thanked", "hired", "interviewed",
         "introduced", "replied to"]
PROSE = ["The quarterly report was delivered on time.",
         "Please review the attached notes before Friday.",
         "Lunch will be served in the main hall.",
         "The system was restarted after the update.",
         "Traffic was heavy on the bridge this morning."]


def _name(rng):
    return f"{rng.choice(FIRST)} {rng.choice(LAST)}"


def build_docs():
    rng = random.Random(20261017)
    docs = ["", " ", "\n\n", "No names here at all.", "x", "...", "A"]

    for t in TITLES:
        for last in ("Smith", "Okafor", "Testperson"):
            docs.append(f"{t} {last} arrived early. {t} {last} left late.")
            docs.append(f"I spoke with {t} {last}, who agreed.")

    for _ in range(45):
        docs.append(f"{_name(rng)} {rng.choice(VERBS)} {_name(rng)} on Monday. "
                    f"{rng.choice(PROSE)}")

    for _ in range(35):
        docs.append(f"{_name(rng)}\n{rng.choice(JOBS)}\n\n{rng.choice(HEADERS)}\n"
                    f"{rng.choice(PROSE)}")
        docs.append(f"{_name(rng)} {rng.choice(JOBS)} at {rng.choice(ORGS)}.")

    for h in HEADERS:
        docs.append(f"{h}\n{_name(rng)} worked at {rng.choice(ORGS)}.\n{h}\nNone.")
    for c in CERTS:
        docs.append(f"{_name(rng)}\n{c}\n{rng.choice(PROSE)}")
        docs.append(f"Certified: {c} and {_name(rng)}.")

    for _ in range(25):
        n = _name(rng)
        docs.append(f"{n} wrote the memo. Later, {n} sent it. {n}'s desk is clean. "
                    f"Then {n.split()[0]} left.")
    for _ in range(15):
        n = _name(rng)
        docs.append(" ".join(f"{n} {rng.choice(VERBS)} {_name(rng)}." for _ in range(8)))

    for _ in range(25):
        n = _name(rng).upper()
        docs.append(f"{n}\n{rng.choice(JOBS)}\n{rng.choice(PROSE)}")
        docs.append(f"{n} - {rng.choice(JOBS)}\n\nSUMMARY\n{rng.choice(PROSE)}")
    docs.append("SAM TESTPERSON\nSAM TESTPERSON SAM TESTPERSON")

    for _ in range(25):
        a, b = _name(rng), _name(rng)
        docs.append(f"# {a} and {b} - {rng.choice(JOBS)}\n\n{rng.choice(PROSE)}")
        docs.append(f"{a} - {rng.choice(JOBS)}\n{rng.choice(PROSE)}")

    for _ in range(30):
        n = _name(rng)
        ph = f"({rng.randint(200, 999)}) 555-{rng.randint(1000, 9999)}"
        em = f"{n.split()[0].lower()}@example.com"
        docs.append(f"{n} {em} {ph}")
        docs.append(f"Contact: {n}, {em}, {ph}. {rng.choice(PROSE)}")
        docs.append(f"{em} {n} 4111 1111 1111 1111 {_name(rng)}")
        docs.append(f"{n}{em} {ph}{_name(rng)}")

    for _ in range(15):
        docs.append(f"{_name(rng)} lives in {rng.choice(ORGS)} and works for "
                    f"{rng.choice(ORGS)}. {rng.choice(PROSE)}")
        docs.append(f"{rng.choice(ORGS)} hired {_name(rng)}.")

    docs.append("Sam, " * 40)
    docs.append("John Smith, " * 30)
    docs.append("Mr. Smith, " * 30)
    docs.append(", ".join(_name(rng) for _ in range(60)))
    docs.append("\n".join(_name(rng) for _ in range(60)))
    docs.append(" ".join(f"{rng.choice(TITLES)} {rng.choice(LAST)}" for _ in range(50)))
    docs.append(" ".join(rng.choice(PROSE) + " " + _name(rng) for _ in range(40)))
    docs.append("Dr. Ann Lee-Testperson and Marie-Anne Faker met bin Nobody and "
                "von Quillfeather. Ana de la Cruz agreed. Jo Li waved. Al Ng spoke.")
    docs.append("Name1 Testperson and 3rd Person met Bob\tRoe and Ann Lee.")
    docs.append("王小明 met Ann Testperson. Zoë Nobody replied.")
    return docs


def capture(text):
    """Run detect_pii, returning the validated list (as plain tuples)."""
    seen = []
    real = detector.validate_entities

    def spy(entities, txt, doc, doc_type="general"):
        out = real(entities, txt, doc, doc_type)
        seen.append([(e.text, e.label, e.start, e.end, e.confidence) for e in out])
        return out

    detector.validate_entities = spy
    try:
        detector.detect_pii(text)
    finally:
        detector.validate_entities = real
    assert len(seen) == 1
    return seen[0]


def main():
    docs = build_docs()
    rows = [{"text": d, "validated": capture(d)} for d in docs]
    FROZEN.write_text(json.dumps(rows, ensure_ascii=False, indent=0) + "\n",
                      encoding="utf-8")
    print(f"wrote {len(rows)} rows to {FROZEN}", file=sys.stderr)


if __name__ == "__main__":
    main()
