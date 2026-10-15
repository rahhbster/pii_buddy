"""Regenerate tests/data/main_covered_spans.json from origin/main's detector.

Like make_baseline_corpus.py, but frozen from the detector on main: for each
input, the character offsets (whitespace excluded) main redacted. Only inputs on
which main redacted something are kept. The tests assert the current detector
covers a superset without needing git.

    python tests/data/make_main_corpus.py path/to/main_detector.py

Run it from the repo root with PII_BUDDY_DIR pointing at a scratch directory.
"""

import importlib.util
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.test_detector_adjacency import _FLAT, _SEPS, _join  # noqa: E402

SEED = 20261015
N_RANDOM = 900
WIDE_SEPS = _SEPS + ["_", "--", "–", "+", "%", ".", "=", " _ "]
EXTRA_ITEMS = ["x.y@z.io", "m@n.co", "ab@cd.ef", "me+tag@mail.example.com"]

REPROS = [
    "jo.q@example.com+sam+x@x.io",
    "jo.q@example.com.sam@x.io",
    "jo.q@example.com_sam@x.io",
    "jo.q@example.com%sam@x.io",
    "a@b.co+c@d.io+e@f.org",
    "mail jo.q@example.com+sam@x.io now",
    "<a@b.co>+<c@d.io>",
    "a@b.co,c@d.io;e@f.org",
]


def main():
    spec = importlib.util.spec_from_file_location(
        "pii_buddy.detector_main", sys.argv[1])
    main_det = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = main_det
    spec.loader.exec_module(main_det)

    rng = random.Random(SEED)
    pool = _FLAT + EXTRA_ITEMS
    texts = list(REPROS)
    seen = set(texts)
    while len(texts) < N_RANDOM + len(REPROS):
        k = 3 if rng.random() < 0.25 else 2
        text = _join([rng.choice(pool) for _ in range(k)], rng.choice(WIDE_SEPS))
        if text not in seen:
            seen.add(text)
            texts.append(text)

    cases = []
    for text in texts:
        covered = sorted(
            {i for e in main_det.detect_pii(text, doc_type="general")
             for i in range(e.start, e.end) if not text[i].isspace()}
        )
        if covered:
            cases.append({"text": text, "covered": covered})
    out = Path(__file__).with_name("main_covered_spans.json")
    out.write_text(json.dumps(
        {"baseline": "origin/main", "cases": cases}, ensure_ascii=True, indent=0))
    print(f"wrote {len(cases)} cases to {out}")


if __name__ == "__main__":
    main()
