"""Regenerate tests/data/baseline_covered_spans.json from commit 63c332d.

The corpus freezes, for each input, the exact character offsets (whitespace
excluded) that the reviewed baseline detector redacted. The tests then assert
the current detector covers a superset of them without needing git.

    python tests/data/make_baseline_corpus.py [path/to/baseline_detector.py]

With no argument the baseline source is read with ``git show 63c332d:...``.
Run it from the repo root with PII_BUDDY_DIR pointing at a scratch directory.
"""

import importlib.util
import json
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.test_detector_adjacency import _FLAT, _SEPS, _join  # noqa: E402

BASELINE = "63c332d"
SEED = 20261014
N_RANDOM = 1100
WIDE_SEPS = _SEPS + ["_", "--", "–", "—", "−", " ", " ",
                     "..", "=", " _ ", " - ", "- ", " -"]

REPROS = [
    "10001-0001_5368 4891 5817 2437",
    "4425–0862–0541–93|1990-12-25T10:00:00",
    "5304 5315 9817 6-1990-12-25T10:00:00",
    "6554 5738 3778 3458 020 7946 0958",
    "6963 6423 2534 7-020 7946 0958",
    "098765 43210--6963 6423 2534 7",
    "INV-5642-29793087-1525", "ref 91-4066-4944-80939-07",
    "INV-8552-80387294-1242",
]


def _load_baseline(source: str):
    path = Path(sys.argv[0]).with_name("_baseline_detector_tmp.py")
    path.write_text(source)
    try:
        spec = importlib.util.spec_from_file_location("pii_buddy.detector_baseline", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
    finally:
        path.unlink()
    return mod


def main():
    if len(sys.argv) > 1:
        source = Path(sys.argv[1]).read_text()
    else:
        source = subprocess.run(
            ["git", "show", f"{BASELINE}:pii_buddy/detector.py"],
            capture_output=True, text=True, check=True, cwd=ROOT,
        ).stdout
    base = _load_baseline(source)

    rng = random.Random(SEED)
    texts = list(REPROS)
    seen = set(texts)
    while len(texts) < N_RANDOM + len(REPROS):
        k = 3 if rng.random() < 0.25 else 2
        items = [rng.choice(_FLAT) for _ in range(k)]
        text = _join(items, rng.choice(WIDE_SEPS))
        if text not in seen:
            seen.add(text)
            texts.append(text)

    corpus = []
    for text in texts:
        covered = sorted(
            {i for e in base.detect_pii(text, doc_type="general")
             for i in range(e.start, e.end) if not text[i].isspace()}
        )
        corpus.append({"text": text, "covered": covered})
    out = Path(__file__).with_name("baseline_covered_spans.json")
    out.write_text(json.dumps(
        {"baseline": BASELINE, "cases": corpus}, ensure_ascii=True, indent=0))
    print(f"wrote {len(corpus)} cases to {out}")


if __name__ == "__main__":
    main()
