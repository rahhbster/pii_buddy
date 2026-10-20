"""restore and redact must stay linear in the number of tags / entities.

t(2N) / t(N) is ~2 for a single-pass restore and ~4 for a per-key replace loop
(or the old redactor `_free_tag` rescan from 1 for every email). Same CPU-time,
minimum-of-five harness as the detector tests. The public restore_text is capped
at 10,000 mapping entries and 200,000 characters, so its inputs are small and
t(N) sits near the 5 ms default floor; those cases use a lower constant floor
so a 4x blow-up still fails rather than hiding under it.
"""

import json
import re

from pii_buddy import core
from pii_buddy.redactor import redact
from pii_buddy.restorer import restore
from tests._scaling import assert_ratio_linear, best_of
from tests.conftest import FakeEntity

SMALL_FLOOR_S = 0.002


def _tags_and_text(n, repeats=1):
    mapping = {f"<<EMAIL_{i}>>": f"user{i}@example.test" for i in range(1, n + 1)}
    text = "".join(f"<<EMAIL_{i}>> x " * repeats for i in range(1, n + 1))
    return text, mapping


def _check_ratio(run, make, label, small, floor):
    t_small = best_of(run, make(small))
    t_large = best_of(run, make(small * 2))
    assert_ratio_linear(t_small, t_large, label, small, small * 2, floor=floor)


def test_restore_text_scales_linearly_in_tags():
    def make(n):
        text, mapping = _tags_and_text(n, repeats=2)
        assert len(text) <= core.MAX_RESTORE_TEXT_CHARS
        return text, mapping

    def run(args):
        text, mapping = args
        return core.restore_text(text, mapping)

    _check_ratio(run, make, "restore_text", 2_500, SMALL_FLOOR_S)
    restored = run(make(5_000))
    assert restored.count("@example.test") == 10_000 and "<<" not in restored


def _mapping_file(tmp_path, name, mapping):
    path = tmp_path / name
    path.write_text(json.dumps({"tags": mapping}), encoding="utf-8")
    return path


def test_restorer_path_scales_linearly_in_text(tmp_path):
    """Fixed 1,000-key mapping, 2x the tag occurrences -> ~2x the time.

    The restorer path is one alternation regex over the keys, so each tag
    occurrence costs O(keys); the key count itself is guarded separately below.
    """
    mapping = {f"<<EMAIL_{i}>>": f"user{i}@example.test" for i in range(1, 1_001)}
    path = _mapping_file(tmp_path, "mapping.json", mapping)

    def make(n):
        return "".join(f"<<EMAIL_{i % 1_000 + 1}>> x " for i in range(n)), path

    def run(args):
        text, path = args
        return restore(text, path)

    _check_ratio(run, make, "restorer.restore (text)", 10_000, SMALL_FLOOR_S)
    restored = run(make(20_000))
    assert restored.count("@example.test") == 20_000 and "<<" not in restored


REFERENCE_RATIO_LIMIT = 24


def test_restorer_path_stays_close_to_single_pass_restore(tmp_path):
    """5,000 tags: restorer.restore vs the linear core.restore_text, same input.

    The alternation regex is O(keys x occurrences), so t(2N)/t(N) is ~3.4 for
    correct code and cannot tell it from a per-key str.replace loop. Their
    cost relative to the single-pass reference can: ~8x for the real code,
    ~50x for the loop, and the ratio does not depend on machine speed.
    """
    text, mapping = _tags_and_text(5_000)
    path = _mapping_file(tmp_path, "mapping.json", mapping)
    t_restorer = best_of(lambda a: restore(*a), (text, path))
    t_reference = best_of(lambda a: core.restore_text(*a), (text, mapping))
    ratio = t_restorer / max(t_reference, SMALL_FLOOR_S)
    assert ratio < REFERENCE_RATIO_LIMIT, (
        f"restorer.restore {t_restorer:.3f}s vs restore_text {t_reference:.3f}s "
        f"= {ratio:.1f}x, expected ~8x"
    )
    assert restore(text, path).count("@example.test") == 5_000


def _email_entities(n):
    text = " ".join(f"user{i}@example.test" for i in range(n))
    ents = [FakeEntity(m.group(), "EMAIL", m.start(), m.end())
            for m in re.finditer(r"\S+", text)]
    return text, ents


def test_redact_scales_linearly_in_distinct_emails():
    def run(args):
        return redact(*args)

    _check_ratio(run, _email_entities, "redact emails", 4_000, SMALL_FLOOR_S)
    redacted, mapping = run(_email_entities(8_000))
    assert len(mapping["tags"]) == 8_000 and "@" not in redacted


def test_redact_text_scales_linearly_in_distinct_emails():
    def make(n):
        return " ".join(f"user{i}@example.test" for i in range(n))

    def run(text):
        return core.redact_text(text)

    run(make(50))
    _check_ratio(run, make, "redact_text emails", 500, 0.005)
    result = run(make(1_000))
    assert len(result.mapping) == 1_000 and "@" not in result.redacted_text
