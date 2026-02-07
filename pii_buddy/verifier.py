"""Orchestrate cloud verification: shard -> send -> reassemble -> patch.

This is the main entry point for the verify feature.  It takes
already-redacted text, shards it, sends it to the PII Buddy Verify API,
and applies any additional redactions that the cloud LLM found.
"""

import logging
import re
from collections import defaultdict

from .detector import get_nlp
from .redactor import _make_initials
from .sharder import build_context, neutralize_tags, shard_text, shuffle_shards
from .verify_client import VerifyClient, VerifyError

logger = logging.getLogger("pii_buddy")


def verify_and_patch(redacted_text: str, mapping: dict, settings) -> tuple[str, dict]:
    """Run cloud verification and apply additional redactions.

    Steps:
        1. Neutralize initials-based tags (``<NAME SJ>`` -> ``<<PERSON_A>>``)
        2. Shard text into sentences
        3. Optionally inject canary shards
        4. Shuffle and send to Verify API
        5. Map findings back and apply second redaction pass

    On API error, logs the issue and returns the original text/mapping
    unchanged (graceful degradation).

    Returns:
        (patched_text, updated_mapping)
    """
    # 1. Neutralize tags
    neutral_text, _tag_reverse = neutralize_tags(redacted_text, mapping)

    # 2. Shard
    nlp = get_nlp()
    shards = shard_text(neutral_text, nlp)
    logger.info(f"  Verify: {len(shards)} shards created")

    if not shards:
        return redacted_text, mapping

    # 3. Canaries (optional)
    canary_set = None
    if getattr(settings, "verify_canaries", False):
        try:
            from .canary import generate_canaries
            canary_set = generate_canaries()
            shards.extend(canary_set.shards)
        except ImportError as e:
            logger.warning(f"  Canaries skipped: {e}")

    # 4. Build context, shuffle, send
    doc_type = _detect_doc_type_simple(redacted_text)
    context = build_context(mapping, doc_type)
    shuffled = shuffle_shards(shards)

    client = VerifyClient(
        api_key=settings.verify_api_key,
        endpoint=settings.verify_endpoint,
    )
    try:
        response = client.verify(
            shuffled, context, settings.verify_confidence
        )
    except VerifyError as e:
        logger.error(f"  Verify API error: {e}")
        return redacted_text, mapping

    logger.info(
        f"  Verify: {len(response.findings)} findings, "
        f"{response.shards_processed} shards processed, "
        f"${response.cost_cents / 100:.4f}"
    )

    # 5. Evaluate canaries
    if canary_set and canary_set.shards:
        try:
            from .canary import evaluate_canaries
            report = evaluate_canaries(canary_set, response.findings)
            logger.info(
                f"  Canary detection: "
                f"{report['detected']}/{report['injected']}"
            )
        except Exception:
            pass

    # 6. Filter to real (non-canary) findings
    canary_ids = canary_set.ids if canary_set else set()
    real_findings = [
        f for f in response.findings if f.shard_id not in canary_ids
    ]

    if not real_findings:
        return redacted_text, mapping

    # 7. Apply second redaction pass
    return _apply_findings(redacted_text, mapping, real_findings)


def _apply_findings(
    text: str, mapping: dict, findings
) -> tuple[str, dict]:
    """Apply verified findings as additional redactions."""
    tags = dict(mapping.get("tags", {}))
    persons = dict(mapping.get("persons", {}))

    # Figure out existing tag numbering to avoid collisions
    type_max = defaultdict(int)
    initials_max: dict[str, int] = defaultdict(int)

    for tag in tags:
        # Person tags: <NAME SJ>, <NAME SJ2>, etc.
        pm = re.match(r"^<NAME ([A-Z]+?)(\d+)?>$", tag)
        if pm:
            n = int(pm.group(2)) if pm.group(2) else 1
            initials_max[pm.group(1)] = max(initials_max[pm.group(1)], n)
            continue
        # Numbered type tags: <<EMAIL_1>>, <<PHONE_2>>, etc.
        inner = tag.strip("<>")
        m = re.match(r"^([A-Z]+)_(\d+)$", inner)
        if m:
            type_max[m.group(1)] = max(type_max[m.group(1)], int(m.group(2)))

    patched = text
    applied = 0

    for finding in findings:
        pii_text = finding.text

        # Skip if it's already a tag or contains tag markers
        if "<NAME " in pii_text or "<<" in pii_text or ">>" in pii_text:
            continue

        # Skip if already redacted (text is a known original value)
        if pii_text in tags.values():
            continue

        # Must actually appear in the text
        if pii_text not in patched:
            continue

        # Assign tag
        if finding.entity_type == "PERSON":
            initials = _make_initials(pii_text)
            initials_max[initials] += 1
            if initials_max[initials] > 1:
                tag = f"<NAME {initials}{initials_max[initials]}>"
            else:
                tag = f"<NAME {initials}>"
            persons[pii_text] = tag
        else:
            type_max[finding.entity_type] += 1
            n = type_max[finding.entity_type]
            tag = f"<<{finding.entity_type}_{n}>>"

        tags[tag] = pii_text

        # Replace all occurrences (case-insensitive, like redactor.py)
        pattern = re.compile(re.escape(pii_text), re.IGNORECASE)
        patched = pattern.sub(tag, patched)
        applied += 1

    if applied:
        logger.info(f"  Verify: {applied} additional redactions applied")

    updated_mapping = dict(mapping)
    updated_mapping["tags"] = tags
    updated_mapping["persons"] = persons
    return patched, updated_mapping


def _detect_doc_type_simple(text: str) -> str:
    """Lightweight doc-type detection from redacted text."""
    sample = text[:1000].lower()
    if any(kw in sample for kw in (
        "resume", "curriculum vitae", "work experience", "education",
    )):
        return "resume"
    if any(kw in sample for kw in ("interviewer:", "speaker", "q:", "a:")):
        return "transcript"
    return "general"
