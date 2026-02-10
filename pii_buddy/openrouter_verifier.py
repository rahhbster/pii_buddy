"""Pass 3 — OpenRouter LLM verification of redacted text.

Orchestrates sharding, batching, API calls, and applying findings.
Mirrors verifier.py structure but uses OpenRouter instead of the
PII Buddy Verify API.
"""

import logging

from .detector import get_nlp
from .openrouter_client import OpenRouterClient, OpenRouterError
from .sharder import neutralize_tags, shard_text
from .verifier import _apply_findings

logger = logging.getLogger("pii_buddy")

# Number of shards to combine per API call
_BATCH_SIZE = 5


def openrouter_verify_and_patch(
    redacted_text: str, mapping: dict, settings
) -> tuple[str, dict]:
    """Run OpenRouter LLM verification and apply additional redactions.

    Steps:
        1. Neutralize tags (hide initials from the LLM)
        2. Shard text into sentences
        3. Batch shards into groups
        4. Send each batch to OpenRouter
        5. Collect and apply findings

    On API error, logs the issue and returns original text/mapping
    unchanged (graceful degradation).

    Returns:
        (patched_text, updated_mapping)
    """
    # 1. Neutralize tags
    neutral_text, _tag_reverse = neutralize_tags(redacted_text, mapping)

    # 2. Shard
    nlp = get_nlp()
    shards = shard_text(neutral_text, nlp)
    logger.info(f"  OpenRouter: {len(shards)} shards created")

    if not shards:
        return redacted_text, mapping

    # 3. Batch shards
    batches = []
    for i in range(0, len(shards), _BATCH_SIZE):
        batch = shards[i : i + _BATCH_SIZE]
        batches.append(batch)

    # 4. Send batches to OpenRouter
    client = OpenRouterClient(
        api_key=settings.openrouter_api_key,
        model=getattr(settings, "openrouter_model", "meta-llama/llama-3.1-8b-instruct:free"),
        endpoint=getattr(settings, "openrouter_endpoint", "https://openrouter.ai/api/v1"),
    )

    all_findings = []
    for batch_idx, batch in enumerate(batches):
        combined = "\n\n".join(s.text for s in batch)
        try:
            response = client.check_pii(combined)
            all_findings.extend(response.findings)
        except OpenRouterError as e:
            logger.error(f"  OpenRouter batch {batch_idx + 1} error: {e}")
            # Continue with remaining batches

    logger.info(f"  OpenRouter: {len(all_findings)} findings from {len(batches)} batches")

    if not all_findings:
        return redacted_text, mapping

    # 5. Apply findings
    return _apply_findings(redacted_text, mapping, all_findings)
