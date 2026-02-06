"""Optional canary injection for verification calibration.

Injects synthetic PII sentences into shard batches to test whether the
cloud LLM is actually detecting PII.  Requires the ``faker`` package
(``pip install faker``).  Off by default — enable with ``verify_canaries``.
"""

import uuid
from dataclasses import dataclass, field

from .sharder import Shard


@dataclass
class CanarySet:
    """A batch of canary shards with their expected findings."""
    shards: list[Shard] = field(default_factory=list)
    # shard_id -> list of expected findings
    expected: dict[str, list[dict]] = field(default_factory=dict)

    @property
    def ids(self) -> set[str]:
        return {s.id for s in self.shards}


def generate_canaries(count: int = 3) -> CanarySet:
    """Generate synthetic PII sentences using faker.

    Returns a CanarySet with shards (is_canary=True) and a mapping of
    expected findings for later evaluation.

    Raises ImportError if faker is not installed.
    """
    try:
        from faker import Faker
    except ImportError:
        raise ImportError(
            "Canary generation requires the 'faker' package. "
            "Install it with: pip install faker"
        )

    fake = Faker()
    result = CanarySet()

    # Each template produces a sentence with known PII
    templates = _build_templates(fake)

    for template in templates[:count]:
        shard_id = str(uuid.uuid4())
        shard = Shard(
            id=shard_id,
            text=template["text"],
            start=-1,
            end=-1,
            is_canary=True,
        )
        result.shards.append(shard)
        result.expected[shard_id] = template["findings"]

    return result


def _build_templates(fake) -> list[dict]:
    """Build canary templates with known PII."""
    name1 = fake.name()
    email1 = fake.email()

    name2 = fake.name()
    phone2 = fake.phone_number()

    name3 = fake.name()
    date3 = fake.date(pattern="%B %d, %Y")

    return [
        {
            "text": f"Please forward all documents to {name1} at {email1}.",
            "findings": [
                {"text": name1, "type": "PERSON"},
                {"text": email1, "type": "EMAIL"},
            ],
        },
        {
            "text": f"Contact {name2} by phone at {phone2} for project details.",
            "findings": [
                {"text": name2, "type": "PERSON"},
                {"text": phone2, "type": "PHONE"},
            ],
        },
        {
            "text": f"The report was prepared by {name3} on {date3}.",
            "findings": [
                {"text": name3, "type": "PERSON"},
                {"text": date3, "type": "DOB"},
            ],
        },
    ]


def evaluate_canaries(canary_set: CanarySet, all_findings) -> dict:
    """Compare expected vs actual findings for canary shards.

    Args:
        canary_set: The CanarySet returned by generate_canaries().
        all_findings: Full list of Finding objects from the API response.

    Returns:
        Report dict with injected/detected counts and detection_rate.
    """
    canary_findings = {
        sid: [] for sid in canary_set.expected
    }
    for f in all_findings:
        if f.shard_id in canary_findings:
            canary_findings[f.shard_id].append(f)

    detected = 0
    missed = []
    total = len(canary_set.expected)

    for shard_id, expected_list in canary_set.expected.items():
        found_types = {f.entity_type for f in canary_findings.get(shard_id, [])}
        expected_types = {e["type"] for e in expected_list}
        if found_types & expected_types:
            detected += 1
        else:
            missed.append(shard_id)

    return {
        "injected": total,
        "detected": detected,
        "detection_rate": detected / total if total > 0 else 0.0,
        "missed_shard_ids": missed,
    }
