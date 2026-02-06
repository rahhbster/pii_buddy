# PII Buddy Verify: Cloud Verification Architecture

## Table of Contents

1. [Overview](#overview)
2. [Pipeline Integration](#pipeline-integration)
3. [Sharding Protocol](#sharding-protocol)
4. [Tag Neutralization](#tag-neutralization)
5. [Verification Prompt Design](#verification-prompt-design)
6. [API Specification](#api-specification)
7. [Security Analysis](#security-analysis)
8. [When Verification Helps vs Doesn't](#when-verification-helps-vs-doesnt)
9. [Canary Injection](#canary-injection)
10. [Business Model](#business-model)
11. [Implementation Roadmap](#implementation-roadmap)
12. [Repository Structure](#repository-structure)

---

## Overview

PII Buddy Verify adds optional cloud-based PII verification to the existing local redaction pipeline. After local redaction completes, the already-redacted text is sharded, shuffled, and sent to a cloud LLM to catch what spaCy missed. This targets the known weak spots in local NER: international names, unusual formatting, and contextual PII.

The service is offered as "PII Buddy Verify" — a paid API where the PII Buddy operator manages LLM keys and infrastructure, and users pay per-shard via API key.

### Design Principles

- **Local-first**: Verification is optional. PII Buddy works fully offline without it.
- **Already-redacted**: Only redacted text leaves the machine. The cloud sees `<<PERSON_A>>` tags, not real PII.
- **Honest about limits**: Sharding provides marginal privacy. The real protection is that text is already redacted. We document this clearly.
- **Stateless server**: The Verify API never stores shard text. Usage-only logging.

---

## Pipeline Integration

### Current Pipeline

```
extract -> detect -> redact -> write
```

### With Verification

```
extract -> detect -> redact -> [verify] -> apply fixes -> write
```

The `[verify]` step slots between redaction (`redactor.redact()`) and output writing (`writers.write_output()`) in `watcher.py:process_file()`. The verifier returns additional `PIIEntity` objects that get applied as a second redaction pass.

### Integration Point

In `watcher.py:process_file()`, after the call to `redact(text, entities)` (line ~99) and before output writing:

```python
# Existing
redacted_text, mapping = redact(text, entities)

# New (when verify_enabled)
if settings.verify_enabled and settings.verify_api_key:
    from pii_buddy.verifier import verify_and_patch
    redacted_text, mapping = verify_and_patch(
        redacted_text, mapping, settings
    )

# Existing (continues)
clean_name = _redact_filename(filepath.stem, mapping.get("persons", {}))
```

The `verify_and_patch()` function:
1. Neutralizes initials-based tags
2. Shards the redacted text
3. Sends shards to the Verify API
4. Maps findings back to document positions
5. Applies additional redactions to `redacted_text`
6. Updates `mapping` with new tags
7. Returns the patched text and updated mapping

---

## Sharding Protocol

### Sentence Splitting

**Unit:** Individual sentences, split using spaCy's sentencizer (already loaded in `detector.py`).

**Merge rule:** Sentences under 5 words merge with their predecessor. This prevents micro-shards that leak sentence boundaries.

**Cap:** 200 tokens per shard. Sentences exceeding this split at the nearest whitespace boundary.

### UUID Assignment

Each shard gets a `uuid4()` identifier. Shards are never sequentially numbered — the server cannot infer document order from IDs.

### Shuffling

Cryptographically random permutation using `secrets.SystemRandom().shuffle()`. The client retains the original order mapping for reassembly.

### Context Header

Each shard includes a context header with entity-type counts only:

```json
{
  "entity_counts": {"PERSON": 3, "EMAIL": 2, "PHONE": 1},
  "document_type": "resume"
}
```

No tag values. No initials. No entity text. This gives the LLM enough context to calibrate its detection ("this is a resume with 3 people mentioned") without leaking identifying information.

### What Shuffling Buys

Marginal privacy against passive observers and honest-but-curious operators. A single intercepted shard is one out-of-context sentence with redacted PII. However, the server sees all shards for a request and could theoretically reassemble them (sentence flow is often guessable).

**The real privacy comes from the text being already redacted.** Shuffling is defense-in-depth, not a primary control.

---

## Tag Neutralization

Before sharding, initials-based tags are replaced with generic sequential tags to prevent initials-based re-identification.

### Mapping

| Original Tag | Neutralized Tag |
|---|---|
| `<<SJ>>` | `<<PERSON_A>>` |
| `<<SJ2>>` | `<<PERSON_B>>` |
| `<<EMAIL_1>>` | `<<EMAIL_A>>` |
| `<<PHONE_1>>` | `<<PHONE_A>>` |

The client retains the neutralization mapping. After verification results return, findings reference neutralized tags, which the client maps back to the original tags.

### Why This Matters

Without neutralization, `<<SJ>>` reveals that the redacted person has initials S.J. Combined with other context in the shard (job title, company name), this could narrow identification significantly. `<<PERSON_A>>` reveals only that a person entity exists.

---

## Verification Prompt Design

The LLM prompt sent with each shard batch instructs the model to find PII that was missed by the initial redaction pass.

### System Prompt

```
You are a PII detection auditor. You receive text that has already been partially
redacted (tags like <<PERSON_A>>, <<EMAIL_A>> indicate redacted entities).

Your job: find any remaining PII that was MISSED by the initial redaction.

Look for:
- Person names (especially international/uncommon names)
- Email addresses, phone numbers, SSNs
- Physical addresses
- Dates of birth
- URLs that could identify someone (LinkedIn profiles, personal websites)
- ID numbers (driver's license, passport, employee IDs)
- Any other personally identifying information

For each finding, return:
- The exact text found
- The PII type (PERSON, EMAIL, PHONE, SSN, URL, DOB, ID_NUMBER, ADDRESS)
- Your confidence (0.0-1.0)
- Character offsets within the shard text

Do NOT flag the existing redaction tags (<<PERSON_A>>, etc.) as findings.
Do NOT flag organization names, job titles, or generic terms.
Only flag information that could identify a specific individual.

Respond in JSON format only.
```

### Per-Shard User Prompt

```
Shard context: This text is from a {document_type} containing {entity_counts}.

Text to audit:
---
{shard_text}
---

Return findings as JSON array. Empty array [] if no missed PII found.
```

### Why Sentence-Level, Not Document-Level

Sending the full document would give the LLM maximum context for detection but would also send the full redacted document to a third party in one request. Sentence-level sharding means each shard is a small, context-limited fragment. The trade-off: the LLM may miss PII that requires cross-sentence context (e.g., "she graduated from [same university as person mentioned 3 paragraphs ago]").

---

## API Specification

### Authentication

```
Authorization: Bearer <api_key>
```

API keys are issued by the PII Buddy Verify service (website/signup). The key identifies the user account for billing and rate limiting.

### Verify Endpoint

```
POST /v1/verify
Content-Type: application/json
Authorization: Bearer <api_key>
```

#### Request

```json
{
  "shards": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "text": "Worked as senior engineer at Acme Corp alongside <<PERSON_A>>.",
      "context": {
        "entity_counts": {"PERSON": 3, "EMAIL": 2, "PHONE": 1},
        "document_type": "resume"
      }
    },
    {
      "id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
      "text": "Contact Rajesh at the Mumbai office for project details.",
      "context": {
        "entity_counts": {"PERSON": 3, "EMAIL": 2, "PHONE": 1},
        "document_type": "resume"
      }
    }
  ],
  "options": {
    "confidence_threshold": 0.7,
    "include_canary_report": false
  }
}
```

**Field descriptions:**

| Field | Type | Required | Description |
|---|---|---|---|
| `shards` | array | yes | List of shard objects to verify |
| `shards[].id` | string (UUID) | yes | Client-generated unique ID |
| `shards[].text` | string | yes | Redacted text to audit |
| `shards[].context` | object | no | Entity counts and document type hint |
| `options.confidence_threshold` | float | no | Minimum confidence for returned findings (default: 0.7) |
| `options.include_canary_report` | bool | no | Whether to include canary detection results (default: false) |

#### Response

```json
{
  "results": [
    {
      "shard_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "findings": []
    },
    {
      "shard_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
      "findings": [
        {
          "text": "Rajesh",
          "type": "PERSON",
          "confidence": 0.85,
          "start_offset": 8,
          "end_offset": 14
        }
      ]
    }
  ],
  "usage": {
    "shards_processed": 2,
    "tokens_used": 420,
    "cost_cents": 0.2
  },
  "canary_report": null
}
```

**Finding fields:**

| Field | Type | Description |
|---|---|---|
| `text` | string | The missed PII text |
| `type` | string | PII type: PERSON, EMAIL, PHONE, SSN, URL, DOB, ID_NUMBER, ADDRESS |
| `confidence` | float | Model's confidence (0.0-1.0) |
| `start_offset` | int | Character offset within shard text |
| `end_offset` | int | Character offset within shard text |

#### Error Responses

```json
// 401 Unauthorized
{"error": "invalid_api_key", "message": "API key is invalid or expired."}

// 402 Payment Required
{"error": "quota_exceeded", "message": "Monthly shard quota exceeded. Upgrade at https://piibuddy.dev/pricing"}

// 429 Too Many Requests
{"error": "rate_limited", "message": "Rate limit exceeded. Retry after 2 seconds.", "retry_after": 2}

// 422 Unprocessable Entity
{"error": "validation_error", "message": "Shard text exceeds maximum length of 2000 characters."}
```

### Health Endpoint

```
GET /v1/health

Response:
{"status": "ok", "version": "1.0.0"}
```

### Usage Endpoint

```
GET /v1/usage
Authorization: Bearer <api_key>

Response:
{
  "period": "2026-02",
  "shards_used": 847,
  "shards_limit": 5000,
  "cost_cents": 84.7
}
```

---

## Security Analysis

### Threat Model

| Threat | Risk Level | Analysis |
|---|---|---|
| Network eavesdropper | Low | TLS encrypts transit. Even if intercepted, content is redacted and shuffled. One captured shard = one out-of-context sentence with PII already replaced by tags. |
| Compromised Verify server | Medium | Server sees all shards for a request. Text is redacted, but missed PII (the whole point of the service) passes through in cleartext. Sharding limits surrounding context but cannot prevent transmission of missed PII. |
| LLM provider logging | Low-Medium | LLM provider sees shards but cannot map them to end users (the API key is the Verify server's, not the end user's). Provider would need to collude with the Verify server operator to link shards to users. |
| Tag-based re-identification | Low (with neutralization) | Generic `<<PERSON_A>>` tags reveal entity count but not initials. Without neutralization, `<<SJ>>` + context could narrow identification. |
| Shard reassembly | Medium | An adversary with all shards from a request could attempt to reassemble document order based on sentence flow. Shuffling makes this harder but not impossible for coherent documents. |
| Client-side key theft | Medium | If an end user's API key is stolen, the attacker gets billing access but no access to previously processed documents (server is stateless). |

### The Inherent Paradox

The service exists to find missed PII. Therefore, any PII it finds necessarily passes through the server. Sharding limits how much context surrounds that missed PII, but cannot prevent its transmission.

**We are transparent about this.** Users who choose verification are accepting that missed PII will transit through the Verify server in exchange for better detection. Users who need absolute local-only processing should not enable verification.

### Data Handling Guarantees

1. **No shard storage**: The server processes shards in-memory and discards them after returning results. No database, no filesystem writes, no message queues that persist shard text.
2. **Usage-only logging**: Logs contain API key, shard count, token count, timestamps. Never shard text.
3. **No cross-request correlation**: The server does not link shards across requests. Each request is independent.
4. **TLS required**: The API endpoint only accepts HTTPS connections. HTTP requests are rejected, not redirected.

---

## When Verification Helps vs Doesn't

### Worth It

- **International/unusual names**: spaCy's English model struggles with names from non-Western naming conventions (e.g., South Asian, East Asian, African names). An LLM trained on broader data catches these.
- **High-stakes documents**: Legal depositions, medical records, government filings where a single missed name could be a compliance violation.
- **Batch processing with QA requirements**: When processing hundreds of documents, verification provides a second-pass safety net.
- **Compliance demonstration**: Documented "best reasonable effort" with two independent detection methods (NER + LLM).

### Not Worth It

- **Simple well-formatted resumes**: spaCy handles standard Western-format resumes well. Verification adds cost without significant improvement.
- **Local-only requirement**: Users who chose PII Buddy specifically to avoid cloud services.
- **Low-risk internal sharing**: Documents shared within a team where perfect redaction is not critical.

### Where Sharding Hurts Accuracy

- **Transcript speaker flow**: Cross-sentence references ("And then she said...") lose context when sentences are isolated.
- **Implicit/contextual PII**: "Graduated from the same school as the CEO" — requires knowing who the CEO is, which is in another shard.
- **Pronoun resolution**: "He works at Google" — "He" refers to someone named 3 sentences ago, now in a different shard.

These are inherent trade-offs of the sharding approach. Document-level verification would be more accurate but less private.

---

## Canary Injection

### Concept

Inject 2-3 synthetic PII sentences into the shard batch using the `faker` library. If the LLM correctly identifies the canary PII, its detection capability is confirmed. If it misses canaries, the provider may be underperforming.

### Design

```python
# Canary generation
canary_shards = [
    {
        "id": uuid4(),
        "text": "Please forward all documents to Priya Chakraborty at priya.c@techsolutions.io.",
        "context": {...},
        "_canary": True,  # client-side only, stripped before sending
        "_expected": [
            {"text": "Priya Chakraborty", "type": "PERSON"},
            {"text": "priya.c@techsolutions.io", "type": "EMAIL"}
        ]
    }
]
```

Canary shards are mixed into the shuffled batch. The server cannot distinguish them from real shards. After results return, the client checks whether the LLM found the planted PII.

### Canary Report

```json
{
  "canaries_injected": 3,
  "canaries_detected": 3,
  "detection_rate": 1.0,
  "missed_canaries": []
}
```

### Limitations

- Adds ~10% cost (extra shards to process)
- Measures "easy" PII detection (obvious names and emails), not the hard edge cases that matter most
- A model that catches faker-generated "Maria Rodriguez" may still miss a real "Arundhati" in context
- Off by default

---

## Business Model

### Model: API Proxy (OpenRouter-style)

The PII Buddy operator manages LLM provider keys (OpenAI, Anthropic, etc.) and routes shard verification requests. End users interact only with the PII Buddy Verify API. The server adds markup to cover infrastructure, development, and margin.

### Pricing Tiers

| Tier | Price | Shards/Month | ~Documents/Month | Notes |
|---|---|---|---|---|
| Free | $0 | 100 | ~3 | Trial/evaluation |
| Pay-as-you-go | $0.001/shard | Unlimited | ~$0.03/resume | No commitment |
| Pro | $10/month | 5,000 | ~165 | Individual power users |
| Team | $25/month | 15,000 | ~500 | Small teams |

**Assumptions:** ~30 shards per document (average resume/deposition). Markup ~25x raw LLM cost (standard for API proxy services).

### Target Customers

| Segment | Use Case | Volume |
|---|---|---|
| Recruiting firms | Anonymizing candidate resumes before sharing with clients | High volume, batch |
| Legal teams | Redacting depositions, contracts, discovery documents | Medium volume, high stakes |
| HR departments | Anonymizing employee records for analytics | Medium volume, batch |
| Researchers | De-identifying interview transcripts, survey responses | Low-medium volume |

### Revenue Projections (Illustrative)

These are rough targets, not forecasts:

- 100 free users (evaluation, feedback)
- 50 pay-as-you-go users at ~$5/month average = $250/month
- 20 Pro users = $200/month
- 5 Team accounts = $125/month
- **Total: ~$575/month at modest adoption**

Infrastructure costs (LLM API, hosting, monitoring) estimated at ~$100/month at this scale, yielding healthy margins due to the markup model.

---

## Implementation Roadmap

### Phase 1: Architecture Document

This document. Committed to the `pii_buddy` repo as the shared specification.

### Phase 2: Client-Side Modules

New files in `pii_buddy/`:

| File | Purpose | Estimated Size |
|---|---|---|
| `sharder.py` | Sentence splitting, tag neutralization, UUID assignment, shuffling | ~150 lines |
| `verify_client.py` | HTTP client for Verify API, retry logic, error handling | ~120 lines |
| `verifier.py` | Orchestrator: shard -> send -> reassemble -> return additional entities | ~100 lines |
| `canary.py` | Optional synthetic PII injection and calibration reporting | ~80 lines |

#### `sharder.py` — Key Functions

```python
def neutralize_tags(text: str, mapping: dict) -> tuple[str, dict]:
    """Replace initials-based tags with generic sequential tags.
    Returns (neutralized_text, neutralization_map).
    """

def shard_text(text: str, nlp) -> list[Shard]:
    """Split text into sentence-level shards.
    Merges sentences under 5 words with predecessor.
    Caps at 200 tokens per shard.
    """

def shuffle_shards(shards: list[Shard]) -> tuple[list[Shard], dict]:
    """Cryptographically random shuffle.
    Returns (shuffled_shards, order_map).
    """

def build_context(mapping: dict, doc_type: str) -> dict:
    """Build entity-count-only context header."""
```

#### `verify_client.py` — Key Functions

```python
class VerifyClient:
    def __init__(self, api_key: str, endpoint: str):
        """Initialize with API key and endpoint URL."""

    async def verify(self, shards: list[dict], options: dict) -> VerifyResponse:
        """Send shards to Verify API, return findings."""

    async def check_usage(self) -> UsageResponse:
        """Query current usage/quota."""

    async def health_check(self) -> bool:
        """Check API availability."""
```

#### `verifier.py` — Orchestrator

```python
def verify_and_patch(
    redacted_text: str,
    mapping: dict,
    settings: Settings
) -> tuple[str, dict]:
    """Full verification pipeline:
    1. Neutralize tags
    2. Shard text
    3. (Optionally) inject canaries
    4. Shuffle and send to API
    5. Map findings back to document positions
    6. Apply additional redactions
    7. Update mapping with new tags
    Returns (patched_text, updated_mapping).
    """
```

#### `canary.py` — Canary Injection

```python
def generate_canaries(count: int = 3) -> list[CanaryShard]:
    """Generate synthetic PII sentences using faker.
    Returns shards with expected findings for later comparison.
    """

def evaluate_canaries(
    canaries: list[CanaryShard],
    results: list[dict]
) -> CanaryReport:
    """Compare expected vs actual findings for canary shards.
    Returns detection rate and missed items.
    """
```

### Phase 3: Pipeline Integration

Modify `watcher.py:process_file()` to insert the verification step. Add a second redaction pass using findings from the Verify API.

Modify `main.py` to add `--verify` and `--verify-key` CLI flags. Verification also works with `--once` and `--paste` modes.

### Phase 4: Settings and Configuration

Add to `settings.py` Settings dataclass:

```python
@dataclass
class Settings:
    # ... existing fields ...
    verify_enabled: bool = False
    verify_api_key: str = ""
    verify_endpoint: str = "https://api.piibuddy.dev/v1"
    verify_confidence: float = 0.7
    verify_canaries: bool = False
```

Add to `settings.conf` template:

```ini
[verify]
# enabled = false
# api_key =
# endpoint = https://api.piibuddy.dev/v1
# confidence_threshold = 0.7
# canaries = false
```

Add CLI flags in `main.py`:

```
--verify              Enable cloud verification after local redaction
--verify-key KEY      PII Buddy Verify API key
--verify-endpoint URL Override verify API endpoint (default: https://api.piibuddy.dev/v1)
--verify-confidence N Minimum confidence threshold (default: 0.7)
```

### Phase 5: Server (Separate Repo)

The `pii_buddy_verify` server is a separate project:

| Component | Technology | Purpose |
|---|---|---|
| API server | FastAPI | Request handling, shard routing |
| Database | PostgreSQL | API keys, usage tracking, billing |
| Cache/rate limiting | Redis | Rate limiting, request deduplication |
| LLM routing | httpx | Forward shards to OpenAI/Anthropic/etc. |
| Auth | API key middleware | Validate keys, check quotas |
| Monitoring | Structured logging | Usage metrics, error tracking (no shard text) |

#### Server Request Flow

```
Client POST /v1/verify
    -> Validate API key
    -> Check quota
    -> Rate limit check
    -> Build LLM prompt (system prompt + shard text)
    -> Send to LLM provider
    -> Parse LLM response into findings
    -> Filter by confidence threshold
    -> Log usage (shard count, tokens, cost)
    -> Return findings to client
    -> Discard shard text from memory
```

### New Dependencies (Client-Side)

| Package | Purpose | Required |
|---|---|---|
| `httpx` | Async HTTP client for concurrent shard sending | Yes (when verify enabled) |
| `faker` | Synthetic PII generation for canaries | Optional (when canaries enabled) |

These are imported conditionally — PII Buddy runs without them if verification is not enabled.

---

## Repository Structure

### Two-Repo Strategy

| Repo | License | Purpose |
|---|---|---|
| `pii_buddy` (this repo) | MIT (open-source) | Client-side: sharding, verify client, canary injection, CLI. Lives alongside existing detection/redaction code. |
| `pii_buddy_verify` (new repo) | Private | Server-side: FastAPI, LLM routing, API key management, billing, usage tracking. Separate deployment and release cycle. |

This document lives in the `pii_buddy` repo and covers both sides — it is the shared specification.

### Client-Side File Layout (After Implementation)

```
pii_buddy/
    __init__.py
    config.py
    detector.py         # PIIEntity, detect_pii()
    extractor.py        # Text extraction from files
    redactor.py         # PII redaction with reversible tags
    restorer.py         # PII restoration from mapping
    settings.py         # Settings dataclass + config loading
    validation.py       # Entity validation and scoring
    watcher.py          # File watcher + process_file()
    writers.py          # Output file writing
    sharder.py          # [NEW] Sentence sharding + tag neutralization
    verify_client.py    # [NEW] HTTP client for Verify API
    verifier.py         # [NEW] Orchestrator: shard -> verify -> patch
    canary.py           # [NEW] Canary injection and evaluation
    data/
        blocklists/
            person_blocklist.txt
            custom_blocklist.txt
docs/
    cloud_verification_architecture.md  # This document
```
