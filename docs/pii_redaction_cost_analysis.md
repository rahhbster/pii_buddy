# PII Redaction Service: Self-Hosted AI vs. Third-Party Services Cost Analysis

## Executive Summary

This document analyzes the costs, trade-offs, and strategic considerations for building a PII redaction API service using either:
1. **Self-hosted AI models** (running open-source models on owned/rented infrastructure)
2. **Third-party AI services** (OpenRouter, OpenAI, Anthropic, etc.)

The goal is to offer a PII redaction API with a credits/subscription business model for developers to integrate into their systems.

---

## Table of Contents

1. [Service Architecture Overview](#service-architecture-overview)
2. [Self-Hosted AI Infrastructure Analysis](#self-hosted-ai-infrastructure-analysis)
3. [Open-Source Model Options](#open-source-model-options)
4. [Third-Party Service Comparison](#third-party-service-comparison)
5. [Cost Comparison Matrix](#cost-comparison-matrix)
6. [Development & Operational Costs](#development--operational-costs)
7. [Business Model Analysis](#business-model-analysis)
8. [The Debate: Self-Host vs. Rent](#the-debate-self-host-vs-rent)
9. [Recommendation](#recommendation)

---

## Service Architecture Overview

### What We're Building

An API service that:
- Accepts text/documents via REST API
- Detects and redacts PII using AI (person names, emails, phones, SSNs, addresses, etc.)
- Returns redacted text with reversible mapping
- Offers credits/subscription pricing
- Ensures logs and processing data are deleted after use
- Prioritizes privacy and security

### Core Requirements

| Requirement | Implication |
|---|---|
| **Real-time processing** | Low latency (< 5 seconds for typical document) |
| **Privacy-first** | No data retention, minimal logging |
| **High accuracy** | Must catch unusual/international names |
| **Scalability** | Handle 10-1000+ requests/day per customer |
| **Cost-effective** | Margins must support sustainable pricing |
| **Reliability** | 99.5%+ uptime expectation |

---

## Self-Hosted AI Infrastructure Analysis

### Hosting Provider Comparison

#### AWS EC2

**GPU Instances (for LLM inference):**

| Instance Type | vCPUs | GPU | RAM | Cost/Hour | Cost/Month (24/7) | Best For |
|---|---|---|---|---|---|---|
| g5.xlarge | 4 | 1x A10G (24GB) | 16GB | $1.006 | ~$730 | Small-scale inference |
| g5.2xlarge | 8 | 1x A10G (24GB) | 32GB | $1.212 | ~$880 | Medium workloads |
| g4dn.xlarge | 4 | 1x T4 (16GB) | 16GB | $0.526 | ~$381 | Budget option |
| p3.2xlarge | 8 | 1x V100 (16GB) | 61GB | $3.06 | ~$2,224 | High performance |

**CPU-Only Instances (for smaller/quantized models):**

| Instance Type | vCPUs | RAM | Cost/Hour | Cost/Month (24/7) | Best For |
|---|---|---|---|---|---|
| c6i.2xlarge | 8 | 16GB | $0.34 | ~$247 | CPU inference |
| c6i.4xlarge | 16 | 32GB | $0.68 | ~$494 | Larger CPU models |
| c7i.4xlarge | 16 | 32GB | $0.68 | ~$494 | Latest gen CPU |

**Additional AWS Costs:**
- EBS Storage: $0.08-0.10/GB/month (need 100-500GB for models)
- Data Transfer: $0.09/GB outbound after 100GB/month
- Load Balancer: ~$20-30/month

#### DigitalOcean Droplets

**GPU Droplets (newer offering, limited availability):**

| Type | vCPUs | GPU | RAM | Storage | Cost/Month |
|---|---|---|---|---|---|
| GPU Basic | 8 | 1x A100 PCIe (40GB) | 30GB | 200GB | $1,479 |
| GPU Pro | 12 | 1x A100 SXM4 (80GB) | 60GB | 400GB | $2,999 |

**CPU Droplets:**

| Type | vCPUs | RAM | Storage | Cost/Month | Transfer |
|---|---|---|---|---|---|
| Premium CPU 4 vCPU | 4 | 8GB | 50GB SSD | $48 | 5TB |
| Premium CPU 8 vCPU | 8 | 16GB | 100GB SSD | $96 | 6TB |
| Premium CPU 16 vCPU | 16 | 32GB | 200GB SSD | $192 | 7TB |

#### Hostinger VPS

**Important Limitation:** Hostinger VPS plans DO NOT offer GPU support. Only suitable for CPU-based inference.

| Plan | vCPUs | RAM | Storage | Cost/Month | Best For |
|---|---|---|---|---|---|
| VPS 1 | 1 | 8GB | 50GB | $4.99 | Not suitable |
| VPS 2 | 2 | 16GB | 100GB | $8.99 | Not suitable |
| VPS 4 | 4 | 32GB | 200GB | $14.99 | Small quantized models |
| VPS 8 | 8 | 64GB | 400GB | $44.99 | Medium quantized models |

**Verdict:** Hostinger is NOT viable for AI model hosting at scale. Lack of GPU support and limited CPU power make it unsuitable for real-time LLM inference.

### Model Resource Requirements

#### Small Language Models (7B-13B parameters)

**Examples:** Llama 3 8B, Mistral 7B, Phi-3 Medium

| Configuration | VRAM/RAM | Inference Speed | Accuracy | Hardware Need |
|---|---|---|---|---|
| FP16 (full precision) | 14-26GB | Fast | Excellent | GPU required |
| INT8 (quantized) | 7-13GB | Medium | Very Good | GPU or high-end CPU |
| INT4 (aggressive quant) | 4-7GB | Fast | Good | CPU possible |

**Cost Estimate:** g4dn.xlarge ($381/month) or Premium CPU 8 vCPU ($96/month with INT4)

#### Medium Language Models (13B-34B parameters)

**Examples:** Llama 3 70B (quantized), Mixtral 8x7B

| Configuration | VRAM/RAM | Inference Speed | Accuracy | Hardware Need |
|---|---|---|---|---|
| FP16 (full precision) | 140GB+ | Slow | Excellent | Multiple GPUs |
| INT8 (quantized) | 70GB | Medium | Excellent | High-end GPU |
| INT4 (aggressive quant) | 35GB | Fast | Very Good | GPU strongly recommended |

**Cost Estimate:** g5.2xlarge ($880/month) or specialized multi-GPU setup ($2000+/month)

#### Specialized NER Models (BERT-based)

**Examples:** spaCy transformers, BERT-NER, RoBERTa-NER

| Configuration | VRAM/RAM | Inference Speed | Accuracy | Hardware Need |
|---|---|---|---|---|
| BERT-base | 1-2GB | Very Fast | Good for standard names | CPU sufficient |
| BERT-large | 3-4GB | Fast | Better | CPU or small GPU |

**Cost Estimate:** c6i.2xlarge ($247/month) - CPU only sufficient

### Infrastructure Scaling Considerations

**Fixed Costs (self-hosted):**
- Server rental: $247-$880/month (depending on choice)
- Storage: $10-50/month
- Monitoring/logging: $20-50/month
- **Total: $277-$980/month REGARDLESS of usage volume**

**Variable Costs (self-hosted):**
- Data transfer: ~$0.09/GB (after free tier)
- Minimal compared to fixed costs

**Break-Even Analysis:**
- If server costs $500/month, you need enough volume to justify this fixed cost
- At low volumes (< 10,000 requests/month), you're paying $500 for infrastructure that sits idle 90% of the time

---

## Open-Source Model Options

### Option 1: General-Purpose LLMs for PII Detection

#### Llama 3.1 8B Instruct

**Pros:**
- Excellent instruction following
- Good at identifying nuanced/contextual PII
- Can handle multiple languages
- Strong community support

**Cons:**
- Overkill for simple pattern matching
- Slower than specialized NER models
- Higher resource requirements

**Resource Needs:**
- FP16: 16GB GPU (g4dn.xlarge: $381/month)
- INT4: 8GB RAM (CPU: c6i.2xlarge: $247/month)

**Inference Speed:** ~2-4 seconds per document (500 tokens)

**Best For:** Complex documents, unusual names, multi-language support

#### Mistral 7B Instruct

**Pros:**
- Smaller, faster than Llama
- Good accuracy for European names
- Lower resource requirements

**Cons:**
- Less accurate on non-Western names than Llama
- Smaller context window

**Resource Needs:**
- FP16: 14GB GPU (g4dn.xlarge: $381/month)
- INT4: 7GB RAM (CPU: c6i.2xlarge: $247/month)

**Inference Speed:** ~1-3 seconds per document

**Best For:** Budget-conscious, European-focused use cases

#### Phi-3 Medium (14B)

**Pros:**
- Microsoft-backed, well-optimized
- Excellent accuracy for size
- Good instruction following

**Cons:**
- Larger than Llama 8B
- Higher resource needs

**Resource Needs:**
- INT4: 14GB GPU (g4dn.xlarge: $381/month)

**Inference Speed:** ~2-4 seconds per document

**Best For:** Balance of accuracy and cost

### Option 2: Specialized NER Models

#### GLiNER (Generalist NER)

**Pros:**
- Purpose-built for entity recognition
- Zero-shot capabilities (define entities at runtime)
- Much faster than LLMs
- Lower resource requirements

**Cons:**
- Less contextual understanding than LLMs
- May miss implicit PII

**Resource Needs:** 2-4GB RAM (CPU sufficient: c6i.2xlarge: $247/month)

**Inference Speed:** ~0.5-1 second per document

**Best For:** High-volume, cost-sensitive deployments

#### spaCy Transformer (en_core_web_trf)

**Pros:**
- Production-ready, well-tested
- Fast inference
- Good accuracy on standard English names
- CPU-friendly

**Cons:**
- Weaker on international/unusual names
- Less flexible than LLMs

**Resource Needs:** 2GB RAM (CPU: c6i.2xlarge: $247/month)

**Inference Speed:** ~0.3-0.5 seconds per document

**Best For:** Cost optimization, simple use cases

### Option 3: Hybrid Approach

**Architecture:**
1. **Fast first pass:** spaCy (regex + NER) catches 90% of PII
2. **LLM verification:** Send pre-redacted text through Llama/Mistral to catch misses
3. **Best of both worlds:** Speed + accuracy

**Resource Needs:** Same as LLM-only (LLM is the bottleneck)

**Cost:** Same as LLM-only

**Benefit:** Better accuracy with minimal cost increase

---

## Third-Party Service Comparison

### OpenRouter

**Business Model:** Aggregator that provides unified API access to multiple LLM providers with markup pricing.

**Pricing (as of 2026):**

| Model | Provider | Input (per 1M tokens) | Output (per 1M tokens) | Context |
|---|---|---|---|---|
| GPT-4o | OpenAI | $5.00 | $15.00 | 128k |
| GPT-4o mini | OpenAI | $0.15 | $0.60 | 128k |
| Claude 3.5 Sonnet | Anthropic | $3.00 | $15.00 | 200k |
| Claude 3.5 Haiku | Anthropic | $0.25 | $1.25 | 200k |
| Llama 3.1 8B | Meta | $0.06 | $0.06 | 128k |
| Llama 3.1 70B | Meta | $0.35 | $0.40 | 128k |
| Mistral 7B | Mistral | $0.06 | $0.06 | 32k |

**OpenRouter Markup:** Typically 10-30% above direct provider pricing

**Pros:**
- Zero infrastructure management
- Pay only for what you use
- Access to latest models instantly
- Built-in failover/routing
- No GPU expertise needed

**Cons:**
- Per-token costs add up at volume
- Less control over data flow
- Dependent on third-party availability
- Margin compression if you add markup

### Direct Provider APIs

#### OpenAI GPT-4o mini

**Pricing:**
- Input: $0.15/1M tokens
- Output: $0.60/1M tokens

**For PII detection:**
- Average document: 500 input tokens, 100 output tokens
- Cost per request: $0.00007 + $0.00006 = $0.00013
- **$0.13 per 1,000 requests**

#### Anthropic Claude 3.5 Haiku

**Pricing:**
- Input: $0.25/1M tokens
- Output: $1.25/1M tokens

**For PII detection:**
- Average document: 500 input tokens, 100 output tokens
- Cost per request: $0.000125 + $0.000125 = $0.00025
- **$0.25 per 1,000 requests**

#### Cost Projection (Third-Party)

| Monthly Volume | GPT-4o mini Cost | Claude Haiku Cost | OpenRouter Llama 8B Cost |
|---|---|---|---|
| 10,000 requests | $1.30 | $2.50 | $0.60 |
| 50,000 requests | $6.50 | $12.50 | $3.00 |
| 100,000 requests | $13.00 | $25.00 | $6.00 |
| 500,000 requests | $65.00 | $125.00 | $30.00 |
| 1,000,000 requests | $130.00 | $250.00 | $60.00 |

### Self-Hosted Open Source via Inference Providers

#### Replicate

**Pricing:** Pay-per-second GPU time
- Llama 3 8B: ~$0.001/second
- Average request: 2 seconds = $0.002
- **$2.00 per 1,000 requests**

**Pros:** No infrastructure management, pay-per-use
**Cons:** 2x-3x more expensive than OpenRouter for equivalent models

#### Together.ai

**Pricing:**
- Llama 3.1 8B: $0.20/1M input tokens, $0.20/1M output tokens
- **~$0.12 per 1,000 requests**

**Pros:** Competitive with OpenRouter, fast inference
**Cons:** Limited model selection vs. OpenRouter

---

## Cost Comparison Matrix

### Scenario 1: Low Volume (10,000 requests/month)

| Approach | Monthly Cost | Cost per Request | Startup Cost | Notes |
|---|---|---|---|---|
| Self-hosted (g4dn.xlarge + Llama 8B) | $381 | $0.0381 | $0 (cloud) | Server idle 95% of time |
| Self-hosted (c6i.2xlarge + GLiNER) | $247 | $0.0247 | $0 (cloud) | More cost-effective but still wasteful |
| OpenRouter (Llama 8B) | $0.60 | $0.00006 | $0 | **640x cheaper** |
| GPT-4o mini | $1.30 | $0.00013 | $0 | **293x cheaper** |
| Claude Haiku | $2.50 | $0.00025 | $0 | **152x cheaper** |

**Winner:** Third-party services (OpenRouter/GPT-4o mini) by massive margin

### Scenario 2: Medium Volume (100,000 requests/month)

| Approach | Monthly Cost | Cost per Request | Startup Cost | Notes |
|---|---|---|---|---|
| Self-hosted (g4dn.xlarge + Llama 8B) | $381 | $0.00381 | $0 (cloud) | Server utilized ~30% |
| Self-hosted (c6i.2xlarge + GLiNER) | $247 | $0.00247 | $0 (cloud) | Better utilization |
| OpenRouter (Llama 8B) | $6.00 | $0.00006 | $0 | **64x cheaper** |
| GPT-4o mini | $13.00 | $0.00013 | $0 | **29x cheaper** |
| Claude Haiku | $25.00 | $0.00025 | $0 | **15x cheaper** |

**Winner:** Still third-party services, but gap narrows

### Scenario 3: High Volume (1,000,000 requests/month)

| Approach | Monthly Cost | Cost per Request | Startup Cost | Notes |
|---|---|---|---|---|
| Self-hosted (g4dn.xlarge + Llama 8B) | $381 | $0.000381 | $0 (cloud) | Server fully utilized |
| Self-hosted (c6i.2xlarge + GLiNER) | $247 | $0.000247 | $0 (cloud) | **Break-even point** |
| OpenRouter (Llama 8B) | $60.00 | $0.00006 | $0 | 6x cheaper than GPU |
| GPT-4o mini | $130.00 | $0.00013 | $0 | 3x cheaper than GPU |
| Claude Haiku | $250.00 | $0.00025 | $0 | Similar to CPU self-host |

**Winner:** Self-hosted becomes competitive at very high volume (1M+ requests/month)

### Break-Even Analysis

**When does self-hosting become cheaper?**

Using cheapest viable self-hosted option (c6i.2xlarge + GLiNER: $247/month):

| Third-Party Service | Monthly Cost at Break-Even Volume | Break-Even Volume |
|---|---|---|
| OpenRouter Llama 8B ($0.00006/req) | $247 | **4,116,667 requests** |
| GPT-4o mini ($0.00013/req) | $247 | **1,900,000 requests** |
| Claude Haiku ($0.00025/req) | $247 | **988,000 requests** |

**Critical Insight:** You need nearly 1 million requests per month (33,000/day) before self-hosting makes economic sense.

---

## Development & Operational Costs

### Self-Hosted: Additional Costs

| Category | Monthly Cost | Annual Cost | One-Time Cost | Notes |
|---|---|---|---|---|
| **Development** ||||
| Model selection & testing | - | - | $5,000-$10,000 | Engineer time (2-3 weeks) |
| Inference optimization | - | - | $3,000-$5,000 | Quantization, batching |
| API development | - | - | $8,000-$12,000 | FastAPI, auth, rate limiting |
| **Operations** ||||
| DevOps/monitoring | $500-$1,000 | $6,000-$12,000 | - | Datadog, PagerDuty, logs |
| Model updates | $200-$500 | $2,400-$6,000 | - | Quarterly retraining/updates |
| Security/compliance | $300-$500 | $3,600-$6,000 | - | Audits, pen testing |
| Engineer on-call | $1,000-$2,000 | $12,000-$24,000 | - | 24/7 incident response |
| **Total First Year** | | **$24,000-$48,000** | **$16,000-$27,000** | |

### Third-Party: Additional Costs

| Category | Monthly Cost | Annual Cost | One-Time Cost | Notes |
|---|---|---|---|---|
| **Development** ||||
| API integration | - | - | $2,000-$3,000 | 1 week of work |
| Error handling/retry logic | - | - | $1,000-$2,000 | Few days |
| **Operations** ||||
| Monitoring (API calls) | $50-$100 | $600-$1,200 | - | Basic observability |
| Failover logic maintenance | $100-$200 | $1,200-$2,400 | - | Quarterly review |
| **Total First Year** | | **$1,800-$3,600** | **$3,000-$5,000** | |

**Total Cost Comparison (First Year, at 100k requests/month):**

| Approach | Infrastructure | Development | Operations | Total Year 1 |
|---|---|---|---|---|
| Self-hosted (GPU) | $4,572 | $16,000-$27,000 | $24,000-$48,000 | **$44,572-$79,572** |
| Self-hosted (CPU) | $2,964 | $16,000-$27,000 | $24,000-$48,000 | **$42,964-$77,964** |
| Third-party | $72-$300 | $3,000-$5,000 | $1,800-$3,600 | **$4,872-$8,900** |

**Third-party is 5-16x cheaper in year 1, even at 100k requests/month.**

---

## Business Model Analysis

### Pricing Strategy

**Goal:** Offer competitive pricing that covers costs + margin while remaining attractive to developers.

#### Market Benchmarks

| Service Type | Typical Pricing | Example Providers |
|---|---|---|
| PII detection APIs | $0.001-$0.01 per request | AWS Comprehend, Azure Text Analytics |
| General NLP APIs | $0.0001-$0.001 per request | OpenAI embeddings, sentiment APIs |
| Document processing | $0.01-$0.10 per document | DocuSign, PDFTron |

**Recommendation:** Target **$0.001-$0.005 per request** to be competitive.

### Revenue Projections

#### Pricing Tiers (Proposed)

| Tier | Monthly Price | Included Requests | Overage Rate | Target Customer |
|---|---|---|---|---|
| Free | $0 | 1,000 | N/A | Developers/testing |
| Starter | $29 | 10,000 | $0.003 | Small startups |
| Pro | $99 | 50,000 | $0.002 | Growing companies |
| Business | $299 | 200,000 | $0.0015 | Mid-market |
| Enterprise | Custom | 1M+ | $0.001 | Large orgs |

#### Scenario: 100 Paying Customers

| Distribution | Customers | MRR | Annual Revenue |
|---|---|---|---|
| Starter | 60 | $1,740 | $20,880 |
| Pro | 30 | $2,970 | $35,640 |
| Business | 8 | $2,392 | $28,704 |
| Enterprise | 2 | $1,000 | $12,000 |
| **Total** | **100** | **$8,102** | **$97,224** |

#### Cost Analysis (at this scale)

**Request Volume:** ~500,000 requests/month (assuming customers use 50% of allocation)

**Option A: Third-Party (GPT-4o mini)**
- Monthly API cost: $65
- Operations: $150
- Marketing/sales: $1,000
- **Total costs: $1,215**
- **Profit margin: 85%**
- **Monthly profit: $6,887**

**Option B: Self-Hosted (c6i.2xlarge)**
- Monthly infrastructure: $247
- Operations: $1,500 (engineer time)
- DevOps/monitoring: $500
- Marketing/sales: $1,000
- **Total costs: $3,247**
- **Profit margin: 60%**
- **Monthly profit: $4,855**

**Third-party provides $2,032/month MORE profit** (40% higher) while requiring less operational complexity.

### Scaling Economics

| Monthly Requests | Third-Party Cost | Self-Hosted Cost | Delta | Winner |
|---|---|---|---|---|
| 100,000 | $13 | $247 | +$234 | Third-party |
| 500,000 | $65 | $247 | +$182 | Third-party |
| 1,000,000 | $130 | $247 | +$117 | Third-party |
| 2,000,000 | $260 | $247 | -$13 | **Self-hosted** |
| 5,000,000 | $650 | $247 | -$403 | **Self-hosted** |

**Break-even point: ~2 million requests/month** (when infrastructure is fully utilized)

---

## The Debate: Self-Host vs. Rent

### Case FOR Self-Hosting

#### Argument 1: Cost at Scale

**"Once you hit critical mass, self-hosting is dramatically cheaper."**

At 5 million requests/month:
- Third-party: $650/month
- Self-hosted: $247/month
- **Savings: $403/month = $4,836/year**

If you believe you can reach this scale within 12-18 months, the upfront investment in self-hosting pays off.

#### Argument 2: Control & Privacy

**"You own the entire stack and can guarantee data deletion."**

- No third-party sees customer data (even redacted)
- Full control over logging, retention, compliance
- Can offer on-premise/private cloud deployments
- Regulatory compliance is cleaner (GDPR, HIPAA)

This can be a significant selling point for enterprise customers who are willing to pay premium pricing for guaranteed privacy.

#### Argument 3: Customization

**"Open-source models can be fine-tuned for your specific use case."**

- Train on industry-specific PII patterns
- Optimize for resumes, medical records, legal documents
- Add custom entity types (employee IDs, internal codes)
- Competitive moat through better accuracy

#### Argument 4: Margin Protection

**"Third-party prices can increase, killing your margins overnight."**

- You're at the mercy of OpenAI/Anthropic pricing changes
- Their 20% price increase = your margin cut in half
- Self-hosting locks in predictable costs

#### Argument 5: Reliability

**"You control uptime and SLAs."**

- Not dependent on OpenAI's rate limits or outages
- Can offer higher SLA guarantees to enterprise customers
- Auto-scaling under your control

### Case AGAINST Self-Hosting

#### Argument 1: Premature Optimization

**"You're optimizing for a scale you haven't reached yet."**

- 95% of startups never reach 2M requests/month
- Spending $40k-$80k in year 1 to save $400/month is backwards
- That capital could go to customer acquisition instead

Better strategy: **Start with third-party, migrate when scale justifies it.**

#### Argument 2: Opportunity Cost

**"Your time is better spent on product and customers."**

- Self-hosting requires:
  - DevOps expertise (managing GPU instances, monitoring, scaling)
  - ML engineering (model selection, optimization, quantization)
  - 24/7 on-call for infrastructure issues

- Third-party lets you focus on:
  - Building great developer docs and SDKs
  - Customer support and integration help
  - Sales and marketing

**The $40k engineering cost in year 1 could instead fund 6 months of a sales/marketing person who brings in 50+ customers.**

#### Argument 3: Model Improvements

**"Third-party providers improve models constantly; you don't."**

- OpenAI releases GPT-4o turbo, GPT-5, etc. — you get them instantly
- Your Llama 3 8B from 2024 becomes stale while competitors use Claude Opus 4.6
- Keeping up requires continuous re-training and updates (expensive)

#### Argument 4: Risk of Under-Utilization

**"Fixed costs are brutal at low volume."**

- At 50k requests/month:
  - Third-party: $6.50
  - Self-hosted: $247
  - **You're paying 38x more for unused capacity**

- If customer churn is high or growth is slower than expected, you're locked into $247-$381/month whether you process 10k or 100k requests

#### Argument 5: Accuracy Trade-Offs

**"Open-source models are 6-12 months behind frontier models."**

Reality check on accuracy:
- GPT-4o mini / Claude Haiku: SOTA performance, especially on edge cases
- Llama 3 8B (INT4 quantized): Good, but measurably worse on unusual names
- GLiNER/spaCy: Fast but miss 10-20% of non-standard PII

**A 5% miss rate on PII can be a deal-breaker for enterprise customers.** The cost savings don't matter if your accuracy isn't competitive.

#### Argument 6: Hidden Costs of Self-Hosting

**"Infrastructure costs are just the beginning."**

Beyond the $247-$381/month instance:
- Monitoring/logging infrastructure: $50-$100/month
- SSL certificates, domain management: $20/month
- Backup/disaster recovery: $50-$100/month
- Security updates and patching: Engineer time
- Model version management: Storage + testing
- Load balancing for high availability: $50+/month

**Real monthly cost: $400-$600**, not $247.

### The Hybrid Approach: Best of Both Worlds?

#### Strategy: Start Third-Party, Migrate Strategically

**Phase 1 (Months 0-12): Rent**
- Use OpenRouter or GPT-4o mini
- Focus on product-market fit, customer acquisition
- Keep burn rate low, iterate fast

**Phase 2 (Months 12-24): Evaluate**
- At 1M+ requests/month, model costs become significant
- Run cost/benefit analysis on self-hosting
- Test open-source models on subset of traffic

**Phase 3 (Months 24+): Hybrid**
- Self-hosted for standard cases (80% of traffic)
- Third-party for high-value/complex requests (20% of traffic)
- Best of both: cost efficiency + SOTA accuracy where it matters

**Example Hybrid Architecture:**
```
Incoming request
    -> Classifier: simple/complex?
    -> Simple (80%): Self-hosted Llama 8B ($247/month handles 1M requests)
    -> Complex (20%): GPT-4o mini ($26/month for 200k requests)
    -> Total: $273/month vs $130 (all third-party) or $247 (all self-hosted)
```

Hybrid is slightly more expensive but gives better accuracy on edge cases while maintaining cost efficiency.

---

## Recommendation

### For a NEW PII Redaction API Service

**Stage 1: MVP and Early Growth (0-100k requests/month)**

**Use third-party services (OpenRouter or GPT-4o mini).**

**Why:**
- Speed to market: 4-6 weeks vs 3-6 months for self-hosted
- Lower capital requirements: $5k vs $40k+ in year 1
- Focus on product/market fit, not infrastructure
- Trivial operational complexity
- Better accuracy out of the box (frontier models)

**Pricing:** $29-$299/month tiers, $0.001-$0.003 per request overage
**Margins:** 80-90% at scale
**Infrastructure cost:** < $100/month until 100k requests/month

---

**Stage 2: Growth (100k-1M requests/month)**

**Continue with third-party, but begin R&D on self-hosted.**

**Why:**
- Still more cost-effective ($13-$130/month vs $247+ baseline)
- Use profits to fund evaluation of open-source alternatives
- Run parallel testing: 5-10% of traffic through self-hosted to measure accuracy

**Action items:**
- Hire/contract ML engineer to evaluate Llama, Mistral, GLiNER
- Stand up test GPU instance (g4dn.xlarge) for benchmarking
- Build deployment pipeline (Docker, model serving, monitoring)

---

**Stage 3: Scale (1M+ requests/month)**

**Migrate to hybrid: self-hosted for standard cases, third-party for edge cases.**

**Why:**
- Cost optimization becomes material ($130+/month third-party cost)
- Infrastructure is now worth the investment
- Proven demand justifies operational complexity

**Architecture:**
- Primary: Self-hosted Llama 3 8B (INT4) on g4dn.xlarge ($381/month)
- Fallback/complex: GPT-4o mini for unusual names, multi-language ($20-$50/month)
- Total infrastructure: $400-$450/month for 1M+ requests

**Break-even point:** ~2M requests/month, hybrid beats all-third-party

---

### The Bottom Line

| Approach | Best For | Avoid If |
|---|---|---|
| **Third-party (OpenRouter/GPT-4o mini)** | MVP, early-stage, < 1M requests/month | You've hit 2M+ requests/month |
| **Self-hosted (open-source)** | High volume (2M+ req/month), privacy-critical customers | You're pre-revenue or below 500k req/month |
| **Hybrid** | Mature product with proven demand (1M+ req/month) | Adds complexity at small scale |

---

## Appendix: Cost Calculators

### Self-Hosted Monthly Cost Formula

```
Infrastructure Cost =
  (GPU Instance Cost) OR (CPU Instance Cost) +
  (Storage: $0.10/GB × model_size_GB) +
  (Data Transfer: $0.09/GB × monthly_outbound_GB) +
  (Monitoring: $50-$100) +
  (Load Balancer: $20-$30)

Total Monthly Cost = Infrastructure Cost + (Engineer Time × $/hour)
```

**Example (g4dn.xlarge + Llama 8B):**
```
$381 (instance) + $5 (50GB storage) + $10 (est. transfer) + $75 (monitoring) + $25 (LB)
= $496/month base infrastructure cost
```

### Third-Party Cost Formula

```
Cost Per Request =
  (Average Input Tokens × Input Price per Token) +
  (Average Output Tokens × Output Price per Token)

Monthly Cost = Cost Per Request × Monthly Request Volume
```

**Example (GPT-4o mini, 500 input / 100 output tokens):**
```
(500 × $0.15 / 1M) + (100 × $0.60 / 1M) = $0.000135 per request
At 100k requests/month: $13.50/month
```

### Break-Even Volume Calculator

```
Break-Even Volume = Monthly Infrastructure Cost / Cost Per Request (Third-Party)
```

**Example:**
```
$247 (self-hosted CPU) / $0.000135 (GPT-4o mini per request)
= 1,829,630 requests/month break-even point
```

---

## Conclusion

**The debate between self-hosting and renting AI services for PII redaction is NOT a binary choice—it's a question of timing and scale.**

- **At low volume (< 1M requests/month):** Third-party services are objectively superior. Lower cost, faster time-to-market, better accuracy, less operational burden. This is where 95% of new services will operate for their first 1-2 years.

- **At high volume (2M+ requests/month):** Self-hosting becomes economically compelling IF you have the engineering resources to do it well. The savings ($400-$600/month) justify the operational complexity.

- **The optimal path:** Start with OpenRouter or GPT-4o mini, prove product-market fit, scale revenue, then migrate to hybrid self-hosted + third-party when demand justifies the investment.

**Premature self-hosting is a common startup mistake.** The $40k-$80k you spend in year 1 building and operating infrastructure could instead fund customer acquisition that brings in $100k+ in revenue. Infrastructure optimization is a luxury you earn by reaching scale, not a prerequisite for launch.

Build fast, learn fast, scale smart.
