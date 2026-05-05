# AI Policy Compiler for Enterprise Security

Converts natural language security policies into deterministic, verified **Cedar** policies via a strict multi-stage pipeline.

> **Core invariant**: The LLM is used _only_ for initial extraction. Every downstream stage — normalization, validation, compilation, verification — is fully deterministic. Same input → same output, every time.

---

## Architecture Overview

```
NL Input
   │
   ▼
┌──────────────────┐
│  LLM Extraction  │  llm.py        → Strict JSON IR (constrained JSON extractor)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Pre-Normalization│  normalizer.py  → 4-tier entity resolution (exact → alias → TF-IDF → LLM bounded)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  IR Validation   │  schema.py     → Type/schema/action/effect checks on canonical keys
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Entity Resolution│  resolver.py   → Catalog lookup (guaranteed hit after normalization)
└────────┬─────────┘
         │
         ├──── [If confidence < threshold] ──→ Human Review (target architecture)
         │
         ▼
┌──────────────────┐
│ Policy Compilation│  compiler.py  → Deterministic Cedar template (zero LLM)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Verification   │  verifier.py   → Cedar CLI parse check (structural lint fallback)
└────────┬─────────┘
         │
         ├──── [Retryable error] ──→ Back to LLM with error context (max 2 retries)
         │
         ▼
   Final Cedar Policy
```

> **Note on human review**: Human review is triggered by the confidence router and acts as a **parallel branch** after entity resolution, not a strictly sequential stage. This routing is part of the target architecture and is not fully implemented in the current prototype.

---

## Current vs Target System State

This section clarifies the distinction between the **implemented prototype** and the **target production architecture**.

### System Capability Matrix

| Component | Current Implementation | Target Architecture |
|---|---|---|
| **Document ingestion** | Basic sentence splitting | Structured document parsing (sections, clauses, references) |
| **Policy classifier** | Not implemented | Full taxonomy with multi-sentence reasoning |
| **LLM extraction** | ✅ Implemented — Groq API (Llama 3.1 8B), constrained JSON extractor with retry | More robust prompts + schema-aware correction |
| **Canonical IR** | ✅ Implemented — core fields only (`principal_intent`, `action_intent`, `resource_intent`, `effect`, `conditions`) | Extended IR with temporal + derivation + audit completeness |
| **Entity normalization** | ✅ Fully implemented — 4-tier system (exact → alias → TF-IDF → LLM bounded) | Same architecture with larger corpus + learning loop |
| **Catalog** | ✅ Static Python dictionary (6 principals, 6 resources) | Live synchronized service (IAM, CMDB, cloud) |
| **Confidence router** | Partial — confidence scores computed but not enforced for routing | Fully enforced routing with queues + APIs |
| **Human review** | ❌ Not implemented | Full review service with feedback loop |
| **Compiler (Cedar)** | ✅ Implemented — deterministic template with `when` clause support | Multi-output compilers (OPA/Rego, YAML, XACML) |
| **Verification** | ✅ Basic — Cedar CLI `check-parse` + structural lint fallback | Full pipeline (conflict detection + simulation + regression) |
| **Deployment** | ❌ Not implemented | Full rollout system (canary, rollback, monitoring) |

### Key Clarification

> [!IMPORTANT]
> The following are **target architecture features** — NOT fully implemented yet:
> - Temporal fields (`valid_from`, `valid_until`, `recurrence`)
> - Derivation chain (audit traceability: `doc_id`, `clause_id`, `extraction_run`)
> - Multi-format compilation (OPA/Rego, Governance YAML, XACML)
> - Full confidence routing with queues
> - Human review as a service
> - Live catalog adapters (IAM, CMDB, cloud inventory)
> - Advanced verification (simulation, regression, conflict detection)
> - Conditional and deny effects — the current pipeline assumes **permit-only** flows. Deny and conditional effects are part of the target architecture and are not fully supported in the current extraction and compilation path.

---

## LLM Module

The LLM layer (`llm.py`) is a **constrained JSON extractor** — not an advanced reasoning system or multi-agent architecture.

**What it does:**
- Sends a natural language policy statement to the **Groq API** (model: `llama-3.1-8b-instant`)
- Uses a strict system prompt that suppresses all non-JSON output
- Enforces `response_format: json_object` at the API level
- Parses the response with a robust JSON object extractor (handles markdown wrappers, partial text)
- Canonicalizes key names (`principal` → `principal_intent`, `subject` → `principal_intent`, etc.)
- On retry, appends a `[CORRECTION REQUIRED]` prompt with the previous error context

**What it does NOT do:**
- No multi-turn reasoning
- No chain-of-thought
- No multi-agent orchestration
- No direct policy generation — it only extracts structured data

**T4 disambiguation** (`normalizer.py`) uses a separate Anthropic API call (`claude-haiku-4-5-20251001`) as a last-resort bounded selector when the first three resolution tiers fail. The LLM is constrained to pick from a provided candidate list — it cannot hallucinate new entities.

---

## Intermediate Representation (IR)

The IR is the core contract between extraction and compilation. No LLM output is trusted until it passes through schema validation.

### Current IR Schema (Implemented)

```python
@dataclass
class PolicyIR:
    principal_intent: str   # Canonical key after normalization
    action_intent: str      # One of: read, write, admin
    resource_intent: str    # Canonical key after normalization
    effect: str             # Currently: "permit" only
    conditions: Conditions  # network_restriction, time_restriction (nullable)
```

### Example: Canonical IR Record (Target — Fully Populated)

The following example shows a **fully populated IR record** as envisioned in the target architecture — after extraction, resolution, and normalization. Fields marked with ⚠️ are **not yet implemented**.

```json
{
  "id": "b7c9f2a1-8d21-4c9f-91b3-2a9d7e1c55ab",
  "version": "1.0.0",
  "status": "pending_review",

  "effect": "permit",

  "principal": {
    "raw": "backend engineers",
    "canonical_key": "developers",
    "arn": "arn:aws:iam::123456789012:role/developers",
    "confidence": 0.82,
    "resolution_tier": "tfidf"
  },

  "action": {
    "raw": "view",
    "normalized": "read"
  },

  "resource": {
    "raw": "production logs",
    "canonical_key": "server logs",
    "arn": "arn:aws:s3:::server-logs",
    "confidence": 0.91,
    "resolution_tier": "alias"
  },

  "conditions": [
    {
      "type": "time",
      "operator": "between",
      "value": "09:00-18:00"
    }
  ],

  "exceptions": [],

  "scope": {
    "org_unit": "engineering",
    "environment": "production",
    "region": "ap-south-1"
  },

  "temporal": {
    "valid_from": "2026-01-01T00:00:00Z",
    "valid_until": null,
    "recurrence": null
  },

  "confidence": {
    "overall": 0.84,
    "principal": 0.82,
    "resource": 0.91,
    "action": 0.99
  },

  "derivation": {
    "doc_id": "policy_doc_001",
    "clause_id": "clause_12",
    "extraction_run": "run_2026_04_01",
    "extractor_version": "v1.2.0"
  },

  "review": {
    "required": true,
    "reviewer": null,
    "decision": null,
    "timestamp": null,
    "correction": null
  }
}
```

**Field implementation status:**

| Field Group | Status |
|---|---|
| `principal`, `action`, `resource` (core) | ✅ Implemented |
| `conditions` (network, time) | ✅ Implemented |
| `confidence` (per-entity scores) | ✅ Implemented (in `resolved_entities` response) |
| `id`, `version`, `status` | ⚠️ Not implemented |
| `scope` (org_unit, environment, region) | ⚠️ Not implemented |
| `temporal` (valid_from, valid_until, recurrence) | ⚠️ Not implemented |
| `derivation` (doc_id, clause_id, extraction_run) | ⚠️ Not implemented |
| `review` (required, reviewer, decision) | ⚠️ Not implemented |
| `exceptions` | ⚠️ Not implemented |

---

## Entity Resolution: 4-Tier System

The normalizer (`normalizer.py`) resolves free-text LLM output to canonical catalog keys using four ordered tiers. **First match wins.** Every decision is logged with tier + confidence score for auditability.

| Tier | Method | Cost | Confidence | Description |
|---|---|---|---|---|
| **T1** | Exact match | O(1) | 1.0 | Raw string exists in candidate list |
| **T2** | Alias table | O(1) | 1.0 | Pre-built synonym map (e.g., `"backend engineers"` → `"developers"`) |
| **T3** | TF-IDF cosine | O(n) | variable (≥ 0.25 threshold) | Synonym-expanded bigram vectorization |
| **T4** | LLM bounded | API call | 0.9 (fixed) | Claude Haiku picks from candidate list — cannot hallucinate |

**Hard contracts:**
- Never returns a key not in the candidate list
- `EntityResolutionError` raised with scored candidates if all tiers fail (non-retryable)
- T3 threshold is explicit (`0.25`) and logged
- Validation runs AFTER normalization — never on raw LLM strings

---

## Known Gaps and Non-Goals

This system is a **production-oriented prototype**, not a fully complete enterprise system. The following limitations are intentional or pending.

### Known Gaps (Planned Improvements)

| Gap | Detail |
|---|---|
| No document ingestion pipeline | Only sentence-level processing — no section/clause/reference parsing |
| Static catalog | Python dictionary with 6 principals + 6 resources — no real-time IAM/cloud integration |
| No persistent review queue | Human review is not API-driven; no reviewer assignment or correction feedback |
| Limited verification | Cedar CLI `check-parse` only — no simulation, regression testing, or conflict detection |
| Temporal constraints not enforced | `valid_from`, `valid_until`, `recurrence` mentioned in target IR but not compiled |
| Derivation chain incomplete | No `doc_id`, `clause_id`, or `extraction_run` tracking for audit trail |
| No policy conflict detection | Cannot detect contradictions or overlaps across multiple compiled rules |
| No deployment pipeline | No canary rollout, rollback, or policy version management |
| Permit-only effect | `deny` and `conditional` effects are not supported in the current extraction or compilation path |

### Non-Goals (Intentional Design Choices)

| Non-Goal | Rationale |
|---|---|
| LLM is NOT used for compilation | Strictly deterministic system — same IR always produces same Cedar output |
| LLM cannot generate arbitrary entities | Resolution is bounded to the catalog candidate list — hallucination is impossible |
| No direct NL → policy compilation | IR is a mandatory intermediate layer; all policies must pass through schema validation |
| No probabilistic enforcement decisions | Only deterministic outputs are produced — no "maybe allow" |

---

## Setup

```bash
# 1. Clone / enter directory
cd deterministic-gateway-proto

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r app/requirements.txt

# 4. Set API key
export GROQ_API_KEY=your-groq-api-key-here

# 5. Run
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# → Server at http://localhost:8000
```

### Optional: Cedar CLI

If you have the Cedar CLI installed (`cargo install cedar-policy-cli`), the verifier will use it automatically. Otherwise, it falls back to structural linting.

### Optional: T4 LLM Disambiguation

For the 4th-tier normalizer (bounded LLM selection), set:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```
If not set, T4 is skipped and resolution uses T1–T3 only.

---

## API

### `POST /generate-policy`

**Request**
```json
{
  "input_text": "Allow developers to read server logs"
}
```

**Success Response (200)**
```json
{
  "status": "success",
  "policy": "permit(\n    principal == Role::\"arn:aws:iam::2222:role/DevTeam\",\n    action == Action::\"read\",\n    resource == Bucket::\"arn:aws:s3:::app-logs-01\"\n);",
  "resolved_entities": {
    "principal": "Role::\"arn:aws:iam::2222:role/DevTeam\"",
    "action": "read",
    "resource": "Bucket::\"arn:aws:s3:::app-logs-01\"",
    "principal_raw": "developers",
    "principal_tier": "exact",
    "principal_score": 1.0,
    "resource_raw": "server logs",
    "resource_tier": "exact",
    "resource_score": 1.0
  },
  "attempts": 1
}
```

**Error Response (400)**
```json
{
  "status": "error",
  "message": "Cannot resolve principal: 'marketing team'. Top candidates by similarity: ['developers' (0.12), 'admin team' (0.08), 'data team' (0.06)]. Add an alias to the resolution table or expand the catalog."
}
```

### `GET /health`

```bash
curl http://localhost:8000/health
# {"status": "ok"}
```

Interactive API docs: http://localhost:8000/docs

---

## Test Scenarios

### 1. Valid case — exact match
```bash
curl -X POST http://localhost:8000/generate-policy \
  -H "Content-Type: application/json" \
  -d '{"input_text": "Allow developers to read server logs"}'
```
**Expected**: `status: success`, 1 attempt, T1 exact match for both entities.

### 2. Unknown entity — hard fail, no retry
```bash
curl -X POST http://localhost:8000/generate-policy \
  -H "Content-Type: application/json" \
  -d '{"input_text": "Allow marketing team to read logs"}'
```
**Expected**: `status: error`, `EntityResolutionError` with scored candidates.

### 3. Synonym resolution — alias match (T2)
```bash
curl -X POST http://localhost:8000/generate-policy \
  -H "Content-Type: application/json" \
  -d '{"input_text": "Allow backend engineers to view production logs"}'
```
**Expected**: `status: success`. `"backend engineers"` → `"developers"` (T2 alias), `"view"` → `"read"` (action synonym), `"production logs"` → `"server logs"` (T2 alias).

### 4. Finance team write payroll
```bash
curl -X POST http://localhost:8000/generate-policy \
  -H "Content-Type: application/json" \
  -d '{"input_text": "Allow the finance team to write to the payroll bucket"}'
```
**Expected**: `status: success`. Finance team → T1 exact, payroll bucket → T1 exact.

---

## Module Reference

| File | Responsibility |
|---|---|
| `main.py` | FastAPI app, routes (thin layer only) |
| `pipeline.py` | Stage orchestration + retry loop (6-stage pipeline) |
| `llm.py` | Groq API call (Llama 3.1 8B), constrained JSON extraction |
| `normalizer.py` | 4-tier semantic entity normalizer (exact → alias → TF-IDF → LLM bounded) |
| `schema.py` | IR dataclass + validation (action synonyms, effect checks) |
| `catalog.py` | Shadow catalog — canonical keys → Cedar ARN mappings |
| `resolver.py` | Entity resolver (normalizer → catalog lookup → `ResolvedEntities`) |
| `compiler.py` | Cedar template engine (deterministic, zero LLM) |
| `verifier.py` | Cedar CLI `check-parse` / structural lint fallback |
| `exceptions.py` | Custom error hierarchy (retryable vs non-retryable) |

---

## Retry Policy

| Error Type | Retried? | Max Attempts | Behavior |
|---|---|---|---|
| `InvalidActionError` | ✅ Yes | 3 total | Re-prompt LLM with error context |
| `SchemaValidationError` | ✅ Yes | 3 total | Re-prompt LLM with error context |
| `LLMExtractionError` | ✅ Yes | 3 total | Re-prompt LLM with error context |
| `VerificationError` | ✅ Yes | 3 total | Re-prompt LLM with error context |
| `EntityResolutionError` | ❌ No | Immediate fail | Genuine unknown — cannot be fixed by retry |

---

## System Evaluation Metrics

System quality is measured across the full pipeline:

### Extraction Quality
| Metric | Description | Target |
|---|---|---|
| Extraction accuracy | % correctly structured IR from NL input | > 90% |
| Schema validation failure rate | % of LLM outputs that fail IR validation | < 10% |
| Retry rate | Frequency of LLM correction loop activation | < 15% |

### Resolution Quality
| Metric | Description | Target |
|---|---|---|
| Entity resolution accuracy | Correct canonical key match rate | > 95% (T1–T3) |
| False positive rate | Incorrect matches above similarity threshold | < 2% |
| False negative rate | Valid entities rejected by all tiers | < 5% |
| Tier distribution | T1 vs T2 vs T3 vs T4 usage breakdown | T1+T2 > 80% |

### Routing Quality (Target Architecture)
| Metric | Description | Target |
|---|---|---|
| Review rate | % policies routed to human review | < 20% |
| Auto-approval precision | High-confidence correctness rate | > 98% |

### Compilation Quality
| Metric | Description | Target |
|---|---|---|
| Compile success rate | % of valid IRs that produce valid Cedar | 100% |
| Deterministic consistency | Same IR → same Cedar output, every time | 100% |

### Verification Quality
| Metric | Description | Target |
|---|---|---|
| Policy parse success rate | % of compiled policies passing Cedar CLI | > 99% |
| Conflict detection rate | Cross-policy contradiction detection (target) | TBD |
| Simulation pass rate | Target scenario coverage (target) | TBD |

### System Performance
| Metric | Description | Target |
|---|---|---|
| End-to-end latency | Time from NL input to verified Cedar policy | < 2 seconds |
| LLM latency contribution | Time spent on Groq API call | < 1 second |
| Resolution time per entity | Per-entity normalization time | < 100ms |

---

## Implementation Roadmap

The system evolves in structured phases:

### Phase 1 — Canonical IR Stabilization ← _Current_

- [x] Define core IR schema (`PolicyIR` dataclass)
- [x] Ensure extraction → IR consistency with schema validation
- [x] Implement action synonym mapping
- [ ] Add missing fields (`temporal`, `derivation`, `scope`)
- [ ] Add IR versioning (`id`, `version`, `status`)

### Phase 2 — Catalog Service Abstraction

- [ ] Replace static `SHADOW_CATALOG` dict with abstract interface
- [ ] Add adapters for IAM / cloud systems (AWS IAM, Azure AD)
- [ ] Introduce dynamic entity sync
- [ ] Support multi-tenant catalog isolation

### Phase 3 — Confidence Router Enforcement

- [ ] Implement routing thresholds strictly (currently scores are computed but not enforced)
- [ ] Add queues (review queue, enrichment queue)
- [ ] Persist routing decisions with audit trail
- [ ] Define configurable threshold policies per entity type

### Phase 4 — Human Review API

- [ ] Build review interface (web UI or API-driven)
- [ ] Store reviewer decisions with timestamps
- [ ] Feed corrections into alias table + catalog (learning loop)
- [ ] Support bulk review workflows

### Phase 5 — Multi-Output Compilation

- [ ] Add OPA / Rego compiler
- [ ] Add Governance YAML output
- [ ] Add XACML output
- [ ] Ensure IR → multiple formats consistency

### Phase 6 — Verification Pipeline

- [ ] Conflict detection engine (cross-policy contradictions)
- [ ] Simulation engine (test policies against scenarios)
- [ ] Regression testing (ensure new policies don't break existing ones)
- [ ] Integrate with CI/CD policy validation

### Phase 7 — Deployment System

- [ ] Policy versioning and changelog
- [ ] Canary rollout (gradual enforcement)
- [ ] Rollback system (instant revert)
- [ ] Monitoring and alerting on policy enforcement

---

## Architectural Assessment

### Strengths
- **Deterministic core**: LLM is sandboxed to extraction only — compilation is pure template substitution
- **4-tier resolution**: Graceful degradation from exact match to bounded LLM — never hallucinates
- **Fail-fast design**: Custom exception hierarchy with clear retryable vs non-retryable semantics
- **Auditability**: Every resolution decision logs tier + confidence score
- **Schema as contract**: No LLM output is trusted until it passes validation

### Risks & Mitigations
| Risk | Mitigation |
|---|---|
| Catalog drift (static dict vs live IAM) | Phase 2 catalog abstraction |
| Low-confidence matches passed without review | Phase 3 confidence routing enforcement |
| Single-format lock-in (Cedar only) | Phase 5 multi-output compilation |
| No conflict detection across policies | Phase 6 verification pipeline |

---

_Version: 1.0.0 · Prototype · Last updated: April 2026_
