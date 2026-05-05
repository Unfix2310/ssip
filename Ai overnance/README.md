# Deterministic AI Governance Gateway

Production-oriented deterministic AI security gateway for regulated SaaS workloads.

## What is implemented

- FastAPI reverse proxy for LLM traffic
- Deterministic pre-LLM controls:
  - PII redaction (Aadhaar, PAN, credit card with Luhn check)
  - Jailbreak deny-list and regex deny-list
- Deterministic post-LLM controls:
  - JSON schema validation
  - Numeric/rate-card assertions against policy
- Semantic NLP layer (gated):
  - Language detection with fastText (fallback to script heuristics)
  - ONNX SetFit-style classifier (fallback to lexical risk classifier)
  - Strict timeout (`timeout_ms`) and fail mode (`allow` or `block`)
- Security and access:
  - `API key`, `JWT`, or `either` auth mode
  - Tenant-scoped JWT claim enforcement (`tenant_id`)
  - Request ID propagation (`x-request-id`)
- Reliability:
  - Redis rate limiting with local fallback
  - Upstream retry with exponential backoff
  - Circuit breaker for upstream failures
- Compliance audit:
  - Async queue-based PostgreSQL writes
  - Hash-chained audit entries for tamper evidence
  - Governance report API
- Operations:
  - `/health`, `/ready`, `/metrics` endpoints
  - Prometheus metrics and structured logs

## Run locally

```bash
cp .env.example .env
docker compose up --build
```

Gateway URL: `http://localhost:8000`

## Benchmark

Run local latency + safety benchmark:

```bash
PYTHONPATH=. python3 scripts/run_benchmark.py --requests 2000 --concurrency 20 --profile default
```

Profiles:

- `default`: current policy behavior
- `semantic_off`: semantic layer disabled
- `timeout_fail_closed`: forced semantic timeout with fail-closed policy

## Main APIs

- `POST /v1/gateway/chat`
- `GET /v1/governance/report?tenant_id=...&from_ts=...&to_ts=...`
- `GET /health`
- `GET /ready`
- `GET /metrics`

## Semantic layer

Semantic extraction is now integrated in `POST /v1/gateway/chat` as a gated stage:

1. Risk heuristics score each prompt.
2. Only grey-area traffic crosses the NLP gate (`min_risk_score`).
3. Language is detected with fastText when model is available.
4. ONNX classifier runs with strict timeout (`timeout_ms`).
5. If model artifacts are missing, lexical fallback still runs.

Model assets expected under `models/`:

- `models/lid.176.ftz`
- `models/semantic_setfit_int8.onnx`
- `models/tokenizer.json`

See [models/README.md](/Volumes/Code/Ai%20overnance/models/README.md).

## Authentication

Set `AUTH_MODE` in `.env`:

- `api_key`: requires `x-gateway-key`
- `jwt`: requires `Authorization: Bearer <token>`
- `either`: accepts JWT first, API key fallback

JWT validation checks `iss`, `aud`, signature, and optional `tenant_id` claim.

## SaaS integration strategy

1. Route all SaaS LLM calls through this gateway.
2. Attach org/tenant identity as `tenant_id` in each request.
3. Keep tenant policies in `policies/<tenant>.yaml`.
4. Expose governance reports from `GET /v1/governance/report`.
5. Feed `/metrics` into Prometheus/Grafana and alert on:
   - blocked request spikes
   - upstream circuit open state
   - error rate increase

## Request example

```json
{
  "tenant_id": "bank-prod",
  "model": "gpt-4.1-mini",
  "messages": [
    {"role": "user", "content": "My PAN is ABCDE1234F, what is my loan EMI?"}
  ],
  "expected_schema": {
    "type": "object",
    "properties": {
      "emi": {"type": "number"},
      "rate_percent": {"type": "number"}
    },
    "required": ["emi", "rate_percent"]
  },
  "numeric_assertions": [
    {"field": "rate_percent", "rule": "loan_rate_card", "product": "home_loan"}
  ]
}
```

## Policy format

See `policies/default.yaml`.

- `meta.version`: policy version identifier
- `meta.signature`: optional HMAC signature
- `rate_limit_per_minute`
- `pii_patterns`
- `jailbreak_deny_list`
- `jailbreak_regex_deny_list`
- `numeric_rules`
- `semantic_layer`

If `POLICY_HMAC_SECRET` is set, policy signature verification is enforced.

To sign a policy file:

```bash
export POLICY_HMAC_SECRET='your-secret'
python3 scripts/sign_policy.py policies/default.yaml
```

## Security posture notes

- This gateway gives deterministic enforcement for defined rules.
- Gated semantic NLP runs inline with strict timeout and explicit fail-mode policy.
- For full enterprise rollout, add mTLS ingress, secret manager integration, and CI security scans in your deployment environment.
