# AI Governance Gateway & Policy Compiler

This repository houses two enterprise LLM security and governance systems built with Python and FastAPI:

| Project | Folder | Description |
| :--- | :--- | :--- |
| **Deterministic AI Governance Gateway** | [`Ai overnance/`](./Ai%20overnance/) | Production-oriented FastAPI reverse proxy enforcing deterministic PII redaction, jailbreak filters, gated ONNX/fastText semantic classification, Redis rate limiting, upstream circuit breaking, and PostgreSQL hash-chained audit logs. |
| **AI Policy Compiler Prototype** | [`SaaS/`](./SaaS/) | Natural-language to multi-format policy compiler (`Cedar`, `OPA/Rego`, `YAML`, `XACML`) with versioning, rollback, and regulatory control routes. |

---

## Quick Links

* **[Gateway Documentation & Benchmark Harness](./Ai%20overnance/README.md)**
* **[Policy Compiler Documentation](./SaaS/README.md)**
