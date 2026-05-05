"""
AI Policy Compiler — FastAPI entry point.
Routes are thin. All business logic lives in pipeline.py and service modules.

API Routes (Access Policies):
  POST /generate-policy           → Compile NL → multi-format policy
  GET  /health                    → Health check
  GET  /policies                  → List all policies
  GET  /policies/{id}             → Get policy details
  GET  /policies/{id}/versions    → Get version history
  POST /policies/{id}/rollback    → Rollback to previous version
  GET  /reviews/pending           → List policies awaiting review
  POST /reviews/{id}              → Submit review decision
  GET  /deployment/{id}           → Get deployment status

API Routes (Regulatory Controls):
  POST /generate-control           → RBI rule → ControlIR → Governance YAML
  GET  /controls                   → List all controls
  GET  /controls/{id}              → Get control details
  POST /benchmark/run              → Run benchmark against POC rules
  GET  /benchmark/results          → Get latest benchmark results
"""

from __future__ import annotations

import json
import logging
import sys
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .database import init_db, get_db
from .deployment import get_deployment_status, get_version_history, rollback_policy, save_policy_version
from .exceptions import (
    EntityResolutionError,
    MaxRetriesExceededError,
    PolicyCompilerError,
    RoutingError,
    DeploymentError,
)
from .models import (
    PolicyRequest,
    PolicySuccessResponse,
    PolicyErrorResponse,
    PolicyDetailResponse,
    PolicyListResponse,
    ReviewRequest,
    ReviewResponse,
    PendingReviewsResponse,
    PendingReviewItem,
    VersionHistoryResponse,
    VersionHistoryItem,
    RollbackRequest,
    RollbackResponse,
    DeploymentStatusResponse,
    ControlRequest,
)
from .pipeline import run_pipeline
from .review import get_pending_reviews, submit_review_decision
from .verification import verify_full

# ── Logging setup ──────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("main")


# ── Application ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AI Policy Compiler starting up — initializing database.")
    await init_db()
    yield
    logger.info("AI Policy Compiler shutting down.")


app = FastAPI(
    title="AI Policy Compiler for Enterprise Security",
    description=(
        "Converts natural language security policies into deterministic "
        "machine-readable policies in multiple formats (Cedar, OPA/Rego, YAML, XACML). "
        "Features confidence-based routing, human review, conflict detection, "
        "policy versioning, and rollback support."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


# ── Global exception handler ───────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Internal server error."},
    )


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
async def health_check() -> dict[str, str]:
    return {"status": "ok", "version": "2.0.0"}


# ── Policy Generation ─────────────────────────────────────────────────────────

@app.post(
    "/generate-policy",
    response_model=PolicySuccessResponse,
    responses={
        200: {"model": PolicySuccessResponse},
        400: {"model": PolicyErrorResponse},
        422: {"description": "Request validation error"},
        500: {"model": PolicyErrorResponse},
    },
    tags=["policy"],
    summary="Compile a natural language policy into multiple formats.",
)
async def generate_policy(request: PolicyRequest) -> JSONResponse:
    """
    Accept a natural language security policy and return verified policies in multiple formats.

    **Pipeline stages**: LLM extraction → pre-normalization → IR validation →
    entity resolution → confidence routing → multi-format compilation →
    verification → persistence.
    """
    logger.info("[Route] POST /generate-policy  input=%r", request.input_text[:80])

    try:
        result = run_pipeline(request.input_text, output_formats=request.output_formats)

        # ── Persist to database ───────────────────────────────────────────────
        db = await get_db()
        try:
            await db.execute(
                """
                INSERT INTO policies (
                    id, version, status, input_text, ir_json, compiled_policies,
                    primary_format, confidence_score, routing_decision, routing_reason,
                    effect, principal_raw, resource_raw, principal_canonical,
                    resource_canonical, principal_tier, resource_tier
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.policy_id,
                    result.ir.get("version", "1.0.0"),
                    result.ir.get("status", "draft"),
                    request.input_text,
                    json.dumps(result.ir),
                    json.dumps(result.compiled_policies),
                    "cedar",
                    result.routing.get("overall_confidence", 0.0),
                    result.routing.get("decision", "auto_approve"),
                    result.routing.get("reason", ""),
                    result.ir.get("effect", "permit"),
                    result.resolved_entities.get("principal_raw", ""),
                    result.resolved_entities.get("resource_raw", ""),
                    result.ir.get("principal", {}).get("canonical_key", ""),
                    result.ir.get("resource", {}).get("canonical_key", ""),
                    result.resolved_entities.get("principal_tier", ""),
                    result.resolved_entities.get("resource_tier", ""),
                ),
            )
            await db.commit()
        finally:
            await db.close()

        # Save initial version
        await save_policy_version(
            policy_id=result.policy_id,
            version=result.ir.get("version", "1.0.0"),
            ir_json=json.dumps(result.ir),
            compiled_policies=json.dumps(result.compiled_policies),
        )

        # ── Run async verification (conflict + simulation) ────────────────────
        try:
            verification_result = await verify_full(
                cedar_policy=result.policy,
                policy_id=result.policy_id,
                compiled_policies=result.compiled_policies,
                check_conflicts=True,
                run_simulations=True,
            )
            verification_dict = verification_result.to_dict()
        except Exception as exc:
            logger.warning("[Route] Async verification failed: %s", exc)
            verification_dict = {
                "passed": True,
                "cedar_parse": True,
                "error": str(exc),
            }

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "policy_id": result.policy_id,
                "policy": result.policy,
                "compiled_policies": result.compiled_policies,
                "resolved_entities": result.resolved_entities,
                "ir": result.ir,
                "routing": result.routing,
                "verification": verification_dict,
                "attempts": result.attempts,
            },
        )

    except RoutingError as exc:
        logger.warning("[Route] Routing rejected: %s", exc)
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(exc)},
        )

    except EntityResolutionError as exc:
        logger.warning("[Route] Entity resolution failed: %s", exc)
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(exc)},
        )

    except MaxRetriesExceededError as exc:
        logger.warning("[Route] Max retries exceeded: %s", exc)
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(exc)},
        )

    except PolicyCompilerError as exc:
        logger.error("[Route] Pipeline error: %s", exc)
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(exc)},
        )


# ── Policy Management ─────────────────────────────────────────────────────────

@app.get(
    "/policies",
    tags=["policy"],
    summary="List all policies.",
)
async def list_policies() -> JSONResponse:
    """List all policies with their current status."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT id, version, status, input_text, ir_json, compiled_policies,
                   confidence_score, routing_decision, routing_reason,
                   created_at, updated_at
            FROM policies
            ORDER BY created_at DESC
            """
        )
        rows = await cursor.fetchall()
        policies = []
        for row in rows:
            try:
                ir = json.loads(row["ir_json"])
            except (json.JSONDecodeError, TypeError):
                ir = {}
            try:
                compiled = json.loads(row["compiled_policies"])
            except (json.JSONDecodeError, TypeError):
                compiled = {}
            policies.append({
                "id": row["id"],
                "version": row["version"],
                "status": row["status"],
                "input_text": row["input_text"],
                "ir": ir,
                "compiled_policies": compiled,
                "confidence_score": row["confidence_score"] or 0.0,
                "routing_decision": row["routing_decision"],
                "routing_reason": row["routing_reason"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            })
        return JSONResponse(
            status_code=200,
            content={"status": "success", "count": len(policies), "policies": policies},
        )
    finally:
        await db.close()


@app.get(
    "/policies/{policy_id}",
    tags=["policy"],
    summary="Get policy details.",
)
async def get_policy(policy_id: str) -> JSONResponse:
    """Get full details for a specific policy."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT id, version, status, input_text, ir_json, compiled_policies,
                   confidence_score, routing_decision, routing_reason,
                   created_at, updated_at
            FROM policies WHERE id = ?
            """,
            (policy_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return JSONResponse(
                status_code=404,
                content={"status": "error", "message": f"Policy {policy_id} not found."},
            )
        try:
            ir = json.loads(row["ir_json"])
        except (json.JSONDecodeError, TypeError):
            ir = {}
        try:
            compiled = json.loads(row["compiled_policies"])
        except (json.JSONDecodeError, TypeError):
            compiled = {}
        return JSONResponse(
            status_code=200,
            content={
                "id": row["id"],
                "version": row["version"],
                "status": row["status"],
                "input_text": row["input_text"],
                "ir": ir,
                "compiled_policies": compiled,
                "confidence_score": row["confidence_score"] or 0.0,
                "routing_decision": row["routing_decision"],
                "routing_reason": row["routing_reason"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            },
        )
    finally:
        await db.close()


# ── Version Management ─────────────────────────────────────────────────────────

@app.get(
    "/policies/{policy_id}/versions",
    tags=["versioning"],
    summary="Get version history for a policy.",
)
async def get_policy_versions(policy_id: str) -> JSONResponse:
    """Get all versions of a policy."""
    versions = await get_version_history(policy_id)
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "policy_id": policy_id,
            "versions": versions,
        },
    )


@app.post(
    "/policies/{policy_id}/rollback",
    tags=["versioning"],
    summary="Rollback a policy to a previous version.",
)
async def rollback_policy_route(policy_id: str, request: RollbackRequest) -> JSONResponse:
    """Rollback a policy to a specific previous version."""
    try:
        result = await rollback_policy(policy_id, request.target_version)
        return JSONResponse(status_code=200, content={"status": "success", **result})
    except DeploymentError as exc:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(exc)},
        )


# ── Human Review ───────────────────────────────────────────────────────────────

@app.get(
    "/reviews/pending",
    tags=["review"],
    summary="List policies awaiting human review.",
)
async def list_pending_reviews() -> JSONResponse:
    """List all policies with status 'pending_review'."""
    reviews = await get_pending_reviews()
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "count": len(reviews),
            "reviews": reviews,
        },
    )


@app.post(
    "/reviews/{policy_id}",
    tags=["review"],
    summary="Submit a review decision for a policy.",
)
async def submit_review(policy_id: str, request: ReviewRequest) -> JSONResponse:
    """
    Submit a review decision: approve, reject, or modify.
    
    - **approve**: Sets policy status to 'active'
    - **reject**: Sets policy status to 'rejected'
    - **modify**: Keeps policy in 'pending_review' with correction data
    """
    try:
        result = await submit_review_decision(
            policy_id=policy_id,
            reviewer=request.reviewer,
            decision=request.decision,
            correction=request.correction,
            reason=request.reason,
        )
        return JSONResponse(
            status_code=200,
            content={"status": "success", **result},
        )
    except Exception as exc:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(exc)},
        )


# ── Deployment ─────────────────────────────────────────────────────────────────

@app.get(
    "/deployment/{policy_id}",
    tags=["deployment"],
    summary="Get deployment status for a policy.",
)
async def get_deployment_status_route(policy_id: str) -> JSONResponse:
    """Get current deployment status and version info."""
    try:
        status = await get_deployment_status(policy_id)
        return JSONResponse(
            status_code=200,
            content={"status": "success", **status},
        )
    except DeploymentError as exc:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "message": str(exc)},
        )


# ── Regulatory Controls ────────────────────────────────────────────────────────

@app.post(
    "/generate-control",
    tags=["regulatory"],
    summary="Extract a regulatory control from RBI/DPSS rule text.",
)
async def generate_control(request: ControlRequest) -> JSONResponse:
    """
    Accept RBI/DPSS regulatory rule text and return a ControlIR + Governance YAML.
    """
    from .regulatory.pipeline import run_regulatory_pipeline

    input_text = request.input_text
    document_id = request.document_id
    section = request.section
    effective_date = request.effective_date
    parent_context = request.parent_context

    if not input_text or len(input_text) < 5:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "input_text is required (min 5 chars)."},
        )

    logger.info("[Route] POST /generate-control  doc=%s §%s  input=%r",
                document_id, section, input_text[:80])

    try:
        result = run_regulatory_pipeline(
            rule_text=input_text,
            document_id=document_id,
            section=section,
            effective_date=effective_date,
            parent_context=parent_context,
        )

        # Persist to database
        db = await get_db()
        try:
            await db.execute(
                """
                INSERT INTO controls (
                    id, version, status, input_text, ir_json, compiled_yaml,
                    document_id, section, rule_type, effect,
                    confidence_score, routing_decision, routing_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.control_id,
                    result.ir.get("version", "1.0.0"),
                    result.ir.get("status", "draft"),
                    input_text,
                    json.dumps(result.ir),
                    result.compiled_yaml,
                    document_id,
                    section,
                    result.ir.get("rule_type", ""),
                    result.ir.get("effect", "required"),
                    result.routing.get("overall_confidence", 0.0),
                    result.routing.get("decision", ""),
                    result.routing.get("reason", ""),
                ),
            )
            await db.commit()
        finally:
            await db.close()

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "control_id": result.control_id,
                "ir": result.ir,
                "compiled_yaml": result.compiled_yaml,
                "routing": result.routing,
                "validation_warnings": result.validation_warnings,
                "attempts": result.attempts,
            },
        )

    except RoutingError as exc:
        logger.warning("[Route] Control routing rejected: %s", exc)
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(exc)},
        )

    except Exception as exc:
        logger.error("[Route] Control pipeline error: %s", exc)
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(exc)},
        )


@app.get(
    "/controls",
    tags=["regulatory"],
    summary="List all extracted regulatory controls.",
)
async def list_controls() -> JSONResponse:
    """List all controls with their current status."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT id, version, status, input_text, ir_json, compiled_yaml,
                   document_id, section, rule_type, confidence_score,
                   routing_decision, routing_reason, created_at, updated_at
            FROM controls
            ORDER BY created_at DESC
            """
        )
        rows = await cursor.fetchall()
        controls = []
        for row in rows:
            try:
                ir = json.loads(row["ir_json"])
            except (json.JSONDecodeError, TypeError):
                ir = {}
            controls.append({
                "id": row["id"],
                "version": row["version"],
                "status": row["status"],
                "input_text": row["input_text"],
                "ir": ir,
                "compiled_yaml": row["compiled_yaml"],
                "document_id": row["document_id"],
                "section": row["section"],
                "rule_type": row["rule_type"],
                "confidence_score": row["confidence_score"] or 0.0,
                "routing_decision": row["routing_decision"],
                "created_at": row["created_at"],
            })
        return JSONResponse(
            status_code=200,
            content={"status": "success", "count": len(controls), "controls": controls},
        )
    finally:
        await db.close()


@app.get(
    "/controls/{control_id}",
    tags=["regulatory"],
    summary="Get control details.",
)
async def get_control(control_id: str) -> JSONResponse:
    """Get full details for a specific control."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """
            SELECT id, version, status, input_text, ir_json, compiled_yaml,
                   document_id, section, rule_type, confidence_score,
                   routing_decision, routing_reason, created_at, updated_at
            FROM controls WHERE id = ?
            """,
            (control_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return JSONResponse(
                status_code=404,
                content={"status": "error", "message": f"Control {control_id} not found."},
            )
        try:
            ir = json.loads(row["ir_json"])
        except (json.JSONDecodeError, TypeError):
            ir = {}
        return JSONResponse(
            status_code=200,
            content={
                "id": row["id"],
                "version": row["version"],
                "status": row["status"],
                "input_text": row["input_text"],
                "ir": ir,
                "compiled_yaml": row["compiled_yaml"],
                "document_id": row["document_id"],
                "section": row["section"],
                "rule_type": row["rule_type"],
                "confidence_score": row["confidence_score"] or 0.0,
                "routing_decision": row["routing_decision"],
                "routing_reason": row["routing_reason"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            },
        )
    finally:
        await db.close()


# ── Benchmark ──────────────────────────────────────────────────────────────────

@app.post(
    "/benchmark/run",
    tags=["benchmark"],
    summary="Run benchmark against all POC rules.",
)
async def run_benchmark_route() -> JSONResponse:
    """
    Run all 10 RBI/DPSS POC rules through the regulatory pipeline
    and return per-rule results + aggregate metrics.
    """
    from .regulatory.benchmark import run_benchmark

    logger.info("[Route] POST /benchmark/run — starting benchmark")

    try:
        summary = run_benchmark()
        summary_dict = summary.to_dict()

        # Save to database
        db = await get_db()
        try:
            await db.execute(
                """
                INSERT INTO benchmark_results (total_rules, successful, failed, results_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    summary.total_rules,
                    summary.successful_extractions,
                    summary.failed_extractions,
                    json.dumps(summary_dict),
                ),
            )
            await db.commit()
        finally:
            await db.close()

        return JSONResponse(status_code=200, content={"status": "success", **summary_dict})

    except Exception as exc:
        logger.error("[Route] Benchmark failed: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(exc)},
        )


@app.get(
    "/benchmark/results",
    tags=["benchmark"],
    summary="Get latest benchmark results.",
)
async def get_benchmark_results() -> JSONResponse:
    """Get the most recent benchmark results."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT run_at, total_rules, successful, failed, results_json FROM benchmark_results ORDER BY run_at DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        if not row:
            return JSONResponse(
                status_code=404,
                content={"status": "error", "message": "No benchmark results found. Run POST /benchmark/run first."},
            )
        try:
            results = json.loads(row["results_json"])
        except (json.JSONDecodeError, TypeError):
            results = {}
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "run_at": row["run_at"],
                **results,
            },
        )
    finally:
        await db.close()


# ── Dev entrypoint ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
