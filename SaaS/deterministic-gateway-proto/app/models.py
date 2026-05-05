"""
Models: Pydantic models for API request/response and database operations.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Request models ─────────────────────────────────────────────────────────────

class PolicyRequest(BaseModel):
    input_text: str = Field(
        ...,
        min_length=5,
        description="Natural language security policy statement.",
        examples=["Allow developers to read server logs"],
    )
    output_formats: list[str] = Field(
        default=["cedar", "opa", "yaml", "xacml"],
        description="Output formats to compile to.",
    )


class ControlRequest(BaseModel):
    input_text: str = Field(
        ...,
        min_length=5,
        description="The raw regulatory rule sentence.",
        examples=["VA shall be conducted at least once in every six months for critical systems in DMZ."],
    )
    document_id: Optional[str] = Field(
        default="",
        description="Source document ID.",
        examples=["RBI/2023-24/107"],
    )
    section: Optional[str] = Field(
        default="",
        description="Section number.",
        examples=["26"],
    )
    effective_date: Optional[str] = Field(
        default=None,
        description="Effective date.",
    )
    parent_context: Optional[str] = Field(
        default=None,
        description="Full text of the parent clause (for compound sub-clauses).",
    )


class ReviewRequest(BaseModel):
    reviewer: str = Field(..., min_length=1, description="Reviewer name or ID.")
    decision: str = Field(
        ...,
        description="Review decision: approve, reject, or modify.",
        pattern="^(approve|reject|modify)$",
    )
    correction: Optional[dict[str, Any]] = Field(
        default=None,
        description="Correction data if decision is 'modify'.",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Reason for the review decision.",
    )


class RollbackRequest(BaseModel):
    target_version: str = Field(..., description="Version string to rollback to.")


# ── Response models ────────────────────────────────────────────────────────────

class PolicySuccessResponse(BaseModel):
    status: str = "success"
    policy_id: str
    policy: str  # Primary format (Cedar)
    compiled_policies: dict[str, str]  # All formats
    resolved_entities: dict[str, Any]
    ir: dict[str, Any]
    routing: dict[str, Any]
    attempts: int


class PolicyErrorResponse(BaseModel):
    status: str = "error"
    message: str


class PolicyDetailResponse(BaseModel):
    id: str
    version: str
    status: str
    input_text: str
    ir: dict[str, Any]
    compiled_policies: dict[str, str]
    confidence_score: float
    routing_decision: str
    routing_reason: Optional[str]
    created_at: str
    updated_at: str


class ReviewResponse(BaseModel):
    status: str = "success"
    policy_id: str
    decision: str
    new_status: str


class PendingReviewItem(BaseModel):
    policy_id: str
    input_text: str
    confidence_score: float
    routing_reason: Optional[str]
    effect: str
    principal_raw: Optional[str]
    resource_raw: Optional[str]
    created_at: str


class PendingReviewsResponse(BaseModel):
    status: str = "success"
    count: int
    reviews: list[PendingReviewItem]


class PolicyListResponse(BaseModel):
    status: str = "success"
    count: int
    policies: list[PolicyDetailResponse]


class VersionHistoryItem(BaseModel):
    version: str
    compiled_policies: dict[str, str]
    created_at: str
    rolled_back: bool


class VersionHistoryResponse(BaseModel):
    status: str = "success"
    policy_id: str
    versions: list[VersionHistoryItem]


class RollbackResponse(BaseModel):
    status: str = "success"
    policy_id: str
    rolled_back_to: str
    new_version: str


class DeploymentStatusResponse(BaseModel):
    status: str = "success"
    policy_id: str
    deployment_status: str
    current_version: str
    total_versions: int
