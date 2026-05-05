from typing import Any, Literal

from pydantic import BaseModel, Field


class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = Field(min_length=1, max_length=50_000)


class NumericAssertion(BaseModel):
    field: str
    rule: str
    product: str | None = None


class GatewayRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=120)
    messages: list[Message] = Field(min_length=1, max_length=64)
    expected_schema: dict[str, Any] | None = None
    numeric_assertions: list[NumericAssertion] = Field(default_factory=list)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)


class RuleAction(BaseModel):
    rule: str
    action: str
    detail: str


class GatewayResponse(BaseModel):
    blocked: bool
    reason: str | None = None
    upstream_response: dict[str, Any] | None = None
    applied_actions: list[RuleAction] = Field(default_factory=list)


class AuthContext(BaseModel):
    subject: str
    tenant_scope: str | None = None
    auth_mode: str


class GovernanceReport(BaseModel):
    tenant_id: str
    from_ts: str
    to_ts: str
    total_requests: int
    blocked_requests: int
    top_block_reasons: list[dict[str, Any]]
