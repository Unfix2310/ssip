import json
import logging
import time
from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

REQUEST_COUNT = Counter(
    "gateway_requests_total",
    "Total gateway requests",
    ["endpoint", "tenant_id", "outcome"],
)
REQUEST_LATENCY = Histogram(
    "gateway_request_latency_seconds",
    "Gateway request latency",
    ["endpoint"],
    buckets=(0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0),
)
UPSTREAM_ERRORS = Counter(
    "gateway_upstream_errors_total",
    "Total upstream call errors",
    ["error_type"],
)
POLICY_BLOCKS = Counter(
    "gateway_policy_blocks_total",
    "Policy block counters",
    ["rule"],
)
SEMANTIC_REQUESTS = Counter(
    "gateway_semantic_requests_total",
    "Semantic layer invocations",
    ["outcome", "engine"],
)
SEMANTIC_LATENCY = Histogram(
    "gateway_semantic_latency_seconds",
    "Semantic layer latency",
    ["engine"],
    buckets=(0.001, 0.002, 0.005, 0.008, 0.01, 0.02, 0.05, 0.1),
)


def configure_logging(level: str) -> None:
    logging.basicConfig(level=level, format="%(message)s")


def log_json(event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    logging.getLogger("ai-governance").info(json.dumps(payload, sort_keys=True, default=str))


def metrics_payload() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST


class LatencyTimer:
    def __init__(self) -> None:
        self.started = time.perf_counter()

    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self.started) * 1000.0
