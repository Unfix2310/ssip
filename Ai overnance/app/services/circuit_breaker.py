import time
from dataclasses import dataclass
from threading import Lock


@dataclass
class CircuitState:
    status: str = "closed"
    failures: int = 0
    opened_at: float = 0.0


class CircuitBreaker:
    def __init__(self, failure_threshold: int, recovery_seconds: int) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self._lock = Lock()
        self._state = CircuitState()

    def allow_request(self) -> bool:
        with self._lock:
            if self._state.status == "closed":
                return True
            if self._state.status == "open":
                if time.time() - self._state.opened_at >= self.recovery_seconds:
                    self._state.status = "half_open"
                    return True
                return False
            return True

    def record_success(self) -> None:
        with self._lock:
            self._state = CircuitState(status="closed", failures=0, opened_at=0.0)

    def record_failure(self) -> None:
        with self._lock:
            self._state.failures += 1
            if self._state.failures >= self.failure_threshold:
                self._state.status = "open"
                self._state.opened_at = time.time()

    def snapshot(self) -> dict[str, str | int]:
        with self._lock:
            return {
                "status": self._state.status,
                "failures": self._state.failures,
            }
