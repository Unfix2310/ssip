from __future__ import annotations

import asyncio
import math
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from app.config import settings
from app.models import RuleAction
from app.services.observability import SEMANTIC_LATENCY, SEMANTIC_REQUESTS, log_json

try:
    import fasttext  # type: ignore
except Exception:  # pragma: no cover - optional dependency at runtime
    fasttext = None  # type: ignore

try:
    import numpy as np
except Exception:  # pragma: no cover - optional dependency at runtime
    np = None  # type: ignore

try:
    import onnxruntime as ort  # type: ignore
except Exception:  # pragma: no cover - optional dependency at runtime
    ort = None  # type: ignore

try:
    from tokenizers import Tokenizer
except Exception:  # pragma: no cover - optional dependency at runtime
    Tokenizer = None  # type: ignore


ROMANIZED_HINDI_SIGNALS = (
    "pichli instruction bhool jao",
    "saare rules ignore karo",
    "guardrail hata do",
    "system prompt dikhao",
)

BASE_RISK_PATTERNS: tuple[tuple[re.Pattern[str], int, str], ...] = (
    (re.compile(r"(?i)\b(ignore|bypass|override)\b.{0,40}\b(instruction|policy|guardrail|rule)\b"), 3, "policy_override"),
    (re.compile(r"(?i)\b(reveal|show|print|exfiltrate)\b.{0,40}\b(system prompt|secret|key|credential)\b"), 3, "secret_exfil"),
    (re.compile(r"(?i)\bdeveloper\s*mode\b"), 2, "developer_mode"),
    (re.compile(r"(?i)\b(jailbreak|prompt injection)\b"), 2, "jailbreak_keyword"),
    (re.compile(r"(?i)\b(?:[a-z]\W+){6,}[a-z]\b"), 2, "obfuscated_spaced_chars"),
    (re.compile(r"(?i)<\|.*?\|>"), 2, "special_token_pattern"),
)


def _csv_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def _softmax(values: list[float]) -> list[float]:
    if not values:
        return []
    max_value = max(values)
    exp_values = [math.exp(v - max_value) for v in values]
    denom = sum(exp_values)
    if denom == 0:
        return [0.0 for _ in values]
    return [v / denom for v in exp_values]


def _script_language_fallback(text: str) -> str:
    if re.search(r"[\u0900-\u097f]", text):
        return "hi"
    if re.search(r"[\u0980-\u09ff]", text):
        return "bn"
    if re.search(r"[\u0a80-\u0aff]", text):
        return "gu"
    if re.search(r"[\u0b80-\u0bff]", text):
        return "ta"
    if re.search(r"[\u0c00-\u0c7f]", text):
        return "te"
    if re.search(r"[\u0c80-\u0cff]", text):
        return "kn"
    if re.search(r"[\u0d00-\u0d7f]", text):
        return "ml"
    ascii_letters = len(re.findall(r"[A-Za-z]", text))
    if ascii_letters > max(3, int(len(text) * 0.25)):
        lowered = text.lower()
        if any(signal in lowered for signal in ROMANIZED_HINDI_SIGNALS):
            return "hinglish"
        return "en"
    return "unknown"


def score_risk(text: str, extra_keywords: list[str]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    lowered = text.lower()

    if len(text) > 2000:
        score += 1
        reasons.append("long_prompt")

    punctuation = len(re.findall(r"[!@#$%^&*_=+\\|<>/~`]", text))
    if punctuation > 30:
        score += 1
        reasons.append("high_symbol_density")

    for pattern, weight, reason in BASE_RISK_PATTERNS:
        if pattern.search(text):
            score += weight
            reasons.append(reason)

    for signal in ROMANIZED_HINDI_SIGNALS:
        if signal in lowered:
            score += 2
            reasons.append("romanized_hindi_bypass_signal")
            break

    for keyword in extra_keywords:
        if keyword.lower() in lowered:
            score += 1
            reasons.append(f"custom_keyword:{keyword.lower()}")

    return score, reasons


@dataclass
class SemanticConfig:
    enabled: bool
    mode: str
    timeout_ms: int
    min_risk_score: int
    fail_mode: str
    min_confidence: float
    onnx_model_path: str
    tokenizer_path: str
    fasttext_model_path: str
    max_length: int
    labels: list[str]
    block_labels: set[str]
    language_allowlist: set[str]
    risk_keywords: list[str]


@dataclass
class SemanticInference:
    label: str
    confidence: float
    language: str
    language_confidence: float
    risk_score: int
    reasons: list[str] = field(default_factory=list)
    engine: str = "lexical_fallback"


@dataclass
class SemanticEvaluation:
    invoked: bool
    blocked: bool
    reason: str | None
    actions: list[RuleAction]


class LanguageDetector:
    def __init__(self) -> None:
        self._fasttext_model = None
        self._fasttext_path = ""
        self._lock = threading.Lock()

    def _load_fasttext(self, model_path: str) -> None:
        if fasttext is None:
            raise RuntimeError("fasttext-wheel is not available")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"fastText model not found: {model_path}")
        if self._fasttext_model is not None and self._fasttext_path == model_path:
            return
        with self._lock:
            if self._fasttext_model is not None and self._fasttext_path == model_path:
                return
            self._fasttext_model = fasttext.load_model(model_path)
            self._fasttext_path = model_path

    def detect(self, text: str, model_path: str) -> tuple[str, float, str]:
        normalized = text.replace("\n", " ").strip()
        if not normalized:
            return "unknown", 0.0, "empty"

        if model_path:
            try:
                self._load_fasttext(model_path)
                labels, probs = self._fasttext_model.predict(normalized, k=1)  # type: ignore[attr-defined]
                lang = str(labels[0]).replace("__label__", "")
                confidence = float(probs[0])
                if lang == "en":
                    lowered = normalized.lower()
                    if any(signal in lowered for signal in ROMANIZED_HINDI_SIGNALS):
                        return "hinglish", min(0.7, confidence), "fasttext+heuristic"
                return lang, confidence, "fasttext"
            except Exception as exc:
                log_json("semantic_lid_fallback", error=str(exc), model_path=model_path)

        fallback_lang = _script_language_fallback(normalized)
        return fallback_lang, 0.5, "heuristic"


class OnnxSetFitClassifier:
    def __init__(self) -> None:
        self._session = None
        self._tokenizer = None
        self._onnx_path = ""
        self._tokenizer_path = ""
        self._lock = threading.Lock()

    def _ensure_loaded(self, onnx_model_path: str, tokenizer_path: str) -> None:
        if ort is None or np is None or Tokenizer is None:
            raise RuntimeError("onnxruntime, numpy, or tokenizers not available")
        if not os.path.exists(onnx_model_path):
            raise FileNotFoundError(f"ONNX model missing: {onnx_model_path}")
        if not os.path.exists(tokenizer_path):
            raise FileNotFoundError(f"Tokenizer missing: {tokenizer_path}")
        if (
            self._session is not None
            and self._tokenizer is not None
            and self._onnx_path == onnx_model_path
            and self._tokenizer_path == tokenizer_path
        ):
            return
        with self._lock:
            if (
                self._session is not None
                and self._tokenizer is not None
                and self._onnx_path == onnx_model_path
                and self._tokenizer_path == tokenizer_path
            ):
                return
            self._session = ort.InferenceSession(onnx_model_path, providers=["CPUExecutionProvider"])
            self._tokenizer = Tokenizer.from_file(tokenizer_path)
            self._onnx_path = onnx_model_path
            self._tokenizer_path = tokenizer_path

    def _model_inputs(self, text: str, max_length: int) -> dict[str, Any]:
        encoded = self._tokenizer.encode(text)  # type: ignore[union-attr]
        input_ids = encoded.ids[:max_length]
        if not input_ids:
            input_ids = [0]
        attention = [1] * len(input_ids)
        if len(input_ids) < max_length:
            pad_len = max_length - len(input_ids)
            input_ids += [0] * pad_len
            attention += [0] * pad_len
        token_type_ids = [0] * max_length

        inputs: dict[str, Any] = {}
        model_inputs = list(self._session.get_inputs())  # type: ignore[union-attr]
        for index, input_meta in enumerate(model_inputs):
            name = input_meta.name
            lowered = name.lower()
            if "token_type" in lowered:
                inputs[name] = np.asarray([token_type_ids], dtype=np.int64)
            elif "attention" in lowered or "mask" in lowered or index == 1:
                inputs[name] = np.asarray([attention], dtype=np.int64)
            else:
                inputs[name] = np.asarray([input_ids], dtype=np.int64)
        return inputs

    def classify(
        self,
        text: str,
        onnx_model_path: str,
        tokenizer_path: str,
        labels: list[str],
        max_length: int,
    ) -> tuple[str, float, str]:
        self._ensure_loaded(onnx_model_path, tokenizer_path)
        inputs = self._model_inputs(text, max_length)
        outputs = self._session.run(None, inputs)  # type: ignore[union-attr]
        if not outputs:
            raise RuntimeError("ONNX model returned no outputs")

        logits_arr = np.asarray(outputs[0], dtype=np.float64)
        if logits_arr.ndim == 2:
            logits = logits_arr[0].tolist()
        elif logits_arr.ndim == 1:
            logits = logits_arr.tolist()
        else:
            logits = logits_arr.reshape(-1).tolist()

        if len(logits) == 1:
            unsafe_prob = _sigmoid(float(logits[0]))
            label_index = 1 if unsafe_prob >= 0.5 and len(labels) > 1 else 0
            confidence = unsafe_prob if label_index == 1 else 1.0 - unsafe_prob
        else:
            probs = _softmax([float(v) for v in logits])
            label_index = max(range(len(probs)), key=lambda i: probs[i])
            confidence = probs[label_index]

        label = labels[label_index] if label_index < len(labels) else f"label_{label_index}"
        return label, float(confidence), "onnx_setfit"


def build_semantic_config(policy: dict[str, Any]) -> SemanticConfig:
    section = policy.get("semantic_layer", {}) if isinstance(policy.get("semantic_layer", {}), dict) else {}
    labels = section.get("labels", _csv_list(settings.semantic_labels))
    block_labels = {
        value.lower()
        for value in section.get("block_labels", _csv_list(settings.semantic_block_labels))
        if str(value).strip()
    }
    language_allowlist = {
        value.lower()
        for value in section.get("language_allowlist", _csv_list(settings.semantic_language_allowlist))
        if str(value).strip()
    }

    return SemanticConfig(
        enabled=bool(section.get("enabled", settings.semantic_enabled_default)),
        mode=str(section.get("mode", settings.semantic_mode_default)).lower(),
        timeout_ms=int(section.get("timeout_ms", settings.semantic_timeout_ms_default)),
        min_risk_score=int(section.get("min_risk_score", settings.semantic_min_risk_score_default)),
        fail_mode=str(section.get("fail_mode", settings.semantic_fail_mode_default)).lower(),
        min_confidence=float(section.get("min_confidence", settings.semantic_min_confidence_default)),
        onnx_model_path=str(section.get("onnx_model_path", settings.semantic_onnx_model_path)),
        tokenizer_path=str(section.get("tokenizer_path", settings.semantic_tokenizer_path)),
        fasttext_model_path=str(section.get("fasttext_model_path", settings.semantic_fasttext_model_path)),
        max_length=int(section.get("max_length", settings.semantic_max_length)),
        labels=[str(label) for label in labels] or ["safe", "unsafe"],
        block_labels=block_labels or {"unsafe"},
        language_allowlist=language_allowlist,
        risk_keywords=[str(item).lower() for item in section.get("risk_keywords", []) if str(item).strip()],
    )


class SemanticLayer:
    def __init__(self) -> None:
        self.language_detector = LanguageDetector()
        self.classifier = OnnxSetFitClassifier()

    def _fallback_classify(self, risk_score: int) -> tuple[str, float, str]:
        if risk_score >= 4:
            confidence = min(0.98, 0.72 + (risk_score - 4) * 0.06)
            return "unsafe", confidence, "lexical_fallback"
        if risk_score >= 2:
            confidence = min(0.75, 0.60 + (risk_score - 2) * 0.05)
            return "unsafe", confidence, "lexical_fallback"
        return "safe", 0.85, "lexical_fallback"

    def _infer_sync(self, text: str, config: SemanticConfig, risk_score: int, reasons: list[str]) -> SemanticInference:
        language, lang_conf, _ = self.language_detector.detect(text, config.fasttext_model_path)
        model_path_available = bool(config.onnx_model_path and config.tokenizer_path)

        if model_path_available:
            try:
                label, confidence, engine = self.classifier.classify(
                    text,
                    config.onnx_model_path,
                    config.tokenizer_path,
                    config.labels,
                    config.max_length,
                )
                return SemanticInference(
                    label=label,
                    confidence=confidence,
                    language=language,
                    language_confidence=lang_conf,
                    risk_score=risk_score,
                    reasons=reasons,
                    engine=engine,
                )
            except Exception as exc:
                log_json("semantic_onnx_fallback", error=str(exc), model=config.onnx_model_path)

        label, confidence, engine = self._fallback_classify(risk_score)
        return SemanticInference(
            label=label,
            confidence=confidence,
            language=language,
            language_confidence=lang_conf,
            risk_score=risk_score,
            reasons=reasons,
            engine=engine,
        )

    async def evaluate(
        self,
        text: str,
        policy: dict[str, Any],
        tenant_id: str,
        request_id: str,
    ) -> SemanticEvaluation:
        config = build_semantic_config(policy)
        if not config.enabled or config.mode == "off":
            return SemanticEvaluation(invoked=False, blocked=False, reason=None, actions=[])

        risk_score, reasons = score_risk(text, config.risk_keywords)
        if risk_score < config.min_risk_score:
            return SemanticEvaluation(invoked=False, blocked=False, reason=None, actions=[])

        timer_start = time.perf_counter()
        timeout_seconds = max(0.001, config.timeout_ms / 1000.0)
        try:
            inference = await asyncio.wait_for(
                asyncio.to_thread(self._infer_sync, text, config, risk_score, reasons),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            blocked = config.fail_mode == "block" and config.mode == "sync_gated"
            outcome = "blocked_timeout" if blocked else "allow_timeout"
            SEMANTIC_REQUESTS.labels(outcome=outcome, engine="timeout").inc()
            SEMANTIC_LATENCY.labels(engine="timeout").observe(time.perf_counter() - timer_start)
            action = RuleAction(
                rule="semantic.timeout",
                action="block" if blocked else "allow",
                detail=f"timeout_ms={config.timeout_ms}",
            )
            return SemanticEvaluation(
                invoked=True,
                blocked=blocked,
                reason="Semantic timeout" if blocked else None,
                actions=[action],
            )
        except Exception as exc:
            blocked = config.fail_mode == "block" and config.mode == "sync_gated"
            outcome = "blocked_error" if blocked else "allow_error"
            SEMANTIC_REQUESTS.labels(outcome=outcome, engine="error").inc()
            SEMANTIC_LATENCY.labels(engine="error").observe(time.perf_counter() - timer_start)
            log_json(
                "semantic_runtime_error",
                tenant_id=tenant_id,
                request_id=request_id,
                error=str(exc),
            )
            action = RuleAction(
                rule="semantic.error",
                action="block" if blocked else "allow",
                detail=f"error={exc.__class__.__name__}",
            )
            return SemanticEvaluation(
                invoked=True,
                blocked=blocked,
                reason="Semantic classifier error" if blocked else None,
                actions=[action],
            )

        SEMANTIC_LATENCY.labels(engine=inference.engine).observe(time.perf_counter() - timer_start)
        block_candidate = (
            inference.label.lower() in config.block_labels
            and inference.confidence >= config.min_confidence
            and config.mode == "sync_gated"
        )
        blocked = block_candidate
        outcome = "blocked" if blocked else "allow"
        SEMANTIC_REQUESTS.labels(outcome=outcome, engine=inference.engine).inc()

        if config.language_allowlist and inference.language.lower() not in config.language_allowlist:
            if config.fail_mode == "block" and config.mode == "sync_gated":
                blocked = True
                outcome = "blocked_language"
            else:
                outcome = "allow_language"
            SEMANTIC_REQUESTS.labels(outcome=outcome, engine=inference.engine).inc()

        action_type = "block" if blocked else ("flag" if block_candidate else "allow")
        actions = [
            RuleAction(
                rule="semantic.classifier",
                action=action_type,
                detail=(
                    f"label={inference.label};confidence={inference.confidence:.3f};"
                    f"language={inference.language};risk={inference.risk_score};engine={inference.engine}"
                ),
            )
        ]
        if reasons:
            actions.append(
                RuleAction(
                    rule="semantic.risk_signals",
                    action="flag",
                    detail=",".join(reasons[:5]),
                )
            )
        reason = "Blocked by semantic policy classifier" if blocked else None
        return SemanticEvaluation(invoked=True, blocked=blocked, reason=reason, actions=actions)

    def runtime_status(self) -> dict[str, bool]:
        return {
            "onnxruntime_available": ort is not None,
            "tokenizers_available": Tokenizer is not None,
            "numpy_available": np is not None,
            "fasttext_available": fasttext is not None,
        }


semantic_layer = SemanticLayer()
