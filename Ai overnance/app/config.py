from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ai-governance-gateway"
    env: str = "dev"
    port: int = 8000
    log_level: str = "INFO"

    gateway_api_key: str = "change-me"
    auth_mode: str = "either"  # api_key | jwt | either
    jwt_secret: str = "change-me-super-secret"
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "ai-governance"
    jwt_audience: str = "ai-governance-clients"

    upstream_llm_url: str = "https://api.openai.com/v1/chat/completions"
    upstream_llm_api_key: str = "change-me"
    llm_timeout_seconds: float = 20.0
    llm_max_retries: int = 2
    llm_retry_backoff_seconds: float = 0.3
    cb_failure_threshold: int = 5
    cb_recovery_seconds: int = 30

    policy_dir: str = "./policies"
    policy_hmac_secret: str | None = None

    redis_url: str = "redis://localhost:6379/0"
    postgres_dsn: str = "postgresql://governance:governance@localhost:5432/governance"
    rate_limit_per_minute: int = 120
    audit_queue_maxsize: int = 10_000
    audit_batch_size: int = 100
    audit_flush_seconds: float = 0.5

    semantic_enabled_default: bool = True
    semantic_mode_default: str = "sync_gated"  # off | sync_gated | async_only
    semantic_timeout_ms_default: int = 10
    semantic_min_risk_score_default: int = 2
    semantic_fail_mode_default: str = "allow"  # allow | block
    semantic_min_confidence_default: float = 0.8
    semantic_onnx_model_path: str = "./models/semantic_setfit_int8.onnx"
    semantic_tokenizer_path: str = "./models/tokenizer.json"
    semantic_fasttext_model_path: str = "./models/lid.176.ftz"
    semantic_max_length: int = 128
    semantic_labels: str = "safe,unsafe"
    semantic_block_labels: str = "unsafe,jailbreak,policy_bypass,data_exfil"
    semantic_language_allowlist: str = "en,hi,mr,bn,ta,te,kn,ml,gu,pa,ur,hinglish"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
