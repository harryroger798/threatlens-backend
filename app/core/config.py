from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "ThreatLens"
    APP_VERSION: str = "1.0.0"
    ENV: str = "local"

    # System of record. Postgres in production (e.g. postgresql+psycopg://user:pass@host/db),
    # SQLite for zero-dependency local runs.
    DATABASE_URL: str = "sqlite:///./threatlens.db"

    # Auth
    SECRET_KEY: str = "threatlens-dev-secret-change-me-in-production"
    ACCESS_TOKEN_MINUTES: int = 30
    REFRESH_TOKEN_DAYS: int = 7
    MFA_REQUIRED_FOR: list[str] = ["administrator"]  # roles where TOTP may be enforced when enrolled

    # Login hardening
    MAX_FAILED_LOGINS: int = 5
    LOCKOUT_MINUTES: int = 15

    # Rate limiting (per principal)
    RATE_LIMIT_PER_MINUTE: int = 240

    # Elasticsearch (optional; when set, search routes to ES)
    ES_URL: str = ''

    # Feed polling defaults (seconds); each feed can override its own schedule
    FEED_POLL_INTERVAL_DEFAULT: int = 900

    # Scoring model weights (documented in services/scoring.py)
    SCORE_W_SOURCE: float = 0.30
    SCORE_W_CONFIDENCE: float = 0.25
    SCORE_W_RECENCY: float = 0.20
    SCORE_W_SIGHTINGS: float = 0.15
    SCORE_W_TYPE: float = 0.10

    # Correlation window for matching indicators to internal events (days)
    CORRELATION_WINDOW_DAYS: int = 7

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
