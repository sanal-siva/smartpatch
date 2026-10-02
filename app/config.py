"""Deployment settings; secrets are never included in public configuration."""
from pathlib import Path
from typing import Literal
from pydantic import Field, field_validator
from urllib.parse import urlparse
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    database_url: str = 'sqlite:///./.state/smart_patch.db'
    state_dir: Path = Path('.state')
    host: str = '100.104.17.32'
    port: int = 8000
    tls_cert: str = ''
    tls_key: str = ''
    log_level: str = 'INFO'
    bootstrap_token: str = ''
    scanner_binary: str = 'grype'
    scanner_db_dir: str = '.state/grype-db'
    scan_timeout_seconds: int = Field(600, ge=5, le=3600)
    scanner_max_output_bytes: int = Field(64 * 1024 * 1024, ge=1024)
    scan_interval_seconds: int = Field(21600, ge=30)
    worker_count: int = Field(1, ge=1, le=4)
    jobs_enabled: bool = True
    source_roots: list[str] = []
    source_revision: str = ''
    ai_enabled: bool = False
    build_evidence_policy: Literal['required', 'optional'] = 'required'
    ai_provider: str = 'openai'
    ai_api_url: str = ''
    ai_api_key: str = ''
    ai_model: str = ''
    ai_max_calls: int = Field(4, ge=0, le=20)
    ai_max_findings: int = Field(10, ge=0, le=100)
    ai_max_tool_calls: int = Field(6, ge=0, le=30)
    ai_max_input_chars: int = Field(24000, ge=1000, le=100000)
    ai_max_output_tokens: int = Field(1200, ge=100, le=8000)
    ai_timeout_seconds: int = Field(30, ge=1, le=120)
    cache_ttl_hours: int = 24
    max_request_bytes: int = 16 * 1024 * 1024
    max_sbom_upload_bytes: int = Field(50 * 1024 * 1024, ge=1024, le=256 * 1024 * 1024)
    online_threshold_seconds: int = 300
    retention_days: int = 365
    alerts_enabled: bool = True
    alert_min_samples: int = Field(20,ge=1,le=8192)
    alert_latency_p95_seconds: float = Field(2,gt=0,le=600)
    alert_cache_hit_rate_percent: float = Field(70,ge=0,le=100)
    alert_error_rate_percent: float = Field(5,ge=0,le=100)
    alert_queue_depth: int = Field(100,ge=0,le=100000)
    sonic_releases: list = []
    sbom_source: str = ''

    @field_validator('ai_api_url')
    @classmethod
    def validate_provider_url(cls,value):
        if not value:return value
        parsed=urlparse(value)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('AI API URL must be HTTP(S) without embedded credentials, query or fragment')
        if parsed.scheme=='http' and parsed.hostname not in ('127.0.0.1','localhost','::1'):
            raise ValueError('Remote AI endpoints require HTTPS; HTTP is only supported for local providers')
        return value.rstrip('/')


settings = Settings()
