import os
from typing import List, Set
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "AI Cyber Threat Intelligence & Automated Response Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./cyber_threat_platform.db"
    )

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    # Secret key
    SECRET_KEY: str = os.getenv("SECRET_KEY", "academic-prototype-cyber-threat-secret-2026")

    # Detection Thresholds
    LOGIN_FAILED_THRESHOLD: int = int(os.getenv("LOGIN_FAILED_THRESHOLD", "5"))
    LOGIN_WINDOW_SECONDS: int = int(os.getenv("LOGIN_WINDOW_SECONDS", "120"))
    
    PORT_SCAN_PORT_THRESHOLD: int = int(os.getenv("PORT_SCAN_PORT_THRESHOLD", "15"))
    PORT_SCAN_WINDOW_SECONDS: int = int(os.getenv("PORT_SCAN_WINDOW_SECONDS", "60"))
    
    CORRELATION_WINDOW_SECONDS: int = int(os.getenv("CORRELATION_WINDOW_SECONDS", "1800"))
    # Login log analysis
    LOGIN_RATIO_WINDOW_DAYS: int = int(os.getenv("LOGIN_RATIO_WINDOW_DAYS", "7"))
    LOGIN_RATIO_MIN_ATTEMPTS: int = int(os.getenv("LOGIN_RATIO_MIN_ATTEMPTS", "8"))
    LOGIN_RATIO_THRESHOLD: float = float(os.getenv("LOGIN_RATIO_THRESHOLD", "3.0"))

    # Risk decay: lose DECAY_PERCENT of the score for every DECAY_STEP_HOURS without new evidence
    DECAY_STEP_HOURS: float = float(os.getenv("DECAY_STEP_HOURS", "6"))
    DECAY_PERCENT: float = float(os.getenv("DECAY_PERCENT", "10"))
    DECAY_FLOOR_RATIO: float = float(os.getenv("DECAY_FLOOR_RATIO", "0.5"))
    DECAY_JOB_INTERVAL_SECONDS: int = int(os.getenv("DECAY_JOB_INTERVAL_SECONDS", "600"))
    GRAPH_JOB_INTERVAL_SECONDS: int = int(os.getenv("GRAPH_JOB_INTERVAL_SECONDS", "900"))
    GRAPH_LOOKBACK_HOURS: int = int(os.getenv("GRAPH_LOOKBACK_HOURS", "24"))

    # Admin login (single admin, see docs)
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "admin123")
    TOKEN_EXPIRE_MINUTES: int = int(os.getenv("TOKEN_EXPIRE_MINUTES", "480"))

    # Decoys planted by the system at startup (Step 8.5). They are copied into the honeytokens
    # table and the detector reads that table. Fixed default list; HONEYTOKENS in .env can replace it.
    HONEYTOKENS: str = os.getenv(
        "HONEYTOKENS",
        "HONEYTOKEN_AWS_DEV_KEY_9921,decoy_admin_token_alpha,svc_backup_decoy,"
        "PROD_DB_SECRET_DECOY_X9,fake_api_gateway_key_demo,/admin/backup-keys",
    )

    @property
    def honeytoken_list(self):
        return [t.strip() for t in self.HONEYTOKENS.split(",") if t.strip()]

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "allow"


settings = Settings()
