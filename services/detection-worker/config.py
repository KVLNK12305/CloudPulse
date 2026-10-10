import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    # Log Analytics & Azure Identity
    WORKSPACE_ID: str = os.getenv("LOG_ANALYTICS_WORKSPACE_ID", "f4fcc158-554b-497e-8231-4cc47c66b194")
    AZURE_CLIENT_ID: str = os.getenv("AZURE_CLIENT_ID", "")
    
    # Database Settings
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "cloudpulse-postgres01.postgres.database.azure.com")
    POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "postgres")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "cloudpulseadmin")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "")
    POSTGRES_SSLMODE: str = os.getenv("POSTGRES_SSLMODE", "require")
    
    # Execution Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
    
    # Query default lookback window (in minutes)
    LOOKBACK_MINUTES: int = int(os.getenv("LOOKBACK_MINUTES", "60"))

    # FinOps Cost Management Telemetry
    COST_LOOKBACK_DAYS: int = int(os.getenv("COST_LOOKBACK_DAYS", "14"))
    COST_QUERY_API_VERSION: str = os.getenv("COST_QUERY_API_VERSION", "2023-11-01")
    AZURE_SUBSCRIPTION_ID: str = os.getenv("AZURE_SUBSCRIPTION_ID", "90b900ea-4273-4b40-a343-091aecfe2911")

    # Azure AI Triage Settings
    AZURE_OPENAI_ENDPOINT: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    AZURE_OPENAI_API_KEY: str = os.getenv("AZURE_OPENAI_API_KEY", "")
    AZURE_OPENAI_DEPLOYMENT_NAME: str = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "cloudpulse-triage")
    AZURE_OPENAI_MODEL_NAME: str = os.getenv("AZURE_OPENAI_MODEL_NAME", "gpt-4.1-mini")
    AZURE_OPENAI_API_VERSION: str = os.getenv("AZURE_OPENAI_API_VERSION", "")
    AI_LIVE_ENABLED: bool = os.getenv("AI_LIVE_ENABLED", "true").lower() in ("true", "1", "yes")
    AI_MOCK_MODE: bool = os.getenv("AI_MOCK_MODE", "false").lower() in ("true", "1", "yes")
    AI_REQUEST_TIMEOUT_SECONDS: int = int(os.getenv("AI_REQUEST_TIMEOUT_SECONDS", "30"))
    AI_MAX_TOKENS: int = int(os.getenv("AI_MAX_TOKENS", "2048"))
    AI_TEMPERATURE: float = float(os.getenv("AI_TEMPERATURE", "0.1"))
    AI_IS_REASONING_MODEL: bool = os.getenv("AI_IS_REASONING_MODEL", "false").lower() in ("true", "1", "yes")
    AI_MAX_RETRIES: int = int(os.getenv("AI_MAX_RETRIES", "3"))
    AI_MAX_INPUT_CHARS: int = int(os.getenv("AI_MAX_INPUT_CHARS", "32000"))


config = Config()
