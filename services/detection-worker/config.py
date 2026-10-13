import os
from dataclasses import dataclass


def _load_dotenv():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, ".env"),
        os.path.join(base_dir, "..", "..", ".env"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("'\"")
                            if k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass


_load_dotenv()


@dataclass(frozen=True)
class Config:
    # Log Analytics & Azure Identity
    # SEC-CONFIG-01: Do not commit production identifiers as defaults.
    # All values MUST be provided via environment variables.
    WORKSPACE_ID: str = os.getenv("LOG_ANALYTICS_WORKSPACE_ID", "")
    AZURE_CLIENT_ID: str = os.getenv("AZURE_CLIENT_ID", "")
    
    # Database Settings
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "")
    POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "postgres")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "")
    POSTGRES_SSLMODE: str = os.getenv("POSTGRES_SSLMODE", "require")
    
    # Execution Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
    
    # Query default lookback window (in minutes)
    LOOKBACK_MINUTES: int = int(os.getenv("LOOKBACK_MINUTES", "60"))

    # FinOps Cost Management Telemetry
    COST_LOOKBACK_DAYS: int = int(os.getenv("COST_LOOKBACK_DAYS", "14"))
    COST_QUERY_API_VERSION: str = os.getenv("COST_QUERY_API_VERSION", "2023-11-01")
    AZURE_SUBSCRIPTION_ID: str = os.getenv("AZURE_SUBSCRIPTION_ID", "")

    # Supabase Authentication & Identity Settings
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_SERVICE_ROLE_KEY: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
    SUPABASE_JWT_SECRET: str = os.getenv("SUPABASE_JWT_SECRET", "")

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
