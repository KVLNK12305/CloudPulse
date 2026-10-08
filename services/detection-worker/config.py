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


config = Config()
