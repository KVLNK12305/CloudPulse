"""
Adversarial Identity, Secrets & Platform Test Suite (Scenarios 28-31)
Tests credential chain pinning, committed secrets and tenant identifiers,
API authN/authZ perimeter vulnerabilities, and PostgreSQL connection/injection safety.
"""

import os
import re
from typing import Dict, Any
from unittest.mock import patch, MagicMock
import pytest

from config import config, Config
from services.azure_network_client import AzureNetworkClient
from services.azure_ai_client import AzureAIClient
from services.auth_service import AuthService
from database.postgres import PostgresDatabase, InMemoryDatabase
from app import create_app


class TestAdversarialIdentityPlatform:

    def test_scenario_28_credential_chain_unpinned_in_production(self):
        """
        Scenario 28: Is DefaultAzureCredential pinned strictly to Managed Identity in prod?
        Audit: When config.AZURE_CLIENT_ID is unset, DefaultAzureCredential() is initialized
        without excluding Developer / Environment credentials (e.g. AzureCliCredential, EnvironmentCredential).
        """
        with patch("services.azure_network_client.DefaultAzureCredential") as mock_dac:
            with patch("services.azure_network_client.config") as mock_cfg:
                mock_cfg.AZURE_CLIENT_ID = ""
                mock_cfg.AZURE_SUBSCRIPTION_ID = "sub-123"
                client = AzureNetworkClient()
                mock_dac.assert_called_once_with()
                # Verify that exclusions (exclude_cli_credential, exclude_environment_credential) were NOT passed
                kwargs = mock_dac.call_args[1]
                assert "exclude_cli_credential" not in kwargs, (
                    "UNPINNED CREDENTIAL CHAIN CONFIRMED: DefaultAzureCredential does not exclude dev/cli credentials, "
                    "allowing local dev/environment secrets to leak in production."
                )

    def test_scenario_29_hardcoded_tenant_identifiers_committed(self):
        """
        Scenario 29: Hardcoded secrets, subscription/resource IDs, ETags committed to repo or docs.
        Verify hardcoded production tenant identifiers in config.py defaults.
        """
        assert config.AZURE_SUBSCRIPTION_ID == "90b900ea-4273-4b40-a343-091aecfe2911", (
            "HARDCODED PRODUCTION IDENTIFIER: AZURE_SUBSCRIPTION_ID committed as default in source code."
        )
        assert config.WORKSPACE_ID == "f4fcc158-554b-497e-8231-4cc47c66b194", (
            "HARDCODED PRODUCTION IDENTIFIER: Log Analytics WORKSPACE_ID committed as default in source code."
        )
        assert "cloudpulse-postgres01.postgres.database.azure.com" in config.POSTGRES_HOST, (
            "HARDCODED INFRASTRUCTURE HOST: POSTGRES_HOST committed as default in source code."
        )
        assert "vrwqpgodyndyszgnnssn.supabase.co" in config.SUPABASE_URL, (
            "HARDCODED TENANT URL: SUPABASE_URL committed as default in source code."
        )

    def test_scenario_30_api_authz_missing_on_read_and_triage_routes(self):
        """
        Scenario 30: Dashboard/API authN & authZ.
        Audit: Critical read and AI triage routes lack authentication decorators:
        - GET /api/incidents
        - POST /api/incidents/<id>/ai-triage
        - PATCH /api/incidents/<id>
        Anyone can read incidents or trigger costly AI triage unauthenticated!
        """
        app = create_app(db_repo=InMemoryDatabase())
        client = app.test_client()

        # 1. GET /api/incidents without Authorization header
        resp_get = client.get("/api/incidents")
        assert resp_get.status_code == 200, (
            f"UNAUTHENTICATED READ ACCESS: GET /api/incidents returned HTTP {resp_get.status_code} without credentials."
        )

        # 2. POST /api/incidents/INC-NONEXISTENT/ai-triage without Authorization header
        resp_ai = client.post("/api/incidents/INC-NONEXISTENT/ai-triage")
        # Route processes request without checking auth (returns 404 for not found rather than 401 Unauthorized)
        assert resp_ai.status_code == 404, (
            f"UNAUTHENTICATED AI TRIAGE INVOCATION: Route reached incident lookup without 401 auth gate."
        )

        # 3. Rate limiting audit: check if Flask app has rate limiting extensions (e.g. Flask-Limiter)
        has_limiter = hasattr(app, "extensions") and any("limit" in k.lower() for k in app.extensions.keys())
        assert not has_limiter, "NO RATE LIMITING: Flask app has no global rate limiting middleware registered."

    def test_scenario_31_postgres_connection_pooling_and_migration_safety(self):
        """
        Scenario 31: Postgres connection security, SQL injection surface, and migration safety.
        Audit:
        - Connection pooling: PostgresDatabase opens a direct psycopg2.connect per query without pooling.
        - Migration safety: Runs unversioned raw DDL without schema migration version table.
        """
        pg = PostgresDatabase(
            host="localhost",
            port=5432,
            database="testdb",
            user="user",
            password="pwd",
        )

        # Check if PostgresDatabase has a connection pool attribute
        has_pool = hasattr(pg, "_pool") or hasattr(pg, "connection_pool")
        assert not has_pool, (
            "CONNECTION EXHAUSTION RISK CONFIRMED: PostgresDatabase does not use a connection pool (opens fresh socket per query)."
        )

        # Check migration file for version tracking table
        migration_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "services",
            "detection-worker",
            "database",
            "migrations",
            "001_initial_schema.sql",
        )
        with open(migration_file, "r", encoding="utf-8") as f:
            ddl_content = f.read()

        has_version_table = "schema_migrations" in ddl_content or "alembic_version" in ddl_content
        assert not has_version_table, (
            "UNVERSIONED MIGRATION HAZARD CONFIRMED: 001_initial_schema.sql lacks migration version tracking table."
        )
