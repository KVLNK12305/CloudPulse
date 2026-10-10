"""
Tests for explicit AI Provider Attribution, graceful degradation, and database degradation visibility.
Verifies Phase 2, Phase 3, Phase 4, and Phase 5 requirements:
- Missing endpoint selects explicitly labelled fallback mode.
- Mock mode cannot be mistaken for live inference.
- Successful inference is labelled LIVE.
- Authentication, authorization, timeout, and rate-limit failures are handled correctly.
- Fallback output never falsely claims a real model (gpt-4o) generated it.
- Database disconnection is reflected in health/readiness.
- In-memory operation is explicitly identified.
- Existing incident invariants remain intact under degradation.
- Dashboard summary accurately reflects live vs fallback execution counts.
"""

import io
import json
import urllib.error
from unittest.mock import MagicMock, patch
import pytest

from database.postgres import InMemoryDatabase
from models.finding import (
    Finding,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    SeverityLevel,
    generate_deterministic_finding_id,
)
from models.incident import Incident, IncidentStatus, generate_deterministic_incident_id
from models.ai_context import AITriageAnalysis, AISafeIncidentContext
from services.azure_ai_client import (
    AzureAIClient,
    AzureAIError,
    AzureAIAuthError,
    AzureAIRateLimitError,
    AzureAITimeoutError,
    AzureAIUnavailableError,
)
from services.ai_triage_service import AITriageService
from app import create_app


RES_ID = "/subscriptions/90b900ea-4273-4b40-a343-091aecfe2911/resourceGroups/cloudpulse-rg/providers/Microsoft.Compute/virtualMachines/vm-sec-01"


def _build_test_incident():
    f = Finding(
        finding_id=generate_deterministic_finding_id("evt-101", RES_ID),
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.HIGH,
        timestamp="2026-10-09T10:00:00Z",
        resource=ResourceInfo(id=RES_ID, type="Microsoft.Compute/virtualMachines", name="vm-sec-01", resource_group="cloudpulse-rg"),
        identity=IdentityInfo(caller="admin@cloudpulse.io"),
        evidence=EvidenceInfo(
            operation="MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
            activity_log_event_id="evt-101",
            subscription_id="90b900ea-4273-4b40-a343-091aecfe2911",
        ),
        confidence=0.95,
    )
    iid = generate_deterministic_incident_id(resource_id=RES_ID)
    incident = Incident(
        incident_id=iid,
        title="High Severity Anomaly on vm-sec-01",
        severity=SeverityLevel.HIGH,
        status=IncidentStatus.OPEN,
        created_at="2026-10-09T10:00:00Z",
        updated_at="2026-10-09T10:00:00Z",
        resource=f.resource,
        identity=f.identity,
        findings=[f.finding_id],
        cost_impact={"actual_cost": 120.0, "baseline_cost": 20.0, "deviation_absolute": 100.0},
        timeline=[{"timestamp": "2026-10-09T10:00:00Z", "event": "CREATED"}],
    )
    return incident, [f]


class TestAIProviderAttribution:

    def test_missing_endpoint_selects_explicitly_labelled_fallback_mode(self):
        """When AZURE_OPENAI_ENDPOINT is empty, client must execute FALLBACK synthesis."""
        client = AzureAIClient(endpoint="", mock_mode=False)
        assert client.get_configuration_status()["status"] == "MISSING_ENDPOINT"
        assert client.get_configuration_status()["execution_mode"] == "FALLBACK"

        incident, findings = _build_test_incident()
        f_map = {f.finding_id: f for f in findings}
        ctx = AISafeIncidentContext.from_incident(incident, f_map)

        result = client.complete_chat(system_prompt="sys", user_prompt="usr", context=ctx)
        assert result["execution_mode"] == "FALLBACK"
        assert result["provider_status"] == "FALLBACK"
        assert result["provider"] == "deterministic-synthesizer"
        assert result["model_identifier"] == "cloudpulse-deterministic-synthesizer/v1"
        assert result["model_identifier"] != "gpt-4o"
        assert result["latency_ms"] is not None

    def test_mock_mode_cannot_be_mistaken_for_live_inference(self):
        """When mock_mode=True, even with an endpoint set, it must NEVER claim LIVE or gpt-4o."""
        client = AzureAIClient(endpoint="https://cloudpulse-ai.openai.azure.com", mock_mode=True)
        assert client.get_configuration_status()["status"] == "MOCK_MODE"
        assert client.get_configuration_status()["execution_mode"] == "FALLBACK"

        incident, findings = _build_test_incident()
        ctx = AISafeIncidentContext.from_incident(incident, {f.finding_id: f for f in findings})

        result = client.complete_chat(system_prompt="sys", user_prompt="usr", context=ctx)
        assert result["execution_mode"] == "FALLBACK"
        assert result["execution_mode"] != "LIVE"
        assert result["provider"] == "deterministic-synthesizer"
        assert result["model_identifier"] == "cloudpulse-deterministic-synthesizer/v1"

    def test_successful_live_inference_labelled_live(self):
        """When real inference succeeds, it must be explicitly labelled LIVE with deployment name."""
        mock_response_body = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps({
                            "summary": "Live inference analyzed compromised VM perimeter.",
                            "risk_assessment": "CRITICAL risk confirmed via model reasoning.",
                            "likely_scenario": "External inbound reconnaissance detected.",
                            "security_impact": "Perimeter exposed to public Internet.",
                            "financial_impact": "$100 cost overrun observed.",
                            "facts": ["VM provisioned by admin@cloudpulse.io"],
                            "inferences": ["External caller may attempt exploitation"],
                            "key_evidence": [{"source": "RESOURCE_CREATION", "observation": "VM created"}],
                            "recommended_actions": [
                                {
                                    "id": "ACT-01",
                                    "title": "Restrict Inbound Access",
                                    "description": "Block public ingress on NSG",
                                    "category": "CONTAINMENT",
                                    "risk": "LOW",
                                    "requires_human_approval": True,
                                }
                            ],
                            "confidence": 0.94,
                            "limitations": ["Live inference token budget restricted to 2048"],
                        })
                    }
                }
            ]
        }

        client = AzureAIClient(
            endpoint="https://cloudpulse-ai.openai.azure.com",
            api_key="mock-api-key",
            deployment_name="cloudpulse-triage",
            model_identifier="gpt-4.1-mini",
            mock_mode=False,
        )

        mock_http_response = MagicMock()
        mock_http_response.read.return_value = json.dumps(mock_response_body).encode("utf-8")
        mock_http_response.__enter__.return_value = mock_http_response

        with patch("urllib.request.urlopen", return_value=mock_http_response):
            result = client.complete_chat(system_prompt="sys", user_prompt="usr")

        assert result["execution_mode"] == "LIVE"
        assert result["provider_status"] == "LIVE"
        assert result["provider"] == "azure-openai"
        assert result["deployment_name"] == "cloudpulse-triage"
        assert result["model_identifier"] == "gpt-4.1-mini"
        assert result["latency_ms"] is not None

    def test_auth_error_sanitized_and_classified_unavailable(self):
        """401/403 authorization failure must degrade to UNAVAILABLE without leaking tokens."""
        mock_client = MagicMock(spec=AzureAIClient)
        mock_client.complete_chat.side_effect = AzureAIAuthError("Azure AI authorization rejected (401)")
        mock_client.deployment_name = "cloudpulse-triage"
        mock_client.model_identifier = "gpt-4.1-mini"

        db = InMemoryDatabase()
        incident, findings = _build_test_incident()
        for f in findings:
            db.save_finding(f)
        db.save_incident(incident)

        svc = AITriageService(db_repo=db, ai_client=mock_client)
        analysis = svc.triage_incident(incident)

        assert analysis.status == "UNAVAILABLE"
        assert analysis.execution_mode == "UNAVAILABLE"
        assert analysis.provider_status == "UNAVAILABLE"
        assert analysis.provider == "none"
        assert analysis.error_category == "AUTH_ERROR"
        assert analysis.model_identifier == "none"
        assert "Bearer" not in (analysis.error_message or "")
        assert "key" not in (analysis.error_message or "").lower()

    def test_rate_limit_classified_unavailable(self):
        """429 Rate Limit must degrade to UNAVAILABLE with RATE_LIMIT category."""
        mock_client = MagicMock(spec=AzureAIClient)
        mock_client.complete_chat.side_effect = AzureAIRateLimitError("Azure AI rate limit exceeded (429)")

        db = InMemoryDatabase()
        incident, findings = _build_test_incident()
        for f in findings:
            db.save_finding(f)
        db.save_incident(incident)

        svc = AITriageService(db_repo=db, ai_client=mock_client)
        analysis = svc.triage_incident(incident)

        assert analysis.status == "UNAVAILABLE"
        assert analysis.execution_mode == "UNAVAILABLE"
        assert analysis.error_category == "RATE_LIMIT"

    def test_timeout_classified_unavailable(self):
        """Timeout must degrade to UNAVAILABLE with TIMEOUT category."""
        mock_client = MagicMock(spec=AzureAIClient)
        mock_client.complete_chat.side_effect = AzureAITimeoutError("Azure AI request timed out after 30s")

        db = InMemoryDatabase()
        incident, findings = _build_test_incident()
        for f in findings:
            db.save_finding(f)
        db.save_incident(incident)

        svc = AITriageService(db_repo=db, ai_client=mock_client)
        analysis = svc.triage_incident(incident)

        assert analysis.status == "UNAVAILABLE"
        assert analysis.execution_mode == "UNAVAILABLE"
        assert analysis.error_category == "TIMEOUT"

    def test_malformed_json_classified_schema_error(self):
        """Malformed or non-JSON model response must degrade to UNAVAILABLE with SCHEMA_ERROR."""
        mock_client = MagicMock(spec=AzureAIClient)
        mock_client.complete_chat.side_effect = AzureAIError("Azure AI response was not valid JSON")

        db = InMemoryDatabase()
        incident, findings = _build_test_incident()
        for f in findings:
            db.save_finding(f)
        db.save_incident(incident)

        svc = AITriageService(db_repo=db, ai_client=mock_client)
        analysis = svc.triage_incident(incident)

        assert analysis.status == "UNAVAILABLE"
        assert analysis.error_category == "SCHEMA_ERROR"

    def test_fallback_output_never_claims_gpt4o(self):
        """AITriageService with fallback client must output model_identifier for synthesizer, not gpt-4o."""
        fallback_client = AzureAIClient(endpoint="", mock_mode=False)
        db = InMemoryDatabase()
        incident, findings = _build_test_incident()
        for f in findings:
            db.save_finding(f)
        db.save_incident(incident)

        svc = AITriageService(db_repo=db, ai_client=fallback_client)
        analysis = svc.triage_incident(incident)

        assert analysis.status == "COMPLETED"
        assert analysis.execution_mode == "FALLBACK"
        assert analysis.provider_status == "FALLBACK"
        assert analysis.provider == "deterministic-synthesizer"
        assert analysis.model_identifier == "cloudpulse-deterministic-synthesizer/v1"
        assert analysis.model_identifier != "gpt-4o"
        assert "gpt-4o" not in analysis.model_identifier

    def test_incident_invariants_preserved_under_ai_degradation(self):
        """Incident severity, cost_impact, findings, and resource remain intact under AI failure."""
        mock_client = MagicMock(spec=AzureAIClient)
        mock_client.complete_chat.side_effect = AzureAIUnavailableError("503")

        db = InMemoryDatabase()
        incident, findings = _build_test_incident()
        for f in findings:
            db.save_finding(f)
        db.save_incident(incident)

        orig_sev = incident.severity
        orig_cost = incident.cost_impact
        orig_findings = list(incident.findings)
        orig_res_id = incident.resource.id

        svc = AITriageService(db_repo=db, ai_client=mock_client)
        svc.triage_incident(incident)

        refreshed = db.get_incident(incident.incident_id)
        assert refreshed is not None
        assert refreshed.severity == orig_sev
        assert refreshed.cost_impact == orig_cost
        assert refreshed.findings == orig_findings
        assert refreshed.resource.id == orig_res_id


class TestDatabaseDegradationVisibility:

    def test_database_disconnection_reflected_in_health_endpoint(self):
        """When PostgreSQL fails to connect, /health must report degraded status and unready database."""
        import dataclasses
        from config import config as base_cfg
        prod_cfg = dataclasses.replace(base_cfg, ENVIRONMENT="production", POSTGRES_PASSWORD="mock-secret-password")

        with patch("app.config", prod_cfg):
            with patch("database.postgres.PostgresDatabase.__init__", side_effect=Exception("Connection refused to cloudpulse-postgres01")):
                app = create_app(db_repo=None, log_client=None)
                client = app.test_client()

                resp = client.get("/health")
                assert resp.status_code == 200
                data = resp.get_json()

                assert data["status"] == "degraded"
                assert data["storage"] == "in_memory"
                assert data["database"]["connected"] is False
                assert data["database"]["durable"] is False
                assert data["database"]["readiness"] == "unhealthy"
                assert data["database"]["degraded"] is True
                assert "failed" in (data["database"]["degradation_reason"] or "")

    def test_in_memory_mode_explicitly_identified_in_triage_api(self):
        """POST /api/incidents/<id>/ai-triage must report storage_mode and storage_warning in in-memory mode."""
        db = InMemoryDatabase()
        incident, findings = _build_test_incident()
        for f in findings:
            db.save_finding(f)
        db.save_incident(incident)

        ai_client = AzureAIClient(endpoint="", mock_mode=False)
        app = create_app(db_repo=db, log_client=None, ai_client=ai_client)
        client = app.test_client()

        resp = client.post(f"/api/incidents/{incident.incident_id}/ai-triage")
        assert resp.status_code == 200
        data = resp.get_json()

        assert data["storage_mode"] == "in_memory"
        assert data["durable"] is False
        assert "volatile" in data["storage_warning"].lower()
        assert data["ai_analysis"]["execution_mode"] == "FALLBACK"
        assert data["ai_analysis"]["provider"] == "deterministic-synthesizer"

    def test_dashboard_summary_reports_live_and_fallback_counts(self):
        """GET /api/dashboard/summary distinguishes triaged_live_count and triaged_fallback_count."""
        db = InMemoryDatabase()
        incident, findings = _build_test_incident()
        for f in findings:
            db.save_finding(f)
        
        # Attach a fallback analysis
        incident.ai_analysis = {
            "summary": "Offline triage",
            "risk_assessment": "Standard",
            "likely_scenario": "Baseline",
            "security_impact": "None",
            "financial_impact": "None",
            "confidence": 0.88,
            "status": "COMPLETED",
            "execution_mode": "FALLBACK",
            "provider_status": "FALLBACK",
            "provider": "deterministic-synthesizer",
            "model_identifier": "cloudpulse-deterministic-synthesizer/v1",
        }
        db.save_incident(incident)

        app = create_app(db_repo=db, log_client=None)
        client = app.test_client()

        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        data = resp.get_json()

        assert data["triaged_count"] >= 1
        assert data["triaged_fallback_count"] >= 1
        assert data["triaged_live_count"] == 0
        assert data["storage_mode"] == "in_memory"
        assert data["durable"] is False

    def test_ai_status_endpoint_reports_configuration(self):
        """GET /api/ai/status safely reports AI provider execution mode without revealing secrets."""
        ai_client = AzureAIClient(
            endpoint="",
            api_key="super-secret-key-12345",
            mock_mode=False,
        )
        app = create_app(db_repo=InMemoryDatabase(), log_client=None, ai_client=ai_client)
        client = app.test_client()

        resp = client.get("/api/ai/status")
        assert resp.status_code == 200
        data = resp.get_json()

        assert data["status"] == "success"
        cfg = data["ai_configuration"]
        assert cfg["status"] == "MISSING_ENDPOINT"
        assert cfg["execution_mode"] == "FALLBACK"
        assert cfg["provider"] == "deterministic-synthesizer"
        # Secret api_key MUST NOT be exposed
        assert "super-secret" not in json.dumps(data)


class TestAzureOpenAIResilienceAndAttribution:

    def test_permission_denied_classification(self):
        """Simulate 401 PermissionDenied data-plane response; verify error classification."""
        from services.azure_ai_client import AzureAIPermissionDeniedError
        client = AzureAIClient(
            endpoint="https://cloudpulse-openai01.openai.azure.com",
            deployment_name="cloudpulse-triage",
            api_key="mock-key",
            mock_mode=False,
            max_retries=0,
        )

        err_body = json.dumps({
            "error": {
                "code": "PermissionDenied",
                "message": "The principal lacks the required data action Microsoft.CognitiveServices/accounts/OpenAI/deployments/chat/completions/action"
            }
        }).encode("utf-8")

        mock_http_err = urllib.error.HTTPError(
            url="https://cloudpulse-openai01.openai.azure.com/openai/v1/chat/completions",
            code=401,
            msg="PermissionDenied",
            hdrs={},
            fp=io.BytesIO(err_body),
        )

        with patch("urllib.request.urlopen", side_effect=mock_http_err):
            with pytest.raises(AzureAIPermissionDeniedError):
                client.complete_chat(system_prompt="sys", user_prompt="usr")

        assert client.get_configuration_status()["error_category"] == "permission_denied"
        assert client.get_configuration_status()["execution_mode"] == "FALLBACK"

    def test_rate_limit_with_retry_after_retried_and_succeeds(self):
        """429 with Retry-After header must be retried and succeed on subsequent attempt."""
        client = AzureAIClient(
            endpoint="https://cloudpulse-openai01.openai.azure.com",
            deployment_name="cloudpulse-triage",
            api_key="mock-key",
            mock_mode=False,
            max_retries=2,
        )

        mock_429 = urllib.error.HTTPError(
            url="https://cloudpulse-openai01.openai.azure.com/openai/v1/chat/completions",
            code=429,
            msg="Too Many Requests",
            hdrs={"Retry-After": "0.01"},
            fp=io.BytesIO(b'{"error":{"code":"429"}}'),
        )

        success_body = {
            "choices": [{"message": {"content": json.dumps({"summary": "Triage ok"})}}]
        }
        mock_200 = MagicMock()
        mock_200.read.return_value = json.dumps(success_body).encode("utf-8")
        mock_200.__enter__.return_value = mock_200

        with patch("urllib.request.urlopen", side_effect=[mock_429, mock_200]):
            with patch("time.sleep", return_value=None):
                res = client.complete_chat(system_prompt="sys", user_prompt="usr")

        assert res["execution_mode"] == "LIVE"
        assert res["provider"] == "azure-openai"
        assert res["deployment_name"] == "cloudpulse-triage"
        assert res["model_identifier"] == "gpt-4.1-mini"
        assert client.get_configuration_status()["execution_mode"] == "LIVE"

    def test_rate_limit_exhausted_raises_with_retry_after(self):
        """When 429 persists through all retries, AzureAIRateLimitError is raised with retry_after."""
        client = AzureAIClient(
            endpoint="https://cloudpulse-openai01.openai.azure.com",
            deployment_name="cloudpulse-triage",
            api_key="mock-key",
            mock_mode=False,
            max_retries=1,
        )

        mock_429 = urllib.error.HTTPError(
            url="https://cloudpulse-openai01.openai.azure.com/openai/v1/chat/completions",
            code=429,
            msg="Too Many Requests",
            hdrs={"Retry-After": "2.5"},
            fp=io.BytesIO(b'{"error":{"code":"429"}}'),
        )

        with patch("urllib.request.urlopen", side_effect=mock_429):
            with patch("time.sleep", return_value=None):
                with pytest.raises(AzureAIRateLimitError) as exc_info:
                    client.complete_chat(system_prompt="sys", user_prompt="usr")

        assert exc_info.value.retry_after == 2.5
        assert client.get_configuration_status()["error_category"] == "rate_limited"

    def test_5xx_transient_error_retried_and_succeeds(self):
        """503 Service Unavailable is retried and succeeds on 2nd attempt."""
        client = AzureAIClient(
            endpoint="https://cloudpulse-openai01.openai.azure.com",
            deployment_name="cloudpulse-triage",
            api_key="mock-key",
            mock_mode=False,
            max_retries=2,
        )

        mock_503 = urllib.error.HTTPError(
            url="https://cloudpulse-openai01.openai.azure.com/openai/v1/chat/completions",
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=io.BytesIO(b'{"error":{"code":"503"}}'),
        )

        success_body = {
            "choices": [{"message": {"content": json.dumps({"summary": "Triage ok"})}}]
        }
        mock_200 = MagicMock()
        mock_200.read.return_value = json.dumps(success_body).encode("utf-8")
        mock_200.__enter__.return_value = mock_200

        with patch("urllib.request.urlopen", side_effect=[mock_503, mock_200]):
            with patch("time.sleep", return_value=None):
                res = client.complete_chat(system_prompt="sys", user_prompt="usr")

        assert res["execution_mode"] == "LIVE"

    def test_deployment_not_found_classification(self):
        """404 returns deployment_not_found error category."""
        from services.azure_ai_client import AzureAIDeploymentNotFoundError
        client = AzureAIClient(
            endpoint="https://cloudpulse-openai01.openai.azure.com",
            deployment_name="missing-deployment",
            api_key="mock-key",
            mock_mode=False,
            max_retries=0,
        )

        mock_404 = urllib.error.HTTPError(
            url="https://cloudpulse-openai01.openai.azure.com/openai/v1/chat/completions",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=io.BytesIO(b'{"error":{"code":"DeploymentNotFound"}}'),
        )

        with patch("urllib.request.urlopen", side_effect=mock_404):
            with pytest.raises(AzureAIDeploymentNotFoundError):
                client.complete_chat(system_prompt="sys", user_prompt="usr")

        assert client.get_configuration_status()["error_category"] == "deployment_not_found"

    def test_empty_or_malformed_response_handling(self):
        """Empty choices or empty content raises AzureAISchemaError and categorizes as malformed_response."""
        from services.azure_ai_client import AzureAISchemaError
        client = AzureAIClient(
            endpoint="https://cloudpulse-openai01.openai.azure.com",
            deployment_name="cloudpulse-triage",
            api_key="mock-key",
            mock_mode=False,
            max_retries=0,
        )

        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"choices": []}'
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with pytest.raises(AzureAISchemaError):
                client.complete_chat(system_prompt="sys", user_prompt="usr")

        assert client.get_configuration_status()["error_category"] == "malformed_response"

    def test_input_capping_truncates_long_input(self):
        """Input exceeding max_input_chars is bounded to prevent expensive runaway calls."""
        client = AzureAIClient(
            endpoint="https://cloudpulse-openai01.openai.azure.com",
            deployment_name="cloudpulse-triage",
            api_key="mock-key",
            mock_mode=False,
            max_input_chars=500,
            max_retries=0,
        )

        captured_requests = []
        def mock_urlopen(req, timeout=None):
            captured_requests.append(req)
            resp = MagicMock()
            resp.read.return_value = json.dumps({"choices": [{"message": {"content": json.dumps({"summary": "ok"})}}]}).encode("utf-8")
            resp.__enter__.return_value = resp
            return resp

        huge_prompt = "A" * 2000
        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            client.complete_chat(system_prompt="Sys prompt", user_prompt=huge_prompt)

        assert len(captured_requests) == 1
        sent_payload = json.loads(captured_requests[0].data.decode("utf-8"))
        sent_user_content = sent_payload["messages"][1]["content"]
        assert len(sent_user_content) < 600
        assert "[INPUT TRUNCATED TO FIT BUDGET]" in sent_user_content

    def test_configurable_reasoning_model_parameters(self):
        """Reasoning models use max_completion_tokens and omit temperature; non-reasoning use max_tokens and temperature."""
        captured_payloads = []
        def mock_urlopen(req, timeout=None):
            captured_payloads.append(json.loads(req.data.decode("utf-8")))
            resp = MagicMock()
            resp.read.return_value = json.dumps({"choices": [{"message": {"content": json.dumps({"summary": "ok"})}}]}).encode("utf-8")
            resp.__enter__.return_value = resp
            return resp

        # Non-reasoning model (gpt-4.1-mini)
        client_mini = AzureAIClient(
            endpoint="https://cloudpulse-openai01.openai.azure.com",
            deployment_name="cloudpulse-triage",
            api_key="mock-key",
            is_reasoning_model=False,
            max_tokens=1000,
            temperature=0.2,
        )
        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            client_mini.complete_chat("sys", "user")

        assert "max_tokens" in captured_payloads[0]
        assert captured_payloads[0]["max_tokens"] == 1000
        assert captured_payloads[0]["temperature"] == 0.2
        assert "max_completion_tokens" not in captured_payloads[0]

        # Reasoning model (gpt-5 reasoning)
        client_reasoning = AzureAIClient(
            endpoint="https://cloudpulse-openai01.openai.azure.com",
            deployment_name="cloudpulse-reasoning",
            api_key="mock-key",
            is_reasoning_model=True,
            max_tokens=2000,
        )
        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            client_reasoning.complete_chat("sys", "user")

        assert "max_completion_tokens" in captured_payloads[1]
        assert captured_payloads[1]["max_completion_tokens"] == 2000
        assert "temperature" not in captured_payloads[1]

    def test_check_connectivity_caching_and_ttl(self):
        """check_connectivity caches result within TTL to avoid hitting the model on every render."""
        client = AzureAIClient(
            endpoint="https://cloudpulse-openai01.openai.azure.com",
            deployment_name="cloudpulse-triage",
            api_key="mock-key",
            mock_mode=False,
        )

        call_count = 0
        def mock_urlopen(req, timeout=None):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.read.return_value = json.dumps({"choices": [{"message": {"content": "OK"}}]}).encode("utf-8")
            resp.__enter__.return_value = resp
            return resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            r1 = client.check_connectivity()
            r2 = client.check_connectivity()
            assert call_count == 1
            assert r1["connected"] is True
            assert r2["connected"] is True

            # Forcing refresh ignores cache
            r3 = client.check_connectivity(force=True)
            assert call_count == 2
            assert r3["connected"] is True

    def test_truthful_execution_mode_only_live_when_real_request_succeeded(self):
        """Client starts in FALLBACK until a real request actually succeeds."""
        client = AzureAIClient(
            endpoint="https://cloudpulse-openai01.openai.azure.com",
            deployment_name="cloudpulse-triage",
            api_key="mock-key",
            mock_mode=False,
        )
        # Initially not LIVE even though endpoint is configured
        assert client.get_configuration_status()["execution_mode"] == "FALLBACK"

        success_body = {
            "choices": [{"message": {"content": json.dumps({"summary": "Triage ok"})}}]
        }
        mock_200 = MagicMock()
        mock_200.read.return_value = json.dumps(success_body).encode("utf-8")
        mock_200.__enter__.return_value = mock_200

        with patch("urllib.request.urlopen", return_value=mock_200):
            res = client.complete_chat("sys", "usr")

        assert res["execution_mode"] == "LIVE"
        assert client.get_configuration_status()["execution_mode"] == "LIVE"
        assert client.get_configuration_status()["last_successful_request_timestamp"] is not None

