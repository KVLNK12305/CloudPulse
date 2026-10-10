"""
Comprehensive test suite for the CloudPulse AI & Application layer.

Covers:
  1.  Incident -> AISafeIncidentContext sanitization and evidence extraction
  2.  Fact vs. inference vs. recommendation tripartition validation
  3.  Schema validation of valid AI responses (AITriageAnalysis)
  4.  Handling of invalid/malformed model responses
  5.  Confidence score boundary validation (0.0 <= conf <= 1.0)
  6.  Timeout, rate-limit (429), auth failure (401/403), and unavailable error handling
  7.  Graceful degradation: AI failure leaves incident accessible with status="UNAVAILABLE"
  8.  Immutable field assertions: AI triage cannot alter severity, incident_id, resource, findings, cost_impact
  9.  Cache vs. force-refresh behaviour
  10. PATCH /api/incidents/<id> status mutation
  11. POST /api/incidents/<id>/actions/<action_id>/approval captures intent, no remediation
  12. GET /api/dashboard/summary calculation verification
  13. GET /dashboard static file serving check
"""

import pytest
import json
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from database.postgres import InMemoryDatabase
from models.finding import (
    Finding,
    ResourceInfo,
    IdentityInfo,
    EvidenceInfo,
    SeverityLevel,
    generate_deterministic_finding_id,
    generate_outbound_finding_id,
    generate_cost_anomaly_finding_id,
)
from models.incident import Incident, IncidentStatus, generate_deterministic_incident_id
from models.ai_context import (
    AISafeIncidentContext,
    AISafeFindingContext,
    AISafeCostImpact,
    AITriageAnalysis,
    AIRecommendedAction,
    ActionCategory,
    ActionRiskLevel,
    ApprovalStatus,
    HumanApprovalIntent,
)
from services.azure_ai_client import (
    AzureAIClient,
    AzureAIError,
    AzureAITimeoutError,
    AzureAIUnavailableError,
    AzureAIRateLimitError,
    AzureAIAuthError,
)
from services.ai_triage_service import AITriageService
from app import create_app


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

RES_ID = "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-sec-01"


def _make_findings():
    """Build a set of 3 findings spanning security + cost detection types."""
    f1 = Finding(
        finding_id=generate_deterministic_finding_id("evt-101", RES_ID),
        finding_type="RESOURCE_CREATION",
        severity=SeverityLevel.LOW,
        timestamp="2026-10-08T10:00:00Z",
        resource=ResourceInfo(id=RES_ID, type="Microsoft.Compute/virtualMachines", name="vm-sec-01", resource_group="rg-prod"),
        identity=IdentityInfo(caller="devops@cloudpulse.io"),
        evidence=EvidenceInfo(
            operation="MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
            activity_log_event_id="evt-101",
            subscription_id="sub-123",
        ),
        confidence=0.95,
    )

    f2 = Finding(
        finding_id=generate_outbound_finding_id(RES_ID, "198.51.100.99", "4444", "VOLUME_SPIKE", time_bucket=0),
        finding_type="SUSPICIOUS_OUTBOUND_ACTIVITY",
        severity=SeverityLevel.HIGH,
        timestamp="2026-10-08T10:15:00Z",
        resource=ResourceInfo(id=RES_ID, type="Microsoft.Compute/virtualMachines", name="vm-sec-01", resource_group="rg-prod"),
        identity=IdentityInfo(caller="devops@cloudpulse.io"),
        evidence=EvidenceInfo(
            operation="FLOW_LOG_EGRESS",
            activity_log_event_id="flow-out-1",
            destination_ip="198.51.100.99",
            destination_port="4444",
            bytes_sent=10737418240,
            anomaly_type="VOLUME_SPIKE",
            subscription_id="sub-123",
        ),
        confidence=0.88,
    )

    f3 = Finding(
        finding_id=generate_cost_anomaly_finding_id(RES_ID, "Compute", "2026-10-08"),
        finding_type="COST_ANOMALY",
        severity=SeverityLevel.HIGH,
        timestamp="2026-10-08T11:00:00Z",
        resource=ResourceInfo(id=RES_ID, type="Microsoft.Compute/virtualMachines", name="vm-sec-01", resource_group="rg-prod"),
        identity=IdentityInfo(caller="devops@cloudpulse.io"),
        evidence=EvidenceInfo(
            operation="COST_ANOMALY_DETECTION",
            activity_log_event_id="cost-eval-2026-10-08",
            actual_cost=450.0,
            baseline_cost=50.0,
            deviation_absolute=400.0,
            percentage_increase=700.0,
            currency="USD",
            cost_category="Compute",
            evaluation_date="2026-10-08",
            subscription_id="sub-123",
        ),
        confidence=0.90,
    )
    return [f1, f2, f3]


def _make_incident(findings=None):
    """Build a test incident with optional findings list."""
    if findings is None:
        findings = _make_findings()

    res = findings[0].resource
    iid = generate_deterministic_incident_id(resource_id=res.id)

    incident = Incident(
        incident_id=iid,
        title="Security & Cost Concurrence on vm-sec-01",
        severity=SeverityLevel.CRITICAL,
        status=IncidentStatus.OPEN,
        created_at="2026-10-08T10:00:00Z",
        updated_at="2026-10-08T11:05:00Z",
        resource=res,
        identity=IdentityInfo(caller="devops@cloudpulse.io"),
        findings=[f.finding_id for f in findings],
        cost_impact={
            "has_cost_anomaly": True,
            "actual_cost": 450.0,
            "baseline_cost": 50.0,
            "overrun_amount": 400.0,
            "deviation_absolute": 400.0,
            "currency": "USD",
        },
        timeline=[
            {"timestamp": "2026-10-08T10:00:00Z", "event": "RESOURCE_CREATED", "details": "VM created"},
            {"timestamp": "2026-10-08T10:15:00Z", "event": "OUTBOUND_DETECTED", "details": "10GB outbound"},
            {"timestamp": "2026-10-08T11:00:00Z", "event": "COST_ANOMALY_DETECTED", "details": "$400 overrun"},
            {"timestamp": "2026-10-08T11:05:00Z", "event": "CORRELATED", "details": "Security+FinOps correlated"},
        ],
    )
    return incident, findings


def _seed_db(db, incident=None, findings=None):
    """Populate an InMemoryDatabase with the test incident and its findings."""
    if incident is None:
        incident, findings = _make_incident()
    for f in findings:
        db.save_finding(f)
    db.save_incident(incident)
    return incident, findings


@pytest.fixture
def fresh_db():
    return InMemoryDatabase()


@pytest.fixture
def seeded_db():
    db = InMemoryDatabase()
    _seed_db(db)
    return db


@pytest.fixture
def ai_mock_client():
    return AzureAIClient(mock_mode=True)


@pytest.fixture
def triage_service(seeded_db, ai_mock_client):
    return AITriageService(db_repo=seeded_db, ai_client=ai_mock_client)


@pytest.fixture
def app_with_seeded_db(seeded_db):
    ai_client = AzureAIClient(mock_mode=True)
    app = create_app(db_repo=seeded_db, log_client=None, ai_client=ai_client)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def seeded_client(app_with_seeded_db):
    return app_with_seeded_db.test_client()


# =====================================================================
# 1. Incident -> AISafeIncidentContext transformation
# =====================================================================

class TestAISafeContextTransformation:
    def test_basic_context_mapping(self):
        """Verify that AISafeIncidentContext correctly maps incident fields."""
        incident, findings = _make_incident()
        findings_map = {f.finding_id: f for f in findings}
        context = AISafeIncidentContext.from_incident(incident, findings_map)

        assert context.incident_id == incident.incident_id
        assert context.title == incident.title
        assert context.severity == "CRITICAL"
        assert context.status == "OPEN"
        assert context.resource.name == "vm-sec-01"
        assert context.resource.resource_group == "rg-prod"
        assert context.resource.subscription_id == "sub-123"

    def test_findings_mapped_with_evidence(self):
        """Verify that each finding type has its evidence extracted correctly."""
        incident, findings = _make_incident()
        findings_map = {f.finding_id: f for f in findings}
        context = AISafeIncidentContext.from_incident(incident, findings_map)

        assert len(context.findings) == 3
        types = {f.finding_type for f in context.findings}
        assert types == {"RESOURCE_CREATION", "SUSPICIOUS_OUTBOUND_ACTIVITY", "COST_ANOMALY"}

        # Outbound finding evidence
        soa_ctx = next(f for f in context.findings if f.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY")
        assert soa_ctx.key_evidence.get("destination_ip") == "198.51.100.99"
        assert soa_ctx.key_evidence.get("bytes_sent") == 10737418240

        # Cost finding evidence
        cost_ctx = next(f for f in context.findings if f.finding_type == "COST_ANOMALY")
        assert cost_ctx.key_evidence.get("actual_cost") == 450.0
        assert cost_ctx.key_evidence.get("deviation_absolute") == 400.0

    def test_timeline_mapped(self):
        """Verify timeline entries are carried to context."""
        incident, findings = _make_incident()
        findings_map = {f.finding_id: f for f in findings}
        context = AISafeIncidentContext.from_incident(incident, findings_map)

        assert len(context.timeline) == 4

    def test_empty_findings_map_yields_empty_context_findings(self):
        """With no findings_map, context.findings should be empty."""
        incident, _ = _make_incident()
        context = AISafeIncidentContext.from_incident(incident, findings_map=None)
        assert context.findings == []


# =====================================================================
# 2. Fact/Inference/Recommendation Tripartition
# =====================================================================

class TestTripartition:
    def test_deterministic_synthesis_tripartition(self, seeded_db, ai_mock_client):
        """Verify deterministic synthesis produces facts, inferences, and actions."""
        svc = AITriageService(db_repo=seeded_db, ai_client=ai_mock_client)
        incident, _ = _make_incident()
        _seed_db(seeded_db, incident, _make_findings())

        analysis = svc.triage_incident(incident)

        assert analysis.status == "COMPLETED"
        assert len(analysis.facts) >= 1
        assert len(analysis.inferences) >= 1
        assert len(analysis.recommended_actions) >= 1
        assert len(analysis.limitations) >= 1

        # Every action must require human approval
        for act in analysis.recommended_actions:
            assert act.requires_human_approval is True
            assert act.category in (ActionCategory.INVESTIGATION, ActionCategory.CONTAINMENT,
                                    ActionCategory.MONITORING, ActionCategory.OPTIMIZATION)
            assert act.risk in (ActionRiskLevel.NONE, ActionRiskLevel.LOW,
                                ActionRiskLevel.MEDIUM, ActionRiskLevel.HIGH)


# =====================================================================
# 3. Valid AI Response Schema Validation
# =====================================================================

class TestSchemaValidation:
    def test_valid_response_parses(self):
        """A well-formed dict validates to AITriageAnalysis."""
        raw = {
            "summary": "Multi-vector compromise on compute instance.",
            "risk_assessment": "CRITICAL risk posture.",
            "likely_scenario": "Compromised VM credentials.",
            "security_impact": "10GB egressed to untrusted IP.",
            "financial_impact": "$400 overrun beyond baseline.",
            "facts": ["10GB outbound on port 4444", "$400 cost spike"],
            "inferences": ["Temporal correlation between egress and cost"],
            "key_evidence": [{"source": "SOA", "observation": "Egress spike"}],
            "recommended_actions": [
                {
                    "id": "ACT-01",
                    "title": "Quarantine VM",
                    "description": "Apply restrictive NSG.",
                    "category": "CONTAINMENT",
                    "risk": "LOW",
                    "requires_human_approval": True,
                }
            ],
            "confidence": 0.88,
            "limitations": ["Payload contents not inspected"],
        }
        validated = AITriageAnalysis.model_validate(raw)
        assert validated.confidence == 0.88
        assert validated.recommended_actions[0].id == "ACT-01"
        assert validated.recommended_actions[0].category == ActionCategory.CONTAINMENT
        assert validated.status == "COMPLETED"  # default

    def test_missing_required_fields_raises(self):
        """Incomplete dict must fail pydantic validation."""
        incomplete = {"summary": "Only summary"}
        with pytest.raises(Exception):
            AITriageAnalysis.model_validate(incomplete)


# =====================================================================
# 4. Malformed / invalid AI responses
# =====================================================================

class TestMalformedResponses:
    def test_non_json_response_degrades_gracefully(self, seeded_db):
        """When the AI client returns invalid JSON, triage must degrade."""
        mock_client = MagicMock(spec=AzureAIClient)
        mock_client.complete_chat.side_effect = AzureAIError("Azure AI returned invalid JSON payload")
        mock_client.deployment_name = "cloudpulse-triage"
        mock_client.model_identifier = "gpt-4.1-mini"

        svc = AITriageService(db_repo=seeded_db, ai_client=mock_client)
        incident, findings = _make_incident()
        _seed_db(seeded_db, incident, findings)

        analysis = svc.triage_incident(incident)
        assert analysis.status == "UNAVAILABLE"
        assert analysis.confidence == 0.0
        # Incident remains accessible
        refreshed = seeded_db.get_incident(incident.incident_id)
        assert refreshed is not None
        assert refreshed.severity == SeverityLevel.CRITICAL

    def test_schema_mismatch_response(self, seeded_db):
        """AI returns valid JSON but wrong shape -> fallback."""
        mock_client = MagicMock(spec=AzureAIClient)
        mock_client.complete_chat.return_value = {"wrong_key": "wrong_value"}
        mock_client.deployment_name = "cloudpulse-triage"
        mock_client.model_identifier = "gpt-4.1-mini"

        svc = AITriageService(db_repo=seeded_db, ai_client=mock_client)
        incident, findings = _make_incident()
        _seed_db(seeded_db, incident, findings)

        analysis = svc.triage_incident(incident)
        assert analysis.status == "UNAVAILABLE"
        assert analysis.confidence == 0.0


# =====================================================================
# 5. Confidence Score Boundary Validation
# =====================================================================

class TestConfidenceBounds:
    def test_confidence_above_1_rejected(self):
        with pytest.raises(Exception):
            AITriageAnalysis(
                summary="t", risk_assessment="t", likely_scenario="t",
                security_impact="t", financial_impact="t",
                facts=["f"], inferences=["i"], key_evidence=[],
                recommended_actions=[], confidence=1.5, limitations=[],
            )

    def test_confidence_below_0_rejected(self):
        with pytest.raises(Exception):
            AITriageAnalysis(
                summary="t", risk_assessment="t", likely_scenario="t",
                security_impact="t", financial_impact="t",
                facts=["f"], inferences=["i"], key_evidence=[],
                recommended_actions=[], confidence=-0.01, limitations=[],
            )

    def test_confidence_at_boundaries(self):
        for val in (0.0, 0.5, 1.0):
            a = AITriageAnalysis(
                summary="t", risk_assessment="t", likely_scenario="t",
                security_impact="t", financial_impact="t",
                facts=["f"], inferences=["i"], key_evidence=[],
                recommended_actions=[], confidence=val, limitations=[],
            )
            assert a.confidence == val


# =====================================================================
# 6. Error Classification: Timeout, Rate Limit, Auth, Unavailable
# =====================================================================

class TestErrorClassification:
    def _run_degraded_triage(self, seeded_db, side_effect):
        mock_client = MagicMock(spec=AzureAIClient)
        mock_client.complete_chat.side_effect = side_effect
        mock_client.deployment_name = "cloudpulse-triage"
        mock_client.model_identifier = "gpt-4.1-mini"
        svc = AITriageService(db_repo=seeded_db, ai_client=mock_client)
        incident, findings = _make_incident()
        _seed_db(seeded_db, incident, findings)
        return svc.triage_incident(incident), incident

    def test_timeout_degrades(self, seeded_db):
        analysis, inc = self._run_degraded_triage(
            seeded_db, AzureAITimeoutError("Request timed out"))
        assert analysis.status == "UNAVAILABLE"
        assert analysis.confidence == 0.0
        assert inc.severity == SeverityLevel.CRITICAL  # Unchanged

    def test_rate_limit_degrades(self, seeded_db):
        analysis, inc = self._run_degraded_triage(
            seeded_db, AzureAIRateLimitError("429 Too Many Requests"))
        assert analysis.status == "UNAVAILABLE"
        assert analysis.confidence == 0.0

    def test_auth_error_degrades(self, seeded_db):
        analysis, inc = self._run_degraded_triage(
            seeded_db, AzureAIAuthError("401 Unauthorized"))
        assert analysis.status == "UNAVAILABLE"
        assert analysis.confidence == 0.0

    def test_unavailable_degrades(self, seeded_db):
        analysis, inc = self._run_degraded_triage(
            seeded_db, AzureAIUnavailableError("503 Service Unavailable"))
        assert analysis.status == "UNAVAILABLE"
        assert analysis.confidence == 0.0


# =====================================================================
# 7. Graceful Degradation: AI Failure Preserves Incident Integrity
# =====================================================================

class TestGracefulDegradation:
    def test_failed_ai_leaves_incident_valid(self, seeded_db):
        """After AI failure, the incident remains fully queryable."""
        mock_client = MagicMock(spec=AzureAIClient)
        mock_client.complete_chat.side_effect = AzureAIUnavailableError("503")
        mock_client.deployment_name = "cloudpulse-triage"
        mock_client.model_identifier = "gpt-4.1-mini"

        svc = AITriageService(db_repo=seeded_db, ai_client=mock_client)
        incident, findings = _make_incident()
        _seed_db(seeded_db, incident, findings)

        svc.triage_incident(incident)

        refreshed = seeded_db.get_incident(incident.incident_id)
        assert refreshed is not None
        assert refreshed.incident_id == incident.incident_id
        assert refreshed.severity == SeverityLevel.CRITICAL
        assert refreshed.ai_analysis is not None
        assert refreshed.ai_analysis["status"] == "UNAVAILABLE"
        assert len(refreshed.findings) == 3


# =====================================================================
# 8. Immutable Field Assertions
# =====================================================================

class TestImmutableFields:
    def test_severity_preserved(self, seeded_db, ai_mock_client):
        svc = AITriageService(db_repo=seeded_db, ai_client=ai_mock_client)
        incident, findings = _make_incident()
        _seed_db(seeded_db, incident, findings)
        original_sev = incident.severity
        svc.triage_incident(incident)
        assert incident.severity == original_sev == SeverityLevel.CRITICAL

    def test_incident_id_preserved(self, seeded_db, ai_mock_client):
        svc = AITriageService(db_repo=seeded_db, ai_client=ai_mock_client)
        incident, findings = _make_incident()
        _seed_db(seeded_db, incident, findings)
        original_id = incident.incident_id
        svc.triage_incident(incident)
        assert incident.incident_id == original_id

    def test_resource_id_preserved(self, seeded_db, ai_mock_client):
        svc = AITriageService(db_repo=seeded_db, ai_client=ai_mock_client)
        incident, findings = _make_incident()
        _seed_db(seeded_db, incident, findings)
        original_res_id = incident.resource.id
        svc.triage_incident(incident)
        assert incident.resource.id == original_res_id

    def test_findings_list_preserved(self, seeded_db, ai_mock_client):
        svc = AITriageService(db_repo=seeded_db, ai_client=ai_mock_client)
        incident, findings = _make_incident()
        _seed_db(seeded_db, incident, findings)
        original_fids = list(incident.findings)
        svc.triage_incident(incident)
        assert incident.findings == original_fids

    def test_cost_impact_preserved(self, seeded_db, ai_mock_client):
        svc = AITriageService(db_repo=seeded_db, ai_client=ai_mock_client)
        incident, findings = _make_incident()
        _seed_db(seeded_db, incident, findings)
        original_cost = dict(incident.cost_impact)
        svc.triage_incident(incident)
        assert incident.cost_impact == original_cost


# =====================================================================
# 9. Cache vs. Force Refresh
# =====================================================================

class TestCacheRefresh:
    def test_cached_analysis_returned_without_re_calling_ai(self, seeded_db):
        mock_client = MagicMock(spec=AzureAIClient)
        mock_client.deployment_name = "cloudpulse-triage"
        mock_client.model_identifier = "gpt-4.1-mini"
        mock_client.complete_chat.return_value = {
            "summary": "Mock", "risk_assessment": "Mock", "likely_scenario": "Mock",
            "security_impact": "Mock", "financial_impact": "Mock",
            "facts": ["f1"], "inferences": ["i1"], "key_evidence": [],
            "recommended_actions": [], "confidence": 0.85, "limitations": [],
        }
        svc = AITriageService(db_repo=seeded_db, ai_client=mock_client)
        incident, findings = _make_incident()
        _seed_db(seeded_db, incident, findings)

        # First call
        r1 = svc.triage_incident(incident, force_refresh=False)
        assert mock_client.complete_chat.call_count == 1

        # Second call — should use cache
        r2 = svc.triage_incident(incident, force_refresh=False)
        assert mock_client.complete_chat.call_count == 1
        assert r2.summary == r1.summary

        # Force refresh — re-invokes AI
        r3 = svc.triage_incident(incident, force_refresh=True)
        assert mock_client.complete_chat.call_count == 2


# =====================================================================
# 10-13. API Integration Tests
# =====================================================================

class TestAPIIntegration:
    def test_get_incidents_list(self, seeded_client):
        res = seeded_client.get("/api/incidents")
        assert res.status_code == 200
        data = res.get_json()
        assert data["count"] >= 1

    def test_get_incidents_with_severity_filter(self, seeded_client):
        res = seeded_client.get("/api/incidents?severity=CRITICAL")
        assert res.status_code == 200
        data = res.get_json()
        assert all(i["severity"] == "CRITICAL" for i in data["incidents"])

    def test_get_single_incident(self, seeded_client, seeded_db):
        incident, _ = _make_incident()
        res = seeded_client.get(f"/api/incidents/{incident.incident_id}")
        assert res.status_code == 200
        assert res.get_json()["incident_id"] == incident.incident_id

    def test_get_incident_findings(self, seeded_client, seeded_db):
        incident, _ = _make_incident()
        res = seeded_client.get(f"/api/incidents/{incident.incident_id}/findings")
        assert res.status_code == 200
        assert res.get_json()["count"] == 3

    def test_get_incident_timeline(self, seeded_client, seeded_db):
        incident, _ = _make_incident()
        res = seeded_client.get(f"/api/incidents/{incident.incident_id}/timeline")
        assert res.status_code == 200
        assert len(res.get_json()["timeline"]) == 4

    def test_trigger_ai_triage(self, seeded_client, seeded_db):
        incident, _ = _make_incident()
        res = seeded_client.post(f"/api/incidents/{incident.incident_id}/ai-triage")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "success"
        assert data["ai_analysis"]["status"] == "COMPLETED"

    def test_get_ai_analysis_after_triage(self, seeded_client, seeded_db):
        incident, _ = _make_incident()
        # Trigger triage first
        seeded_client.post(f"/api/incidents/{incident.incident_id}/ai-triage")
        # Then fetch analysis
        res = seeded_client.get(f"/api/incidents/{incident.incident_id}/ai-analysis")
        assert res.status_code == 200
        assert res.get_json()["status"] == "COMPLETED"

    def test_ai_analysis_not_triaged_returns_404(self, seeded_client, seeded_db):
        incident, _ = _make_incident()
        # Without triggering triage
        res = seeded_client.get(f"/api/incidents/{incident.incident_id}/ai-analysis")
        assert res.status_code == 404

    def test_patch_incident_status(self, seeded_client, seeded_db):
        incident, _ = _make_incident()
        res = seeded_client.patch(
            f"/api/incidents/{incident.incident_id}",
            json={"status": "INVESTIGATING", "caller": "rishi@cloudpulse.io"},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "INVESTIGATING"
        assert any(e.get("event") == "STATUS_UPDATED" for e in data["timeline"])

    def test_patch_invalid_status_returns_400(self, seeded_client, seeded_db):
        incident, _ = _make_incident()
        res = seeded_client.patch(
            f"/api/incidents/{incident.incident_id}",
            json={"status": "NONSENSE"},
        )
        assert res.status_code == 400


class TestHumanApproval:
    def test_approval_records_intent_without_remediation(self, seeded_client, seeded_db):
        """Full approval lifecycle: triage -> approve -> verify no remediation executed."""
        incident, _ = _make_incident()

        # 1. Trigger AI triage to generate recommended actions
        triage_res = seeded_client.post(f"/api/incidents/{incident.incident_id}/ai-triage")
        assert triage_res.status_code == 200
        actions = triage_res.get_json()["ai_analysis"]["recommended_actions"]
        assert len(actions) >= 1
        action_id = actions[0]["id"]

        # 2. Approve the action
        appr_res = seeded_client.post(
            f"/api/incidents/{incident.incident_id}/actions/{action_id}/approval",
            json={"status": "APPROVED", "operator": "rishi@cloudpulse.io", "notes": "Staging env. Approved."},
        )
        assert appr_res.status_code == 200
        appr_data = appr_res.get_json()
        assert appr_data["status"] == "success"
        assert appr_data["approval"]["status"] == "APPROVED"
        assert appr_data["approval"]["remediation_executed"] is False  # CRITICAL SAFETY CHECK

        # 3. Verify persisted state
        inc_res = seeded_client.get(f"/api/incidents/{incident.incident_id}").get_json()
        assert inc_res["remediation"]["action_id"] == action_id
        assert inc_res["remediation"]["status"] == "APPROVED"
        assert inc_res["remediation"]["operator"] == "rishi@cloudpulse.io"
        assert inc_res["remediation"]["remediation_executed"] is False
        assert any(e.get("event") == "ACTION_APPROVED" for e in inc_res["timeline"])

    def test_rejection_records_intent_without_remediation(self, seeded_client, seeded_db):
        incident, _ = _make_incident()
        seeded_client.post(f"/api/incidents/{incident.incident_id}/ai-triage")
        actions = seeded_client.get(f"/api/incidents/{incident.incident_id}/ai-analysis").get_json()["recommended_actions"]
        action_id = actions[0]["id"]

        rej_res = seeded_client.post(
            f"/api/incidents/{incident.incident_id}/actions/{action_id}/approval",
            json={"status": "REJECTED", "operator": "lead@cloudpulse.io", "notes": "Too risky."},
        )
        assert rej_res.status_code == 200
        assert rej_res.get_json()["approval"]["status"] == "REJECTED"
        assert rej_res.get_json()["approval"]["remediation_executed"] is False

    def test_invalid_approval_decision_returns_400(self, seeded_client, seeded_db):
        incident, _ = _make_incident()
        seeded_client.post(f"/api/incidents/{incident.incident_id}/ai-triage")

        res = seeded_client.post(
            f"/api/incidents/{incident.incident_id}/actions/ACT-01/approval",
            json={"status": "INVALID_DECISION"},
        )
        assert res.status_code == 400


class TestDashboardSummary:
    def test_summary_counts(self, seeded_client, seeded_db):
        res = seeded_client.get("/api/dashboard/summary")
        assert res.status_code == 200
        data = res.get_json()
        assert data["total_incidents"] >= 1
        assert data["by_severity"]["CRITICAL"] >= 1
        assert data["correlated_incidents"] >= 1
        assert data["total_financial_overrun"] > 0

    def test_triaged_count_increments_after_triage(self, seeded_client, seeded_db):
        incident, _ = _make_incident()

        before = seeded_client.get("/api/dashboard/summary").get_json()
        before_triaged = before["triaged_count"]

        seeded_client.post(f"/api/incidents/{incident.incident_id}/ai-triage")

        after = seeded_client.get("/api/dashboard/summary").get_json()
        assert after["triaged_count"] == before_triaged + 1


class TestDashboardServing:
    def test_dashboard_returns_html(self, seeded_client):
        res = seeded_client.get("/dashboard")
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert "CloudPulse" in html

    def test_incident_not_found_returns_404(self, seeded_client):
        res = seeded_client.get("/api/incidents/NONEXISTENT-ID")
        assert res.status_code == 404
