import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from database.postgres import DatabaseRepository
from models.ai_context import (
    AISafeIncidentContext,
    AITriageAnalysis,
    AIRecommendedAction,
    AIKeyEvidenceItem,
)
from models.finding import Finding
from models.incident import Incident
from services.azure_ai_client import (
    AzureAIClient,
    AzureAIError,
    AzureAIAuthError,
    AzureAIPermissionDeniedError,
    AzureAIRateLimitError,
    AzureAITimeoutError,
    AzureAIUnavailableError,
    AzureAISchemaError,
)

logger = logging.getLogger("cloudpulse.services.ai_triage")


SYSTEM_PROMPT = """You are an incident triage assistant for CloudPulse — an Azure Autonomous FinOps & Threat Surface Triage Engine.
You analyze deterministic telemetry and normalized findings.

CRITICAL ARCHITECTURAL RULES:
1. Use only the supplied evidence in the incident context.
2. Distinguish verified FACTS from INFERENCES from RECOMMENDATIONS. Do not blur these categories.
3. Explicitly acknowledge missing or unverified evidence in the 'limitations' array.
4. Avoid unsupported claims of causality.
   - BAD: "The attacker exfiltrated 5 GB of confidential data."
   - GOOD: "The incident contains evidence of approximately 5 GB of anomalous outbound traffic. The available evidence does not establish that the traffic contained confidential data or that exfiltration occurred."
5. Explain security impact and financial impact separately.
6. Identify the most important evidence from the findings.
7. Recommend reversible, controlled operator actions. Every action must specify 'requires_human_approval': true.
8. NEVER claim that remediation has already occurred.
9. NEVER invent Azure resource state, prices, costs, identities, or network connections.
10. NEVER override or modify deterministic incident severity.
11. Output MUST be valid JSON strictly matching the schema:
{
  "summary": "...",
  "risk_assessment": "...",
  "likely_scenario": "...",
  "security_impact": "...",
  "financial_impact": "...",
  "facts": ["..."],
  "inferences": ["..."],
  "key_evidence": [{"source": "...", "finding_id": "...", "observation": "..."}],
  "recommended_actions": [{"id": "ACT-01", "title": "...", "description": "...", "category": "INVESTIGATION", "risk": "LOW", "requires_human_approval": true}],
  "confidence": 0.85,
  "limitations": ["..."]
}
"""


class AITriageService:
    """
    Coordinates AI incident triage generation, context isolation, response validation,
    and safe persistence without altering deterministic engine state.
    """

    def __init__(
        self,
        db_repo: DatabaseRepository,
        ai_client: Optional[AzureAIClient] = None,
    ):
        self._db = db_repo
        self._client = ai_client or AzureAIClient()

    def triage_incident(
        self,
        incident: Incident,
        force_refresh: bool = False,
    ) -> AITriageAnalysis:
        """
        Execute AI triage for the specified incident.
        Caches and returns existing ai_analysis unless force_refresh is True.
        Never breaks incident integrity if AI service fails.
        """
        # 1. Return cached analysis if available and not forcing refresh
        if not force_refresh and incident.ai_analysis:
            try:
                # If cached analysis is already completed, return it
                cached = AITriageAnalysis(**incident.ai_analysis)
                if cached.status == "COMPLETED":
                    logger.info("Returning cached AI triage analysis for incident %s", incident.incident_id)
                    return cached
            except Exception as e:
                logger.warning("Cached AI analysis parsing failed for incident %s: %s", incident.incident_id, str(e))

        # 2. Gather findings map from database
        findings_map: Dict[str, Finding] = {}
        for fid in incident.findings:
            f = self._db.get_finding(fid)
            if f:
                findings_map[fid] = f

        # 3. Build AI-Safe Context
        safe_context = AISafeIncidentContext.from_incident(
            incident=incident,
            findings_map=findings_map,
        )

        user_prompt = f"Analyze the following CloudPulse incident and produce structured triage:\n\n{json.dumps(safe_context.model_dump(), indent=2)}"

        # 4. Invoke Azure AI with graceful degradation
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            raw_response = self._client.complete_chat(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
                context=safe_context,
            )

            # Ensure timestamp
            if "triage_timestamp" not in raw_response:
                raw_response["triage_timestamp"] = now_iso

            # Resolve execution mode, provider, and model identifier based on actual execution path
            exec_mode = raw_response.get("execution_mode")
            if not exec_mode:
                if raw_response.get("model_identifier") == "cloudpulse-deterministic-synthesizer/v1":
                    exec_mode = "FALLBACK"
                else:
                    exec_mode = "LIVE"

            raw_response["execution_mode"] = exec_mode
            raw_response["provider_status"] = exec_mode

            if exec_mode == "FALLBACK":
                raw_response["provider"] = "deterministic-synthesizer"
                raw_response["model_identifier"] = "cloudpulse-deterministic-synthesizer/v1"
            else:
                raw_response["provider"] = "azure-openai"
                if "model_identifier" not in raw_response or raw_response["model_identifier"] == "cloudpulse-deterministic-synthesizer/v1":
                    raw_response["model_identifier"] = getattr(self._client, "model_identifier", getattr(self._client, "deployment_name", "gpt-4.1-mini"))

            raw_response["status"] = "COMPLETED"
            raw_response["error_message"] = None
            raw_response["error_category"] = None

            # Validate response schema
            analysis = AITriageAnalysis(**raw_response)

        except Exception as ex:
            logger.warning("AI triage generation degraded/failed for %s: %s", incident.incident_id, str(ex))

            # Categorize error safely without exposing credentials or internal tokens
            error_cat = "UNKNOWN_ERROR"
            if isinstance(ex, AzureAIAuthError):
                error_cat = "AUTH_ERROR"
            elif isinstance(ex, AzureAIRateLimitError):
                error_cat = "RATE_LIMIT"
            elif isinstance(ex, AzureAITimeoutError):
                error_cat = "TIMEOUT"
            elif isinstance(ex, AzureAIUnavailableError):
                error_cat = "SERVICE_UNAVAILABLE"
            elif isinstance(ex, (AzureAISchemaError, json.JSONDecodeError, ValueError)) or "json" in str(ex).lower() or "schema" in str(ex).lower():
                error_cat = "SCHEMA_ERROR"

            clean_error = str(ex)
            for sensitive_kw in ("Bearer", "api-key", "token", "password", "secret"):
                if sensitive_kw in clean_error:
                    clean_error = f"{error_cat}: Request failed with security credentials redacted"
                    break

            # Graceful degradation fallback — Incident remains fully valid!
            # Never attribute failed/unavailable requests to a live model identifier
            analysis = AITriageAnalysis(
                summary="AI analysis unavailable. Deterministic detection and correlation remain fully operational.",
                risk_assessment="Assessment unavailable. Refer to deterministic detector severity and evidence.",
                likely_scenario="AI interpretation unavailable at this time.",
                security_impact="Review individual finding evidence records.",
                financial_impact="Review correlated cost_impact records.",
                facts=["Deterministic finding records active in repository."],
                inferences=[],
                key_evidence=[],
                recommended_actions=[],
                confidence=0.0,
                limitations=[f"Azure AI triage unavailable ({error_cat}): {clean_error}"],
                triage_timestamp=now_iso,
                model_identifier="none",
                status="UNAVAILABLE",
                execution_mode="UNAVAILABLE",
                provider_status="UNAVAILABLE",
                provider="none",
                error_category=error_cat,
                error_message=clean_error,
            )

        # 5. Invariant Checks: Ensure deterministic fields are never polluted
        # Snapshot immutable fields before assignment
        preserved_id = incident.incident_id
        preserved_severity = incident.severity
        preserved_resource_id = incident.resource.id
        preserved_cost_impact = incident.cost_impact
        preserved_findings = list(incident.findings)

        # 6. Attach analysis to incident
        incident.ai_analysis = analysis.model_dump()
        incident.updated_at = now_iso

        # Append timeline entry for AI triage if completed
        if analysis.status == "COMPLETED":
            ai_timeline_entry = {
                "timestamp": now_iso,
                "event": "AI_TRIAGE_PERFORMED",
                "operation": "AZURE_AI_TRIAGE_COMPLETION",
                "caller": "cloudpulse-ai-triage-engine",
                "activity_log_event_id": f"ai-triage-{incident.incident_id}",
                "correlation_metadata": {
                    "model": analysis.model_identifier,
                    "execution_mode": analysis.execution_mode,
                    "provider": analysis.provider,
                    "confidence": analysis.confidence,
                    "actions_count": len(analysis.recommended_actions),
                },
            }
            # Deduplicate or update AI_TRIAGE_PERFORMED entry in timeline
            found_idx = None
            for idx, entry in enumerate(incident.timeline):
                if entry.get("event") == "AI_TRIAGE_PERFORMED":
                    found_idx = idx
                    break
            if found_idx is not None:
                incident.timeline[found_idx] = ai_timeline_entry
            else:
                incident.timeline.append(ai_timeline_entry)

        # Confirm invariants hold
        assert incident.incident_id == preserved_id
        assert incident.severity == preserved_severity
        assert incident.resource.id == preserved_resource_id
        assert incident.cost_impact == preserved_cost_impact
        assert incident.findings == preserved_findings

        # 7. Persist updated incident
        self._db.save_incident(incident)
        logger.info("Successfully persisted AI triage analysis for incident %s (status: %s)", incident.incident_id, analysis.status)

        return analysis
