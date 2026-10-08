import json
import logging
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List

from azure.identity import DefaultAzureCredential
from config import config
from models.ai_context import AISafeIncidentContext

logger = logging.getLogger("cloudpulse.services.azure_ai_client")


class AzureAIError(Exception):
    """Base exception for Azure AI communication errors."""
    pass


class AzureAIAuthError(AzureAIError):
    """Raised on authentication or permission failure (401/403)."""
    pass


class AzureAIRateLimitError(AzureAIError):
    """Raised when rate limit is exceeded (429)."""
    pass


class AzureAITimeoutError(AzureAIError):
    """Raised on request timeout."""
    pass


class AzureAIUnavailableError(AzureAIError):
    """Raised when service returns 5xx or connection refused."""
    pass


class AzureAIClient:
    """
    Client for interacting with Azure OpenAI Service / Azure AI Inference endpoints.
    Uses Managed Identity (DefaultAzureCredential) or AZURE_OPENAI_API_KEY.
    Adheres strictly to docs/ai/incident-triage.md and least-privilege principles.
    """

    COGNITIVE_SERVICES_SCOPE = "https://cognitiveservices.azure.com/.default"

    def __init__(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        deployment_name: Optional[str] = None,
        api_version: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        mock_mode: Optional[bool] = None,
        credential=None,
    ):
        self.endpoint = (endpoint or config.AZURE_OPENAI_ENDPOINT or "").strip().rstrip("/")
        self.api_key = api_key or config.AZURE_OPENAI_API_KEY
        self.deployment_name = deployment_name or config.AZURE_OPENAI_DEPLOYMENT_NAME or "gpt-4o"
        self.api_version = api_version or config.AZURE_OPENAI_API_VERSION or "2024-08-01-preview"
        self.timeout = timeout_seconds or config.AI_REQUEST_TIMEOUT_SECONDS or 30
        self.mock_mode = mock_mode if mock_mode is not None else config.AI_MOCK_MODE

        self._cached_token: Optional[str] = None
        self._token_expires_on: float = 0.0

        if credential is not None:
            self._credential = credential
        else:
            if config.AZURE_CLIENT_ID:
                self._credential = DefaultAzureCredential(managed_identity_client_id=config.AZURE_CLIENT_ID)
            else:
                self._credential = DefaultAzureCredential()

    def _get_auth_headers(self) -> Dict[str, str]:
        """
        Produce authentication headers using either API Key or Managed Identity Bearer Token.
        """
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["api-key"] = self.api_key
            return headers

        # Use Managed Identity OAuth2 token
        now = time.time()
        if not self._cached_token or now >= (self._token_expires_on - 300):
            try:
                token_obj = self._credential.get_token(self.COGNITIVE_SERVICES_SCOPE)
                self._cached_token = token_obj.token
                self._token_expires_on = float(getattr(token_obj, "expires_on", now + 3600))
            except Exception as e:
                logger.error("Failed to acquire Azure credential token for Cognitive Services: %s", str(e))
                raise AzureAIAuthError(f"Azure AI authentication failed: {str(e)}") from e

        headers["Authorization"] = f"Bearer {self._cached_token}"
        return headers

    def complete_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        context: Optional[AISafeIncidentContext] = None,
    ) -> Dict[str, Any]:
        """
        Execute a chat completion against Azure OpenAI requesting structured JSON.
        If in mock_mode or endpoint is unconfigured, delegates to deterministic synthesizer.
        """
        if self.mock_mode or not self.endpoint:
            logger.info("Azure AI Client operating in mock/fallback mode (no live endpoint queried)")
            return self._generate_deterministic_synthesis(context)

        url = f"{self.endpoint}/openai/deployments/{self.deployment_name}/chat/completions?api-version={self.api_version}"
        payload = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
            "max_tokens": 2048,
        }

        try:
            headers = self._get_auth_headers()
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                choice = resp_data.get("choices", [{}])[0]
                message = choice.get("message", {})
                content_str = message.get("content", "{}")
                return json.loads(content_str)

        except urllib.error.HTTPError as he:
            logger.error("Azure AI HTTP Error %d: %s", he.code, he.reason)
            if he.code in (401, 403):
                raise AzureAIAuthError(f"Azure AI authorization rejected ({he.code}): {he.reason}") from he
            elif he.code == 429:
                raise AzureAIRateLimitError(f"Azure AI rate limit exceeded ({he.code})") from he
            elif he.code >= 500:
                raise AzureAIUnavailableError(f"Azure AI service unavailable ({he.code})") from he
            raise AzureAIError(f"Azure AI error ({he.code}): {he.reason}") from he

        except urllib.error.URLError as ue:
            logger.error("Azure AI connection error: %s", str(ue))
            if "timed out" in str(ue).lower():
                raise AzureAITimeoutError("Azure AI request timed out") from ue
            raise AzureAIUnavailableError(f"Azure AI unreachable: {str(ue)}") from ue

        except json.JSONDecodeError as jde:
            logger.error("Failed to parse JSON response from Azure AI: %s", str(jde))
            raise AzureAIError("Azure AI returned invalid JSON payload") from jde

        except Exception as ex:
            if isinstance(ex, AzureAIError):
                raise
            logger.exception("Unexpected error during Azure AI completion: %s", str(ex))
            raise AzureAIError(f"Unexpected Azure AI failure: {str(ex)}") from ex

    def _generate_deterministic_synthesis(
        self,
        context: Optional[AISafeIncidentContext],
    ) -> Dict[str, Any]:
        """
        Deterministic, offline synthesis engine implementing CloudPulse contract principles.
        Generates realistic, fact-grounded triage when in test environments or offline without live Azure AI.
        """
        if not context:
            return {
                "summary": "Incident telemetry loaded without extended contextual metadata.",
                "risk_assessment": "Standard operational risk assessment.",
                "likely_scenario": "Telemetric activity observed across monitored workload.",
                "security_impact": "Operational state requires analyst review.",
                "financial_impact": "No abnormal financial impact established.",
                "facts": ["Baseline incident record initialized."],
                "inferences": ["Operational telemetry observed."],
                "key_evidence": [],
                "recommended_actions": [
                    {
                        "id": "ACT-01",
                        "title": "Review Workload Security Configuration",
                        "description": "Inspect cloud configuration against security baseline.",
                        "category": "INVESTIGATION",
                        "risk": "NONE",
                        "requires_human_approval": True,
                    }
                ],
                "confidence": 0.85,
                "limitations": ["Operating with offline deterministic synthesis engine."],
                "model_identifier": "cloudpulse-deterministic-synthesizer/v1",
            }

        res_name = context.resource.name
        res_type = context.resource.type.split("/")[-1]
        finding_types = {f.finding_type for f in context.findings}
        has_upe = "UNEXPECTED_PUBLIC_EXPOSURE" in finding_types
        has_soa = "SUSPICIOUS_OUTBOUND_ACTIVITY" in finding_types
        has_cost = "COST_ANOMALY" in finding_types
        has_rc = "RESOURCE_CREATION" in finding_types

        facts: List[str] = []
        inferences: List[str] = []
        key_evidence: List[Dict[str, Any]] = []
        recommended_actions: List[Dict[str, Any]] = []
        limitations: List[str] = []

        # Extract facts from findings
        for f in context.findings:
            if f.finding_type == "RESOURCE_CREATION":
                op = f.key_evidence.get("operation", "Resource write")
                caller = context.identity.caller if context.identity else "Unknown principal"
                facts.append(f"Resource '{res_name}' was provisioned via operation '{op}' by '{caller}'.")
                key_evidence.append({
                    "source": "RESOURCE_CREATION",
                    "finding_id": f.finding_id,
                    "observation": f"Provisioned resource '{res_name}' ({res_type})",
                })
            elif f.finding_type == "UNEXPECTED_PUBLIC_EXPOSURE":
                port = f.key_evidence.get("destination_port", "unspecified")
                exp_type = f.key_evidence.get("exposure_type", "PUBLIC_EXPOSURE")
                nsg_rule = f.key_evidence.get("nsg_rule_name", "unnamed rule")
                facts.append(f"Public ingress to port {port} ({exp_type}) permitted via NSG rule '{nsg_rule}'.")
                key_evidence.append({
                    "source": "UNEXPECTED_PUBLIC_EXPOSURE",
                    "finding_id": f.finding_id,
                    "observation": f"Exposed port {port} to public Internet via rule {nsg_rule}",
                })
            elif f.finding_type == "SUSPICIOUS_OUTBOUND_ACTIVITY":
                dst_ip = f.key_evidence.get("destination_ip", "unspecified IP")
                dst_port = f.key_evidence.get("destination_port", "unspecified")
                bytes_sent = f.key_evidence.get("bytes_sent", 0)
                mb_sent = round(bytes_sent / (1024 * 1024), 1)
                anomaly_type = f.key_evidence.get("anomaly_type", "OUTBOUND_EGRESS")
                facts.append(f"Transmitted {mb_sent} MB to external destination {dst_ip}:{dst_port} ({anomaly_type}).")
                key_evidence.append({
                    "source": "SUSPICIOUS_OUTBOUND_ACTIVITY",
                    "finding_id": f.finding_id,
                    "observation": f"Egress of {mb_sent} MB to {dst_ip}:{dst_port} ({anomaly_type})",
                })
            elif f.finding_type == "COST_ANOMALY":
                cost_cat = f.key_evidence.get("cost_category", "FinOps")
                delta = f.key_evidence.get("deviation_absolute", 0.0)
                pct = f.key_evidence.get("percentage_increase", 0.0)
                facts.append(f"Actual expenditure on category '{cost_cat}' exceeded baseline by +${delta:.2f} (+{pct:.0f}%).")
                key_evidence.append({
                    "source": "COST_ANOMALY",
                    "finding_id": f.finding_id,
                    "observation": f"+${delta:.2f} overrun (+{pct:.0f}%) on {cost_cat}",
                })

        # Cost impact facts if correlated
        financial_impact = "No abnormal expenditure detected beyond baseline."
        if context.cost_impact:
            ci = context.cost_impact
            facts.append(
                f"FinOps correlation confirmed: +${ci.deviation_absolute:.2f} ({ci.currency}) overrun on {ci.cost_category} "
                f"with {ci.correlation_strength} concurrence strength (confidence: {ci.correlation_confidence:.2f})."
            )
            financial_impact = (
                f"Billed expenditure reached ${ci.actual_cost:.2f} vs expected ${ci.baseline_cost:.2f} "
                f"(+${ci.deviation_absolute:.2f}, +{ci.percentage_increase:.0f}% increase). "
                f"Unchecked continuation projects approximately ${ci.actual_cost * 30:.2f}/month."
            )

        # Scenarios & Inferences
        if has_upe and has_soa and has_cost:
            summary = (
                f"Multi-stage workload compromise pattern on {res_name}: Internet exposure coincided with "
                f"high-volume outbound data transfer and an unexpected Azure billing surge."
            )
            risk_assessment = (
                f"CRITICAL risk. Workload '{res_name}' exhibits confirmed public perimeter exposure, abnormal external egress, "
                f"and quantifiable financial drain."
            )
            likely_scenario = (
                f"The resource was reachable from the public Internet, followed by external communication to an untrusted IP. "
                f"Concurrently, Azure billing registered an unexpected network egress surge. Available evidence suggests potential "
                f"external access and data staging, but cannot establish data confidentiality without payload inspection."
            )
            security_impact = (
                f"Perimeter protection compromised on listening interfaces. Outbound sessions suggest active external communication "
                f"or beaconing. Network controls failed to contain egress."
            )
            inferences.append("Egress volume spike likely explains the concurrent Azure network bandwidth billing surge.")
            inferences.append("Public exposure may have enabled external probing or unauthorized interaction.")
            limitations.append("Flow logs record network volume and tuples, but payload contents were not inspected.")
            limitations.append("Host-level process execution data is not available to identify specific binaries.")

            recommended_actions.append({
                "id": "ACT-01",
                "title": "Restrict Inbound NSG Exposure",
                "description": f"Update NSG rules on '{res_name}' to restrict inbound access from wildcard to authorized management IP ranges.",
                "category": "CONTAINMENT",
                "risk": "MEDIUM",
                "requires_human_approval": True,
            })
            recommended_actions.append({
                "id": "ACT-02",
                "title": "Block Malicious Destination Egress",
                "description": "Apply outbound NSG deny rule for the observed destination IP pending forensic validation.",
                "category": "CONTAINMENT",
                "risk": "LOW",
                "requires_human_approval": True,
            })
            recommended_actions.append({
                "id": "ACT-03",
                "title": "Inspect Workload Sockets and Processes",
                "description": f"Log into '{res_name}' and examine active network sockets and running processes matching the egress timestamp.",
                "category": "INVESTIGATION",
                "risk": "NONE",
                "requires_human_approval": True,
            })

        elif has_cost and has_rc:
            summary = f"Newly provisioned resource '{res_name}' generated immediate uncharacteristic expenditure."
            risk_assessment = "HIGH financial and governance risk. Immediate cost acceleration following creation."
            likely_scenario = (
                f"Resource was created recently and configured with high-tier compute, storage, or operational capacity, "
                f"exceeding standard subscription baselines."
            )
            security_impact = "No perimeter exposure or malicious network traffic observed at this time."
            financial_impact = financial_impact or "Rapid expenditure run-rate detected within initial provisioning window."
            inferences.append("Workload SKU or instance tier may exceed budgeted operational requirements.")
            limitations.append("Billing rate cards reflect Azure standard list pricing; reservation discounts may apply retroactively.")

            recommended_actions.append({
                "id": "ACT-01",
                "title": "Verify Provisioning Approval",
                "description": f"Confirm with initiating caller ({context.identity.caller if context.identity else 'operator'}) whether resource scale was authorized.",
                "category": "INVESTIGATION",
                "risk": "NONE",
                "requires_human_approval": True,
            })
            recommended_actions.append({
                "id": "ACT-02",
                "title": "Evaluate Workload Rightsizing",
                "description": f"Analyze CPU and memory utilization on '{res_name}' to identify opportunities to downscale SKU.",
                "category": "OPTIMIZATION",
                "risk": "LOW",
                "requires_human_approval": True,
            })

        elif has_upe:
            summary = f"Unexpected public Internet exposure identified on resource '{res_name}'."
            risk_assessment = "HIGH perimeter exposure risk. Direct reachability without approved edge proxy architecture."
            likely_scenario = "Network Security Group rule or Public IP assignment permitted broad untrusted ingress."
            security_impact = "Workload interfaces exposed to external port scanners and automated exploitation attempts."
            inferences.append("Exposure may be unintentional misconfiguration during deployment or testing.")
            limitations.append("Point-in-time configuration verified; active connection attempts require firewall/flow telemetry.")

            recommended_actions.append({
                "id": "ACT-01",
                "title": "Narrow Source IP Ranges",
                "description": f"Replace wildcard source ('*') with specific administrative corporate CIDRs on '{res_name}'.",
                "category": "CONTAINMENT",
                "risk": "LOW",
                "requires_human_approval": True,
            })

        else:
            summary = f"Security and FinOps operational telemetry evaluated for resource '{res_name}'."
            risk_assessment = f"Evaluated as {context.severity} severity based on deterministic findings."
            likely_scenario = "Observed telemetry reflects standard workload operations or isolated configuration event."
            security_impact = "Control-plane activity recorded; no active security breach indicated."
            inferences.append("Observed events align with normal platform lifecycle operations.")
            limitations.append("Further contextual correlation requires subsequent telemetry evaluation windows.")

            recommended_actions.append({
                "id": "ACT-01",
                "title": "Acknowledge and Monitor Workload",
                "description": f"Continue monitoring telemetry on '{res_name}' over next 24-hour cycle.",
                "category": "MONITORING",
                "risk": "NONE",
                "requires_human_approval": True,
            })

        return {
            "summary": summary,
            "risk_assessment": risk_assessment,
            "likely_scenario": likely_scenario,
            "security_impact": security_impact,
            "financial_impact": financial_impact,
            "facts": facts or ["Incident record captured with associated telemetry findings."],
            "inferences": inferences or ["Telemetry evaluated against standard CloudPulse baselines."],
            "key_evidence": key_evidence,
            "recommended_actions": recommended_actions,
            "confidence": 0.88,
            "limitations": limitations or ["Assessment limited to ingested telemetry windows."],
            "model_identifier": "cloudpulse-deterministic-synthesizer/v1",
        }
