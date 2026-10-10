import json
import logging
import random
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from azure.identity import DefaultAzureCredential
from config import config
from models.ai_context import AISafeIncidentContext

logger = logging.getLogger("cloudpulse.services.azure_ai_client")


class AzureAIError(Exception):
    """Base exception for Azure AI communication errors."""
    pass


class AzureAIAuthError(AzureAIError):
    """Raised on authentication failure (401)."""
    pass


class AzureAIPermissionDeniedError(AzureAIAuthError):
    """Raised on authorization failure / missing RBAC permissions (403 or 401 PermissionDenied)."""
    pass


class AzureAIRateLimitError(AzureAIError):
    """Raised when rate limit is exceeded (429)."""
    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class AzureAITimeoutError(AzureAIError):
    """Raised on request timeout."""
    pass


class AzureAIDeploymentNotFoundError(AzureAIError):
    """Raised when deployment is not found (404 / DeploymentNotFound)."""
    pass


class AzureAIUnavailableError(AzureAIError):
    """Raised when service returns 5xx or connection refused."""
    pass


class AzureAINetworkError(AzureAIUnavailableError):
    """Raised on network connection errors."""
    pass


class AzureAISchemaError(AzureAIError):
    """Raised when model returns malformed JSON or schema violation."""
    pass


class AzureAIInputLimitError(AzureAIError):
    """Raised when request input exceeds max character limit."""
    pass


class AzureAIClient:
    """
    Client for interacting with Azure OpenAI Service / Azure AI Inference endpoints.
    Uses Microsoft Entra ID Managed Identity (DefaultAzureCredential) or AZURE_OPENAI_API_KEY.
    Adheres strictly to docs/ai/incident-triage.md and least-privilege principles.
    Uses the v1 API: POST {endpoint}openai/v1/chat/completions with "model": "<deployment_name>".
    """

    COGNITIVE_SERVICES_SCOPE = "https://cognitiveservices.azure.com/.default"

    def __init__(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        deployment_name: Optional[str] = None,
        model_identifier: Optional[str] = None,
        api_version: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        mock_mode: Optional[bool] = None,
        live_enabled: Optional[bool] = None,
        is_reasoning_model: Optional[bool] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        max_retries: Optional[int] = None,
        max_input_chars: Optional[int] = None,
        credential=None,
    ):
        self.endpoint = (endpoint if endpoint is not None else config.AZURE_OPENAI_ENDPOINT).strip().rstrip("/")
        self.api_key = api_key or config.AZURE_OPENAI_API_KEY
        self.deployment_name = deployment_name or config.AZURE_OPENAI_DEPLOYMENT_NAME or "cloudpulse-triage"
        self.model_identifier = model_identifier or config.AZURE_OPENAI_MODEL_NAME or "gpt-4.1-mini"
        self.api_version = api_version if api_version is not None else config.AZURE_OPENAI_API_VERSION
        self.timeout = timeout_seconds or config.AI_REQUEST_TIMEOUT_SECONDS or 30
        self.mock_mode = mock_mode if mock_mode is not None else config.AI_MOCK_MODE
        self.live_enabled = live_enabled if live_enabled is not None else getattr(config, "AI_LIVE_ENABLED", True)
        self.is_reasoning_model = is_reasoning_model if is_reasoning_model is not None else getattr(config, "AI_IS_REASONING_MODEL", False)
        self.max_tokens = max_tokens or getattr(config, "AI_MAX_TOKENS", 2048)
        self.temperature = temperature if temperature is not None else getattr(config, "AI_TEMPERATURE", 0.1)
        self.max_retries = max_retries if max_retries is not None else getattr(config, "AI_MAX_RETRIES", 3)
        self.max_input_chars = max_input_chars or getattr(config, "AI_MAX_INPUT_CHARS", 32000)

        self._cached_token: Optional[str] = None
        self._token_expires_on: float = 0.0

        self._last_successful_request_timestamp: Optional[str] = None
        self._last_error_category: Optional[str] = None
        self._last_error_timestamp: Optional[str] = None

        self._connectivity_cache: Optional[Dict[str, Any]] = None
        self._connectivity_cache_time: float = 0.0
        self._connectivity_ttl_seconds: float = 60.0

        if credential is not None:
            self._credential = credential
        else:
            if config.AZURE_CLIENT_ID:
                self._credential = DefaultAzureCredential(managed_identity_client_id=config.AZURE_CLIENT_ID)
            else:
                self._credential = DefaultAzureCredential()

    def get_configuration_status(self) -> Dict[str, Any]:
        """
        Safe inspection of client configuration without revealing secrets or bearer tokens.
        Preserves truthful execution modes: LIVE only when a real request succeeded.
        """
        has_endpoint = bool(self.endpoint and self.endpoint.startswith("https://"))
        auth_mode = "api_key" if bool(self.api_key) else ("managed_identity" if self._credential else "none")

        if self.mock_mode:
            status = "MOCK_MODE"
            execution_mode = "FALLBACK"
            provider = "deterministic-synthesizer"
        elif not has_endpoint:
            status = "MISSING_ENDPOINT"
            execution_mode = "FALLBACK"
            provider = "deterministic-synthesizer"
        elif not self.live_enabled:
            status = "DISABLED"
            execution_mode = "FALLBACK"
            provider = "deterministic-synthesizer"
        elif self._last_successful_request_timestamp and not self._last_error_category:
            status = "READY"
            execution_mode = "LIVE"
            provider = "azure-openai"
        elif self._last_error_category:
            status = "DEGRADED"
            execution_mode = "FALLBACK"
            provider = "deterministic-synthesizer"
        else:
            status = "READY"
            # Endpoint is configured and ready, but until a real call succeeds, execution mode is FALLBACK
            execution_mode = "FALLBACK"
            provider = "deterministic-synthesizer"

        return {
            "status": status,
            "mock_mode": bool(self.mock_mode),
            "live_enabled": bool(self.live_enabled),
            "endpoint_configured": has_endpoint,
            "deployment_name": self.deployment_name if has_endpoint else None,
            "model_identifier": self.model_identifier,
            "api_version": self.api_version or "",
            "auth_mode": auth_mode,
            "execution_mode": execution_mode,
            "provider": provider,
            "timeout_seconds": self.timeout,
            "max_tokens": self.max_tokens,
            "is_reasoning_model": self.is_reasoning_model,
            "last_successful_request_timestamp": self._last_successful_request_timestamp,
            "error_category": self._last_error_category,
        }

    def _get_auth_headers(self) -> Dict[str, str]:
        """
        Produce authentication headers using either API Key or Managed Identity Bearer Token.
        Never leaks raw tokens or keys to loggers or exception strings.
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
                logger.error("Failed to acquire Azure credential token for Cognitive Services scope")
                self._last_error_category = "auth"
                raise AzureAIAuthError("Azure AI authentication failed: unable to acquire Managed Identity token") from e

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
        Uses the v1 API: POST {endpoint}openai/v1/chat/completions with "model": "<deployment_name>".
        If in mock_mode, unconfigured, or live_enabled is False, delegates to deterministic synthesizer.
        Always records explicit execution_mode (LIVE vs FALLBACK) and inference latency.
        """
        start_time = time.perf_counter()

        if self.mock_mode or not self.endpoint or not self.live_enabled:
            logger.info(
                "Azure AI Client operating in fallback mode (mock_mode=%s, endpoint_configured=%s, live_enabled=%s)",
                self.mock_mode,
                bool(self.endpoint),
                self.live_enabled,
            )
            result = self._generate_deterministic_synthesis(context)
            result["execution_mode"] = "FALLBACK"
            result["provider_status"] = "FALLBACK"
            result["provider"] = "deterministic-synthesizer"
            result["model_identifier"] = "cloudpulse-deterministic-synthesizer/v1"
            result["latency_ms"] = round((time.perf_counter() - start_time) * 1000, 2)
            return result

        # Bounded input check to prevent runaway payload sizes
        total_chars = len(system_prompt) + len(user_prompt)
        if total_chars > self.max_input_chars:
            allowed_user = max(200, self.max_input_chars - len(system_prompt) - 50)
            user_prompt = user_prompt[:allowed_user] + "\n[INPUT TRUNCATED TO FIT BUDGET]"

        url = f"{self.endpoint}/openai/v1/chat/completions"
        if self.api_version:
            url = f"{url}?api-version={self.api_version}"

        payload: Dict[str, Any] = {
            "model": self.deployment_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }

        # Configurable model-specific parameters:
        # gpt-4.1-mini is non-reasoning: uses max_tokens and temperature normally.
        # If is_reasoning_model is True (e.g. gpt-5 reasoning), use max_completion_tokens and omit temperature.
        effective_max_tokens = min(self.max_tokens, 4096)
        if self.is_reasoning_model:
            payload["max_completion_tokens"] = effective_max_tokens
        else:
            payload["max_tokens"] = effective_max_tokens
            payload["temperature"] = self.temperature

        attempt = 0
        max_attempts = max(1, 1 + self.max_retries)

        while attempt < max_attempts:
            attempt += 1
            try:
                headers = self._get_auth_headers()
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )

                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp_bytes = resp.read()
                    if not resp_bytes:
                        raise AzureAISchemaError("Azure AI returned empty response body")
                    resp_data = json.loads(resp_bytes.decode("utf-8"))
                    choices = resp_data.get("choices", [])
                    if not choices:
                        raise AzureAISchemaError("Azure AI response contained no choices")
                    choice = choices[0]
                    message = choice.get("message", {})
                    content_str = message.get("content", "")
                    if not content_str:
                        raise AzureAISchemaError("Azure AI choice message contained empty content")
                    parsed_content = json.loads(content_str)
                    if not isinstance(parsed_content, dict):
                        raise AzureAISchemaError("Azure AI response content is not a JSON object")

                    # Record successful request timestamp and clear error state
                    self._last_successful_request_timestamp = datetime.now(timezone.utc).isoformat()
                    self._last_error_category = None

                    # Explicitly stamp verified LIVE execution state
                    parsed_content["execution_mode"] = "LIVE"
                    parsed_content["provider_status"] = "LIVE"
                    parsed_content["provider"] = "azure-openai"
                    parsed_content["deployment_name"] = self.deployment_name
                    parsed_content["model_identifier"] = self.model_identifier
                    parsed_content["latency_ms"] = round((time.perf_counter() - start_time) * 1000, 2)
                    return parsed_content

            except urllib.error.HTTPError as he:
                error_body = ""
                try:
                    error_body = he.read().decode("utf-8", errors="replace")
                except Exception:
                    pass

                # Handle retryable status codes (429 and 5xx)
                if attempt < max_attempts and (he.code == 429 or he.code >= 500):
                    retry_after_sec = None
                    if he.headers and "Retry-After" in he.headers:
                        try:
                            retry_after_sec = float(he.headers["Retry-After"])
                        except (ValueError, TypeError):
                            pass

                    if retry_after_sec is not None:
                        backoff = min(max(retry_after_sec, 0.1), 10.0)
                    else:
                        base = 0.5
                        jitter = random.uniform(0.05, 0.25)
                        backoff = min((base * (2 ** (attempt - 1))) + jitter, 10.0)

                    logger.warning("Azure AI HTTP %d (attempt %d/%d). Retrying in %.2fs...", he.code, attempt, max_attempts, backoff)
                    time.sleep(backoff)
                    continue

                # Final failure mapping
                if he.code in (401, 403):
                    is_permission_denied = (he.code == 403) or ("permissiondenied" in error_body.lower())
                    if is_permission_denied:
                        self._last_error_category = "permission_denied"
                        raise AzureAIPermissionDeniedError(
                            "Azure AI authorization rejected: principal lacks required data action (PermissionDenied)"
                        ) from he
                    self._last_error_category = "auth"
                    raise AzureAIAuthError(f"Azure AI authorization rejected ({he.code})") from he

                elif he.code == 404 or "deploymentnotfound" in error_body.lower():
                    self._last_error_category = "deployment_not_found"
                    raise AzureAIDeploymentNotFoundError(f"Azure AI deployment '{self.deployment_name}' not found") from he

                elif he.code == 429:
                    self._last_error_category = "rate_limited"
                    retry_after_hdr = float(he.headers.get("Retry-After", 0)) if (he.headers and he.headers.get("Retry-After")) else None
                    raise AzureAIRateLimitError(f"Azure AI rate limit exceeded ({he.code})", retry_after=retry_after_hdr) from he

                elif he.code >= 500:
                    self._last_error_category = "service_unavailable"
                    raise AzureAIUnavailableError(f"Azure AI service unavailable ({he.code})") from he

                self._last_error_category = "network"
                raise AzureAIError(f"Azure AI error ({he.code})") from he

            except urllib.error.URLError as ue:
                err_str = str(ue).lower()
                if "timed out" in err_str:
                    self._last_error_category = "timeout"
                    raise AzureAITimeoutError(f"Azure AI request timed out after {self.timeout}s") from ue
                self._last_error_category = "network"
                raise AzureAINetworkError("Azure AI unreachable") from ue

            except json.JSONDecodeError as jde:
                self._last_error_category = "malformed_response"
                raise AzureAISchemaError("Azure AI returned invalid JSON payload") from jde

            except AzureAISchemaError:
                self._last_error_category = "malformed_response"
                raise

            except Exception as ex:
                if isinstance(ex, AzureAIError):
                    raise
                self._last_error_category = "network"
                raise AzureAIError(f"Unexpected Azure AI failure: {type(ex).__name__}") from ex

    def check_connectivity(self, force: bool = False, timeout: int = 5) -> Dict[str, Any]:
        """
        Lightweight authenticated connectivity check without logging prompts,
        responses, or credentials. Uses short TTL caching (60s) to avoid hitting
        the model on every dashboard render or health check.
        """
        now = time.time()
        if not force and self._connectivity_cache and (now - self._connectivity_cache_time) < self._connectivity_ttl_seconds:
            return self._connectivity_cache

        if self.mock_mode or not self.endpoint or not self.live_enabled:
            res = {
                "connected": False,
                "execution_mode": "FALLBACK",
                "status": "MOCK_OR_UNCONFIGURED",
                "error_category": None,
                "cached": False,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self._connectivity_cache = res
            self._connectivity_cache_time = now
            return res

        url = f"{self.endpoint}/openai/v1/chat/completions"
        if self.api_version:
            url = f"{url}?api-version={self.api_version}"

        payload: Dict[str, Any] = {
            "model": self.deployment_name,
            "messages": [{"role": "user", "content": "Reply with OK."}],
        }
        if self.is_reasoning_model:
            payload["max_completion_tokens"] = 5
        else:
            payload["max_tokens"] = 5
            payload["temperature"] = 0.0

        try:
            headers = self._get_auth_headers()
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                has_content = bool(data.get("choices", [{}])[0].get("message", {}).get("content", "").strip())
                self._last_successful_request_timestamp = datetime.now(timezone.utc).isoformat()
                self._last_error_category = None
                result = {
                    "connected": True,
                    "execution_mode": "LIVE",
                    "status": "OPERATIONAL",
                    "error_category": None,
                    "has_content": has_content,
                    "timestamp": self._last_successful_request_timestamp,
                }
        except urllib.error.HTTPError as he:
            body = ""
            try:
                body = he.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            if he.code in (401, 403):
                cat = "permission_denied" if (he.code == 403 or "permissiondenied" in body.lower()) else "auth"
            elif he.code == 404 or "deploymentnotfound" in body.lower():
                cat = "deployment_not_found"
            elif he.code == 429:
                cat = "rate_limited"
            elif he.code >= 500:
                cat = "service_unavailable"
            else:
                cat = "network"
            self._last_error_category = cat
            result = {
                "connected": False,
                "execution_mode": "FALLBACK",
                "status": "FAILED",
                "error_category": cat,
                "http_status": he.code,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as ex:
            cat = "timeout" if "timeout" in str(ex).lower() else "network"
            self._last_error_category = cat
            result = {
                "connected": False,
                "execution_mode": "FALLBACK",
                "status": "FAILED",
                "error_category": cat,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        self._connectivity_cache = result
        self._connectivity_cache_time = now
        return result

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
                "execution_mode": "FALLBACK",
                "provider_status": "FALLBACK",
                "provider": "deterministic-synthesizer",
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
            "execution_mode": "FALLBACK",
            "provider_status": "FALLBACK",
            "provider": "deterministic-synthesizer",
        }
