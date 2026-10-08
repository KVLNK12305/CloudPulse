import json
import logging
import re
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
from azure.identity import DefaultAzureCredential

logger = logging.getLogger("cloudpulse.telemetry.monitor_metrics")


class AzureMonitorMetricsError(Exception):
    """Base exception for Azure Monitor Metrics API failures."""
    pass


class AzureMonitorMetricsAuthenticationError(AzureMonitorMetricsError):
    """Raised when acquiring authentication token or bearer credentials fails."""
    pass


class AzureMonitorMetricsPermissionError(AzureMonitorMetricsError):
    """Raised when identity lacks monitoring permissions on target resource."""
    pass


class AzureMonitorMetricsNotFoundError(AzureMonitorMetricsError):
    """Raised when target resource is not found."""
    pass


class AzureMonitorMetricsBadRequestError(AzureMonitorMetricsError):
    """Raised when metric request syntax or parameters are invalid."""
    pass


class AzureMonitorMetricsClient:
    """
    Client for querying Azure Monitor runtime metrics across Azure resources.
    Read-only operator telemetry client backing CloudPulse SecOps & FinOps console.
    """

    ARM_RESOURCE_URI = "https://management.azure.com/.default"
    METRICS_API_VERSION = "2018-01-01"

    # Strict resource-type aware metric catalog
    RESOURCE_METRIC_MAP = {
        "microsoft.compute/virtualmachines": [
            "Percentage CPU",
            "Network In",
            "Network Out",
            "Disk Read Bytes",
            "Disk Write Bytes",
        ],
        "microsoft.dbforpostgresql/flexibleservers": [
            "cpu_percent",
            "memory_percent",
            "storage_percent",
            "active_connections",
            "network_bytes_ingress",
            "network_bytes_egress",
        ],
        "microsoft.storage/storageaccounts": [
            "UsedCapacity",
            "Transactions",
            "Ingress",
            "Egress",
        ],
        "microsoft.app/containerapps": [
            "UsageNanoCores",
            "WorkingSetBytes",
            "Requests",
            "Replicas",
        ],
        "microsoft.containerregistry/registries": [
            "StorageUsed",
            "TotalPullCount",
            "SuccessfulPullCount",
            "TotalPushCount",
        ],
        "microsoft.keyvault/vaults": [
            "ServiceApiHit",
            "ServiceApiLatency",
            "Availability",
        ],
        "microsoft.operationalinsights/workspaces": [
            "Ingestion Volume",
            "Query Count",
        ],
    }

    METRIC_DISPLAY_NAMES = {
        "Percentage CPU": "CPU Utilization",
        "Network In": "Network Ingress",
        "Network Out": "Network Egress",
        "Disk Read Bytes": "Disk Read Throughput",
        "Disk Write Bytes": "Disk Write Throughput",
        "cpu_percent": "CPU Utilization",
        "memory_percent": "Memory Utilization",
        "storage_percent": "Storage Utilization",
        "active_connections": "Active Client Connections",
        "network_bytes_ingress": "Network Ingress",
        "network_bytes_egress": "Network Egress",
        "UsedCapacity": "Capacity In Use",
        "Transactions": "Transaction Count",
        "Ingress": "Storage Ingress",
        "Egress": "Storage Egress",
        "UsageNanoCores": "CPU Usage (NanoCores)",
        "WorkingSetBytes": "Working Set Memory",
        "Requests": "HTTP Requests",
        "Replicas": "Active Replicas",
        "StorageUsed": "Registry Storage Used",
        "TotalPullCount": "Total Image Pulls",
        "SuccessfulPullCount": "Successful Image Pulls",
        "TotalPushCount": "Total Image Pushes",
        "ServiceApiHit": "Vault API Hits",
        "ServiceApiLatency": "Vault API Latency",
        "Availability": "Vault Availability",
        "Ingestion Volume": "Log Analytics Ingestion Volume",
        "Query Count": "Log Analytics Query Count",
    }

    def __init__(self, credential=None, client_id: Optional[str] = None):
        """
        Initialize Azure Monitor Metrics client with DefaultAzureCredential
        or an injected test credential.
        """
        if credential is not None:
            self._credential = credential
        else:
            cid = client_id
            if not cid:
                try:
                    from config import config
                    cid = config.AZURE_CLIENT_ID
                except Exception:
                    cid = None

            if cid:
                self._credential = DefaultAzureCredential(managed_identity_client_id=cid)
            else:
                self._credential = DefaultAzureCredential()

    @staticmethod
    def validate_resource_id(resource_id: str) -> bool:
        """
        Validate whether a resource ID matches canonical Azure Resource Manager format.
        Must start with /subscriptions/, contain /resourceGroups/, and have /providers/.
        """
        if not resource_id or not isinstance(resource_id, str):
            return False
        pattern = r"^/subscriptions/[a-zA-Z0-9\-_]+/resourcegroups/[a-zA-Z0-9\-_\.]+/providers/[a-zA-Z0-9\-_\.]+/.+"
        return bool(re.match(pattern, resource_id.strip(), re.IGNORECASE))

    @classmethod
    def extract_resource_type(cls, resource_id: str) -> Optional[str]:
        """
        Extract the ARM resource type from a valid ARM Resource ID.
        E.g. /subscriptions/.../providers/Microsoft.DBforPostgreSQL/flexibleServers/... -> microsoft.dbforpostgresql/flexibleservers
        """
        if not cls.validate_resource_id(resource_id):
            return None
        parts = resource_id.strip().split("/providers/")
        if len(parts) < 2:
            return None
        provider_part = parts[1].split("/")
        if len(provider_part) >= 2:
            return f"{provider_part[0]}/{provider_part[1]}".lower()
        return None

    def get_supported_metrics(self, resource_type: str) -> List[str]:
        """
        Get the list of metric names configured for the specified resource type.
        """
        if not resource_type:
            return []
        return self.RESOURCE_METRIC_MAP.get(resource_type.strip().lower(), [])

    def _get_access_token(self) -> str:
        """Acquire Bearer token for Azure Resource Manager."""
        try:
            token_obj = self._credential.get_token(self.ARM_RESOURCE_URI)
            return token_obj.token
        except Exception as ex:
            logger.error("Failed to acquire Azure access token for Monitor Metrics: %s", str(ex))
            raise AzureMonitorMetricsAuthenticationError(f"Azure authentication failed: {str(ex)}") from ex

    def get_resource_metrics(
        self,
        resource_id: str,
        timespan: str = "PT1H",
        metric_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve runtime metrics for the specified Azure resource.

        Args:
            resource_id: Full canonical ARM resource ID
            timespan: ISO 8601 duration window, e.g. 'PT1H' (past 1 hour)
            metric_names: Optional list of explicit metric names to query

        Returns:
            Dictionary containing metrics availability, parsed metric points, latest values,
            and source attribution.
        """
        cleaned_id = resource_id.strip()
        if not self.validate_resource_id(cleaned_id):
            return {
                "resource_id": cleaned_id,
                "supported": False,
                "metrics_available": False,
                "message": "Invalid Azure Resource ID format",
                "source": "Azure Monitor",
                "metrics": {},
            }

        res_type = self.extract_resource_type(cleaned_id)
        configured_metrics = metric_names or (self.get_supported_metrics(res_type) if res_type else [])

        if not configured_metrics:
            return {
                "resource_id": cleaned_id,
                "resource_type": res_type,
                "supported": False,
                "metrics_available": False,
                "message": "Metrics unavailable for this resource type",
                "source": "Azure Monitor",
                "metrics": {},
            }

        # Build ARM Metrics REST API URL
        metrics_param = urllib.parse.quote(",".join(configured_metrics))
        url = (
            f"https://management.azure.com{cleaned_id}/providers/Microsoft.Insights/metrics"
            f"?api-version={self.METRICS_API_VERSION}&metricnames={metrics_param}&timespan={timespan}"
        )

        try:
            token = self._get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
            req = urllib.request.Request(url, headers=headers, method="GET")

            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            parsed_metrics = self._parse_metrics_response(data)
            has_data = any(m.get("latest_value") is not None for m in parsed_metrics.values())

            return {
                "resource_id": cleaned_id,
                "resource_type": res_type,
                "supported": True,
                "metrics_available": has_data,
                "message": None if has_data else "No metrics emitted in the selected observation window",
                "timespan": timespan,
                "source": "Azure Monitor",
                "metrics": parsed_metrics,
            }

        except urllib.error.HTTPError as http_err:
            status_code = http_err.code
            err_body = ""
            try:
                err_body = http_err.read().decode("utf-8", errors="ignore")
            except Exception:
                pass

            if status_code == 400:
                # Unsupported metric or SKU does not emit metrics
                logger.warning("Metrics returned 400 for resource %s: %s", cleaned_id, err_body)
                return {
                    "resource_id": cleaned_id,
                    "resource_type": res_type,
                    "supported": False,
                    "metrics_available": False,
                    "message": "Metrics unavailable for this resource type",
                    "source": "Azure Monitor",
                    "metrics": {},
                }
            elif status_code in (401, 403):
                logger.error("Permissions denied querying metrics on %s: %s", cleaned_id, err_body)
                raise AzureMonitorMetricsPermissionError(
                    f"Insufficient permissions to read Azure Monitor metrics on resource ({status_code})"
                ) from http_err
            elif status_code == 404:
                logger.warning("Resource not found when querying metrics: %s", cleaned_id)
                raise AzureMonitorMetricsNotFoundError(f"Resource not found: {cleaned_id}") from http_err
            else:
                logger.error("Azure Monitor HTTP error %d on %s: %s", status_code, cleaned_id, err_body)
                raise AzureMonitorMetricsError(f"Azure Monitor error {status_code}: {err_body}") from http_err

        except urllib.error.URLError as url_err:
            logger.error("Network error querying Azure Monitor metrics: %s", str(url_err))
            raise AzureMonitorMetricsError(f"Network error querying Azure Monitor: {str(url_err)}") from url_err

        except Exception as ex:
            if isinstance(ex, AzureMonitorMetricsError):
                raise
            logger.exception("Unexpected error querying Azure Monitor metrics: %s", str(ex))
            raise AzureMonitorMetricsError(f"Failed to query metrics: {str(ex)}") from ex

    def _parse_metrics_response(self, raw_response: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Extract clean metric timeseries, latest value, units, and timestamps.
        """
        result: Dict[str, Dict[str, Any]] = {}
        for item in raw_response.get("value", []):
            metric_id = item.get("name", {}).get("value")
            if not metric_id:
                continue

            display_name = (
                item.get("name", {}).get("localizedValue")
                or self.METRIC_DISPLAY_NAMES.get(metric_id)
                or metric_id
            )
            unit = item.get("unit") or "Count"
            timeseries = item.get("timeseries", [])

            history: List[Dict[str, Any]] = []
            latest_value = None
            latest_timestamp = None
            aggregation_type = "Average"

            if timeseries:
                ts_data = timeseries[0].get("data", [])
                for pt in ts_data:
                    # Resolve whichever aggregation is non-null
                    val = None
                    if pt.get("average") is not None:
                        val = pt["average"]
                        aggregation_type = "Average"
                    elif pt.get("total") is not None:
                        val = pt["total"]
                        aggregation_type = "Total"
                    elif pt.get("maximum") is not None:
                        val = pt["maximum"]
                        aggregation_type = "Maximum"
                    elif pt.get("minimum") is not None:
                        val = pt["minimum"]
                        aggregation_type = "Minimum"
                    elif pt.get("count") is not None:
                        val = pt["count"]
                        aggregation_type = "Count"

                    if val is not None:
                        t = pt.get("timeStamp")
                        history.append({"timestamp": t, "value": round(val, 3) if isinstance(val, float) else val})
                        latest_value = val
                        latest_timestamp = t

            if isinstance(latest_value, float):
                latest_value = round(latest_value, 2)

            result[metric_id] = {
                "name": metric_id,
                "display_name": display_name,
                "unit": unit,
                "aggregation": aggregation_type,
                "latest_value": latest_value,
                "latest_timestamp": latest_timestamp,
                "data_points_count": len(history),
                "history": history[-15:],  # Keep last 15 points for visual micro-trend
            }

        return result
