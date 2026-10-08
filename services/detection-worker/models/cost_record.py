import hashlib
import re
from typing import Optional, List, Dict, Any, Tuple
from pydantic import BaseModel, Field


def generate_cost_record_id(
    subscription_id: str,
    resource_id: str,
    meter_name: str,
    usage_date: str,
    cost_type: str = "ActualCost",
) -> str:
    """
    Generate deterministic unique identifier: CR-{SHA256[:16]}.
    Section 12.A of docs/finops/cost-telemetry.md.
    """
    cleaned_sub = subscription_id.strip().lower()
    cleaned_res = resource_id.strip().lower()
    cleaned_meter = meter_name.strip().lower()
    cleaned_date = usage_date.strip()
    cleaned_type = cost_type.strip().lower()

    seed = f"{cleaned_sub}:{cleaned_res}:{cleaned_meter}:{cleaned_date}:{cleaned_type}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16].upper()
    return f"CR-{digest}"


def classify_cost_category(
    resource_type: str,
    service_name: str,
    meter_category: str,
) -> str:
    """
    Deterministic cost category classification matrix per Section 5 of contract.
    Strict case-insensitive priority order:
    1. Network/Egress
    2. Compute
    3. Database
    4. Container
    5. Storage
    6. Other
    """
    r_type = (resource_type or "").strip().lower()
    s_name = (service_name or "").strip().lower()
    m_cat = (meter_category or "").strip().lower()

    # 1. Network/Egress
    network_meter_keywords = ("bandwidth", "data transfer", "virtual network")
    network_service_names = {
        "virtual network",
        "bandwidth",
        "nat gateway",
        "vpn gateway",
        "expressroute",
        "public ip addresses",
    }
    if any(k in m_cat for k in network_meter_keywords) or s_name in network_service_names:
        return "Network/Egress"

    # 2. Compute
    compute_type_prefixes = ("microsoft.compute/virtualmachines", "microsoft.web/serverfarms")
    compute_service_names = {"virtual machines", "azure app service", "cloud services", "batch"}
    if any(r_type.startswith(p) for p in compute_type_prefixes) or s_name in compute_service_names:
        return "Compute"

    # 3. Database
    db_type_prefixes = (
        "microsoft.sql",
        "microsoft.dbforpostgresql",
        "microsoft.dbformysql",
        "microsoft.documentdb",
    )
    db_service_keywords = ("database", "cosmos", "sql")
    if any(r_type.startswith(p) for p in db_type_prefixes) or any(k in s_name for k in db_service_keywords):
        return "Database"

    # 4. Container
    container_type_prefixes = (
        "microsoft.containerservice",
        "microsoft.app",
        "microsoft.containerregistry",
    )
    container_service_names = {"azure kubernetes service", "container apps", "container registry"}
    if any(r_type.startswith(p) for p in container_type_prefixes) or s_name in container_service_names:
        return "Container"

    # 5. Storage
    storage_meter_keywords = ("storage", "disks")
    storage_service_names = {"storage", "managed disks", "storage accounts"}
    if (
        r_type.startswith("microsoft.storage")
        or any(k in m_cat for k in storage_meter_keywords)
        or s_name in storage_service_names
    ):
        return "Storage"

    # 6. Other
    return "Other"


def parse_usage_date(usage_date: Any) -> str:
    """
    Convert integer YYYYMMDD (e.g. 20261007) or ISO timestamp into YYYY-MM-DD.
    Section 4.C of docs/finops/cost-telemetry.md.
    """
    if usage_date is None:
        raise ValueError("Usage date cannot be None")

    s = str(usage_date).strip()
    # If integer string format YYYYMMDD
    if len(s) == 8 and s.isdigit():
        return f"{s[:4]}-{s[4:6]}-{s[6:8]}"

    # If ISO timestamp string e.g. 2026-10-07T00:00:00Z or 2026-10-07
    if len(s) >= 10 and s[4] == "-" and s[7] == "-":
        return s[:10]

    return s


def extract_arm_metadata(
    raw_resource_id: Optional[str],
    default_sub_id: str = "",
    default_rg: str = "",
) -> Tuple[str, str, str, str, str]:
    """
    Parse canonical Azure Resource ID into:
    (canonical_id, resource_name, resource_type, resource_group, subscription_id)
    Section 4.C & Section 13.B.1.
    """
    if not raw_resource_id or raw_resource_id.strip().lower() in ("unallocated", "", "none"):
        sub = default_sub_id.strip().lower() or "unallocated"
        canonical_id = f"/subscriptions/{sub}/resourcegroups/unallocated"
        return (
            canonical_id,
            "unallocated",
            "Microsoft.Resources/unallocated",
            "unallocated",
            sub,
        )

    clean_id = raw_resource_id.strip()
    canonical_id = clean_id.lower()
    resource_name = clean_id.split("/")[-1]

    # Extract subscription ID
    subscription_id = default_sub_id
    sub_match = re.search(r"/subscriptions/([^/]+)", clean_id, re.IGNORECASE)
    if sub_match:
        subscription_id = sub_match.group(1)

    # Extract resource group
    resource_group = default_rg
    rg_match = re.search(r"/resourceGroups/([^/]+)", clean_id, re.IGNORECASE)
    if rg_match:
        resource_group = rg_match.group(1)

    # Extract resource type: provider segments, e.g. Microsoft.Compute/virtualMachines
    resource_type = "Microsoft.Resources/resource"
    providers_match = re.search(r"/providers/([^/]+)/([^/]+)", clean_id, re.IGNORECASE)
    if providers_match:
        resource_type = f"{providers_match.group(1)}/{providers_match.group(2)}"

    return (
        canonical_id,
        resource_name,
        resource_type,
        resource_group,
        subscription_id,
    )


class CostRecord(BaseModel):
    """
    Normalized internal domain model for Azure Cost Management telemetry.
    Section 4.B of docs/finops/cost-telemetry.md.
    """
    record_id: str = Field(..., description="Deterministic unique identifier: CR-{SHA256}")
    timestamp: str = Field(..., description="UTC date of the billing bucket: YYYY-MM-DD")
    subscription_id: str = Field(..., description="Azure Subscription GUID")
    resource_id: str = Field(..., description="Canonical Azure Resource ID (lowercase)")
    resource_group: str = Field(..., description="Azure Resource Group name")
    resource_name: str = Field(..., description="Extracted resource name")
    resource_type: str = Field(..., description="Azure Resource Provider namespace, e.g. Microsoft.Compute/virtualMachines")
    service_name: str = Field(..., description="Azure service name as reported by Cost Management")
    cost_category: str = Field(..., description="Deterministic category: Compute, Storage, Network/Egress, Database, Container, Other")
    meter_category: str = Field(..., description="Azure meter category")
    meter_subcategory: Optional[str] = Field(None, description="Azure meter subcategory")
    meter_name: str = Field(..., description="Azure meter name")
    usage_quantity: float = Field(default=0.0, description="Quantitative usage value reported by meter")
    usage_unit: Optional[str] = Field(None, description="Unit of measurement, e.g. Hours, GB, 10k Operations")
    actual_cost: float = Field(..., description="Authoritative billed cost amount")
    currency: str = Field(default="USD", description="ISO 4217 currency code")
    cost_type: str = Field(default="ActualCost", description="Cost type: ActualCost or AmortizedCost")
    is_provisional: bool = Field(default=False, description="True if record is from recent window and subject to reconciliation")


class CostObservation(BaseModel):
    """
    Output observation delivering evaluated actuals and calculated baseline
    to the future COST_ANOMALY detector.
    Section 8 of docs/finops/cost-telemetry.md.
    """
    resource_id: str = Field(..., description="Canonical Azure Resource ID")
    resource_name: str = Field(..., description="Workload resource name")
    resource_group: str = Field(..., description="Resource group name")
    cost_category: str = Field(..., description="Compute, Storage, Network/Egress, etc.")
    evaluation_date: str = Field(..., description="Target UTC date: YYYY-MM-DD")
    current_cost: float = Field(..., description="Actual cost on evaluation date")
    baseline_cost: float = Field(..., description="Mean daily baseline cost over window")
    deviation_absolute: float = Field(..., description="current_cost - baseline_cost")
    deviation_ratio: float = Field(..., description="current_cost / baseline_cost (0 if baseline is 0)")
    percentage_increase: float = Field(..., description="Percentage change vs baseline")
    std_dev: float = Field(default=0.0, description="Standard deviation over window")
    currency: str = Field(default="USD", description="Billing currency code")
    sample_days: int = Field(..., description="Number of active baseline days evaluated")
    is_cold_start: bool = Field(default=False, description="True if historical samples < 3 days")
    high_volatility: bool = Field(default=False, description="True if standard deviation exceeds 50% of mean")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Data completeness confidence score")
    records: List[CostRecord] = Field(default_factory=list, description="Underlying meter-level records")
