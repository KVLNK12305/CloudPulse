import hashlib
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ResourceInfo(BaseModel):
    id: str = Field(..., description="Full Azure Resource ID")
    type: str = Field(..., description="Azure Resource Type, e.g. Microsoft.Compute/virtualMachines")
    name: str = Field(..., description="Azure Resource Name")
    resource_group: str = Field(..., description="Resource Group name")


class IdentityInfo(BaseModel):
    principal_id: Optional[str] = Field(None, description="Azure AD principal ID")
    principal_type: Optional[str] = Field(None, description="Principal type, e.g. User, ServicePrincipal")
    caller: Optional[str] = Field(None, description="Caller UPN, email, or SPN identifier")


class EvidenceInfo(BaseModel):
    operation: str = Field(..., description="Operation name, e.g. Microsoft.Compute/virtualMachines/write")
    activity_log_event_id: str = Field(..., description="Unique Azure Activity Log EventDataId")
    correlation_id: Optional[str] = Field(None, description="Azure Correlation ID")
    subscription_id: Optional[str] = Field(None, description="Azure Subscription ID")
    caller_ip: Optional[str] = Field(None, description="Client IP address initiating the action")
    raw_event: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Raw event payload for evidence preservation")

    # UNEXPECTED_PUBLIC_EXPOSURE contract fields (optional for backward compatibility with RESOURCE_CREATION)
    protocol: Optional[str] = Field(None, description="IP protocol, e.g. TCP, UDP, *")
    source_address_prefix: Optional[str] = Field(None, description="Source CIDR or service tag, e.g. 0.0.0.0/0, Internet, *")
    destination_port: Optional[str] = Field(None, description="Target port or port range, e.g. 22, 3389, 1-1024")
    exposure_type: Optional[str] = Field(None, description="Exposure classification, e.g. MANAGEMENT_PORT, DATABASE_PORT, WILDCARD_PORTS, UNPROTECTED_SERVICE")
    public_ip: Optional[str] = Field(None, description="Public IP address")
    public_ip_resource_id: Optional[str] = Field(None, description="Resource ID of Public IP")
    nsg_id: Optional[str] = Field(None, description="Resource ID of associated NSG")
    nsg_rule_name: Optional[str] = Field(None, description="Name of NSG security rule")
    nic_id: Optional[str] = Field(None, description="Resource ID of network interface")
    subnet_id: Optional[str] = Field(None, description="Resource ID of subnet")


def generate_deterministic_finding_id(activity_log_event_id: str, resource_id: str) -> str:
    """
    Generate a deterministic finding ID based on the Activity Log EventDataId and Resource ID.
    This guarantees that reprocessing the exact same Azure event always yields the identical finding ID.
    """
    cleaned_id = activity_log_event_id.strip().lower()
    cleaned_resource = resource_id.strip().lower()
    seed = f"{cleaned_id}:{cleaned_resource}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
    return f"F-RC-{digest}"


def generate_exposure_finding_id(
    resource_id: str,
    nsg_rule_id: str,
    protocol: str,
    destination_port: str,
) -> str:
    """
    Generate a deterministic finding ID for UNEXPECTED_PUBLIC_EXPOSURE based on
    resource_id, nsg_rule_id, protocol, and destination_port.
    Formula: seed = resource_id + ":" + nsg_rule_id + ":" + protocol + ":" + destination_port
             finding_id = "F-UPE-" + SHA256(seed)[:12].upper()
    """
    seed = f"{resource_id}:{nsg_rule_id}:{protocol}:{destination_port}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
    return f"F-UPE-{digest}"


class Finding(BaseModel):
    finding_id: str = Field(..., description="Deterministic unique identifier for the finding")
    finding_type: str = Field("RESOURCE_CREATION", description="Detection contract ID")
    severity: SeverityLevel = Field(..., description="Initial severity assessment")
    timestamp: str = Field(..., description="Timestamp of the detected event in ISO 8601 format")
    resource: ResourceInfo
    identity: IdentityInfo
    evidence: EvidenceInfo
    confidence: float = Field(..., description="Detector confidence score between 0.0 and 1.0")

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"Confidence score must be between 0.0 and 1.0, got {v}")
        return round(v, 2)

    @field_validator("finding_type")
    @classmethod
    def validate_finding_type(cls, v: str) -> str:
        if v not in ("RESOURCE_CREATION", "UNEXPECTED_PUBLIC_EXPOSURE"):
            raise ValueError(f"Invalid finding_type for this detector: {v}")
        return v
