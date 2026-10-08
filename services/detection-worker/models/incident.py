import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from .finding import ResourceInfo, IdentityInfo, SeverityLevel


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


def generate_deterministic_incident_id(resource_id: str, caller: Optional[str] = None) -> str:
    """
    Generate a deterministic incident ID based on the canonical Azure resource ID.
    This guarantees that all findings for the creation of this resource correlate to the
    same incident, regardless of caller presentation variations or subsequent operations.
    """
    seed = resource_id.strip().lower()
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10].upper()
    return f"INC-RC-{digest}"


class Incident(BaseModel):
    incident_id: str = Field(..., description="Unique deterministic incident identifier")
    title: str = Field(..., description="Human-readable incident title")
    severity: SeverityLevel = Field(..., description="Incident severity level")
    status: IncidentStatus = Field(default=IncidentStatus.OPEN, description="Current triage status")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="Creation timestamp")
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="Last update timestamp")
    resource: ResourceInfo
    identity: IdentityInfo
    findings: List[str] = Field(default_factory=list, description="Associated CloudPulse Finding IDs")
    timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Chronological evidence events")
    
    # MVP boundary fields: explicit nulls/empty, preserving future extensibility without premature implementation
    cost_impact: Optional[Dict[str, Any]] = Field(None, description="FinOps correlation (MVP: null)")
    ai_analysis: Optional[Dict[str, Any]] = Field(None, description="AI triage explanation (MVP: null)")
    remediation: Optional[Dict[str, Any]] = Field(None, description="Controlled remediation plan (MVP: null)")
