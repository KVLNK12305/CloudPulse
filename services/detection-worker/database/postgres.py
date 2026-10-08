import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any

from models.finding import Finding, ResourceInfo, IdentityInfo, EvidenceInfo, SeverityLevel
from models.incident import Incident, IncidentStatus

logger = logging.getLogger("cloudpulse.database")


class DatabaseRepository(ABC):
    """Abstract interface for CloudPulse persistence."""

    @abstractmethod
    def initialize_schema(self) -> None:
        pass

    @abstractmethod
    def save_finding(self, finding: Finding) -> bool:
        """Saves a finding. Returns True if inserted, False if duplicate."""
        pass

    @abstractmethod
    def get_finding(self, finding_id: str) -> Optional[Finding]:
        pass

    @abstractmethod
    def list_findings(self, limit: int = 100) -> List[Finding]:
        pass

    @abstractmethod
    def save_incident(self, incident: Incident) -> bool:
        """Saves an incident. Returns True if inserted, False if duplicate."""
        pass

    @abstractmethod
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        pass

    @abstractmethod
    def list_incidents(self, limit: int = 100) -> List[Incident]:
        pass

    @abstractmethod
    def link_incident_finding(self, incident_id: str, finding_id: str) -> bool:
        pass


class PostgresDatabase(DatabaseRepository):
    """PostgreSQL implementation of DatabaseRepository using psycopg2."""

    def __init__(
        self,
        host: str,
        port: int,
        database: str,
        user: str,
        password: str,
        sslmode: str = "require",
    ):
        self._host = host
        self._port = port
        self._database = database
        self._user = user
        self._password = password
        self._sslmode = sslmode

    def _get_connection(self):
        import psycopg2
        return psycopg2.connect(
            host=self._host,
            port=self._port,
            dbname=self._database,
            user=self._user,
            password=self._password,
            sslmode=self._sslmode,
            connect_timeout=10,
        )

    def initialize_schema(self) -> None:
        """Run SQL migration scripts to create tables and indexes."""
        migration_path = os.path.join(
            os.path.dirname(__file__), "migrations", "001_initial_schema.sql"
        )
        if not os.path.exists(migration_path):
            raise FileNotFoundError(f"Migration file not found at {migration_path}")

        with open(migration_path, "r", encoding="utf-8") as f:
            ddl = f.read()

        logger.info("Initializing PostgreSQL schema from migration 001...")
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(ddl)
            conn.commit()
        logger.info("PostgreSQL schema initialized successfully.")

    def save_finding(self, finding: Finding) -> bool:
        """
        Persists a Finding. If finding_id already exists, ignores insert and returns False (duplicate).
        """
        sql = """
        INSERT INTO findings (
            finding_id,
            finding_type,
            severity,
            timestamp,
            resource_id,
            resource_type,
            resource_name,
            resource_group,
            principal_id,
            principal_type,
            caller,
            operation,
            activity_log_event_id,
            correlation_id,
            confidence,
            evidence
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (finding_id) DO NOTHING
        RETURNING id;
        """
        evidence_json = json.dumps(finding.evidence.model_dump(), default=str)

        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        finding.finding_id,
                        finding.finding_type,
                        finding.severity.value,
                        finding.timestamp,
                        finding.resource.id,
                        finding.resource.type,
                        finding.resource.name,
                        finding.resource.resource_group,
                        finding.identity.principal_id,
                        finding.identity.principal_type,
                        finding.identity.caller,
                        finding.evidence.operation,
                        finding.evidence.activity_log_event_id,
                        finding.evidence.correlation_id,
                        finding.confidence,
                        evidence_json,
                    ),
                )
                res = cur.fetchone()
            conn.commit()

        inserted = res is not None
        if not inserted:
            logger.info("Finding %s is a duplicate, skipped insert.", finding.finding_id)
        return inserted

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        sql = """
        SELECT
            finding_id, finding_type, severity, timestamp,
            resource_id, resource_type, resource_name, resource_group,
            principal_id, principal_type, caller,
            operation, activity_log_event_id, correlation_id,
            confidence, evidence
        FROM findings
        WHERE finding_id = %s;
        """
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (finding_id,))
                row = cur.fetchone()

        if not row:
            return None

        evidence_data = row[15] if isinstance(row[15], dict) else json.loads(row[15])
        return Finding(
            finding_id=row[0],
            finding_type=row[1],
            severity=SeverityLevel(row[2]),
            timestamp=str(row[3]),
            resource=ResourceInfo(
                id=row[4],
                type=row[5],
                name=row[6],
                resource_group=row[7],
            ),
            identity=IdentityInfo(
                principal_id=row[8],
                principal_type=row[9],
                caller=row[10],
            ),
            evidence=EvidenceInfo(**evidence_data),
            confidence=float(row[14]),
        )

    def list_findings(self, limit: int = 100) -> List[Finding]:
        sql = """
        SELECT
            finding_id, finding_type, severity, timestamp,
            resource_id, resource_type, resource_name, resource_group,
            principal_id, principal_type, caller,
            operation, activity_log_event_id, correlation_id,
            confidence, evidence
        FROM findings
        ORDER BY timestamp DESC
        LIMIT %s;
        """
        findings = []
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (limit,))
                rows = cur.fetchall()

        for row in rows:
            evidence_data = row[15] if isinstance(row[15], dict) else json.loads(row[15])
            findings.append(
                Finding(
                    finding_id=row[0],
                    finding_type=row[1],
                    severity=SeverityLevel(row[2]),
                    timestamp=str(row[3]),
                    resource=ResourceInfo(
                        id=row[4],
                        type=row[5],
                        name=row[6],
                        resource_group=row[7],
                    ),
                    identity=IdentityInfo(
                        principal_id=row[8],
                        principal_type=row[9],
                        caller=row[10],
                    ),
                    evidence=EvidenceInfo(**evidence_data),
                    confidence=float(row[14]),
                )
            )
        return findings

    def save_incident(self, incident: Incident) -> bool:
        """
        Persists an Incident. If incident_id already exists, updates updated_at and attached findings list.
        """
        sql = """
        INSERT INTO incidents (
            incident_id,
            title,
            severity,
            status,
            resource,
            identity,
            findings,
            timeline,
            cost_impact,
            ai_analysis,
            remediation,
            created_at,
            updated_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (incident_id) DO UPDATE SET
            title = EXCLUDED.title,
            severity = EXCLUDED.severity,
            status = EXCLUDED.status,
            identity = EXCLUDED.identity,
            findings = EXCLUDED.findings,
            timeline = EXCLUDED.timeline,
            updated_at = EXCLUDED.updated_at
        RETURNING id;
        """
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        incident.incident_id,
                        incident.title,
                        incident.severity.value,
                        incident.status.value,
                        json.dumps(incident.resource.model_dump(), default=str),
                        json.dumps(incident.identity.model_dump(), default=str),
                        json.dumps(incident.findings, default=str),
                        json.dumps(incident.timeline, default=str),
                        json.dumps(incident.cost_impact, default=str) if incident.cost_impact else None,
                        json.dumps(incident.ai_analysis, default=str) if incident.ai_analysis else None,
                        json.dumps(incident.remediation, default=str) if incident.remediation else None,
                        incident.created_at,
                        incident.updated_at,
                    ),
                )
                res = cur.fetchone()
            conn.commit()

        return res is not None

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        sql = """
        SELECT
            incident_id, title, severity, status,
            resource, identity, findings, timeline,
            cost_impact, ai_analysis, remediation,
            created_at, updated_at
        FROM incidents
        WHERE incident_id = %s;
        """
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (incident_id,))
                row = cur.fetchone()

        if not row:
            return None

        resource_data = row[4] if isinstance(row[4], dict) else json.loads(row[4])
        identity_data = row[5] if isinstance(row[5], dict) else json.loads(row[5])
        findings_data = row[6] if isinstance(row[6], list) else json.loads(row[6])
        timeline_data = row[7] if isinstance(row[7], list) else json.loads(row[7])

        return Incident(
            incident_id=row[0],
            title=row[1],
            severity=SeverityLevel(row[2]),
            status=IncidentStatus(row[3]),
            resource=ResourceInfo(**resource_data),
            identity=IdentityInfo(**identity_data),
            findings=findings_data,
            timeline=timeline_data,
            cost_impact=row[8] if isinstance(row[8], dict) or row[8] is None else json.loads(row[8]),
            ai_analysis=row[9] if isinstance(row[9], dict) or row[9] is None else json.loads(row[9]),
            remediation=row[10] if isinstance(row[10], dict) or row[10] is None else json.loads(row[10]),
            created_at=str(row[11]),
            updated_at=str(row[12]),
        )

    def list_incidents(self, limit: int = 100) -> List[Incident]:
        sql = """
        SELECT
            incident_id, title, severity, status,
            resource, identity, findings, timeline,
            cost_impact, ai_analysis, remediation,
            created_at, updated_at
        FROM incidents
        ORDER BY created_at DESC
        LIMIT %s;
        """
        incidents = []
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (limit,))
                rows = cur.fetchall()

        for row in rows:
            resource_data = row[4] if isinstance(row[4], dict) else json.loads(row[4])
            identity_data = row[5] if isinstance(row[5], dict) else json.loads(row[5])
            findings_data = row[6] if isinstance(row[6], list) else json.loads(row[6])
            timeline_data = row[7] if isinstance(row[7], list) else json.loads(row[7])

            incidents.append(
                Incident(
                    incident_id=row[0],
                    title=row[1],
                    severity=SeverityLevel(row[2]),
                    status=IncidentStatus(row[3]),
                    resource=ResourceInfo(**resource_data),
                    identity=IdentityInfo(**identity_data),
                    findings=findings_data,
                    timeline=timeline_data,
                    cost_impact=row[8] if isinstance(row[8], dict) or row[8] is None else json.loads(row[8]),
                    ai_analysis=row[9] if isinstance(row[9], dict) or row[9] is None else json.loads(row[9]),
                    remediation=row[10] if isinstance(row[10], dict) or row[10] is None else json.loads(row[10]),
                    created_at=str(row[11]),
                    updated_at=str(row[12]),
                )
            )
        return incidents

    def link_incident_finding(self, incident_id: str, finding_id: str) -> bool:
        sql = """
        INSERT INTO incident_findings (incident_id, finding_id)
        VALUES (%s, %s)
        ON CONFLICT (incident_id, finding_id) DO NOTHING;
        """
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (incident_id, finding_id))
            conn.commit()
        return True


class InMemoryDatabase(DatabaseRepository):
    """
    In-memory implementation of DatabaseRepository.
    Used for automated unit testing and isolated test environments.
    """

    def __init__(self):
        self.findings: Dict[str, Finding] = {}
        self.incidents: Dict[str, Incident] = {}
        self.incident_findings: List[Dict[str, str]] = []

    def initialize_schema(self) -> None:
        pass

    def save_finding(self, finding: Finding) -> bool:
        if finding.finding_id in self.findings:
            return False
        self.findings[finding.finding_id] = finding
        return True

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        return self.findings.get(finding_id)

    def list_findings(self, limit: int = 100) -> List[Finding]:
        return list(self.findings.values())[:limit]

    def save_incident(self, incident: Incident) -> bool:
        if incident.incident_id in self.incidents:
            existing = self.incidents[incident.incident_id]
            # Merge findings and update
            merged_findings = list(set(existing.findings + incident.findings))
            existing.findings = merged_findings
            existing.updated_at = incident.updated_at
            return False
        self.incidents[incident.incident_id] = incident
        return True

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def list_incidents(self, limit: int = 100) -> List[Incident]:
        return list(self.incidents.values())[:limit]

    def link_incident_finding(self, incident_id: str, finding_id: str) -> bool:
        link = {"incident_id": incident_id, "finding_id": finding_id}
        if link not in self.incident_findings:
            self.incident_findings.append(link)
        return True
