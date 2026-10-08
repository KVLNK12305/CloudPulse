-- CloudPulse PostgreSQL Initial Schema
-- Migration 001: Findings, Incidents, and Incident Correlation

CREATE TABLE IF NOT EXISTS findings (
    id BIGSERIAL PRIMARY KEY,
    finding_id VARCHAR(64) UNIQUE NOT NULL,
    finding_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    resource_id TEXT NOT NULL,
    resource_type VARCHAR(128) NOT NULL,
    resource_name VARCHAR(128) NOT NULL,
    resource_group VARCHAR(128) NOT NULL,
    principal_id VARCHAR(128),
    principal_type VARCHAR(64),
    caller VARCHAR(256),
    operation VARCHAR(256) NOT NULL,
    activity_log_event_id VARCHAR(128) NOT NULL,
    correlation_id VARCHAR(128),
    confidence NUMERIC(3, 2) NOT NULL,
    evidence JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Note: finding_id UNIQUE constraint automatically creates a unique index on finding_id.
-- Additional indexes for frequent analytical query filters:
CREATE INDEX IF NOT EXISTS idx_findings_finding_type ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_resource_id ON findings(resource_id);
CREATE INDEX IF NOT EXISTS idx_findings_correlation_id ON findings(correlation_id);

CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(64) UNIQUE NOT NULL,
    title VARCHAR(256) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
    resource JSONB NOT NULL,
    identity JSONB NOT NULL,
    findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    timeline JSONB NOT NULL DEFAULT '[]'::jsonb,
    cost_impact JSONB,
    ai_analysis JSONB,
    remediation JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Note: incident_id UNIQUE constraint automatically creates a unique index on incident_id.
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);

CREATE TABLE IF NOT EXISTS incident_findings (
    incident_id VARCHAR(64) NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    finding_id VARCHAR(64) NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (incident_id, finding_id)
);

-- Index for reverse lookups (finding -> incidents)
CREATE INDEX IF NOT EXISTS idx_incident_findings_finding_id ON incident_findings(finding_id);
