-- CloudPulse PostgreSQL Migration 002: Multi-Tenant Data Isolation
-- Fixes SEC-TENANT-01: Add tenant_id and subscription_id for mandatory data scoping

-- Schema migrations tracking table (fixes DB-POOL-01)
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(64) PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT
);

-- Add tenant isolation columns to findings
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(128);

-- Add tenant isolation columns to incidents
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(128);

-- Create indexes for tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_subscription_id ON findings(subscription_id);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_id ON incidents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_incidents_subscription_id ON incidents(subscription_id);

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_findings_tenant_subscription ON findings(tenant_id, subscription_id);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_subscription ON incidents(tenant_id, subscription_id);

-- Record migration
INSERT INTO schema_migrations (version, description) VALUES
    ('002', 'Add tenant_id and subscription_id for multi-tenant data isolation')
ON CONFLICT (version) DO NOTHING;
