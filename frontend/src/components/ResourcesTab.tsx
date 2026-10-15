import React, { useEffect, useMemo, useRef, useState } from 'react';
import gsap from 'gsap';
import { Check, ExternalLink, Eye, Search } from 'lucide-react';
import { formatCurrency } from '../services/api';
import { Persona, ResourceItem, Severity } from '../types';
import { PERSONA_CONFIGS } from '../services/personaConfig';

interface ResourcesTabProps {
  resources: ResourceItem[];
  onInspectResource: (resourceId: string) => void;
  activePersona?: Persona;
  azureEnabled?: boolean;
}

export const ResourcesTab: React.FC<ResourcesTabProps> = ({
  resources,
  onInspectResource,
  activePersona = 'secops',
  azureEnabled = false,
}) => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [sevFilter, setSevFilter] = useState<string>('');
  const containerRef = useRef<HTMLDivElement>(null);
  const pCfg = PERSONA_CONFIGS[activePersona];

  useEffect(() => {
    if (containerRef.current) {
      gsap.fromTo(
        containerRef.current,
        { opacity: 0, y: 10 },
        { opacity: 1, y: 0, duration: 0.35, ease: 'power2.out' }
      );
    }
  }, []);

  const types = useMemo(() => {
    return Array.from(new Set(resources.map(r => r.type).filter(Boolean))).sort();
  }, [resources]);

  const filtered = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    const tf = typeFilter.toLowerCase();
    const sf = sevFilter.toUpperCase();

    return resources.filter(r => {
      if (tf && (r.type || '').toLowerCase() !== tf) return false;
      if (sf) {
        if (sf === 'CLEAN' && (r.findings_count > 0 || r.max_severity)) return false;
        if (sf !== 'CLEAN' && (r.max_severity || '') !== sf) return false;
      }
      if (q) {
        const matchName = (r.name || '').toLowerCase().includes(q);
        const matchType = (r.type || '').toLowerCase().includes(q);
        const matchId = (r.id || '').toLowerCase().includes(q);
        if (!matchName && !matchType && !matchId) return false;
      }
      return true;
    });
  }, [resources, searchQuery, typeFilter, sevFilter]);

  const sortedResources = useMemo(() => {
    return [...filtered].sort((a, b) => {
      if (activePersona === 'secops') {
        // High findings and critical severity first
        if ((b.findings_count || 0) !== (a.findings_count || 0)) {
          return (b.findings_count || 0) - (a.findings_count || 0);
        }
        const sevOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, CLEAN: 0 };
        const bSev = sevOrder[b.max_severity as keyof typeof sevOrder] || 0;
        const aSev = sevOrder[a.max_severity as keyof typeof sevOrder] || 0;
        return bSev - aSev;
      }
      if (activePersona === 'finops') {
        // High billed cost first
        const costA = a.actual_cost || 0;
        const costB = b.actual_cost || 0;
        return costB - costA;
      }
      if (activePersona === 'platform') {
        // Live monitored workloads first
        if (b.metrics_supported !== a.metrics_supported) {
          return b.metrics_supported ? 1 : -1;
        }
        return (a.name || '').localeCompare(b.name || '');
      }
      // Executive: findings density and spend confluence
      return (b.findings_count || 0) - (a.findings_count || 0);
    });
  }, [filtered, activePersona]);

  return (
    <div ref={containerRef} className="page-stack">

      {/* Resources Table Container */}
      <div className="data-table-container">
        <div className="table-toolbar">
          <div className="toolbar-left">
            <div className="search-input-wrapper">
              <Search size={14} className="search-icon" />
              <input
                type="text"
                className="search-input"
                placeholder="Search resource name, type, or ARM ID..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
              />
            </div>

            <select
              className="filter-select"
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}
            >
              <option value="">All Resource Types</option>
              {types.map(t => (
                <option key={t} value={t}>
                  {t.split('/').pop() || t}
                </option>
              ))}
            </select>

            <select
              className="filter-select"
              value={sevFilter}
              onChange={e => setSevFilter(e.target.value)}
            >
              <option value="">All Security States</option>
              <option value="CRITICAL">Critical Severity</option>
              <option value="HIGH">High Severity</option>
              <option value="MEDIUM">Medium Severity</option>
              <option value="LOW">Low Severity</option>
              <option value="CLEAN">Clean (No Findings)</option>
            </select>

          </div>

          <div className="toolbar-right">
            <span
              style={{ fontSize: '0.7rem', color: pCfg.color, display: 'inline-flex', alignItems: 'center', gap: '5px' }}
              title={`Rows are ordered for the ${pCfg.label} perspective`}
            >
              <Eye size={12} />
              <span>Sorted for {pCfg.label.split(' ')[0]}</span>
            </span>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>
              {sortedResources.length} of {resources.length}
            </span>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Resource Name</th>
                <th>Resource Type</th>
                <th>Location</th>
                <th>State</th>
                <th>Actual Cost</th>
                <th>Runtime Utilization</th>
                <th>Security Findings</th>
                <th>Severity</th>
                <th style={{ textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {sortedResources.length === 0 ? (
                <tr>
                  <td colSpan={9} className="empty-state">
                    {resources.length > 0
                      ? 'No resources match these filters.'
                      : azureEnabled
                      ? 'No resources discovered in the subscription.'
                      : 'No inventory: Azure integration is offline.'}
                  </td>
                </tr>
              ) : (
                sortedResources.map(r => {
                  const shortType = (r.type || '').split('/').pop() || r.type;
                  const shortId = (r.id || '').split('/').pop() || '';
                  const sev: Severity = r.max_severity || (r.findings_count > 0 ? 'HIGH' : 'CLEAN');

                  return (
                    <tr
                      key={r.id}
                      onClick={() => onInspectResource(r.id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.84rem' }}>
                          {r.name}
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.66rem', color: 'var(--text-tertiary)' }}>
                          {shortId}
                        </div>
                      </td>
                      <td>
                        <span className="source-badge arg">{shortType}</span>
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: '0.76rem' }}>
                        {r.location || 'global'}
                      </td>
                      <td>
                        <span style={{ fontSize: '0.72rem', color: 'var(--accent-teal)', fontFamily: 'var(--font-mono)', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                          <Check size={12} />
                          <span>{r.provisioning_state || 'Succeeded'}</span>
                        </span>
                      </td>
                      <td>
                        {r.actual_cost !== null && r.actual_cost !== undefined ? (
                          <span style={{ fontFamily: 'var(--font-mono)', color: '#38d9a9', fontWeight: 700 }}>
                            {formatCurrency(r.actual_cost, r.currency)}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-tertiary)', fontSize: '0.72rem' }}>
                            No billing data
                          </span>
                        )}
                      </td>
                      <td>
                        {r.metrics_supported ? (
                          <span
                            className="source-badge monitor"
                            style={{ fontSize: '0.68rem', display: 'inline-flex', alignItems: 'center', gap: '5px' }}
                          >
                            <span className="status-dot live" style={{ width: '5px', height: '5px', margin: 0 }} />
                            <span>Live Monitor</span>
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-tertiary)', fontSize: '0.70rem' }}>
                            Unavailable
                          </span>
                        )}
                      </td>
                      <td>
                        {r.findings_count > 0 ? (
                          <span className="badge-status OPEN">
                            {r.findings_count} Finding{r.findings_count > 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span className="source-badge monitor" style={{ color: '#38d9a9', borderColor: 'rgba(56,217,169,0.3)' }}>
                            Clean
                          </span>
                        )}
                      </td>
                      <td>
                        <span className={`badge-sev ${sev}`}>{sev}</span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                          onClick={e => {
                            e.stopPropagation();
                            onInspectResource(r.id);
                          }}
                        >
                          <ExternalLink size={12} />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
