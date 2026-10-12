import React, { useState } from 'react';
import { Check, Copy, Download, FileText, Send, Share2, X } from 'lucide-react';
import { formatCurrency } from '../services/api';
import { Incident } from '../types';

interface ExportBriefModalProps {
  isOpen: boolean;
  incident: Incident | null;
  onClose: () => void;
  onShowToast: (type: 'info' | 'success' | 'warning' | 'error', title: string, message?: string) => void;
}

export const ExportBriefModal: React.FC<ExportBriefModalProps> = ({
  isOpen,
  incident,
  onClose,
  onShowToast,
}) => {
  const [format, setFormat] = useState<'markdown' | 'jira' | 'slack'>('markdown');
  const [copied, setCopied] = useState<boolean>(false);

  if (!isOpen || !incident) return null;

  const costSurge = incident.cost_impact
    ? `+${incident.cost_impact.percentage_increase.toFixed(0)}% (+${formatCurrency(
        incident.cost_impact.deviation_absolute,
        incident.cost_impact.currency || 'USD'
      )})`
    : 'No correlated surge';

  const generateMarkdown = () => {
    return `# [CLOUDPULSE SECURITY & FINOPS INCIDENT BRIEF]
**Incident ID**: ${incident.incident_id}
**Severity**: ${incident.severity}
**Status**: ${incident.status}
**Target Workload**: ${incident.resource.name} (${incident.resource.type})
**Resource Group**: ${incident.resource.resource_group}
**Detected At**: ${incident.created_at}

## EXECUTIVE SUMMARY
${incident.ai_analysis?.summary || incident.title}

## ATTACK SURFACE & FINANCIAL IMPACT
- **Cost Category**: ${incident.cost_impact?.cost_category || 'N/A'}
- **Financial Surge**: ${costSurge}
- **Historical Baseline**: ${formatCurrency(incident.cost_impact?.baseline_cost || 0, incident.cost_impact?.currency || 'USD')}
- **Actual Closed Billing**: ${formatCurrency(incident.cost_impact?.actual_cost || 0, incident.cost_impact?.currency || 'USD')}

## VERIFIED TELEMETRY FACTS
${(incident.ai_analysis?.facts || ['Correlated telemetry findings recorded in Azure Resource Graph.']).map(f => `- ${f}`).join('\n')}

## RECOMMENDED CONTROLLED REMEDIATIONS
${(incident.ai_analysis?.recommended_actions || []).map(a => `- [${a.id}] ${a.title}: ${a.description}`).join('\n')}

---
*Exported from CloudPulse Autonomous Operator Console*`;
  };

  const generateJira = () => {
    return `h1. [CloudPulse] ${incident.severity}: ${incident.title}
*Incident ID*: ${incident.incident_id}
*Workload*: ${incident.resource.name}
*Financial Impact*: ${costSurge}

h2. Summary
${incident.ai_analysis?.summary || incident.title}

h2. Risk Assessment
${incident.ai_analysis?.risk_assessment || 'Critical risk to cloud environment.'}

h2. Remediation Gate
Human authorization required in CloudPulse console for live ARM containment.`;
  };

  const generateSlack = () => {
    return `*[SECURITY ALERT]* CloudPulse Threat Intelligence | *${incident.severity}*
*Incident*: ${incident.title} (\`${incident.incident_id}\`)
*Workload*: \`${incident.resource.name}\`
*Financial Surge*: ${costSurge}
*AI Synthesis*: ${incident.ai_analysis?.summary || 'Threat detected'}
*Console URL*: http://127.0.0.1:8080/dashboard`;
  };

  const content =
    format === 'markdown'
      ? generateMarkdown()
      : format === 'jira'
      ? generateJira()
      : generateSlack();

  const handleCopy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    onShowToast('success', 'Incident Brief Copied', `Copied ${format.toUpperCase()} format to clipboard.`);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `cloudpulse-${incident.incident_id.toLowerCase()}.md`;
    link.click();
    URL.revokeObjectURL(url);
    onShowToast('success', 'Brief Downloaded', 'Saved incident report file.');
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-dialog" style={{ width: '600px', maxWidth: '95vw' }} onClick={e => e.stopPropagation()}>
        <div className="panel-header">
          <div className="panel-title">
            <Share2 size={18} color="var(--accent-sky)" />
            <span>Export & Share Incident Brief</span>
          </div>
          <button className="btn btn-secondary" style={{ padding: '4px', borderRadius: '50%' }} onClick={onClose}>
            <X size={14} />
          </button>
        </div>

        <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {/* Format Selector */}
          <div style={{ display: 'flex', gap: '8px' }}>
            {[
              { id: 'markdown', label: 'Executive Markdown' },
              { id: 'jira', label: 'Jira Issue' },
              { id: 'slack', label: 'Slack Webhook Payload' },
            ].map(f => (
              <button
                key={f.id}
                className={`nav-tab ${format === f.id ? 'active' : ''}`}
                style={{ padding: '6px 12px', fontSize: '0.74rem' }}
                onClick={() => setFormat(f.id as 'markdown' | 'jira' | 'slack')}
              >
                {f.label}
              </button>
            ))}
          </div>

          {/* Preview Box */}
          <textarea
            readOnly
            style={{
              width: '100%',
              height: '240px',
              background: 'var(--bg-inset)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '12px 14px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.72rem',
              color: 'var(--text-primary)',
              lineHeight: 1.5,
              resize: 'none',
              outline: 'none',
            }}
            value={content}
          />

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>
              Ready to paste into Jira, ServiceNow, or executive stakeholder channels.
            </span>

            <div style={{ display: 'flex', gap: '8px' }}>
              <button className="btn btn-secondary" onClick={handleDownload}>
                <Download size={13} />
                <span>Download .md</span>
              </button>
              <button className="btn btn-accent" onClick={handleCopy}>
                {copied ? <Check size={13} color="var(--accent-teal)" /> : <Copy size={13} />}
                <span>{copied ? 'Copied!' : 'Copy to Clipboard'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
