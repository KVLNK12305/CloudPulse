import React from 'react';
import { AlertCircle, AlertTriangle, RefreshCw } from 'lucide-react';

interface AlertsBannerProps {
  dbDegradedWarning?: string | null;
  apiErrors: string[];
  onRetry: () => void;
}

export const AlertsBanner: React.FC<AlertsBannerProps> = ({
  dbDegradedWarning,
  apiErrors,
  onRetry,
}) => {
  if (!dbDegradedWarning && apiErrors.length === 0) return null;

  return (
    <div style={{ marginBottom: '20px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
      {dbDegradedWarning && (
        <div
          style={{
            background: 'rgba(246, 173, 85, 0.10)',
            border: '1px solid rgba(246, 173, 85, 0.35)',
            borderRadius: 'var(--radius-sm)',
            padding: '12px 16px',
            fontSize: '0.80rem',
            color: '#feebc8',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertTriangle size={18} color="#f6ad55" style={{ flexShrink: 0 }} />
            <div>
              <strong>Database Degradation:</strong> {dbDegradedWarning}
            </div>
          </div>
          <span
            className="source-badge"
            style={{
              background: 'rgba(246, 173, 85, 0.20)',
              color: '#f6ad55',
              fontWeight: 700,
              flexShrink: 0,
            }}
          >
            VOLATILE STORAGE
          </span>
        </div>
      )}

      {apiErrors.length > 0 && (
        <div
          style={{
            background: 'rgba(252, 129, 129, 0.10)',
            border: '1px solid rgba(252, 129, 129, 0.35)',
            borderRadius: 'var(--radius-sm)',
            padding: '12px 16px',
            fontSize: '0.80rem',
            color: '#fed7d7',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertCircle size={18} color="#fc8181" style={{ flexShrink: 0 }} />
            <div>
              <strong>Telemetry Service Notice:</strong> {apiErrors.join('; ')}
            </div>
          </div>
          <button
            className="btn btn-secondary"
            style={{ padding: '4px 10px', fontSize: '0.72rem', flexShrink: 0 }}
            onClick={onRetry}
          >
            <RefreshCw size={12} />
            <span>Retry Telemetry</span>
          </button>
        </div>
      )}
    </div>
  );
};
