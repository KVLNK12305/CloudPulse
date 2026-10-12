import React, { useEffect, useState } from 'react';
import { Check, ShieldAlert, X } from 'lucide-react';

interface ActionModalProps {
  isOpen: boolean;
  actionId: string;
  actionTitle: string;
  targetStatus: 'APPROVED' | 'REJECTED';
  onConfirm: (notes: string) => void;
  onCancel: () => void;
  isLoading: boolean;
}

export const ActionModal: React.FC<ActionModalProps> = ({
  isOpen,
  actionId,
  actionTitle,
  targetStatus,
  onConfirm,
  onCancel,
  isLoading,
}) => {
  const [notes, setNotes] = useState<string>('');

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen && !isLoading) {
        onCancel();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, isLoading, onCancel]);

  if (!isOpen) return null;

  const isApproval = targetStatus === 'APPROVED';

  return (
    <div className="modal-overlay" onClick={isLoading ? undefined : onCancel}>
      <div className="modal-dialog" onClick={e => e.stopPropagation()}>
        <div className="panel-header">
          <div className="panel-title">
            <ShieldAlert size={18} color={isApproval ? 'var(--accent-teal)' : 'var(--accent-rose)'} />
            <span>{isApproval ? 'Authorize Remediation Action' : 'Reject Remediation Action'}</span>
          </div>
          <button
            className="btn btn-secondary"
            style={{ padding: '4px', borderRadius: '50%' }}
            onClick={onCancel}
            disabled={isLoading}
          >
            <X size={14} />
          </button>
        </div>

        <div style={{ padding: '22px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--accent-sky)', fontFamily: 'var(--font-mono)' }}>
              {actionId}
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '2px' }}>
              {actionTitle}
            </div>
          </div>

          <div
            style={{
              fontSize: '0.78rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.55,
              background: 'var(--bg-inset)',
              padding: '12px 14px',
              borderRadius: 'var(--radius-sm)',
              borderLeft: `3px solid ${isApproval ? 'var(--accent-teal)' : 'var(--accent-rose)'}`,
            }}
          >
            {isApproval ? (
              <span>
                Authorizing this action grants permission to execute targeted Azure Resource Manager mutations. An audit trail entry will be recorded with operator identity <code>secops-operator</code>.
              </span>
            ) : (
              <span>
                Rejecting this action marks it closed in the incident audit trail. No Azure mutations will be executed.
              </span>
            )}
          </div>

          <div>
            <label
              style={{
                display: 'block',
                fontSize: '0.70rem',
                color: 'var(--text-tertiary)',
                textTransform: 'uppercase',
                fontWeight: 700,
                letterSpacing: '0.04em',
                marginBottom: '6px',
              }}
            >
              Operator Audit Notes (Optional)
            </label>
            <textarea
              style={{
                width: '100%',
                height: '80px',
                background: 'var(--bg-inset)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                padding: '10px 12px',
                color: 'var(--text-primary)',
                fontSize: '0.80rem',
                fontFamily: 'inherit',
                resize: 'none',
                outline: 'none',
              }}
              placeholder="e.g. Verified with cloud security team; approved for immediate execution."
              value={notes}
              onChange={e => setNotes(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '6px' }}>
            <button className="btn btn-secondary" onClick={onCancel} disabled={isLoading}>
              Cancel
            </button>
            <button
              className={isApproval ? 'btn btn-success' : 'btn btn-danger'}
              onClick={() => onConfirm(notes)}
              disabled={isLoading}
            >
              <Check size={14} />
              <span>{isLoading ? 'Recording...' : isApproval ? 'Authorize Action' : 'Reject Action'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
