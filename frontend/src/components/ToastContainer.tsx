import React from 'react';
import { AlertCircle, AlertTriangle, CheckCircle, Info, X } from 'lucide-react';
import { ToastMessage } from '../types';

interface ToastContainerProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;

  return (
    <div className="toast-container">
      {toasts.map(t => {
        const Icon =
          t.type === 'success'
            ? CheckCircle
            : t.type === 'error'
            ? AlertCircle
            : t.type === 'warning'
            ? AlertTriangle
            : Info;

        const iconColor =
          t.type === 'success'
            ? 'var(--accent-teal)'
            : t.type === 'error'
            ? 'var(--accent-rose)'
            : t.type === 'warning'
            ? 'var(--accent-amber)'
            : 'var(--accent-sky)';

        return (
          <div key={t.id} className={`toast ${t.type}`}>
            <Icon size={18} color={iconColor} style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                {t.title}
              </div>
              {t.message && (
                <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  {t.message}
                </div>
              )}
            </div>
            <button
              onClick={() => onDismiss(t.id)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-tertiary)',
                cursor: 'pointer',
                padding: '2px',
              }}
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
};
