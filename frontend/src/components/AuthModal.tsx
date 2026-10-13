import React, { useEffect, useRef, useState } from 'react';
import {
  ArrowLeft,
  Check,
  Key,
  Lock,
  Mail,
  RefreshCw,
  Send,
  Shield,
  Sparkles,
  X,
} from 'lucide-react';
import { api } from '../services/api';
import { OperatorProfile } from '../types';
import { OPERATOR_TEAM } from '../services/personaConfig';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthenticated: (user: OperatorProfile, token: string) => void;
  activeOperator: OperatorProfile;
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  onAuthenticated,
}) => {
  const [step, setStep] = useState<'email' | 'otp'>('email');
  const [email, setEmail] = useState<string>('kushal@cloudpulse.io');
  const [otpDigits, setOtpDigits] = useState<string[]>(['', '', '', '', '', '']);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);
  const [devOtp, setDevOtp] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState<number>(0);
  const [showKeyConfig, setShowKeyConfig] = useState<boolean>(false);
  const [customKey, setCustomKey] = useState<string>('');
  const [hasResendKey, setHasResendKey] = useState<boolean>(false);

  const otpInputsRef = useRef<(HTMLInputElement | null)[]>([]);

  // Check auth status & Resend key on mount
  useEffect(() => {
    if (isOpen) {
      api.fetchAuthStatus().then(status => {
        setHasResendKey(status.has_resend_key);
      }).catch(() => {});
    }
  }, [isOpen]);

  // Cooldown timer
  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setInterval(() => {
      setCooldown(prev => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [cooldown]);

  // Auto-focus first OTP input when reaching step 2
  useEffect(() => {
    if (step === 'otp') {
      setTimeout(() => {
        otpInputsRef.current[0]?.focus();
      }, 100);
    }
  }, [step]);

  if (!isOpen) return null;

  const handleRequestOtp = async (targetEmail?: string) => {
    const toSend = (targetEmail || email).trim().toLowerCase();
    if (!toSend || !toSend.includes('@')) {
      setErrorMessage('Please enter a valid work email address.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);
    setInfoMessage(null);

    try {
      const res = await api.requestOtp(toSend);
      if (res.success) {
        setEmail(toSend);
        setStep('otp');
        setOtpDigits(['', '', '', '', '', '']);
        setCooldown(res.cooldown_seconds || 45);
        setDevOtp(res.dev_otp || null);
        setInfoMessage(res.message || `Verification code sent to ${toSend}`);
      } else {
        setErrorMessage(res.error || 'Failed to dispatch verification code.');
        if (res.cooldown_seconds) setCooldown(res.cooldown_seconds);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network error';
      setErrorMessage(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyOtp = async (codeToVerify?: string) => {
    const fullCode = codeToVerify || otpDigits.join('');
    if (fullCode.length !== 6) {
      setErrorMessage('Please enter the complete 6-digit verification code.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const res = await api.verifyOtp(email, fullCode);
      if (res.success && res.user && res.token) {
        localStorage.setItem('cloudpulse_auth_token', res.token);
        localStorage.setItem('cloudpulse_auth_user', JSON.stringify(res.user));
        onAuthenticated(res.user, res.token);
        onClose();
      } else {
        setErrorMessage(res.error || 'Invalid verification code.');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Verification failed';
      setErrorMessage(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleOtpDigitChange = (index: number, val: string) => {
    const clean = val.replace(/\D/g, '');
    if (!clean) {
      const newDigits = [...otpDigits];
      newDigits[index] = '';
      setOtpDigits(newDigits);
      return;
    }

    // If pasted full 6-digit code
    if (clean.length === 6) {
      const split = clean.split('');
      setOtpDigits(split);
      otpInputsRef.current[5]?.focus();
      handleVerifyOtp(clean);
      return;
    }

    // Single digit input
    const char = clean.slice(-1);
    const newDigits = [...otpDigits];
    newDigits[index] = char;
    setOtpDigits(newDigits);

    // Auto advance
    if (index < 5 && char) {
      otpInputsRef.current[index + 1]?.focus();
    }

    // Auto submit if all 6 digits entered
    if (index === 5 && char) {
      const code = newDigits.join('');
      if (code.length === 6) {
        handleVerifyOtp(code);
      }
    }
  };

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !otpDigits[index] && index > 0) {
      otpInputsRef.current[index - 1]?.focus();
    }
  };

  const handleConfigureKey = async () => {
    if (!customKey.trim() || !customKey.startsWith('re_')) {
      setErrorMessage('Resend API key must start with "re_".');
      return;
    }
    setIsLoading(true);
    try {
      const res = await api.configureResendKey(customKey.trim());
      if (res.success) {
        setHasResendKey(true);
        setShowKeyConfig(false);
        setInfoMessage('Resend API key successfully active! OTPs will now land in real inboxes.');
        setErrorMessage(null);
      } else {
        setErrorMessage(res.error || 'Failed to save Resend key.');
      }
    } catch {
      setErrorMessage('Failed to configure key.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1000,
        background: 'rgba(3, 6, 12, 0.85)',
        backdropFilter: 'blur(12px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
        animation: 'fadeIn 0.2s ease',
      }}
      onClick={e => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '460px',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-medium)',
          borderRadius: 'var(--radius-md)',
          boxShadow: '0 24px 60px rgba(0, 0, 0, 0.75), 0 0 1px rgba(99, 179, 237, 0.3)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          animation: 'slideUp 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '20px 24px 16px',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'linear-gradient(180deg, rgba(255, 255, 255, 0.03) 0%, transparent 100%)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div className="brand-icon" style={{ width: 30, height: 30 }}>
              <Shield size={16} color="#ffffff" strokeWidth={2.5} />
            </div>
            <div>
              <div style={{ fontWeight: 800, fontSize: '0.96rem', color: 'var(--text-primary)' }}>
                CloudPulse Command Auth
              </div>
              <div style={{ fontSize: '0.64rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Zero-Trust One-Time Password
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <button
              onClick={() => setShowKeyConfig(prev => !prev)}
              style={{
                background: 'transparent',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-xs)',
                padding: '4px 6px',
                color: hasResendKey ? '#38d9a9' : 'var(--text-tertiary)',
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                fontSize: '0.62rem',
                fontWeight: 700,
              }}
              title="Configure Resend API Key"
            >
              <Key size={11} />
              <span>{hasResendKey ? 'Resend Live' : 'Set Key'}</span>
            </button>

            <button
              onClick={onClose}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-tertiary)',
                cursor: 'pointer',
                padding: '4px',
                borderRadius: 'var(--radius-xs)',
              }}
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Resend Key Inline Drawer */}
        {showKeyConfig && (
          <div
            style={{
              padding: '12px 20px',
              background: 'rgba(99, 179, 237, 0.05)',
              borderBottom: '1px solid var(--border-subtle)',
              fontSize: '0.72rem',
            }}
          >
            <div style={{ fontWeight: 700, color: 'var(--accent-sky)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Key size={12} />
              <span>Resend API Key Configuration</span>
            </div>
            <p style={{ margin: '0 0 8px', color: 'var(--text-tertiary)', fontSize: '0.66rem' }}>
              Paste your <code>re_...</code> key to dispatch live verification emails directly to inboxes.
            </p>
            <div style={{ display: 'flex', gap: 6 }}>
              <input
                type="password"
                placeholder="re_1234567890..."
                value={customKey}
                onChange={e => setCustomKey(e.target.value)}
                style={{
                  flex: 1,
                  background: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid var(--border-medium)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '5px 8px',
                  color: 'var(--text-primary)',
                  fontSize: '0.72rem',
                  fontFamily: 'var(--font-mono)',
                  outline: 'none',
                }}
              />
              <button
                className="btn btn-accent"
                onClick={handleConfigureKey}
                disabled={isLoading}
                style={{ padding: '4px 10px', fontSize: '0.70rem' }}
              >
                Save
              </button>
            </div>
          </div>
        )}

        {/* Body */}
        <div style={{ padding: '24px' }}>
          {errorMessage && (
            <div
              style={{
                marginBottom: '16px',
                padding: '8px 12px',
                borderRadius: 'var(--radius-xs)',
                background: 'rgba(252, 129, 129, 0.12)',
                border: '1px solid rgba(252, 129, 129, 0.3)',
                color: '#fc8181',
                fontSize: '0.72rem',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <span>{errorMessage}</span>
            </div>
          )}

          {infoMessage && (
            <div
              style={{
                marginBottom: '16px',
                padding: '8px 12px',
                borderRadius: 'var(--radius-xs)',
                background: 'rgba(56, 217, 169, 0.12)',
                border: '1px solid rgba(56, 217, 169, 0.3)',
                color: '#38d9a9',
                fontSize: '0.72rem',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <Check size={12} />
              <span>{infoMessage}</span>
            </div>
          )}

          {/* STEP 1: Enter Email */}
          {step === 'email' && (
            <div>
              <label
                style={{
                  display: 'block',
                  fontSize: '0.74rem',
                  fontWeight: 700,
                  color: 'var(--text-secondary)',
                  marginBottom: '8px',
                }}
              >
                Enterprise Operator Email
              </label>

              <div style={{ position: 'relative', marginBottom: '16px' }}>
                <div
                  style={{
                    position: 'absolute',
                    left: '12px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    color: 'var(--text-tertiary)',
                  }}
                >
                  <Mail size={14} />
                </div>
                <input
                  type="email"
                  placeholder="name@cloudpulse.io"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter') handleRequestOtp();
                  }}
                  autoFocus
                  style={{
                    width: '100%',
                    padding: '10px 12px 10px 36px',
                    background: 'rgba(0, 0, 0, 0.25)',
                    border: '1px solid var(--border-medium)',
                    borderRadius: 'var(--radius-sm)',
                    color: 'var(--text-primary)',
                    fontSize: '0.84rem',
                    fontFamily: 'inherit',
                    outline: 'none',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              {/* Quick Login Chips for Team Members */}
              <div style={{ marginBottom: '20px' }}>
                <div
                  style={{
                    fontSize: '0.64rem',
                    color: 'var(--text-tertiary)',
                    textTransform: 'uppercase',
                    fontWeight: 800,
                    letterSpacing: '0.05em',
                    marginBottom: '8px',
                  }}
                >
                  1-Click Team Member Presets:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {OPERATOR_TEAM.map(op => {
                    const isSelected = email.toLowerCase() === op.email.toLowerCase();
                    return (
                      <div
                        key={op.id}
                        onClick={() => {
                          setEmail(op.email);
                          handleRequestOtp(op.email);
                        }}
                        style={{
                          padding: '6px 10px',
                          borderRadius: 'var(--radius-xs)',
                          border: isSelected ? '1px solid var(--accent-sky)' : '1px solid var(--border-subtle)',
                          background: isSelected ? 'rgba(99, 179, 237, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                          <span
                            style={{
                              width: 18,
                              height: 18,
                              borderRadius: '50%',
                              background: op.isSuperAdmin
                                ? 'linear-gradient(135deg, #f6ad55, #fc8181)'
                                : 'linear-gradient(135deg, #63b3ed, #9f7aea)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontSize: '0.55rem',
                              fontWeight: 800,
                              color: '#fff',
                            }}
                          >
                            {op.initials}
                          </span>
                          <div>
                            <span style={{ fontWeight: 700, fontSize: '0.74rem', color: 'var(--text-primary)' }}>
                              {op.name}
                            </span>
                            <span style={{ fontSize: '0.64rem', color: 'var(--text-tertiary)', marginLeft: 6 }}>
                              ({op.role})
                            </span>
                          </div>
                        </div>

                        {op.isSuperAdmin && (
                          <span
                            style={{
                              fontSize: '0.52rem',
                              fontFamily: 'var(--font-mono)',
                              fontWeight: 800,
                              color: '#f6ad55',
                              background: 'rgba(246, 173, 85, 0.15)',
                              border: '1px solid rgba(246, 173, 85, 0.3)',
                              padding: '1px 5px',
                              borderRadius: 'var(--radius-xs)',
                            }}
                          >
                            ★ FULL ACCESS
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              <button
                className="btn btn-accent"
                onClick={() => handleRequestOtp()}
                disabled={isLoading}
                style={{
                  width: '100%',
                  padding: '10px',
                  fontSize: '0.82rem',
                  gap: 8,
                }}
              >
                {isLoading ? <RefreshCw size={14} className="spin" /> : <Send size={14} />}
                <span>{isLoading ? 'Dispatching OTP…' : 'Send One-Time Password'}</span>
              </button>
            </div>
          )}

          {/* STEP 2: Enter 6-Digit OTP */}
          {step === 'otp' && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
                <button
                  onClick={() => {
                    setStep('email');
                    setErrorMessage(null);
                  }}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-tertiary)',
                    fontSize: '0.70rem',
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  <ArrowLeft size={12} />
                  <span>Change Email</span>
                </button>

                <span style={{ fontSize: '0.70rem', color: 'var(--accent-sky)', fontWeight: 600 }}>
                  {email}
                </span>
              </div>

              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  gap: '8px',
                  margin: '20px 0 24px',
                }}
              >
                {otpDigits.map((digit, i) => (
                  <input
                    key={i}
                    ref={el => { otpInputsRef.current[i] = el; }}
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={digit}
                    onChange={e => handleOtpDigitChange(i, e.target.value)}
                    onKeyDown={e => handleOtpKeyDown(i, e)}
                    style={{
                      width: '46px',
                      height: '52px',
                      textAlign: 'center',
                      fontSize: '1.4rem',
                      fontWeight: 800,
                      fontFamily: 'var(--font-mono)',
                      background: 'rgba(0, 0, 0, 0.35)',
                      border: digit ? '2px solid var(--accent-sky)' : '1px solid var(--border-medium)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--accent-sky)',
                      outline: 'none',
                      boxShadow: digit ? '0 0 10px rgba(99, 179, 237, 0.25)' : 'none',
                      transition: 'all 0.15s ease',
                    }}
                  />
                ))}
              </div>

              {/* Dev Mode Sandbox Auto-fill Banner */}
              {devOtp && (
                <div
                  style={{
                    marginBottom: '16px',
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-xs)',
                    background: 'rgba(159, 122, 234, 0.10)',
                    border: '1px solid rgba(159, 122, 234, 0.25)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Sparkles size={12} color="var(--accent-violet)" />
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                      Sandbox Code: <strong style={{ color: 'var(--accent-violet)', fontFamily: 'var(--font-mono)' }}>{devOtp}</strong>
                    </span>
                  </div>
                  <button
                    onClick={() => {
                      const split = devOtp.split('');
                      setOtpDigits(split);
                      handleVerifyOtp(devOtp);
                    }}
                    style={{
                      background: 'rgba(159, 122, 234, 0.2)',
                      border: 'none',
                      borderRadius: 'var(--radius-xs)',
                      padding: '3px 8px',
                      color: '#ffffff',
                      fontSize: '0.64rem',
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    Auto-Fill
                  </button>
                </div>
              )}

              <button
                className="btn btn-accent"
                onClick={() => handleVerifyOtp()}
                disabled={isLoading || otpDigits.join('').length !== 6}
                style={{
                  width: '100%',
                  padding: '10px',
                  fontSize: '0.82rem',
                  gap: 8,
                  marginBottom: '12px',
                }}
              >
                {isLoading ? <RefreshCw size={14} className="spin" /> : <Lock size={14} />}
                <span>{isLoading ? 'Verifying Session…' : 'Authenticate & Enter Console'}</span>
              </button>

              <div style={{ textAlign: 'center' }}>
                {cooldown > 0 ? (
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-tertiary)' }}>
                    Resend code available in <strong>{cooldown}s</strong>
                  </span>
                ) : (
                  <button
                    onClick={() => handleRequestOtp()}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: 'var(--accent-sky)',
                      fontSize: '0.70rem',
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    Didn’t receive code? Resend Email
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
