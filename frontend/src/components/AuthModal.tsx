import React, { useEffect, useRef, useState } from 'react';
import {
  ArrowLeft,
  Check,
  Lock,
  Mail,
  RefreshCw,
  Send,
  Shield,
  X,
} from 'lucide-react';
import { api } from '../services/api';
import { OperatorProfile } from '../types';
import { OPERATOR_TEAM } from '../services/personaConfig';
import { supabase, isSupabaseConfigured } from '../services/supabaseClient';

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
  const [email, setEmail] = useState<string>('');
  // Passwordless sign-in and dev passcodes exist only when the backend enables them
  const [devAuth, setDevAuth] = useState<boolean>(false);

  useEffect(() => {
    if (!isOpen) return;
    api.fetchAuthStatus().then(st => setDevAuth(Boolean(st.dev_auth_enabled))).catch(() => setDevAuth(false));
  }, [isOpen]);
  const [otpDigits, setOtpDigits] = useState<string[]>(['', '', '', '', '', '']);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState<number>(0);

  const otpInputsRef = useRef<(HTMLInputElement | null)[]>([]);

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

  const handleInstantLogin = async (targetEmail?: string) => {
    const toSend = (targetEmail || email).trim().toLowerCase();
    if (!toSend || !toSend.includes('@')) {
      setErrorMessage('Please enter a valid work email address.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);
    setInfoMessage(null);

    try {
      const res = await api.operatorLogin(toSend);
      if (res.success && res.token && res.user) {
        localStorage.setItem('cloudpulse_auth_token', res.token);
        localStorage.setItem('cloudpulse_auth_user', JSON.stringify(res.user));
        onAuthenticated(res.user, res.token);
        onClose();
      } else {
        setErrorMessage(res.error || 'Failed to authenticate operator.');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Login failed';
      setErrorMessage(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRequestOtp = async (targetEmail?: string) => {
    const toSend = (targetEmail || email).trim().toLowerCase();
    if (!toSend || !toSend.includes('@')) {
      setErrorMessage('Please enter a valid work email address.');
      return;
    }

    if (!isSupabaseConfigured) {
      setErrorMessage(
        'Supabase Anon Key is not yet set. Please paste your anon key into frontend/.env (VITE_SUPABASE_ANON_KEY=...) to dispatch live OTPs.'
      );
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);
    setInfoMessage(null);

    try {
      const { error } = await supabase.auth.signInWithOtp({
        email: toSend,
        options: {
          shouldCreateUser: true,
        },
      });

      if (error) {
        const msg = error.message.toLowerCase();
        const isRateLimit = msg.includes('rate limit') || msg.includes('security purposes') || msg.includes('over_email_send_rate_limit');
        if (isRateLimit && devAuth) {
          // Supabase free tier rate limit encountered: transition smoothly to OTP step with dev code
          setEmail(toSend);
          setStep('otp');
          setOtpDigits(['1', '2', '3', '4', '5', '6']);
          setInfoMessage(
            'Supabase email rate limit active (free tier). We pre-filled dev passcode 123456 so you can sign in immediately.'
          );
          return;
        }
        setErrorMessage(error.message);
      } else {
        setEmail(toSend);
        setStep('otp');
        setOtpDigits(['', '', '', '', '', '']);
        setCooldown(45);
        setInfoMessage(`6-digit verification code sent to ${toSend} via Supabase Auth.`);
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
      let token: string | null = null;
      let user: OperatorProfile | null = null;

      const isDevCode = devAuth && (fullCode === '123456' || fullCode === '000000');

      // 1. If not dev code, try Supabase Auth direct OTP verification
      if (!isDevCode) {
        try {
          const { data, error } = await supabase.auth.verifyOtp({
            email,
            token: fullCode,
            type: 'email',
          });
          if (!error && data?.session?.access_token) {
            token = data.session.access_token;
          }
        } catch {
          // Fall through to backend verification
        }
      }

      // 2. If Supabase verify didn't produce a token (rate-limited / dev code), verify via CloudPulse backend
      if (!token) {
        const backendRes = await api.verifyOtp(email, fullCode);
        if (backendRes.success && backendRes.token) {
          token = backendRes.token;
          user = backendRes.user || null;
        }
      }

      // 3. Fallback: direct operator login if using dev code
      if (!token && isDevCode) {
        const opRes = await api.operatorLogin(email);
        if (opRes.success && opRes.token) {
          token = opRes.token;
          user = opRes.user || null;
        }
      }

      if (token) {
        // Validate / sync session with backend
        // The backend session is the source of truth for role and privileges
        const sessionRes = await api.fetchSession(token);
        const resolvedUser: OperatorProfile | null = (sessionRes?.authenticated && sessionRes.user)
          ? sessionRes.user
          : user;
        if (!resolvedUser) {
          setErrorMessage('Signed in with Supabase, but the CloudPulse backend could not validate the session.');
          return;
        }

        localStorage.setItem('cloudpulse_auth_token', token);
        localStorage.setItem('cloudpulse_auth_user', JSON.stringify(resolvedUser));
        onAuthenticated(resolvedUser, token);
        onClose();
      } else {
        setErrorMessage('Verification failed. Check the code or request a new one.');
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

    // Single digit entry
    const newDigits = [...otpDigits];
    newDigits[index] = clean.slice(-1);
    setOtpDigits(newDigits);

    // Auto advance
    if (index < 5 && clean) {
      otpInputsRef.current[index + 1]?.focus();
    }

    // Auto submit if all 6 filled
    if (index === 5 || newDigits.every(d => d !== '')) {
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

  const handlePaste = (e: React.ClipboardEvent<HTMLDivElement>) => {
    e.preventDefault();
    const paste = e.clipboardData.getData('text').trim().replace(/\D/g, '');
    if (paste.length >= 6) {
      const digits = paste.slice(0, 6).split('');
      setOtpDigits(digits);
      otpInputsRef.current[5]?.focus();
      handleVerifyOtp(paste.slice(0, 6));
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: 'rgba(5, 8, 15, 0.85)',
        backdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
      }}
    >
      <div
        className="card"
        style={{
          width: '100%',
          maxWidth: '480px',
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border-medium)',
          borderRadius: 'var(--radius-lg)',
          boxShadow: '0 25px 60px rgba(0, 0, 0, 0.7), 0 0 40px rgba(99, 179, 237, 0.08)',
          overflow: 'hidden',
          animation: 'fadeIn 0.2s ease',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '20px 24px',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'linear-gradient(180deg, rgba(255,255,255,0.03) 0%, transparent 100%)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div
              style={{
                width: '38px',
                height: '38px',
                borderRadius: 'var(--radius-md)',
                background: 'linear-gradient(135deg, rgba(99, 179, 237, 0.2), rgba(159, 122, 234, 0.2))',
                border: '1px solid rgba(99, 179, 237, 0.35)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent-sky)',
              }}
            >
              <Shield size={20} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 800, letterSpacing: '-0.01em' }}>
                  Enterprise Operator Access
                </h3>
              </div>
              <p style={{ margin: 0, fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>
                Supabase Zero-Trust Passwordless Verification
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                fontSize: '0.62rem',
                padding: '2px 8px',
                borderRadius: 'var(--radius-xs)',
                fontWeight: 700,
                background: isSupabaseConfigured ? 'rgba(56, 217, 169, 0.12)' : 'rgba(255, 193, 7, 0.15)',
                color: isSupabaseConfigured ? 'var(--accent-emerald)' : '#ffc107',
                border: `1px solid ${isSupabaseConfigured ? 'rgba(56, 217, 169, 0.3)' : 'rgba(255, 193, 7, 0.3)'}`,
              }}
            >
              {isSupabaseConfigured ? '● Supabase Active' : '⚠ Config Required'}
            </span>

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
                  placeholder="kls2edmentre@gmail.com"
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
                        onClick={() => setEmail(op.email)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '8px 12px',
                          background: isSelected ? 'rgba(99, 179, 237, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                          border: `1px solid ${isSelected ? 'var(--accent-sky)' : 'var(--border-subtle)'}`,
                          borderRadius: 'var(--radius-sm)',
                          cursor: 'pointer',
                          textAlign: 'left',
                          transition: 'all 0.15s ease',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <div
                            style={{
                              width: '26px',
                              height: '26px',
                              borderRadius: '50%',
                              background: 'rgba(99, 179, 237, 0.2)',
                              color: 'var(--accent-sky)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontSize: '0.66rem',
                              fontWeight: 800,
                            }}
                          >
                            {op.initials}
                          </div>
                          <div>
                            <div style={{ fontSize: '0.76rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                              {op.name}
                            </div>
                            <div style={{ fontSize: '0.64rem', color: 'var(--text-tertiary)' }}>
                              {op.role}
                            </div>
                          </div>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span
                            style={{
                              fontSize: '0.62rem',
                              padding: '2px 6px',
                              borderRadius: 'var(--radius-xs)',
                              background: op.isSuperAdmin ? 'rgba(159, 122, 234, 0.15)' : 'rgba(255,255,255,0.05)',
                              color: op.isSuperAdmin ? 'var(--accent-violet)' : 'var(--text-secondary)',
                              fontWeight: 700,
                            }}
                          >
                            {op.isSuperAdmin ? 'SuperAdmin' : op.primaryPersona.toUpperCase()}
                          </span>
                          {devAuth && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setEmail(op.email);
                              handleInstantLogin(op.email);
                            }}
                            disabled={isLoading}
                            style={{
                              fontSize: '0.62rem',
                              padding: '3px 8px',
                              borderRadius: 'var(--radius-xs)',
                              background: 'rgba(56, 217, 169, 0.18)',
                              color: 'var(--accent-emerald)',
                              border: '1px solid rgba(56, 217, 169, 0.4)',
                              fontWeight: 800,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '3px',
                            }}
                          >
                            ⚡ Sign In
                          </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {devAuth && (
                <button
                  className="btn btn-accent"
                  onClick={() => handleInstantLogin()}
                  disabled={isLoading}
                  style={{
                    width: '100%',
                    padding: '11px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    fontSize: '0.84rem',
                    fontWeight: 700,
                    background: 'linear-gradient(135deg, #38d9a9 0%, #3182ce 100%)',
                    border: 'none',
                    color: '#fff',
                    boxShadow: '0 4px 15px rgba(56, 217, 169, 0.3)',
                  }}
                >
                  {isLoading ? (
                    <>
                      <RefreshCw size={14} className="spin" />
                      <span>Authenticating Operator...</span>
                    </>
                  ) : (
                    <>
                      <Shield size={14} />
                      <span>⚡ Instant Operator Sign-In (Zero Wait)</span>
                    </>
                  )}
                </button>
                )}

                <button
                  className="btn btn-secondary"
                  onClick={() => handleRequestOtp()}
                  disabled={isLoading}
                  style={{
                    width: '100%',
                    padding: '9px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    fontSize: '0.78rem',
                    fontWeight: 600,
                    background: 'rgba(255, 255, 255, 0.04)',
                    border: '1px solid var(--border-medium)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  <Send size={13} />
                  <span>Dispatch Live OTP via Supabase</span>
                </button>
              </div>
            </div>
          )}

          {/* STEP 2: Enter 6-digit OTP */}
          {step === 'otp' && (
            <div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '12px',
                }}
              >
                <button
                  onClick={() => setStep('email')}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-secondary)',
                    fontSize: '0.70rem',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                    padding: 0,
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
                onPaste={handlePaste}
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  gap: '8px',
                  margin: '16px 0 16px',
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

              {devAuth && (
              <div style={{ textAlign: 'center', marginBottom: '16px' }}>
                <button
                  type="button"
                  onClick={() => {
                    const devDigits = ['1', '2', '3', '4', '5', '6'];
                    setOtpDigits(devDigits);
                    handleVerifyOtp('123456');
                  }}
                  disabled={isLoading}
                  style={{
                    background: 'rgba(56, 217, 169, 0.1)',
                    border: '1px solid rgba(56, 217, 169, 0.3)',
                    color: 'var(--accent-emerald)',
                    borderRadius: 'var(--radius-xs)',
                    padding: '4px 10px',
                    fontSize: '0.68rem',
                    fontWeight: 700,
                    cursor: 'pointer',
                  }}
                >
                  ⚡ Auto-Fill Dev Passcode (123456)
                </button>
              </div>
              )}

              <button
                className="btn btn-accent"
                onClick={() => handleVerifyOtp()}
                disabled={isLoading || otpDigits.join('').length !== 6}
                style={{
                  width: '100%',
                  padding: '11px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  fontSize: '0.84rem',
                  fontWeight: 700,
                }}
              >
                {isLoading ? (
                  <>
                    <RefreshCw size={14} className="spin" />
                    <span>Verifying Code...</span>
                  </>
                ) : (
                  <>
                    <Lock size={14} />
                    <span>Verify & Establish Session</span>
                  </>
                )}
              </button>

              <div
                style={{
                  marginTop: '16px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.70rem',
                  color: 'var(--text-tertiary)',
                  gap: 6,
                }}
              >
                <span>Didn't receive code?</span>
                <button
                  onClick={() => handleRequestOtp()}
                  disabled={cooldown > 0 || isLoading}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: cooldown > 0 ? 'var(--text-tertiary)' : 'var(--accent-sky)',
                    fontWeight: 700,
                    cursor: cooldown > 0 ? 'not-allowed' : 'pointer',
                    padding: 0,
                  }}
                >
                  {cooldown > 0 ? `Resend in ${cooldown}s` : 'Resend Code'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
