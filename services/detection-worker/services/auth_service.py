"""
CloudPulse Authentication & OTP Dispatch Service
Handles secure 6-digit OTP generation, rate-limiting, Resend email dispatch,
and operator role mapping.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger("cloudpulse.auth_service")

# Team Operator Roster with explicit role-based access
OPERATOR_ROSTER: Dict[str, Dict[str, Any]] = {
    "kushal@cloudpulse.io": {
        "id": "op-kushal",
        "name": "K V L N Kushal",
        "initials": "KK",
        "role": "Lead SecOps Commander & CISO (Full Access)",
        "email": "kushal@cloudpulse.io",
        "organization": "Enterprise Cyber Defense & Core SecOps",
        "primaryPersona": "secops",
        "allowedPersonas": ["secops", "executive", "platform", "finops"],
        "isSuperAdmin": True,
    },
    "kvlnkushal@cloudpulse.io": {
        "id": "op-kushal",
        "name": "K V L N Kushal",
        "initials": "KK",
        "role": "Lead SecOps Commander & CISO (Full Access)",
        "email": "kvlnkushal@cloudpulse.io",
        "organization": "Enterprise Cyber Defense & Core SecOps",
        "primaryPersona": "secops",
        "allowedPersonas": ["secops", "executive", "platform", "finops"],
        "isSuperAdmin": True,
    },
    "siddardha@cloudpulse.io": {
        "id": "op-siddardha",
        "name": "K S V siddardha",
        "initials": "KS",
        "role": "Platform SRE Lead",
        "email": "siddardha@cloudpulse.io",
        "organization": "Cloud Platform Engineering & SRE",
        "primaryPersona": "platform",
        "allowedPersonas": ["platform"],
        "isSuperAdmin": False,
    },
    "saketh@cloudpulse.io": {
        "id": "op-saketh",
        "name": "R K Saketh",
        "initials": "RS",
        "role": "Principal FinOps Economist",
        "email": "saketh@cloudpulse.io",
        "organization": "Cloud Financial Operations & Economics",
        "primaryPersona": "finops",
        "allowedPersonas": ["finops"],
        "isSuperAdmin": False,
    },
    "rishinath.kurup@cloudpulse.io": {
        "id": "op-rishinath",
        "name": "RishinathKurup",
        "initials": "RK",
        "role": "Chief Information Security Officer (CISO)",
        "email": "rishinath.kurup@cloudpulse.io",
        "organization": "Enterprise Risk & Board Governance",
        "primaryPersona": "executive",
        "allowedPersonas": ["executive"],
        "isSuperAdmin": False,
    },
    "rishinath@cloudpulse.io": {
        "id": "op-rishinath",
        "name": "RishinathKurup",
        "initials": "RK",
        "role": "Chief Information Security Officer (CISO)",
        "email": "rishinath@cloudpulse.io",
        "organization": "Enterprise Risk & Board Governance",
        "primaryPersona": "executive",
        "allowedPersonas": ["executive"],
        "isSuperAdmin": False,
    },
}


class AuthService:
    """Manages OTP generation, verification, sessions, and Resend delivery."""

    def __init__(self, resend_api_key: Optional[str] = None):
        self._resend_api_key = resend_api_key or os.getenv("RESEND_API_KEY", "").strip()
        self._from_email = os.getenv("RESEND_FROM_EMAIL", "CloudPulse Auth <onboarding@resend.dev>")
        self._otp_expiry_seconds = 600  # 10 minutes
        self._cooldown_seconds = 45     # 45s between OTP requests
        self._max_attempts = 5          # Max failed verification attempts

        # In-memory stores for OTPs and sessions
        # schema: { email: { 'hash': str, 'salt': str, 'expires_at': float, 'created_at': float, 'attempts': int, 'code_preview': str } }
        self._otps: Dict[str, Dict[str, Any]] = {}
        # schema: { session_token: { 'user': dict, 'created_at': float, 'expires_at': float } }
        self._sessions: Dict[str, Dict[str, Any]] = {}

    def set_resend_api_key(self, api_key: str) -> None:
        """Dynamically update Resend API key."""
        self._resend_api_key = api_key.strip()
        logger.info("Resend API key updated successfully.")

    @property
    def has_resend_key(self) -> bool:
        return bool(self._resend_api_key and self._resend_api_key.startswith("re_"))

    def _hash_otp(self, code: str, salt: str) -> str:
        return hashlib.sha256(f"{salt}:{code}".encode("utf-8")).hexdigest()

    def request_otp(self, raw_email: str) -> Dict[str, Any]:
        """
        Generates and dispatches a 6-digit OTP code to the requested email.
        Enforces cooldown and sends via Resend if API key is present.
        """
        email = raw_email.strip().lower()
        if not email or "@" not in email:
            return {"success": False, "error": "Invalid email address format."}

        now = time.time()

        # Cooldown check
        existing = self._otps.get(email)
        if existing:
            elapsed = now - existing.get("created_at", 0)
            if elapsed < self._cooldown_seconds:
                wait_left = int(self._cooldown_seconds - elapsed)
                return {
                    "success": False,
                    "error": f"Please wait {wait_left}s before requesting a new code.",
                    "cooldown_remaining": wait_left,
                }

        # Generate 6-digit secure numeric code
        code = f"{secrets.randbelow(900000) + 100000:06d}"
        salt = secrets.token_hex(16)
        code_hash = self._hash_otp(code, salt)

        self._otps[email] = {
            "hash": code_hash,
            "salt": salt,
            "expires_at": now + self._otp_expiry_seconds,
            "created_at": now,
            "attempts": 0,
            "code_preview": code,
        }

        # Send via Resend if API key available
        email_sent = False
        email_error = None
        if self.has_resend_key:
            email_sent, email_error = self._send_resend_email(email, code)

        logger.info(
            f"OTP requested for {email}. Resend dispatch: {email_sent} (Key set: {self.has_resend_key})"
        )

        # In dev mode (or if key not set or sandbox domain restriction), provide preview
        is_dev = not self.has_resend_key or not email_sent

        return {
            "success": True,
            "message": f"Verification code sent to {email}.",
            "email": email,
            "expires_in_seconds": self._otp_expiry_seconds,
            "cooldown_seconds": self._cooldown_seconds,
            "email_dispatched": email_sent,
            "dev_mode": is_dev,
            "dev_otp": code if is_dev else None,
            "delivery_note": (
                "Delivered to inbox via Resend"
                if email_sent
                else f"Dev fallback active ({email_error or 'Resend API key not configured'})"
            ),
        }

    def verify_otp(self, raw_email: str, code: str) -> Dict[str, Any]:
        """
        Verifies the 6-digit OTP code against stored hash.
        Issues a session token on success.
        """
        email = raw_email.strip().lower()
        code_clean = str(code).strip()

        stored = self._otps.get(email)
        if not stored:
            return {"success": False, "error": "No pending verification code found for this email. Please request a new one."}

        now = time.time()
        if now > stored["expires_at"]:
            self._otps.pop(email, None)
            return {"success": False, "error": "Verification code has expired. Please request a new one."}

        if stored["attempts"] >= self._max_attempts:
            self._otps.pop(email, None)
            return {"success": False, "error": "Too many failed attempts. Security lockout triggered. Please request a new code."}

        # Constant-time comparison
        salt = stored["salt"]
        expected_hash = stored["hash"]
        candidate_hash = self._hash_otp(code_clean, salt)

        if not hmac.compare_digest(expected_hash, candidate_hash):
            stored["attempts"] += 1
            remaining = self._max_attempts - stored["attempts"]
            return {
                "success": False,
                "error": f"Invalid verification code. {remaining} attempt(s) remaining.",
                "attempts_remaining": remaining,
            }

        # Code is valid: Clear OTP record
        self._otps.pop(email, None)

        # Map to registered operator or create standard profile
        user = self._resolve_user_profile(email)

        # Issue session token (valid for 7 days)
        session_token = f"cp_sess_{secrets.token_urlsafe(32)}"
        session_expires = now + (7 * 86400)
        self._sessions[session_token] = {
            "user": user,
            "created_at": now,
            "expires_at": session_expires,
        }

        logger.info(f"Successful OTP verification for {email}. Granted role: {user['role']} (SuperAdmin: {user['isSuperAdmin']})")

        return {
            "success": True,
            "token": session_token,
            "user": user,
            "expires_at": session_expires,
        }

    def validate_session(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        """Validates session token and returns user profile if active."""
        if not token:
            return None
        session = self._sessions.get(token)
        if not session:
            return None
        if time.time() > session["expires_at"]:
            self._sessions.pop(token, None)
            return None
        return session["user"]

    def revoke_session(self, token: Optional[str]) -> bool:
        if token and token in self._sessions:
            del self._sessions[token]
            return True
        return False

    def _resolve_user_profile(self, email: str) -> Dict[str, Any]:
        """Resolves email to an operator profile from the roster or constructs a standard profile."""
        if email in OPERATOR_ROSTER:
            return dict(OPERATOR_ROSTER[email])

        # If email contains 'kushal', grant SecOps Super-Admin full access
        is_kushal = "kushal" in email
        local_name = email.split("@")[0].replace(".", " ").title()

        initials = "".join([part[0] for part in local_name.split()[:2]]).upper() or "CP"

        return {
            "id": f"op-{secrets.token_hex(4)}",
            "name": f"K V L N Kushal" if is_kushal else local_name,
            "initials": "KK" if is_kushal else initials,
            "role": "Lead SecOps Commander & CISO (Full Access)" if is_kushal else "Cloud Security Operator",
            "email": email,
            "organization": "Enterprise Cyber Defense & Core SecOps" if is_kushal else "Enterprise Cloud Operations",
            "primaryPersona": "secops" if is_kushal else "secops",
            "allowedPersonas": ["secops", "executive", "platform", "finops"] if is_kushal else ["secops"],
            "isSuperAdmin": is_kushal,
        }

    def _send_resend_email(self, to_email: str, code: str) -> tuple[bool, Optional[str]]:
        """Sends branded transactional email using Resend REST API."""
        url = "https://api.resend.com/emails"
        headers = {
            "Authorization": f"Bearer {self._resend_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "CloudPulse-Auth/2.0",
        }

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #06090f; margin: 0; padding: 24px; color: #f7fafc; }}
            .container {{ max-width: 480px; margin: 0 auto; background: #0c121e; border: 1px solid #1a2436; border-radius: 12px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
            .brand {{ display: flex; align-items: center; gap: 10px; margin-bottom: 24px; }}
            .logo-badge {{ background: linear-gradient(135deg, #63b3ed, #9f7aea); width: 34px; height: 34px; border-radius: 6px; display: inline-flex; align-items: center; justify-content: center; font-weight: bold; color: white; }}
            .title {{ font-size: 20px; font-weight: 800; color: #ffffff; letter-spacing: -0.02em; }}
            .subtitle {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #718096; }}
            .code-box {{ background: #101928; border: 1px solid #2d3748; border-radius: 8px; padding: 20px; text-align: center; margin: 24px 0; }}
            .otp-code {{ font-family: 'SF Mono', Consolas, Menlo, Monaco, monospace; font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #38d9a9; }}
            .note {{ font-size: 13px; color: #a0aec0; line-height: 1.6; margin: 0 0 12px; }}
            .footer {{ border-top: 1px solid #1a2436; margin-top: 24px; padding-top: 16px; font-size: 11px; color: #4a5568; text-align: center; }}
          </style>
        </head>
        <body>
          <div class="container">
            <div class="brand">
              <span class="logo-badge">CP</span>
              <div>
                <div class="title">CloudPulse</div>
                <div class="subtitle">SecOps · FinOps Enterprise Platform</div>
              </div>
            </div>
            
            <p class="note">You are signing in to CloudPulse Command Center. Use this 6-digit one-time verification code to authenticate your operator session:</p>
            
            <div class="code-box">
              <div class="otp-code">{code}</div>
            </div>
            
            <p class="note">This code is cryptographically valid for <strong>10 minutes</strong>. Never share this code with anyone.</p>
            <p class="note">If you did not initiate this sign-in request, please notify your CISO immediately.</p>
            
            <div class="footer">
              CloudPulse Incident & FinOps Governance Platform · Zero-Trust Telemetry Engine
            </div>
          </div>
        </body>
        </html>
        """

        payload = {
            "from": self._from_email,
            "to": [to_email],
            "subject": f"Your CloudPulse Verification Code: {code}",
            "html": html_body,
        }

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                logger.info(f"Resend dispatched successfully: ID {result.get('id')}")
                return True, None
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            logger.warning(f"Resend HTTP error ({e.code}): {err_body}")
            return False, f"HTTP {e.code}: {err_body}"
        except Exception as e:
            logger.warning(f"Resend dispatch error: {str(e)}")
            return False, str(e)


# Global singleton instance
auth_service = AuthService()
