# Authentication Feature — Developer-Ready Specification (Web + Mobile)

## Compact Summary
A secure, responsive authentication system covering: login (email/password, SSO, or mobile+OTP), first-time sign-up (email or mobile), email verification before password set, optional mobile OTP flows, password reset, and a password visibility toggle. Deliverables include UI wireframes, React reference UI code snippets, REST JSON API design with examples, PostgreSQL schema (with tokens/OTPs), sequence diagrams, security/validation rules, acceptance criteria, accessibility guidance, and test cases. Defaults: Argon2id hashing, Access JWT 15m, Refresh 30d, Email token TTL 24h, OTP TTL 5m, password ≥ 10 chars.

---

## 1) UI Specification & Wireframes

### 1.1 Screen List
- **Login**: Logo, Email + Password, "Show password" toggle, SSO button(s), "Sign in with mobile (OTP)", link to Sign up, Forgot password.
- **Sign-up**: Email or Mobile, Name (first/last), Email verification step (separate screen), "Set password" after email verified.
- **Email Verification**: Enter verification code OR magic link confirmation page.
- **Mobile OTP**: Request OTP (enter mobile), then Verify OTP (6 digits), optional resend with cooldown.
- **Forgot Password**: Request reset (email), and Reset screen (new password + confirm) after token link.

### 1.2 Layout & Placement Guidance
- **Logo placeholder**: top-center, fixed-size box (e.g., 120×120 on desktop, 72×72 on mobile); supports dark/light.
- **Password visibility icon**: right end of password input, accessible toggle button (aria-pressed) with eye/eye-off icon.
- **Forgot password**: right-aligned link below password field.
- **Error banners**: above form; inline field errors below inputs.
- **Primary button**: full-width on mobile; labeled with action (e.g., "Sign in").

### 1.3 Wireframes (ASCII)
**Desktop — Login**
```
┌─────────────────────────────────────────────────────────────────────┐
│                              [ Company Logo ]                       │
│                                                                     │
│  Email ---------------------------------------------------------    │
│  Password ------------------------------------------- [👁 toggle]   │
│  [ Sign in ]                                                        │
│  (Forgot password?)                                 (Sign up)       │
│                                                                     │
│  ── or ─────────────────────────────────────────────────────────    │
│  [ Continue with Google ]  [ Continue with Microsoft ]              │
│  [ Sign in with Mobile OTP ]                                       │
└─────────────────────────────────────────────────────────────────────┘
```

**Mobile — Login**
```
[ Logo ]
Email [______________]
Password [________👁]
[ Sign in ]
Forgot password?   Sign up
── or ──
[ Google ] [ Microsoft ]
[ Mobile OTP ]
```

**Sign-up (Step 1: Choose email or mobile)**
```
[ Logo ]
Full name [____________________]
Email [________________________]    (or)   Mobile [+91 ______________]
[ Continue ]
Small: "We’ll send a verification to your email or an OTP to your phone."
```

**Email Verification (Step 2)**
```
We sent a link to <you@example.com>
[ Resend email ] (cooldown 60s)
[ I’ll verify later ]
```
If using a code: `Enter 6-digit code: [_] [_] [_] [_] [_] [_]  [ Verify ]`

**Set Password (Step 3)**
```
New password [_____________ 👁]
Confirm     [_____________ 👁]
[ Save & Continue ]
```

**Mobile OTP (Sign up / Sign in)**
```
Mobile [+91 ____________]   [ Get OTP ]
Enter OTP: [_][_][_][_][_][_]  (00:59)
[ Verify ]   [ Resend OTP ] (disabled during cooldown)
```

**Forgot Password**
```
Enter email to reset: [________________]
[ Send reset link ]
```
Reset page (from emailed link): New password + confirm + Save.

### 1.4 Visual & Responsive Guidance
- Inputs: 44px min height, 16px text, 4px corner radius (mobile 48px touch targets).
- Color contrast: WCAG AA (4.5:1 for text, 3:1 for large text/icons). Error color with sufficient contrast & clear messaging.
- Focus states: visible outlines for keyboard users.
- Loading: spinners on submit; disable form to avoid duplicate submissions.

---

## 2) React Reference UI (TypeScript + Tailwind) — Minimal Components
> Independent of specific state mgmt; swap API URLs.

### 2.1 Folder Sketch
```
src/
  components/
    AuthLayout.tsx
    PasswordInput.tsx
  pages/
    Login.tsx
    Signup.tsx
    VerifyEmail.tsx
    ForgotPassword.tsx
    OtpLogin.tsx
  lib/api.ts
  App.tsx
```

### 2.2 Shared Components
```tsx
// src/components/AuthLayout.tsx
import React from 'react';
export default function AuthLayout({ title, children }: {title:string; children:React.ReactNode}) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
      <div className="w-full max-w-md bg-white shadow-lg rounded-2xl p-8">
        <div className="flex flex-col items-center mb-6">
          <div className="h-20 w-20 bg-gray-200 rounded-xl mb-3" aria-label="Company logo placeholder" />
          <h1 className="text-xl font-semibold">{title}</h1>
        </div>
        {children}
      </div>
    </div>
  );
}

// src/components/PasswordInput.tsx
import React from 'react';
export function PasswordInput({value,onChange,name,placeholder}:{value:string;onChange:(v:string)=>void;name:string;placeholder?:string;}){
  const [visible,setVisible]=React.useState(false);
  return (
    <div className="relative">
      <input
        type={visible?"text":"password"}
        name={name}
        placeholder={placeholder||"Password"}
        value={value}
        onChange={e=>onChange(e.target.value)}
        className="w-full border rounded-lg px-3 py-3 pr-10 focus:outline-none focus:ring"
        aria-describedby={`${name}-hint`}
      />
      <button
        type="button"
        onClick={()=>setVisible(v=>!v)}
        className="absolute right-2 top-1/2 -translate-y-1/2 p-2"
        aria-label={visible?"Hide password":"Show password"}
        aria-pressed={visible}
      >{visible?"🙈":"👁"}</button>
    </div>
  );
}
```

### 2.3 Pages (examples)
```tsx
// src/pages/Login.tsx
import React from 'react';
import AuthLayout from '../components/AuthLayout';
import { PasswordInput } from '../components/PasswordInput';
import { api } from '../lib/api';

export default function Login(){
  const [email,setEmail]=React.useState("");
  const [password,setPassword]=React.useState("");
  const [error,setError]=React.useState<string|null>(null);
  const [loading,setLoading]=React.useState(false);

  async function onSubmit(e:React.FormEvent){
    e.preventDefault(); setError(null); setLoading(true);
    try{
      const res = await api.post('/auth/login',{ email, password });
      // store tokens, redirect
    }catch(err:any){ setError(err.message||'Sign-in failed'); }
    finally{ setLoading(false); }
  }

  return (
    <AuthLayout title="Sign in">
      {error && <div role="alert" className="mb-3 text-sm text-red-700 bg-red-50 p-2 rounded">{error}</div>}
      <form onSubmit={onSubmit} className="space-y-4">
        <input type="email" className="w-full border rounded-lg px-3 py-3" placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)} required/>
        <PasswordInput name="password" value={password} onChange={setPassword} />
        <div className="flex items-center justify-between text-sm">
          <a href="/forgot" className="text-blue-600">Forgot password?</a>
          <a href="/signup" className="text-gray-600">Sign up</a>
        </div>
        <button disabled={loading} className="w-full rounded-lg bg-blue-600 text-white py-3 disabled:opacity-50">{loading? 'Signing in…':'Sign in'}</button>
      </form>
      <div className="my-4 flex items-center gap-3"><div className="flex-1 h-px bg-gray-200"/><span className="text-xs text-gray-500">or</span><div className="flex-1 h-px bg-gray-2 00"/></div>
      <div className="grid grid-cols-1 gap-2">
        <a href="/auth/sso/google" className="border rounded-lg py-2 text-center">Continue with Google</a>
        <a href="/otp" className="border rounded-lg py-2 text-center">Sign in with Mobile OTP</a>
      </div>
    </AuthLayout>
  );
}
```

```tsx
// src/pages/Signup.tsx
import React from 'react';
import AuthLayout from '../components/AuthLayout';
import { api } from '../lib/api';

export default function Signup(){
  const [name,setName]=React.useState("");
  const [email,setEmail]=React.useState("");
  const [mobile,setMobile]=React.useState("");
  const [error,setError]=React.useState<string|null>(null);
  const [ok,setOk]=React.useState(false);

  async function submit(e:React.FormEvent){
    e.preventDefault(); setError(null);
    try{
      const res=await api.post('/auth/register',{ name, email: email||undefined, mobile: mobile||undefined });
      setOk(true);
    }catch(err:any){ setError(err.message||'Sign-up failed'); }
  }

  if(ok){
    return (
      <AuthLayout title="Check your email / SMS">
        <p className="text-sm text-gray-700">We sent you a verification. Follow the link or enter the OTP to continue.</p>
        <a className="text-blue-600 text-sm" href="/verify-email">Enter verification code</a>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout title="Create your account">
      {error && <div role="alert" className="mb-3 text-sm text-red-700 bg-red-50 p-2 rounded">{error}</div>}
      <form onSubmit={submit} className="space-y-4">
        <input className="w-full border rounded-lg px-3 py-3" placeholder="Full name" value={name} onChange={e=>setName(e.target.value)} required/>
        <input className="w-full border rounded-lg px-3 py-3" placeholder="Email (or leave blank)" type="email" value={email} onChange={e=>setEmail(e.target.value)} />
        <input className="w-full border rounded-lg px-3 py-3" placeholder="Mobile (optional)" type="tel" value={mobile} onChange={e=>setMobile(e.target.value)} />
        <button className="w-full rounded-lg bg-blue-600 text-white py-3">Continue</button>
      </form>
    </AuthLayout>
  );
}
```

(Additional pages `VerifyEmail.tsx`, `OtpLogin.tsx`, `ForgotPassword.tsx` follow the same pattern; omitted for brevity.)

```ts
// src/lib/api.ts
export const api = {
  async post(path: string, body: any){
    const res = await fetch(path,{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    if(!res.ok){ throw new Error((await res.json()).error||res.statusText); }
    return res.json();
  }
}
```

---

## 3) User Journeys / Sequence Diagrams (ASCII)

### 3.1 First-time Sign-up via Email
```
User -> FE: Submit name+email
FE -> API: POST /auth/register {name,email}
API -> DB: create user {email_verified=false}
API -> Email: send verification link (token=EVT)
API -> FE: 200 {message}
User -> Email: click link with EVT
FE -> API: POST /auth/verify-email {token:EVT}
API -> DB: mark email_verified=true; allow set-password
User -> FE: Set password
FE -> API: POST /auth/set-password {email,new_password}
API -> DB: store hash; issue tokens
API -> FE: 200 {access,refresh}
```

### 3.2 First-time Sign-up via Mobile OTP
```
User -> FE: Enter name+mobile
FE -> API: POST /auth/register {name,mobile}
API -> DB: create user (mobile_unverified)
API -> SMS: send OTP (OTPC)
FE -> API: POST /auth/otp/verify {mobile, code:OTPC}
API -> DB: verify mobile; create account active; issue tokens OR prompt email add
```

### 3.3 Sign-in via Email/Password
```
User -> FE: email+password
FE -> API: POST /auth/login
API -> DB: check hash; enforce lockout/rate limit
API -> FE: 200 {access,refresh} OR 401 {error}
```

### 3.4 Sign-in via SSO (High-level)
```
User -> FE: Click "Continue with <IdP>"
FE -> IdP: Redirect to authorization endpoint
IdP -> FE: Redirect back with code
FE -> API: GET /auth/sso/callback?code=...
API -> IdP: POST token exchange -> userinfo
API -> DB: upsert user + sso_identity; issue tokens
API -> FE: 200 {access,refresh}
```

### 3.5 Forgot-password Reset Flow
```
User -> FE: submit email
FE -> API: POST /auth/password/reset-request
API -> Email: send link (token=RPT, TTL 30m)
User -> FE: open link; set new password
FE -> API: POST /auth/password/reset-confirm {token,new_password}
API -> DB: invalidate token; store hash
API -> FE: 200 {message}
```

---

## 4) Backend JSON API (Language-agnostic)
**Base URL:** `/auth/...`  
**Content-Type:** `application/json`  
**Auth:** Access JWT (15m) + Refresh JWT (30d) — default values; changeable.

### 4.1 Register (email or mobile)
`POST /auth/register`
```json
{
  "name": "Ada Lovelace",
  "email": "ada@example.com",
  "mobile": "+919876543210"
}
```
**201**
```json
{ "message": "If email provided, we sent a verification link. If mobile provided, we sent an OTP." }
```
**409** `{ "error": "Email already in use" }`

### 4.2 Send Email Verification (resend)
`POST /auth/verify-email/send`
```json
{ "email": "ada@example.com" }
```
**200** `{ "message": "Verification email sent" }`

### 4.3 Verify Email (token)
`POST /auth/verify-email`
```json
{ "token": "EVT_abc123" }
```
**200** `{ "message": "Email verified. You may set a password now." }`  
**400/410** `{ "error": "Invalid or expired token" }`

### 4.4 Set Password (post-verification)
`POST /auth/set-password`
```json
{ "email": "ada@example.com", "password": "correct-horse-battery-staple" }
```
**200** `{ "access": "jwt...", "refresh": "jwt..." }`

### 4.5 Login (email/password)
`POST /auth/login`
```json
{ "email": "ada@example.com", "password": "••••••••" }
```
**200** `{ "access": "jwt...", "refresh": "jwt..." }`  
**401** `{ "error": "Invalid credentials" }`  
**423** `{ "error": "Account locked. Try again in 15 minutes." }`

### 4.6 OTP — Request
`POST /auth/otp/request`
```json
{ "mobile": "+919876543210" }
```
**200** `{ "message": "OTP sent" }`  
**429** `{ "error": "Too many requests. Try later." }`

### 4.7 OTP — Verify (Sign in or complete sign-up)
`POST /auth/otp/verify`
```json
{ "mobile": "+919876543210", "code": "123456" }
```
**200** `{ "access": "jwt...", "refresh": "jwt..." }`  
**400** `{ "error": "Invalid or expired OTP" }`

### 4.8 SSO Callback (OIDC/OAuth2)
`GET /auth/sso/callback?code=...&state=...`  
**200** `{ "access": "jwt...", "refresh": "jwt..." }`  
**400** `{ "error": "SSO validation failed" }`

### 4.9 Forgot Password — Request
`POST /auth/password/reset-request`
```json
{ "email": "ada@example.com" }
```
**200** `{ "message": "If that email exists, a reset link is sent." }`

### 4.10 Forgot Password — Confirm
`POST /auth/password/reset-confirm`
```json
{ "token": "RPT_xyz", "new_password": "new-strong-pass" }
```
**200** `{ "message": "Password updated" }`  
**400/410** `{ "error": "Invalid or expired token" }`

### 4.11 Token Refresh (optional)
`POST /auth/token/refresh`
```json
{ "refresh": "jwt..." }
```
**200** `{ "access": "jwt..." }`

**Error Model (example)**
```json
{ "error": "<human-readable>", "code": "<MACHINE_CODE>", "details": {}}
```

---

## 5) Database Schema (PostgreSQL)

### 5.1 Tables
- **users** — core profile & auth flags
- **email_verification_tokens** — one-time, TTL 24h
- **password_reset_tokens** — one-time, TTL 30m
- **otp_codes** — phone OTP (max attempts, TTL 5m)
- **sso_identities** — mapping to IdP subject
- **refresh_tokens** (optional if rotating refresh)

### 5.2 SQL
```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  email CITEXT UNIQUE,
  mobile TEXT UNIQUE,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  mobile_verified BOOLEAN NOT NULL DEFAULT FALSE,
  password_hash TEXT, -- null until set
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at TIMESTAMPTZ,
  failed_login_attempts INT NOT NULL DEFAULT 0,
  lockout_until TIMESTAMPTZ
);

CREATE TABLE email_verification_tokens (
  token TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);

CREATE TABLE password_reset_tokens (
  token TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);

CREATE TABLE otp_codes (
  id SERIAL PRIMARY KEY,
  mobile TEXT NOT NULL,
  code CHAR(6) NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('signup','login')),
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 5,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  consumed_at TIMESTAMPTZ
);

CREATE INDEX ON otp_codes (mobile);
CREATE INDEX ON otp_codes (expires_at);

CREATE TABLE sso_identities (
  id SERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  UNIQUE (provider, subject)
);

CREATE TABLE refresh_tokens (
  token TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);

-- Example record
INSERT INTO users (name, email, email_verified) VALUES
('Ada Lovelace', 'ada@example.com', false);
```

**Notes**
- Use `CITEXT` extension for case-insensitive emails (or normalize to lowercase).
- Store phone numbers E.164 format (`+<country><number>`). Add check constraints if needed.
- Rotate refresh tokens; store only hashes if treating them as secrets.

---

## 6) Security, Validation, Operational Rules

### 6.1 Password Policy (defaults; changeable)
- **Length ≥ 10**, at least **1 letter** and **1 number**.
- Block top 10k leaked passwords (use a denylist/Pwned Passwords API — optional).
- Encourage passphrases; no mandatory special chars to reduce user friction.

### 6.2 Hashing & Sessions
- **Argon2id** (t=2, m=64MB, p=1) preferred; else **bcrypt** cost=12.
- **JWT**: Access 15 minutes; Refresh 30 days (httpOnly, Secure cookies on web; or Authorization header in mobile).
- Include `jti`, `iat`, `exp`, `sub`; audience/issuer claims set.
- CSRF: if using cookies, protect with SameSite=Lax/Strict + CSRF token on state-changing calls.

### 6.3 Email Verification Token
- Random 128-bit token, base64url; **TTL 24h**; single-use; store hashed version.

### 6.4 OTP Rules
- 6-digit numeric; **TTL 5 minutes**; max **5 attempts**, then invalidate.
- Resend cooldown **60s**; cap **5 OTPs per 30 minutes** per mobile.
- Store last-4 digits masked in logs.

### 6.5 Brute-force & Abuse Protections
- Rate-limit `/auth/login` by IP and by account (e.g., 5/min); exponential backoff.
- Lock account for **15 minutes** after **5** failed attempts; show generic error.
- Add reCAPTCHA/hCaptcha after multiple failures (optional).
- Log security events: register, verify, login success/failure, reset requests, token refresh, SSO link.

### 6.6 Transport & Secrets
- Enforce HTTPS/HSTS. Sign JWTs with strong keys; rotate keys. Secrets in vault (no hardcoding).

---

## 7) Implementation Notes & Pseudocode

### 7.1 Create User & Send Verification Email (Node/Express-style)
```js
// POST /auth/register
async function register(req,res){
  const { name, email, mobile } = req.body;
  // validate
  // check uniqueness
  const user = await db.users.insert({ name, email: email?.toLowerCase(), mobile });
  if(email){
    const token = randomToken();
    await db.email_tokens.insert({ tokenHash: hash(token), user_id: user.id, expires_at: now()+24h });
    await mail.send(email, makeVerifyEmailLink(token));
  }
  if(mobile){ await sendOtp(mobile,'signup'); }
  return res.status(201).json({ message: 'If email provided, we sent a verification link. If mobile provided, we sent an OTP.' });
}
```

### 7.2 Verify Email Token & Enable Password Set
```js
// POST /auth/verify-email
async function verifyEmail(req,res){
  const { token } = req.body;
  const row = await db.email_tokens.findValidByHash(hash(token));
  if(!row) return res.status(400).json({error:'Invalid or expired token'});
  await db.tx(async t=>{
    await t.users.update(row.user_id,{ email_verified:true });
    await t.email_tokens.consume(row.token);
  });
  res.json({ message:'Email verified. You may set a password now.' });
}
```

### 7.3 Generate & Validate OTP
```js
async function sendOtp(mobile,purpose){
  enforceRateLimit(mobile);
  const code = (Math.floor(100000+Math.random()*900000)).toString();
  await db.otp.insert({ mobile, code, purpose, expires_at: now()+5m });
  await sms.send(mobile, `Your code is ${code}. Expires in 5 minutes.`);
}

// POST /auth/otp/verify
async function verifyOtp(req,res){
  const { mobile, code } = req.body;
  const row = await db.otp.findLatestValid(mobile);
  if(!row || row.expires_at < now() || row.consumed_at) return res.status(400).json({error:'Invalid or expired OTP'});
  if(row.attempts+1 > row.max_attempts) return res.status(400).json({error:'Too many attempts'});
  await db.otp.incrementAttempts(row.id);
  if(row.code !== code) return res.status(400).json({error:'Invalid or expired OTP'});
  await db.otp.consume(row.id);
  const user = await upsertUserByMobile(mobile);
  const tokens = issueTokens(user.id);
  return res.json(tokens);
}
```

### 7.4 Login Validation
```js
// POST /auth/login
async function login(req,res){
  const { email, password } = req.body;
  const user = await db.users.findByEmail(email.toLowerCase());
  if(!user) return res.status(401).json({error:'Invalid credentials'});
  if(user.lockout_until && user.lockout_until>now()) return res.status(423).json({error:'Account locked. Try again in 15 minutes.'});
  const ok = await verifyPassword(password, user.password_hash);
  if(!ok){ await recordFailed(user); return res.status(401).json({error:'Invalid credentials'}); }
  await clearFailures(user);
  const tokens = issueTokens(user.id);
  res.json(tokens);
}
```

---

## 8) UX Microcopy & Validation Messages
- **Email**: "Enter a valid email address"
- **Mobile**: "Enter a valid mobile number (e.g., +91 98765 43210)"
- **Name**: "Please enter your full name"
- **Password**: "Password must be at least 10 characters and include a letter and a number"
- **Sign-in error**: "Invalid email or password"
- **Locked**: "Too many attempts. Try again in 15 minutes"
- **Verification sent**: "Check your inbox for a verification link"
- **OTP sent**: "We sent a 6‑digit code via SMS"
- **OTP expired**: "Your code expired. Request a new one"
- **Reset link sent**: "If that email exists, we sent a reset link"
- **Password updated**: "Your password has been updated"

---

## 9) Acceptance Criteria & Test Cases

### 9.1 Sign-up via Email (Happy Path)
- Register returns 201 and sends a verification email.
- Verification token usable once within 24h; after use, `email_verified=true`.
- After verify, user can set password that meets policy; receives tokens.

**Edge cases**: duplicate email → 409; invalid token → 400; expired token → 410; resend limited by rate limits.

### 9.2 Sign-up via Mobile OTP
- Register with mobile sends OTP; verifying within 5m creates/activates user and returns tokens.
- Max 5 attempts; after that returns appropriate error.

**Edge cases**: wrong OTP; expired OTP; too many OTP requests → 429; phone already used → 409.

### 9.3 Login (Email/Password)
- Valid creds → 200 + tokens; updates `last_login_at`.
- 5 failed attempts → account locked 15m; returns 423.

**Edge cases**: unverified email → 403 (if policy blocks sign-in before verify); rate-limit by IP.

### 9.4 SSO
- Clicking SSO redirects to IdP; callback exchanges code; user is created/linked if first time; tokens issued.

**Edge cases**: state mismatch → 400; token exchange failure → 400; email collision → link to existing account flow.

### 9.5 Forgot Password
- Request always returns 200 (don’t leak existence); valid token within 30m allows password reset once.

**Edge cases**: expired/used token → 410; weak password → 400; reuse of token → 410.

---

## 10) Accessibility & Visual Guidance
- Place **Logo** centered above form; provide `alt` text (or `aria-label` if decorative).
- **Forgot password** link: right-aligned under password input.
- **Password toggle**: button inside input at trailing end; `aria-label` toggles; preserve input type for screen readers; ensure 44×44 px target.
- Labels: visible labels or `aria-labelledby`. Inputs must have accessible names.
- Announce errors via `role="alert"`; link focus rings visible.
- Contrast and spacing per WCAG AA; test high-contrast mode.

---

## 11) OIDC/OAuth2 Integration Template (High-level)

### Provider Config
- **Authorization Endpoint**: `https://idp/authorize`
- **Token Endpoint**: `https://idp/token`
- **UserInfo Endpoint**: `https://idp/userinfo`
- **Client ID/Secret**: from IdP
- **Redirect URI**: `https://app.example.com/auth/sso/callback`
- **Scopes**: `openid email profile`

### Backend Steps
1. Generate `state` + `code_verifier` (PKCE); store hashed `code_verifier` server-side.
2. Redirect user to Authorization Endpoint with `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `code_challenge`.
3. On callback, validate `state`; exchange `code` + `code_verifier` at Token Endpoint.
4. Fetch `userinfo`; upsert user; persist `provider+subject` mapping.
5. Issue app JWTs; set cookies or return in JSON.

---

## 12) Optional Enhancements (clearly optional)
- **MFA (TOTP/SMS)** after password sign-in.
- **CAPTCHA** on suspicious traffic.
- **Device/session management** page (revoke refresh tokens).
- **Email magic links** for passwordless sign-in.

---

## 13) Example Validation (JSON Schema fragments)
```json
// POST /auth/register
{
  "type":"object",
  "properties":{
    "name": {"type":"string","minLength":1},
    "email": {"type":"string","format":"email"},
    "mobile": {"type":"string","pattern":"^\\+[1-9]\\d{7,14}$"}
  },
  "anyOf":[{"required":["email"]},{"required":["mobile"]}],
  "additionalProperties": false
}
```

---

## 14) Minimal Password Reset Email (Example)
Subject: `Reset your password`  
Body: `Click this link to reset your password: https://app.example.com/reset?token=RPT_xyz (expires in 30 minutes). If you didn’t request this, ignore this email.`

---

## 15) Non-functional Requirements
- P99 auth latency < 500ms (excluding 3rd‑party providers).
- High availability for token endpoints; idempotent resend endpoints.
- Observability: metrics for success/failure rates, OTP send/verify, email send success rates.

---

## 16) Ready-to-Change Defaults (clearly marked)
- **Password min length**: 10 (changeable)
- **Access JWT TTL**: 15m (changeable)
- **Refresh JWT TTL**: 30d (changeable)
- **Email token TTL**: 24h (changeable)
- **OTP TTL**: 5m (changeable)
- **Lockout**: 5 failed → 15m (changeable)

---

## 17) Quick Start Checklist (Dev Team)
- [ ] Create DB & run schema migrations
- [ ] Set SMTP + SMS providers (and sandbox modes)
- [ ] Configure OIDC client + redirect URIs
- [ ] Implement API per endpoints
- [ ] Wire React pages to API
- [ ] Add rate limiting + logging
- [ ] Ship end-to-end tests (flows above)
- [ ] Accessibility audit and contrast check

