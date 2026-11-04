# Cybersecurity Internship Guide: Application Security Controls Explanation

**Document Purpose**: This document provides an audit-ready breakdown of the 15 core application security controls implemented in the *Secure User Authentication System*. It is formatted specifically for cybersecurity interns, IT compliance analysts, and junior penetration testers preparing for technical reviews, GRC evaluations, or internship defense presentations.

Each section follows the standardized **Control – Purpose – Risk – Implementation – Testing – Evidence – Limitations** format.

---

## 1. Password Hashing

- **What the Control Is**: A one-way cryptographic transformation that converts plaintext passwords into fixed-length cryptographic hashes using the Bcrypt algorithm with an adaptive work factor (cost factor 12) and an automatically generated 128-bit pseudo-random salt.
- **Why It Is Required**: Plaintext passwords in database storage are completely exposed if an attacker achieves unauthorized database read access (via SQL/NoSQL injection, backup theft, or compromised credentials).
- **What Risk It Addresses**:
  - Offline dictionary attacks
  - Pre-computed rainbow table lookups
  - Massive credential exposure in the event of a database breach
- **Where It Is Implemented**:
  - `routes/authRoutes.ts` line 104 (`await bcrypt.hash(password, BCRYPT_SALT_ROUNDS)`)
  - `models/User.ts` (Mongoose schema stores `passwordHash: String`, zero plaintext password fields)
- **How It Can Be Tested**:
  - Register an account with a known password (e.g., `SuperSecret123!`).
  - Query the database record in MongoDB.
  - Verify that the stored value is an irreversible hash string starting with `$2a$12$` or `$2b$12$` and that `SuperSecret123!` appears nowhere in the database.
- **What Evidence an Auditor Could Collect**:
  - MongoDB document screenshot showing the `passwordHash` field: e.g. `$2b$12$6K1t1Ad64NdSqWvoXdpFn...`
  - Automated test log for Test 1.6 & Test 5.1 in `tests/testRunner.ts`.
- **What Limitations Remain**:
  - Bcrypt does not prevent users from choosing weak, easily guessable passwords (e.g. `password123`). Password policy rules and breach checking must complement hashing.

---

## 2. Authentication & Timing Attack Defense

- **What the Control Is**: The verification of claimed identity during login by comparing submitted credentials against the stored Bcrypt hash using `bcrypt.compare()`, supplemented with a pre-computed dummy comparison for non-existent users.
- **Why It Is Required**: Standard database lookups that return early when a user is not found take significantly less time (~1ms) than hashing a password (~250ms). Attackers use network latency timing differences (side-channel timing attacks) to enumerate valid email addresses.
- **What Risk It Addresses**:
  - Unauthorized system access / Account takeover
  - Side-channel timing attacks
  - User account enumeration
- **Where It Is Implemented**:
  - `routes/authRoutes.ts` lines 155–186 (`DUMMY_HASH`, `bcrypt.compare()`, generic 401 response).
- **How It Can Be Tested**:
  - Send login requests for an existing email with a wrong password, and for a non-existent email.
  - Measure response durations; observe that both take approximately the same time (~200–300ms) and return identical error messages: `"Invalid email or password."`
- **What Evidence an Auditor Could Collect**:
  - HTTP 401 response payloads showing uniform error messages.
  - Test logs for Tests 2.1, 2.2, and 2.3 in `tests/testRunner.ts`.
- **What Limitations Remain**:
  - Without Multi-Factor Authentication (MFA), compromised credentials still allow successful authentication.

---

## 3. Server-Side Authorization & Access Control

- **What the Control Is**: Mandatory backend middleware (`requireAuth`) that evaluates whether an active, valid server-side session exists before permitting access to protected resources (`/api/profile`).
- **Why It Is Required**: Frontend security checks (such as hiding a dashboard button with CSS or JavaScript) can easily be bypassed by opening browser DevTools or sending HTTP requests via curl or Postman.
- **What Risk It Addresses**:
  - Insecure Direct Object References (IDOR / BOLA)
  - Broken Object Level Authorization (OWASP Top 10 A01)
  - Unauthorized data exposure
- **Where It Is Implemented**:
  - `middleware/authentication.ts` lines 23–52 (`requireAuth` middleware)
  - `routes/profileRoutes.ts` line 12 (`router.get('/', requireAuth, ...)`)
- **How It Can Be Tested**:
  - Send `GET /api/profile` without session cookies (or click "Simulate Unauthenticated Probe" on `/dashboard.html`).
  - Observe immediate HTTP 401 Unauthorized rejection.
  - Append query parameters such as `?userId=654321` while authenticated; observe that the server ignores the query and strictly returns the profile belonging to `req.session.userId`.
- **What Evidence an Auditor Could Collect**:
  - Network logs proving that an uncredentialed `curl -i http://localhost:3000/api/profile` returns HTTP 401.
  - Automated test results for Tests 3.1, 3.2, and 3.3.
- **What Limitations Remain**:
  - Currently implements single-tier user authorization. Multi-tenant or Role-Based Access Control (RBAC) with granular roles (Admin, Auditor, User) would be required for complex enterprise systems.

---

## 4. Input Validation & Data Normalization

- **What the Control Is**: Multi-layered validation that inspects all incoming data on the backend before processing, enforcing type checks, RFC 5322 email syntax, string length bounds (name: 2–50 chars; password: 8–72 chars), and string trimming.
- **Why It Is Required**: Never trust client-side input. Malformed, excessively large, or unexpected inputs can cause Denial of Service (DoS), database crashes, or exploitation. Bcrypt specifically truncates inputs longer than 72 bytes; failing to reject passwords > 72 characters causes silent truncation vulnerabilities.
- **What Risk It Addresses**:
  - Denial of Service via buffer stuffing
  - Bcrypt silent truncation bypasses
  - Corrupted database state / malformed records
- **Where It Is Implemented**:
  - `routes/authRoutes.ts` lines 42–95 (presence, regex, length constraints)
  - `models/User.ts` (Mongoose schema validation)
- **How It Can Be Tested**:
  - Submit registration requests with empty names, invalid emails (e.g. `bademail`), and passwords with length < 8 or > 72.
  - Confirm backend returns HTTP 400 Bad Request with descriptive, safe error messages.
- **What Evidence an Auditor Could Collect**:
  - HTTP 400 response bodies for Tests 1.1 through 1.5 in the automated test runner.
- **What Limitations Remain**:
  - Does not currently check against dictionary password blocklists (e.g. HaveIBeenPwned).

---

## 5. Server-Side Session Management

- **What the Control Is**: Stateful session handling using `express-session` coupled with a MongoDB session store (`connect-mongo`), issuing a session identifier to the client while storing session data on the backend.
- **Why It Is Required**: Stateless tokens stored in browser `localStorage` (such as JWTs) are completely exposed to malicious JavaScript during any Cross-Site Scripting (XSS) compromise.
- **What Risk It Addresses**:
  - Token theft via XSS
  - Inability to revoke active sessions immediately upon account compromise
- **Where It Is Implemented**:
  - `server.ts` lines 58–75 (`express-session` with `MongoStore.create()`)
  - MongoDB `sessions` collection
- **How It Can Be Tested**:
  - Log in; inspect MongoDB `sessions` collection using Mongo Shell or Compass.
  - Verify that a document exists containing the serialized session and expiration timestamp.
- **What Evidence an Auditor Could Collect**:
  - Screenshot of the `sessions` collection in MongoDB.
  - Absence of any session tokens or passwords in browser `localStorage`.
- **What Limitations Remain**:
  - Requires database write operations on session creation and touch events.

---

## 6. Session Fixation Mitigation (Session Regeneration)

- **What the Control Is**: Regenerating the session identifier (`req.session.regenerate()`) immediately upon successful credential verification.
- **Why It Is Required**: In session fixation attacks, an attacker obtains a valid session identifier and tricks a victim into authenticating with it (e.g. via a malicious link). If the application retains the same session ID after login, the attacker can hijack the victim's authenticated session.
- **What Risk It Addresses**:
  - Session Fixation (CWE-384)
- **Where It Is Implemented**:
  - `routes/authRoutes.ts` lines 191–217 (`req.session.regenerate(...)`)
- **How It Can Be Tested**:
  - Note the `connect.sid` cookie before logging in.
  - Submit valid login credentials.
  - Observe that the server returns a `Set-Cookie` header containing a brand-new `connect.sid` value.
- **What Evidence an Auditor Could Collect**:
  - HTTP Network trace showing different session cookie values before and after `POST /api/login`.
  - Test 4.2 in `tests/testRunner.ts`.
- **What Limitations Remain**:
  - Does not invalidate other active concurrent sessions from different devices unless explicitly programmed.

---

## 7. Secure Cookie Configuration (`HttpOnly`, `SameSite`, `Secure`)

- **What the Control Is**: Setting protective security flags on the session cookie:
  - `HttpOnly: true` (disallows JavaScript access via `document.cookie`)
  - `SameSite: 'Lax'` (restricts cross-site cookie transmission)
  - `Secure: true` (restricts transmission to encrypted HTTPS connections in production)
- **Why It Is Required**: Prevents script-based session exfiltration during XSS incidents, and provides baseline defense against Cross-Site Request Forgery (CSRF).
- **What Risk It Addresses**:
  - Session hijacking via Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Man-in-the-Middle (MitM) cookie interception over unencrypted HTTP
- **Where It Is Implemented**:
  - `server.ts` lines 67–73 (`cookie: { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 3600000 }`)
- **How It Can Be Tested**:
  - Open browser DevTools Console and execute `console.log(document.cookie)`.
  - Observe that `connect.sid` is completely absent.
- **What Evidence an Auditor Could Collect**:
  - DevTools Network tab showing `Set-Cookie: connect.sid=...; Path=/; HttpOnly; SameSite=Lax`.
- **What Limitations Remain**:
  - `SameSite=Lax` allows cookies on top-level GET navigations; state-changing requests must never use GET methods.

---

## 8. Session Invalidation at Logout

- **What the Control Is**: Explicit destruction of the session record on the backend (`req.session.destroy()`) and client cookie removal (`res.clearCookie('connect.sid')`) during the logout request.
- **Why It Is Required**: Simply deleting a cookie on the client does not invalidate the session on the server. If an attacker captured the session token before logout, they could continue using it unless the server destroys the session.
- **What Risk It Addresses**:
  - Session replay attacks
  - Abandoned terminal hijacking (shared or public computers)
- **Where It Is Implemented**:
  - `routes/authRoutes.ts` lines 249–272 (`POST /api/logout`)
- **How It Can Be Tested**:
  - Log in, record the session cookie, and click "Sign Out".
  - Attempt to send `GET /api/profile` using the previously captured session cookie.
  - Verify that the server returns HTTP 401 Unauthorized because the session record was permanently destroyed in MongoDB.
- **What Evidence an Auditor Could Collect**:
  - Server MongoDB query showing the session document removed from the `sessions` collection.
  - Automated test log for Test 4.1.
- **What Limitations Remain**:
  - Dependent on the user actually clicking "Log Out" (mitigated by a 60-minute session TTL timeout).

---

## 9. Rate Limiting & Brute-Force Prevention

- **What the Control Is**: Throttling requests per IP address using a sliding window algorithm (`express-rate-limit`):
  - 20 requests per 15-minute window on `/api/login` and `/api/register`.
  - 200 requests per 15-minute window globally across `/api`.
- **Why It Is Required**: Automated bots can submit thousands of credential combinations per second. Rate limiting dramatically increases the time required for brute-force attacks, rendering dictionary attacks impractical.
- **What Risk It Addresses**:
  - Credential stuffing
  - Automated brute-force password guessing
  - Application-layer Denial-of-Service (DoS)
- **Where It Is Implemented**:
  - `middleware/security.ts` lines 6–28
  - `routes/authRoutes.ts` applied to `/register` and `/login`
- **How It Can Be Tested**:
  - Send 21 consecutive POST requests to `/api/login`.
  - Verify that request #21 is blocked with HTTP 429 Too Many Requests and header `Retry-After`.
- **What Evidence an Auditor Could Collect**:
  - HTTP 429 response trace with `RateLimit-Limit: 20` and `RateLimit-Remaining: 0`.
- **What Limitations Remain**:
  - IP-based rate limiting can affect multiple users sharing an egress NAT gateway/proxy, and sophisticated attackers can distribute requests across botnets with rotating IP addresses.

---

## 10. Secure Secrets Management

- **What the Control Is**: Storing configuration secrets (`MONGODB_URI`, `SESSION_SECRET`, `PORT`, `NODE_ENV`) in environment variables loaded at runtime, keeping secrets completely out of source code.
- **Why It Is Required**: Hardcoding database passwords or session signing secrets in git repositories leads to credential exposure when code is shared or pushed to public repositories.
- **What Risk It Addresses**:
  - Credential leakage via source code management (GitHub leaks)
  - Insecure default credentials
- **Where It Is Implemented**:
  - `.env.example` (template with placeholders)
  - `.gitignore` (excludes `.env*` while preserving `.env.example`)
  - `server.ts` & `config/database.ts` (retrieves values from `process.env`)
- **How It Can Be Tested**:
  - Execute `git status` or inspect repository commits to confirm `.env` is never tracked.
  - Verify that database connection logging masks passwords: `config/database.ts` sanitizes URIs to `//***:***@`.
- **What Evidence an Auditor Could Collect**:
  - Git repository commit history showing clean source code with zero hardcoded keys.
- **What Limitations Remain**:
  - Production deployments require secure key vaults (e.g. AWS Secrets Manager, Google Cloud Secret Manager) rather than unencrypted `.env` files on disk.

---

## 11. Database Access Controls & Data Protection at Rest

- **What the Control Is**: Segregating data models, enforcing unique constraints on the email field via MongoDB indexes, and stripping sensitive fields (`passwordHash`, `__v`) from API output serialization.
- **Why It Is Required**: Prevents duplicate account creation and eliminates accidental information disclosure where internal database attributes leak into API responses.
- **What Risk It Addresses**:
  - Account collision & race conditions
  - Information leakage (exposing password hashes to frontend clients)
- **Where It Is Implemented**:
  - `models/User.ts` lines 23–33 (`unique: true`, `index: true`)
  - `models/User.ts` lines 47–67 (`toJSON` and `toObject` transforms delete `passwordHash`)
- **How It Can Be Tested**:
  - Attempt to register two accounts with identical emails; verify second request fails with HTTP 409 Conflict.
  - Inspect the JSON response of `POST /api/register` and `GET /api/profile`; verify `passwordHash` is absent.
- **What Evidence an Auditor Could Collect**:
  - API response JSON payloads confirming absence of `passwordHash`.
  - MongoDB index list: `db.users.getIndexes()` showing `{ email: 1 }, { unique: true }`.
- **What Limitations Remain**:
  - Relies on application-level schema enforcement; database administrator credentials should be restricted to least-privilege roles in production.

---

## 12. Safe Centralized Error Handling

- **What the Control Is**: A single centralized Express error middleware that catches all unhandled exceptions, logs operational details safely on the server, and returns generic, sanitized JSON responses to clients.
- **Why It Is Required**: Default framework error handlers often dump full stack traces, source file paths, database query syntax, and connection parameters to the client, providing attackers with valuable reconnaissance data.
- **What Risk It Addresses**:
  - Information Disclosure / Reconnaissance (OWASP Top 10 A05)
  - Unhandled exception crashes
- **Where It Is Implemented**:
  - `middleware/errorHandler.ts`
  - `server.ts` line 102 (`app.use(errorHandler)`)
- **How It Can Be Tested**:
  - Send a POST request with malformed JSON syntax (e.g. `{ "email": `).
  - Verify server returns HTTP 400 with `{"success": false, "error": "Malformed JSON payload in request body."}` and no Node.js stack trace.
- **What Evidence an Auditor Could Collect**:
  - Response traces for malformed requests confirming clean JSON payloads without stack traces.
- **What Limitations Remain**:
  - Server logs must be monitored and forwarded to a secure Security Information and Event Management (SIEM) system in enterprise environments.

---

## 13. HTTP Security Headers (Helmet)

- **What the Control Is**: Integration of Helmet middleware to set industry-standard HTTP security headers:
  - `Content-Security-Policy` (CSP)
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - Removal of `X-Powered-By: Express`
- **Why It Is Required**: Directs browsers to restrict risky behavior such as executing unauthorized scripts, MIME-sniffing non-script files into executable contexts, or embedding the application inside malicious iframes (clickjacking).
- **What Risk It Addresses**:
  - Cross-Site Scripting (XSS)
  - Clickjacking
  - MIME-confusion attacks
  - Technology stack fingerprinting
- **Where It Is Implemented**:
  - `server.ts` lines 31–46 (`app.use(helmet(...))`)
- **How It Can Be Tested**:
  - Issue `curl -I http://localhost:3000` or inspect network headers in DevTools.
  - Verify that `x-content-type-options: nosniff` is present and `x-powered-by` is absent.
- **What Evidence an Auditor Could Collect**:
  - HTTP response header capture showing active security headers.
- **What Limitations Remain**:
  - Development mode allows `'unsafe-inline'` styles for Tailwind/Vite compatibility; production CSP should enforce strict cryptographic nonces or hashes.

---

## 14. CSRF Protection (Cross-Site Request Forgery)

- **What the Control Is**: Combining `SameSite=Lax` cookie policy with a session-bound CSRF token (`GET /api/csrf-token`) verified on state-changing operations via header `X-CSRF-Token`.
- **Why It Is Required**: Prevents malicious third-party websites from tricking an authenticated user's browser into submitting unauthorized requests to the application.
- **What Risk It Addresses**:
  - Cross-Site Request Forgery (CSRF)
- **Where It Is Implemented**:
  - `middleware/security.ts` lines 34–68 (`verifyCsrfToken`, `getOrCreateCsrfToken`)
  - `public/js/common.js` (automatically attaches `X-CSRF-Token` header)
- **How It Can Be Tested**:
  - Fetch `/api/csrf-token` to verify token generation.
  - Submit state-changing requests with and without valid `X-CSRF-Token` headers.
- **What Evidence an Auditor Could Collect**:
  - API response from `GET /api/csrf-token`.
- **What Limitations Remain**:
  - If Cross-Site Scripting (XSS) is present, attackers can steal the CSRF token from DOM memory. Defending against XSS is a prerequisite for CSRF defense.

---

## 15. Automated Security Verification & Audit Documentation

- **What the Control Is**: Comprehensive test harness (`tests/testRunner.ts`, CLI `npm test`, and web UI `/test-runner.html`) executing 17 automated tests verifying security assertions across all authentication and access control paths.
- **Why It Is Required**: Security controls degrade over time as code is modified. Continuous security testing provides regression protection and auditable evidence of control effectiveness.
- **What Risk It Addresses**:
  - Security regressions during code updates
  - Unverified or fabricated security claims
- **Where It Is Implemented**:
  - `tests/testRunner.ts` (core test definitions)
  - `tests/run-tests.ts` (CLI harness)
  - `public/test-runner.html` (interactive web UI)
- **How It Can Be Tested**:
  - Run `npm test` in the terminal or click "Run All 17 Security Tests" in the web application.
- **What Evidence an Auditor Could Collect**:
  - Terminal log output showing `17 tests passed, 0 tests failed`.
  - Markdown audit report exported from `/test-runner.html`.
- **What Limitations Remain**:
  - Automated unit/integration tests verify expected behavior; they do not replace human penetration testing or fuzz testing for zero-day vulnerabilities.

---

## Summary Matrix: CIA Triad & Control Mapping

| Security Control | Primary CIA Principle | Key OWASP Category | Verification Method |
|---|---|---|---|
| **Bcrypt Password Hashing** | Confidentiality | A02: Cryptographic Failures | Automated Test 1.6 & DB inspection |
| **Server-Side Access Control** | Confidentiality & Integrity | A01: Broken Access Control | Automated Test 3.1 & 3.3 |
| **Input Validation** | Integrity & Availability | A03: Injection | Automated Tests 1.1 – 1.5 |
| **Session Fixation Defense** | Confidentiality | A07: Identification Failures | Automated Test 4.2 |
| **HttpOnly Cookies** | Confidentiality | A03: Cross-Site Scripting | Browser Console Inspection |
| **Rate Limiting** | Availability | A04: Insecure Design | Automated Test 2.1 & HTTP 429 probe |
| **Safe Error Handling** | Confidentiality | A05: Security Misconfiguration | Malformed JSON probe |
| **Helmet Security Headers** | Integrity | A05: Security Misconfiguration | HTTP Header inspection |
| **Session Invalidation** | Confidentiality | A07: Identification Failures | Automated Test 4.1 |

*Prepared for academic cybersecurity internship demonstration and IT security control evaluation.*
