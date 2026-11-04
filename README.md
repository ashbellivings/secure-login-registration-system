# Secure User Authentication System Using Full-Stack Web Technologies

A complete, beginner-friendly cybersecurity internship demonstration project implementing a secure user registration and login system with cryptographic password hashing, input validation, authenticated server-side sessions, protected dashboard access control, and automated security verification.

---

## 1. Project Overview

In web applications, user authentication is the frontline defense against unauthorized access, credential stuffing, and data breaches. Flaws in authentication mechanisms (such as storing passwords in plaintext, using weak hashing, or trusting client-side tokens without server verification) consistently rank among the most severe security vulnerabilities (e.g., OWASP Top 10 A01: Broken Access Control and A07: Identification and Authentication Failures).

This project demonstrates how to build and audit a defense-in-depth authentication system using full-stack web technologies:
- **Frontend**: Vanilla HTML5, CSS3, and JavaScript (no heavy frameworks, emphasizing direct DOM security and clear form flows).
- **Backend**: Node.js and Express.js REST API executing all security-critical operations server-side.
- **Database**: MongoDB with Mongoose object data modeling and unique indexes.
- **Password Security**: Salted, adaptive Bcrypt password hashing (work factor 12).
- **Session Security**: Server-side session management backed by MongoDB (`connect-mongo`) with `HttpOnly` and `SameSite` cookies, plus session ID regeneration on login.
- **Verification Harness**: 17 automated security test cases checking input validation, cryptographic integrity, session invalidation, and access control.

---

## 2. Project Objectives

1. **Understand Fundamental Application Security Controls**: Implement controls for Confidentiality, Integrity, and Availability (CIA Triad).
2. **Master Password Protection Principles**: Learn why plaintext storage and reversible encryption are catastrophic vulnerabilities, and how salted adaptive hashing mitigates offline attacks.
3. **Differentiate Authentication from Authorization**: Verify that authenticating an identity does not automatically grant permissions, and ensure server-side access control checks occur on every protected endpoint.
4. **Prevent Common Web Vulnerabilities**:
   - Insecure Direct Object References (IDOR)
   - Cross-Site Scripting (XSS) credential theft (via `HttpOnly` cookies)
   - Cross-Site Request Forgery (CSRF)
   - Session Fixation
   - User Enumeration & Timing Attacks
   - Automated Brute-Force Password Guessing
5. **Produce Audit-Ready Evidence**: Provide concrete evidence (hashes, HTTP status codes, headers, and automated test logs) suitable for an IT security evaluation or internship defense.

---

## 3. Features Implemented

- **Secure User Registration (`/register.html` & `POST /api/register`)**:
  - Full Name, Email, and Password collection with show/hide password visibility toggle.
  - Client-side usability checks and independent backend security validation.
  - Normalization of email addresses to lowercase and trimmed strings.
  - Password policy enforcement: minimum 8 characters, maximum 72 characters (preventing Bcrypt silent truncation).
  - Uniqueness validation via Mongoose schema and unique MongoDB index.
  - Bcrypt salt generation and password hashing prior to database persistence.
  - Safe API responses returning zero password hashes or internal database details.

- **Defensive User Login (`/login.html` & `POST /api/login`)**:
  - Email and password verification against stored Bcrypt hashes.
  - Constant-time dummy comparison for non-existent users to eliminate timing attacks.
  - Generic error messages ("Invalid email or password") preventing user enumeration.
  - Rate limiting via sliding window (20 attempts / 15 minutes) to deter automated brute-force attacks.
  - Session identifier regeneration (`req.session.regenerate()`) to eliminate session fixation risks.
  - Cookie issuance with `HttpOnly`, `SameSite=Lax`, and `path=/`.

- **Protected User Dashboard (`/dashboard.html` & `GET /api/profile`)**:
  - Strict server-side authorization check (`requireAuth` middleware).
  - Identity derived exclusively from verified session state; browser-supplied IDs are never trusted.
  - Returns HTTP 401 Unauthorized for missing or invalid sessions and redirects unauthenticated users.
  - Interactive "Live Access Control Probe" demonstrating server-side rejection of uncredentialed requests.

- **Secure Logout Flow (`POST /api/logout`)**:
  - Server-side destruction of the active session record in MongoDB.
  - Explicit client cookie clearance via `res.clearCookie('connect.sid')`.
  - Invalidation verified: old session cannot access protected endpoints upon refresh or replay.

- **Security Controls Documentation & Audit Portal (`/security-controls.html`)**:
  - Control-Evidence-Testing guides for 15+ core security controls.
  - Live inspection endpoint (`GET /api/security/audit-info`) providing real database counts and masked hash evidence.

- **Automated Security Test Runner (`/test-runner.html` & CLI `npm test`)**:
  - 17 automated security test cases verifying input validation, Bcrypt hashes, timing defense, IDOR prevention, and session lifecycles.

---

## 4. Technologies Used and Rationale

| Technology | Role | Why It Was Chosen |
|---|---|---|
| **Node.js (v22)** | Runtime Environment | High-performance asynchronous runtime enabling secure backend request pipelines and modular package integration. |
| **Express.js (v4.21)** | Web Framework | Lightweight, unopinionated framework providing granular control over middleware order, security headers, sessions, and routing. |
| **MongoDB & Mongoose** | Database & ODM | Document-oriented database providing schema validation, type safety, and unique index constraints (`index: true`, `unique: true`). |
| **Bcrypt (bcryptjs)** | Password Hashing | Battle-tested implementation of Bruce Schneier & Niels Provos's adaptive hashing algorithm with built-in salting and work factor configuration. |
| **express-session** | Session Management | Proven server-side session middleware storing state in a centralized store rather than client-side `localStorage`. |
| **connect-mongo** | Persistent Session Store | Stores active session tokens in MongoDB, ensuring sessions survive server restarts and support scalable multi-instance deployments. |
| **Helmet** | HTTP Security Headers | Automatically sets critical browser defense headers (Content-Security-Policy, X-Content-Type-Options: nosniff, Frameguard, removes X-Powered-By). |
| **express-rate-limit** | Request Throttling | Mitigates credential stuffing, password spray attacks, and Denial-of-Service (DoS) abuse on sensitive endpoints. |
| **HTML5, CSS3 & Vanilla JS** | Frontend | Standard web technologies providing pure DOM control without abstraction layers, illustrating how secure cookies and CSRF tokens work natively. |

---

## 5. Application Architecture

```
                              [ Browser / Client ]
                                        │
                         HTTPS / SameSite HttpOnly Cookie
                                        │
                                        ▼
                             [ Helmet Security Headers ]
                                        │
                             [ Global & Auth Rate Limiter ]
                                        │
                            [ Request Body Parsers (10KB) ]
                                        │
                     [ Express Session + connect-mongo Store ]
                                        │
       ┌────────────────────────────────┴────────────────────────────────┐
       │                                                                 │
       ▼                                                                 ▼
[ Public Auth Routes ]                                        [ Protected Routes ]
- POST /api/register                                          - GET /api/profile
  └─ Validate input                                             └─ requireAuth Middleware
  └─ Bcrypt hash (rounds: 12)                                        └─ Extract req.session.userId
  └─ Save to MongoDB                                                 └─ Query User by ID (Server)
- POST /api/login                                                    └─ Return user profile (No hash)
  └─ Validate credentials
  └─ Bcrypt compare (constant-time)
  └─ req.session.regenerate()
  └─ Save session to MongoDB
- POST /api/logout
  └─ req.session.destroy()
  └─ res.clearCookie('connect.sid')
       │                                                                 │
       └────────────────────────────────┬────────────────────────────────┘
                                        │
                                        ▼
                                [ MongoDB Database ]
                                ├── Collection: users (unique index on email, passwordHash)
                                └── Collection: sessions (MongoDB-backed active sessions)
```

---

## 6. Registration and Login Workflow

### A. Registration Workflow
1. **User Input**: User submits Full Name, Email, and Password on `/register.html`.
2. **Client Usability Check**: Frontend JavaScript validates format and displays real-time checklist feedback.
3. **Transmission**: Payload is dispatched as a JSON `POST` request to `/api/register`.
4. **Backend Security Validation**: Server independently verifies:
   - Presence of name (2–50 chars).
   - Valid RFC 5322 email syntax (normalized to lowercase).
   - Password length between 8 and 72 characters.
5. **Duplicate Check**: Database is queried for existing email. If found, HTTP 409 Conflict is returned with a generic message.
6. **Salt & Hash**: Bcrypt generates a random 128-bit salt and computes the hash with 12 cost rounds (`$2a$12$...`).
7. **Storage**: The new document is persisted to the `users` collection containing `name`, `email`, and `passwordHash`.
8. **Response**: HTTP 201 Created is returned with safe user metadata. The password hash is stripped.

### B. Login Workflow
1. **User Input**: User submits Email and Password on `/login.html`.
2. **Transmission**: Dispatched as `POST /api/login`.
3. **Lookup**: Server queries `users` collection by normalized email.
4. **Side-Channel Mitigation**: If the user does not exist, a pre-computed dummy Bcrypt comparison is executed to guarantee constant execution time.
5. **Hash Verification**: `bcrypt.compare(password, user.passwordHash)` verifies whether the password matches the stored hash.
6. **Credential Rejection**: If invalid, HTTP 401 Unauthorized is returned with generic message: *"Invalid email or password"*.
7. **Session Fixation Defense**: Upon valid credentials, `req.session.regenerate()` discards the pre-login session ID and allocates a fresh identifier.
8. **Session Persistence**: User ID is stored in the session record inside MongoDB (`sessions` collection).
9. **Cookie Transmission**: The server returns HTTP 200 OK along with a `Set-Cookie: connect.sid=...; HttpOnly; SameSite=Lax; Path=/` header.

---

## 7. Password Hashing vs Reversible Encryption

| Criterion | Password Hashing (Bcrypt) | Reversible Encryption (AES/RSA) |
|---|---|---|
| **Mathematical Nature** | One-Way Mathematical Function | Two-Way Mathematical Algorithm |
| **Reversibility** | Impossible to reverse back to plaintext | Can be decrypted back to plaintext if the secret key is known |
| **Salting** | Unique 128-bit random salt per user prevents rainbow table lookups | Requires IV (Initialization Vector) but relies primarily on key secrecy |
| **Work Factor (Cost)** | Configurable iteration count (work factor 12 = 4,096 iterations) slows down hardware-accelerated brute forcing | Designed to be fast for bulk data throughput (vulnerable to fast cracking) |
| **Security Suitability** | **Standard of Care for Passwords** | **Unacceptable for Passwords** (compromise of the key exposes all user passwords) |

---

## 8. Authentication vs Authorization

- **Authentication ("Who are you?")**: The process of verifying a claimed identity (e.g., verifying that a user knows the password associated with an email address).
- **Authorization ("What are you allowed to do?")**: The process of determining whether an authenticated user has permission to access a specific resource or execute an operation.

**Implementation in this application**:
- Authentication is handled during `/api/login` by verifying Bcrypt hashes and issuing a session cookie.
- Authorization is enforced by the `requireAuth` middleware on `/api/profile`. It does not rely on any parameter supplied by the client (such as `?userId=...` or `{ "userId": "..." }`). Instead, it extracts `req.session.userId` directly from the validated server session in MongoDB. This eliminates **Insecure Direct Object Reference (IDOR)** vulnerabilities.

---

## 9. API Endpoint Documentation

| Method | Endpoint | Access | Purpose | Expected Status Codes |
|---|---|---|---|---|
| `POST` | `/api/register` | Public (Rate-limited) | Register a new user account with Bcrypt password hashing | `201` Created<br>`400` Bad Request<br>`409` Conflict<br>`429` Rate Limited |
| `POST` | `/api/login` | Public (Rate-limited) | Verify credentials and establish server session | `200` OK<br>`400` Bad Request<br>`401` Unauthorized<br>`429` Rate Limited |
| `GET` | `/api/profile` | Protected (Session required) | Retrieve current user's profile information | `200` OK<br>`401` Unauthorized |
| `POST` | `/api/logout` | Session | Destroy active server session and clear cookie | `200` OK |
| `GET` | `/api/auth/status` | Public | Check if current client request holds an active session | `200` OK |
| `GET` | `/api/csrf-token` | Public | Obtain session-bound CSRF token | `200` OK |
| `GET` | `/api/security/audit-info` | Public | Retrieve active security controls and masked hash evidence | `200` OK |
| `POST` | `/api/security/run-automated-tests` | Public | Execute 17 automated security test cases against running backend | `200` OK |

---

## 10. Prerequisites & Installation

### Prerequisites
- **Node.js**: Version 18.x or higher (Node.js 22 LTS recommended).
- **npm**: Version 9.x or higher.
- **MongoDB**: Optional for local execution (the system includes an automatic embedded `MongoMemoryServer` that starts if no remote MongoDB URI is configured).

### Installation Steps

1. **Clone or Download the Project**:
   ```bash
   git clone <repository-url>
   cd secure-authentication-system
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Configure Environment Variables**:
   Copy the example environment configuration:
   ```bash
   cp .env.example .env
   ```

   Edit `.env` as appropriate:
   ```env
   NODE_ENV=development
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/secure_auth_system
   SESSION_SECRET=a-very-long-and-cryptographically-secure-random-secret-key-32chars
   BCRYPT_SALT_ROUNDS=12
   ```
   *(Note: If `MONGODB_URI` is left blank or cannot connect, the application automatically launches an embedded in-memory MongoDB instance for immediate demonstration!)*

4. **Start the Application**:
   ```bash
   npm run dev
   ```
   Or for production:
   ```bash
   npm start
   ```

5. **Open in Browser**:
   Navigate to: `http://localhost:3000`

---

## 11. Running Automated Tests

Run the CLI automated test harness:
```bash
npm test
```

Or execute tests interactively in the web browser:
1. Start the server (`npm run dev`).
2. Navigate to `http://localhost:3000/test-runner.html`.
3. Click **"Run All 17 Security Tests"**.
4. Review the real-time test table showing HTTP statuses, tested controls, and cryptographic evidence.

---

## 12. Security Controls Implemented

1. **Cryptographic Password Hashing**: Salted Bcrypt work factor 12.
2. **Timing Attack & Enumeration Defense**: Constant-time dummy compares on non-existent users; generic 401 error messages.
3. **Mandatory Server-Side Access Control**: Protected endpoints derive identity from verified sessions, defeating IDOR.
4. **Session Fixation Defense**: Session identifier regenerated upon successful authentication.
5. **Secure Cookie Configuration**: `HttpOnly: true` (prevents XSS cookie theft), `SameSite: Lax` (mitigates CSRF).
6. **Session Termination**: Server-side session record destruction on logout + cookie clearance.
7. **Rate Limiting**: Throttling authentication endpoints to 20 attempts per 15-minute window.
8. **Input Validation & Normalization**: RFC 5322 email syntax validation, string trimming, lowercase normalization, password length bounding (8–72 characters).
9. **HTTP Security Headers**: Helmet middleware enforcing CSP, `nosniff`, `SAMEORIGIN`, and eliminating `X-Powered-By`.
10. **Information Disclosure Prevention**: Centralized error handler stripping stack traces and internal database errors.
11. **Secret Management**: Environment variables loaded via `dotenv`; `.gitignore` excludes `.env`.
12. **Database Integrity**: Unique email indexes on MongoDB collections preventing duplicate account collisions.

---

## 13. Known Limitations and Future Improvements

1. **Multi-Factor Authentication (MFA/2FA)**: Future versions could implement TOTP (Time-Based One-Time Passwords via authenticator apps) or WebAuthn/FIDO2 hardware security keys.
2. **Account Lockout & CAPTCHA**: Currently, rate limiting throttles requests per IP address. In enterprise production, introducing progressive CAPTCHA challenges (e.g., Cloudflare Turnstile) after repeated failures would further improve protection.
3. **Password Breach Checking**: Integrating the HaveIBeenPwned k-Anonymity API to prevent users from selecting known compromised passwords.
4. **Email Verification**: Integrating an SMTP service to send cryptographically signed verification tokens prior to account activation.

---

## 14. Screenshot Placeholders

- `[Screenshot 1: Landing Page & Security Overview]`
- `[Screenshot 2: User Registration with Live Password Policy Feedback]`
- `[Screenshot 3: User Login with Generic Error Defense]`
- `[Screenshot 4: Protected User Dashboard with Live Access Control Probe]`
- `[Screenshot 5: Security Controls Audit Portal with Live Database Evidence]`
- `[Screenshot 6: 17/17 Automated Security Tests Passing in Verification Harness]`

---

## 15. Disclaimer

*This application is an educational prototype engineered for academic cybersecurity demonstrations, internship defense presentations, and IT security control evaluations. It has not undergone a formal third-party penetration test or commercial audit. Do not deploy to production with default secrets or unencrypted HTTP channels.*
