# Junie AI Assistant Guidelines

This file provides context for the Junie AI assistant (JetBrains) when contributing to OWASP Juice Shop.

**Important**: The primary authoritative source for all AI contributions is the [root AGENTS.md](../AGENTS.md). Please refer to that file for comprehensive guidelines, project overview, and shared skills.

**Skill Discovery**: Before performing any task, check if a matching skill exists by reading the `Skills` section of [AGENTS.md](../AGENTS.md). If a relevant skill is found, read and follow its `SKILL.md` from `.ai/skills/` before proceeding.

---

## Security Remediation Notes (Broken Authentication / OWASP A07:2021)

> These notes document a targeted Broken Authentication remediation applied to the backend, recorded here as a required project-guide deliverable. The same notes are mirrored in `.claude/CLAUDE.md`. **No existing test files were edited**; tests that assert the now-fixed vulnerable behavior are listed below as requiring updates.

### New dependency added
- **`bcryptjs`** (`^3.0.2`, runtime) and **`@types/bcryptjs`** (`^2.4.6`, dev) were added to `package.json`.
- Used for password hashing at **cost factor 12**, with comparison via **`bcrypt.compare()`**.
- **Rationale:** replaces the broken MD5 password hashing; pure-JS (no native build) and compatible with Node 22–26.
- The helpers **`hashPassword()`** / **`comparePassword()`** live in **`lib/insecurity.ts`**. (The legacy MD5 `hash()` helper is *retained* for non-authentication uses such as order IDs and email-display hashes.)

### Newly required environment variables
Documented with placeholder values in **`/.env.example`**:
- **`JWT_PRIVATE_KEY`** *(required)* — RSA private key used to sign session JWTs. **`JWT_PRIVATE_KEY_PATH`** is an optional file/path fallback so local/dev boots still succeed when the inline variable is unset.
- **`HMAC_SECRET`** *(required)* — secret for HMAC operations.
- **`ADMIN_PASSWORD`** *(optional)* — overrides the seeded admin password; falls back to the seed value when unset.
- **`COOKIE_SECRET`** *(optional)* — externalizes the cookie-parser secret.

These variables must be provisioned before/with deployment. The JWT key file/path fallback prevents local boot failure when the inline variable is absent.

### Summary of fixes
- **JWT hardening:** signing key externalized to the environment; `RS256` pinned at all verification sites; access-token lifetime reduced from **6h → 1h**.
- **Password hashing:** bcrypt cost-12 hashing and `bcrypt.compare()` on all password paths (model setter, login, change-password, 2FA).
- **Hardcoded secrets:** HMAC secret externalized to the environment (alongside the JWT signing key).
- **Account enumeration:** login and the security-question endpoint hardened to return a uniform message, response shape, and timing, so email existence cannot be inferred.
- **Token invalidation:** server-side logout (**`POST /rest/user/logout`**) added, backed by an in-memory token denylist enforced during verification.

### Existing tests requiring updates (NOT edited by this work)
These assert the now-fixed vulnerable behavior and must be updated separately:
- **Server unit:** `test/server/insecurity.unit.test.ts`, `test/server/verify.unit.test.ts`, `test/server/currentUser.unit.test.ts`, `test/server/saveLoginIp.unit.test.ts`
- **API:** `test/api/login.test.ts`, `test/api/password.test.ts`, `test/api/2fa.test.ts`, `test/api/authenticated-users.test.ts`, `test/api/user.test.ts`, `test/api/user-profile.test.ts`, `test/api/helpers/auth.ts`
- **Cypress E2E:** `test/cypress/e2e/login.spec.ts`, `test/cypress/e2e/changePassword.spec.ts`, `test/cypress/e2e/forgotPassword.spec.ts`, `test/cypress/e2e/passwordHashLeak.spec.ts`, `test/cypress/e2e/forgedJwt.spec.ts`, `test/cypress/e2e/register.spec.ts`, `test/cypress/e2e/totpSetup.spec.ts`

### CTF challenges neutralized by the fixes
OWASP Juice Shop is intentionally vulnerable; these fixes deliberately neutralize the corresponding challenges: **weak-password**, **change-password (Bender)**, **unsigned-JWT**, **forged-JWT**, **password-hash-leak**, and related login challenges. Recorded so reviewers understand the intended behavior change.

### Secrets-management note
No secret values are committed; `/.env.example` carries placeholders only, and production secrets must be supplied through the deployment environment.

### Review note
The change set is intentionally narrow and security-only, suitable for focused security review before deployment.
