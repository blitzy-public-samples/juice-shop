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
- **`JWT_PRIVATE_KEY`** *(required in production, wired)* — RSA private key (PEM; literal `\n` sequences are normalized) used to sign session JWTs. Read by `lib/insecurity.ts`. **`JWT_PRIVATE_KEY_PATH`** *(optional, wired)* points to a PEM file on disk instead; an uncommitted local `encryptionkeys/jwt.key` file is also honored if present. The verification public key is **always derived from the active private key** (`crypto.createPublicKey`), so any operator-supplied key is mutually consistent and the formerly-committed `encryptionkeys/jwt.pub` is no longer assumed to match the signing key. The original inline RSA private key has been **removed from source entirely**: when no key is configured the app **fails closed in production** (throws on startup) and, outside production only, generates a **throwaway ephemeral RSA key pair** (2048-bit, regenerated every boot, never the original secret) so local/dev/test still boot.
- **`HMAC_SECRET`** *(required in production, wired)* — secret for HMAC operations (security-answer hashing and the deluxe-membership token). Read by `lib/insecurity.ts` (`hmac()`). When unset the app **fails closed in production** (throws on startup); outside production it uses a throwaway random per-boot secret, except under `NODE_ENV==='test'` where a fixed test-only fixture value is used so deterministic test vectors still hold (see the secrets-management note below).

The two variables above are the only auth-related variables consumed by the current code. `JWT_PRIVATE_KEY` (or `JWT_PRIVATE_KEY_PATH`) and `HMAC_SECRET` **must be provisioned before/with any production deployment — production boot fails closed without them.** In local/dev/test runs they are optional: the ephemeral JWT key pair and the random/test-fixture HMAC secret described above keep boots working without committing any secret.

#### Documented placeholders — NOT wired in this checkpoint
The following entries appear in `/.env.example` as forward-looking placeholders only. **No current code reads them**, so they require no provisioning and changing them has no runtime effect today. They are documented so a future, separately scoped change can wire them up:
- **`ADMIN_PASSWORD`** *(optional, not yet wired)* — reserved to override the seeded admin password at deploy time. Not consumed by code: the seed value in `data/static/users.yml` (`admin123`) is still used as-is.
- **`COOKIE_SECRET`** *(optional, not yet wired)* — reserved to externalize the cookie-parser secret. Not consumed by code: `server.ts` still uses the in-source `cookieParser('kekse')` secret.

### Summary of fixes
- **JWT hardening:** the inline RSA signing key was **removed from source** and is now sourced only from the environment (`JWT_PRIVATE_KEY` / `JWT_PRIVATE_KEY_PATH` / an uncommitted local key file), with the verification public key **derived from the active private key**; production **fails closed** when no key is configured, while dev/test use a throwaway **ephemeral** key pair. `RS256` is pinned at all verification sites; access-token lifetime reduced from **6h → 1h**.
- **Password hashing:** bcrypt cost-12 hashing and `bcrypt.compare()` on all password paths (model setter, login, change-password, 2FA).
- **Hardcoded secrets:** the HMAC secret is sourced from `HMAC_SECRET`; production **fails closed** when it is unset, dev uses a random per-boot secret, and the former literal is retained only as a `NODE_ENV==='test'` gated fixture — so no committed secret is operative in production or default runtime.
- **Account enumeration:** login and the security-question endpoint hardened to return a uniform message, response shape, **and database access pattern/timing** — the security-question endpoint performs an identical `count()` + `findByPk()` lookup for registered and unregistered emails, returning a deterministic decoy `{ question }` for the latter — so email existence cannot be inferred from the body, status, query count, or latency.
- **Token invalidation:** server-side logout (**`POST /rest/user/logout`**) added, backed by an in-memory token denylist enforced during verification. Every authenticated-user **registry read path** (`get()` / `from()` / `appendUserId()`) now re-validates the token through the hardened `verify()` (signature + expiry + denylist) and evicts stale entries, so expired or logged-out tokens are rejected consistently at every registry-backed route, not only at `verify()`.

### New security test suites added by this work
Two new security test suites were added to validate the remediation (these are **new files**; no existing test files were modified):
- **`test/server/authSecurityFix.unit.test.ts`** — server unit coverage for `lib/insecurity.ts`: bcrypt cost-12 `hashPassword`/`comparePassword`, RS256-pinned `verify()` (rejecting `alg=none`, HS256-signed-with-the-public-key, expired, and denylisted tokens), the `invalidate()`/`isTokenBlocked` denylist, registry re-validation in `get()`/`from()`, the ≤ 1-hour `authorize()` lifetime, and the unique per-token `jti` nonce (so an immediate re-login after logout yields a fresh, non-denylisted token).
- **`test/api/authSecurityFix.test.ts`** — end-to-end API coverage: bcrypt login with generic failure messages, non-enumerating login/security-question responses, server-side logout token invalidation (including the `GET /rest/saveLoginIp` UI-logout path), change-password requiring the current password, API-layer rejection of forged/expired JWTs, the ≤ 1-hour token lifetime, and immediate relogin after logout (QA Issue #2).

### Existing tests requiring updates (NOT edited by this work)
These assert the now-fixed vulnerable behavior and must be updated separately:
- **Server unit:** `test/server/insecurity.unit.test.ts`, `test/server/verify.unit.test.ts`, `test/server/currentUser.unit.test.ts`, `test/server/saveLoginIp.unit.test.ts`
    - *Observed failing in a full `npm run test:server` run (349 pass / 6 fail), because they assert the now-fixed vulnerable behavior:* `insecurity.unit.test.ts` (`authenticatedUsers` "returns user by associated token" and "returns user by associated token from request" — these inject a fake token (`'11111'`) directly into the registry, which the hardened `get()` / `from()` now re-validate through `verify()` and reject); `verify.unit.test.ts` (`forgedFeedbackChallenge` — relies on a fake registry token `'token12345'` rejected by the same revalidation; and `jwtForgedChallenge` two sub-tests — hardcoded tokens HMAC-signed with the real `jwt.pub`, which no longer verify under the derived/ephemeral RS256 key). `currentUser.unit.test.ts` fails on a pre-existing fixture token that lacks an `exp` claim, independent of these fixes.
- **API:** `test/api/login.test.ts`, `test/api/password.test.ts`, `test/api/2fa.test.ts`, `test/api/authenticated-users.test.ts`, `test/api/user.test.ts`, `test/api/user-profile.test.ts`, `test/api/helpers/auth.ts`, `test/api/basket.test.ts`, `test/api/search.test.ts`, `test/api/security-question.test.ts`
    - *Observed failing in a full `npm run test:api` run (551 pass / 10 fail), because they assert the now-fixed vulnerable behavior:* `basket.test.ts` (`GET /rest/basket/:id` "should accept forged JWTs" — forged tokens are now rejected by RS256 pinning); `search.test.ts` (`GET /rest/products/search` UNION-SELECT that leaks the password-hash column — passwords are now bcrypt, so the asserted MD5 hash format no longer holds); `security-question.test.ts` (`GET /rest/user/security-question` "returns nothing for an unknown email address" — the endpoint now returns a deterministic decoy `{ question }` to prevent enumeration). The remaining observed failures fall under already-listed files: `login.test.ts` (SQL-injection login attacks), `password.test.ts` (change-password for Bender without the current password), and `authenticated-users.test.ts` (password column masked).
- **Cypress E2E:** `test/cypress/e2e/login.spec.ts`, `test/cypress/e2e/changePassword.spec.ts`, `test/cypress/e2e/forgotPassword.spec.ts`, `test/cypress/e2e/passwordHashLeak.spec.ts`, `test/cypress/e2e/forgedJwt.spec.ts`, `test/cypress/e2e/register.spec.ts`, `test/cypress/e2e/totpSetup.spec.ts`

### CTF challenges neutralized by the fixes
OWASP Juice Shop is intentionally vulnerable; these fixes deliberately neutralize the corresponding challenges: **weak-password**, **change-password (Bender)**, **unsigned-JWT**, **forged-JWT**, **password-hash-leak**, and related login challenges. Recorded so reviewers understand the intended behavior change.

### Secrets-management note
The original inline RSA private key has been **removed from source entirely**, and `/.env.example` carries placeholders only — so no JWT signing secret is committed. The one secret string still appearing in source is the former HMAC value in `lib/insecurity.ts` — used **solely as a `NODE_ENV==='test'` gated test fixture** (and quoted once in the adjacent `[SECURITY FIX]` annotation that documents this very change); it is **never used in production or default runtime**, where a missing `HMAC_SECRET` makes the app **fail closed**. In production no secret material is read from source at all: `JWT_PRIVATE_KEY` / `JWT_PRIVATE_KEY_PATH` and `HMAC_SECRET` must be supplied through the deployment environment, and the app refuses to start in production without them.

### Review note
The change set is intentionally narrow and security-only, suitable for focused security review before deployment.
