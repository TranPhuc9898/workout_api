---
type: red-team-review
lens: security-adversary
plan: plans/260702-facebook-login-oauth
pass: 2
date: 2026-07-03
reviewer: code-reviewer (rt2-security)
---

# Red-Team Pass 2 — Security Adversary — B7 Facebook Login (OAuth)

Hostile review of the restructured plan (Path 2 self-bootstrap + JWKS verify + `accessToken`→`identityToken` rename). Extra scrutiny on flaws introduced by the 2026-07-03 restructure. The prior accepted finding (no auto-link by email → `409 EMAIL_LINK_REQUIRED` + password-confirm) is NOT re-litigated; it is verified present in Phase 3.

## Fact-Check & Contract Verification (verification role)

| Claim (plan) | Result | Evidence |
|---|---|---|
| Repo is bare `nest new` skeleton, 0 Prisma/auth/.env/git commits | VERIFIED | `git log` → "does not have any commits yet"; `ls .env*` → no matches; `prisma/` absent; `package.json` deps = only `@nestjs/{common,core,platform-express}`, `reflect-metadata`, `rxjs` |
| No consumer calls `/auth/facebook` (rename `accessToken`→`identityToken` is contract-safe) | VERIFIED | `grep -rn "auth/facebook\|identityToken\|fetch(" src/features/vfit` (my-expo-app) → 0 hits; FE `facebook-login-button.tsx` makes no backend call |
| `FACEBOOK_APP_ID=1548957553621793` sourced from `my-expo-app/.env` | VERIFIED | `my-expo-app/.env:1` `FACEBOOK_APP_ID=1548957553621793` |
| FE produces Limited-Login JWT (not classic access token) | VERIFIED | `facebook-login-button.tsx:63` `AuthenticationToken.getAuthenticationTokenIOS()`; decodes JWT locally |
| Real token claims = iss `https://www.facebook.com`, aud `1548957553621793`, sub, email, name, picture (string), exp | VERIFIED | brainstorm report `260703-...-mismatch.md:45-52` |
| Token also carries `nonce` + `at_hash` claims | VERIFIED | same report line 52: `"iat":..., "exp":..., "nonce":"...", "at_hash":"..."` |
| App Secret not needed for JWKS verify | VERIFIED | Meta docs: JWKS verify needs only appId (aud) |
| Phase 4 success criteria use `pnpm test` | FAILED (inconsistency) | repo is npm-based (all other phases `npm install`; `package.json` scripts use `jest` via `npm`) — `pnpm` is wrong runner |

Contract note (not a finding): request DTO field is `identityToken` but the **response** stays `{ accessToken: jwt }` (Phase 3 architecture). Intentional asymmetry; the future FE wiring phase must send `identityToken`, read `accessToken`.

---

## Finding 1: Meta-required `nonce` verification is omitted → token replay
- **Severity:** High
- **Location:** Phase 2, "Requirements" / "Architecture" (`verifyIdentityToken`)
- **Flaw:** Meta's official Limited-Login validation requires checking that "the nonce matches the nonce you provided." The plan verifies only `iss`/`aud`/`exp`/signature and never checks `nonce`. The FE (`facebook-login-button.tsx:57`) calls `LoginManager.logInWithPermissions(['public_profile','email'])` with no `LoginConfiguration` nonce, so no server-issued nonce is bound to the token.
- **Failure scenario:** An `identityToken` captured anywhere (TLS-terminating proxy, device/app log, a malicious SDK) can be replayed against `POST /auth/facebook` by any party until `exp`, minting a valid system JWT (7-day) for the victim's account. There is zero binding between the token and the requesting client.
- **Evidence:** Plan Phase 2:17 lists only `iss`/`aud`/`exp`; Architecture `jwtVerify(identityToken, JWKS, { issuer, audience })` has no `nonce`. Real token contains a nonce claim: `260703-...-mismatch.md:52`. Meta docs (search): "check ... that the nonce matches the nonce you provided." FE sends no nonce: `facebook-login-button.tsx:57`.
- **Suggested fix:** Add a nonce round-trip: backend issues a short-lived server nonce, FE passes it via `LoginConfiguration(nonce:)`, backend verifies `payload.nonce` equals the issued value (one-time, TTL). Capture this as an explicit requirement in the (out-of-scope) FE wiring phase so the backend contract isn't finalized without it. At minimum, document replay exposure as an accepted risk with a hard cap on system-JWT lifetime.

## Finding 2: `P2002`-on-email refetch bypasses `409 EMAIL_LINK_REQUIRED` and logs the Facebook user into an existing password account
- **Severity:** High
- **Location:** Phase 3, "Architecture" — `findOrCreateFacebookUser` catch block
- **Flaw:** The whole plan's security control is: email matches an existing account → do NOT auto-link, return `409 EMAIL_LINK_REQUIRED` (requires password). But the create-race catch does `if (target.includes('email')) return prisma.user.findUniqueOrThrow({ where: { email: profile.email! } })` — it **returns the email-owner's user record**, which the controller then signs a JWT for. This silently links/logs-in without any password confirmation — the exact hijack the 409 control exists to prevent.
- **Failure scenario:** A password-only user with email X exists (or is created between the pre-check SELECT and the INSERT). A Facebook login whose claim `email == X` hits the pre-check window, the INSERT fails `P2002` on `email`, the catch returns user X, and `signToken(X.id)` issues a full session for the password account — no password ever verified. Trigger window is narrow (race / concurrent creation) but the branch defeats a Critical control and is plainly inconsistent with the branch 30 lines above that throws `409` for the identical condition.
- **Evidence:** Plan Phase 3:56-59 (non-race email match) throws `ConflictException({ code: 'EMAIL_LINK_REQUIRED' })`; Phase 3:71 (race path) instead `return prisma.user.findUniqueOrThrow({ where: { email: profile.email! } })`. Two contradictory behaviors for the same precondition.
- **Suggested fix:** On `P2002` with `target.includes('email')`, throw the same `ConflictException({ code: 'EMAIL_LINK_REQUIRED', email })` — never return/log-in. Only the `facebookId` target is safe to refetch-and-return (same identity).

## Finding 3: `.env.test` is NOT gitignored → test DB credentials committed to git
- **Severity:** High
- **Location:** Phase 4, "Related Code Files" (`Create: .env.test`) + Phase 1 gitignore checklist gap
- **Flaw:** Phase 4 creates `.env.test` holding `DATABASE_URL_TEST` (a Postgres connection string incl. password). The repo `.gitignore` ignores `.env`, `.env.*.local` variants — but **not** `.env.test`. Phase 1's verification step only checks that `.env` is ignored, giving false assurance. First commit of this repo (currently 0 commits) would bake the test DB password into history.
- **Failure scenario:** Developer runs `git add . && git commit` after Phase 4; `.env.test` with DB credentials enters git history permanently. Even a placeholder becomes a habit that leaks when someone points `.env.test` at a shared/staging DB.
- **Evidence:** `git check-ignore .env .env.example .env.test` → prints only `.env` (so `.env.test` is tracked). `.gitignore` tail contains `.env`, `.env.test.local`, `.env.local` — no bare `.env.test`. Phase 1:68/step-8 checks only `.env`.
- **Suggested fix:** Add `.env.test` (and `.env.*` except `.env.example`) to `.gitignore` in Phase 1; make Phase 1's success criterion assert `git check-ignore .env.test` passes. Prefer injecting `DATABASE_URL_TEST` via CI env rather than a committed-adjacent file.

## Finding 4: `JWT_SECRET` read via `process.env` in synchronous `JwtModule.register` — init-order fragility + no presence/strength validation
- **Severity:** Medium
- **Location:** Phase 3, "Implementation Steps" step 2 / Architecture
- **Flaw:** `JwtModule.register({ secret: process.env.JWT_SECRET, ... })` evaluates `process.env.JWT_SECRET` at module-metadata (import) time. If `ConfigModule.forRoot()` (which loads dotenv into `process.env`) hasn't executed first, the secret is `undefined`. There is also no validation that `JWT_SECRET` exists and is high-entropy.
- **Failure scenario:** Depending on module import order, tokens get signed with `undefined`/empty secret (forgeable by anyone) or the app throws opaquely at first sign. A weak dev secret silently carried to prod lets an attacker forge system JWTs (`{ sub }`) for any user id.
- **Evidence:** Plan Phase 3:33 comment and step 2: `JwtModule.register({ secret: process.env.JWT_SECRET, signOptions: { expiresIn: '7d' } })`. No env-validation step in any phase (`grep` of plan for `Joi`/`validationSchema`/min-length → none).
- **Suggested fix:** Use `JwtModule.registerAsync({ inject: [ConfigService], useFactory })` and validate `JWT_SECRET` at boot (`@nestjs/config` `validationSchema`, require length ≥ 32). Fail startup if missing.

## Finding 5: `linkFacebookAccount` does not guard `profile.email == null` before `findUnique({ where: { email } })` → 500 on direct call
- **Severity:** Medium
- **Location:** Phase 3, "Architecture" — `linkFacebookAccount` first query
- **Flaw:** `link-confirm` is a directly-callable public endpoint. `linkFacebookAccount` immediately runs `prisma.user.findUnique({ where: { email: profile.email } })`. Phase 2 explicitly maps a missing email claim to `null`. Prisma `findUnique` on a unique field with `null` throws a validation error (not a clean domain error).
- **Failure scenario:** Attacker (or a legit user who denied the `email` permission) POSTs a valid token with no email claim to `/auth/facebook/link-confirm`. `profile.email` is `null` → Prisma throws → unhandled 500 (error boundary violation on external input; noisy, and leaks a stack trace if not filtered).
- **Evidence:** Plan Phase 3:90 `where: { email: profile.email }`; Phase 2:41 `email: (payload.email as string) ?? null`. No null-guard between them.
- **Suggested fix:** At the top of `linkFacebookAccount` (and/or in the DTO/controller), reject when `profile.email` is null with a clean `400/409` before any query.

## Finding 6: `jwtVerify` does not pin `algorithms` (no `RS256` allowlist)
- **Severity:** Medium
- **Location:** Phase 2, "Architecture" (`jwtVerify` options)
- **Flaw:** The verify call passes only `{ issuer, audience }` and no `algorithms: ['RS256']`. `jose` derives the alg from the resolved JWK and rejects `alg: none`, so exploitability is low — but pinning the expected asymmetric algorithm is standard OIDC hardening and cheap.
- **Failure scenario:** Defense-in-depth gap: if Facebook's JWKS ever serves a key type/alg the code doesn't expect, or a future refactor swaps key material, an unpinned verifier accepts a wider set than intended. Belt-and-suspenders against alg-substitution.
- **Evidence:** Plan Phase 2:32-35 `jwtVerify(identityToken, JWKS, { issuer, audience })` — no `algorithms`.
- **Suggested fix:** Add `algorithms: ['RS256']` to the `jwtVerify` options (Facebook signs RS256).

## Finding 7: No rate-limiting on `/auth/facebook/link-confirm` password check
- **Severity:** Medium
- **Location:** Phase 3, `POST /auth/facebook/link-confirm` (`linkFacebookAccount` → `bcrypt.compare`)
- **Flaw:** The link-confirm endpoint is an unauthenticated password-verification oracle (`bcrypt.compare`) with no throttling/lockout in the plan. `@nestjs/throttler` is not mentioned in any phase.
- **Failure scenario:** Online password brute-force against a target account. Real-world exploitability is reduced because the attacker needs a Facebook token whose `email` claim equals the victim's email (Facebook only issues tokens with the holder's own verified email), so this is defense-in-depth rather than a wide-open oracle — but the control is absent and the endpoint gates account-takeover.
- **Evidence:** Plan Phase 3:100 `bcrypt.compare(password, user.passwordHash)`; no `throttler`/rate-limit in Phases 1-4 (`grep -i throttle` of plan → none).
- **Suggested fix:** Apply `@nestjs/throttler` (tight limit per IP + per email) to `link-confirm`, and consider a per-account failed-attempt counter.

---

## Summary (severity-ordered)
- High: (1) missing `nonce` verification → replay; (2) `P2002`-email refetch bypasses `EMAIL_LINK_REQUIRED`; (3) `.env.test` not gitignored → committed test DB creds.
- Medium: (4) `JWT_SECRET` init-order + no validation; (5) null-email 500 in link-confirm; (6) unpinned JWKS algorithms; (7) no throttling on link-confirm.
- Not re-litigated: no-auto-link / `409 EMAIL_LINK_REQUIRED` control — verified present and correct in Phase 3 for the non-race branch.
