# Red-Team (Assumption Destroyer) — Plan Review Report

- **Date:** 2026-07-03
- **Reviewer role:** code-reviewer (hostile), Assumption Destroyer + Fact Checker + Contract Verifier
- **Plan:** `plans/260702-facebook-login-oauth/` (B7 Facebook Login, Path-2 vertical slice)
- **Repo state at review:** bare `nest new` skeleton, `yarn.lock` only, 0 git commits, no `prisma/`, no `.env`, no `src/auth/`. Docker **not installed** on machine. Node v22.21.1.

This is the SECOND red-team pass. The prior accepted decision (no auto-link by email; `409 EMAIL_LINK_REQUIRED` + `link-confirm`) is NOT re-litigated — except where I found it is *incompletely enforced* in the actual phase text (Finding 3).

---

## Fact Checker — sampled claims

| Claim (plan) | Result | Evidence |
|---|---|---|
| Repo has 0 Prisma / 0 auth lib / 0 `.env` / 0 git commit | VERIFIED | `package.json` deps = only `@nestjs/{common,core,platform-express}`, `reflect-metadata`, `rxjs`; `git log` → "does not have any commits yet"; no `prisma/`, no `.env*` |
| `FACEBOOK_APP_ID = 1548957553621793` matches FE app | VERIFIED | `my-expo-app/.env` contains `1548957553621793` (grep count 1) |
| Real JWT `iss = https://www.facebook.com`, `aud = 1548957553621793`, `picture` = flat string | VERIFIED | `my-expo-app/plans/260702-facebook-login-button/reports/260703-facebook-token-backend-verify-mismatch.md` "Update 2026-07-03" logged claims |
| DTO rename `accessToken`→`identityToken` has no consumers | VERIFIED | grep `identityToken\|accessToken\|/auth/facebook` in `my-expo-app/src` → 0 hits; backend has 0 code. Contract change is safe. |
| jose error classes `JWTExpired`/`JWTClaimValidationFailed`/`JWSSignatureVerificationFailed` | VERIFIED (names correct) | Correct jose export names; Phase 4 assertion of `JWTClaimValidationFailed` for aud mismatch is accurate — NOT a finding |
| `NSMotionUsageDescription`/config plugin claims | N/A | out of scope |

## Contract Verifier — `accessToken`→`identityToken`

Enumerated all callers across BOTH repos: `grep -rn "identityToken\|accessToken\|/auth/facebook"` in `my-expo-app/src` = 0; `workout-api/src` = 0 (no auth code exists). **Confirmed zero consumers** — rename is safe. FE `facebook-login-button.tsx` never calls any backend (`LoginManager.logOut()` in `finally`, no fetch). The plan's safety claim (plan.md:31) is accurate.

---

## Finding 1: Docker is not installed on the target machine — Phase 1 & 4 are dead on arrival
- **Severity:** Critical
- **Location:** Phase 1, "Implementation Steps" step 3 / "Success Criteria"; Phase 4, "Implementation Steps" step 3
- **Flaw:** The entire plan foundation assumes `docker compose up -d` works. Docker is not present on this machine at all.
- **Failure scenario:** Executor runs Phase 1 step 3 `docker compose up -d` → `command not found`. No Postgres → `npx prisma migrate dev` fails (no DB to connect to) → PrismaClient never generates the `User` model types → Phase 2/3 code that imports `@prisma/client` types won't compile → Phase 4 e2e (`docker-compose.test.yml`) cannot start. Every Success Criterion in Phase 1 is unreachable. The plan has no "install Docker / is Docker running?" precondition and no native-Postgres fallback (Phase 1 explicitly forbids native Postgres: "không cài Postgres native lên máy").
- **Evidence:** Plan `phase-01-schema-prisma-user.md:63` "`docker compose up -d`"; `:72` success criterion "`docker compose up -d` chạy Postgres local thành công". Machine check: `which docker` → "docker not found"; `docker info` → "DAEMON DOWN/UNAVAILABLE".
- **Suggested fix:** Add a Phase 0 precondition: verify `docker --version` + `docker info` succeed, or provide an explicit fallback (Postgres.app / Homebrew `postgresql@16` / a hosted dev DB). Gate Phase 1 on this check; do not assume Docker.

## Finding 2: `ConfigModule.forRoot()` is never wired — `JWT_SECRET` and `FACEBOOK_APP_ID` are `undefined` at runtime
- **Severity:** Critical
- **Location:** Phase 2, "Architecture" + step 2; Phase 3, "Architecture" (`JwtModule.register`) + step 2
- **Flaw:** Node does not auto-load `.env`. Prisma loads `DATABASE_URL` via its own dotenv, so migrations work — but NestJS runtime code does not. The plan installs `@nestjs/config` (Phase 2 step 2) yet no step anywhere imports `ConfigModule.forRoot({ isGlobal: true })` into `AppModule`. Meanwhile Phase 3 registers `JwtModule.register({ secret: process.env.JWT_SECRET, ... })` reading `process.env` directly, and Phase 2 shows `verifyIdentityToken` as a **module-level free function** with `audience: FACEBOOK_APP_ID` — a bare symbol that is neither imported nor defined, and cannot read from DI `ConfigService`.
- **Failure scenario:** App boots. `process.env.JWT_SECRET` is `undefined` (nothing loaded `.env`) → `@nestjs/jwt` `sign()` throws `secretOrPrivateKey must have a value`, so `POST /auth/facebook` 500s on every request. Even if a shell happened to export `JWT_SECRET`, `FACEBOOK_APP_ID` in the module-level function is a `ReferenceError`/`undefined` → `jwtVerify(..., { audience: undefined })` accepts any audience OR the file won't compile (`Cannot find name 'FACEBOOK_APP_ID'`). The plan's own comment says "từ ConfigService" but the code shape (free function, module scope) makes ConfigService unreachable.
- **Evidence:** `src/app.module.ts` `imports: []` (empty); `src/main.ts` has no dotenv/config; `grep -rn "ConfigModule\|ConfigService\|dotenv" src/` → NONE. Plan `phase-02-facebook-verify-service.md:29-35` module-level `const JWKS`/free `async function` referencing `FACEBOOK_APP_ID`; `:47` "đọc qua `@nestjs/config`". Plan `phase-03-...:33` `JwtModule.register({ secret: process.env.JWT_SECRET ... })`; `:123` same. No step wires `ConfigModule.forRoot`.
- **Suggested fix:** Add explicit step: import `ConfigModule.forRoot({ isGlobal: true })` in `AppModule` (Phase 1 or 3). Make `FacebookAuthService` a real injectable class reading `this.config.getOrThrow('FACEBOOK_APP_ID')`; move JWKS/appId inside the instance (or pass `audience` per-call). Use `JwtModule.registerAsync` with `ConfigService`, not bare `process.env`. Add `getOrThrow` so a missing secret fails loudly at boot, not per-request.

## Finding 3: The `P2002`-on-`email` refetch silently bypasses the `409 EMAIL_LINK_REQUIRED` gate — the plan's headline security control
- **Severity:** High
- **Location:** Phase 3, "Architecture" → `findOrCreateFacebookUser` catch block
- **Flaw:** The pre-check throws `409 EMAIL_LINK_REQUIRED` when an email already belongs to a user. But the `try/catch` around `create` handles a `P2002` unique-violation on `email` by `return prisma.user.findUniqueOrThrow({ where: { email } })` — i.e. it **returns the pre-existing email account and the controller then signs a system JWT for it**, with no password/link-confirm. That is exactly the auto-link-by-email the whole plan was rewritten to forbid, just reachable through a race window instead of the happy path.
- **Failure scenario:** Two requests interleave: (T0) Facebook login checks `findUnique({email})` → null; (T1) a password user with that email is created concurrently (manual seed, or a future `/auth/register` which the plan says will reuse the same `signToken`); (T2) `create({facebookId,email})` → `P2002` target `email`; (T3) catch refetches by email → returns the **password user**; (T4) controller issues a system JWT authenticating the Facebook caller AS the password account — no password ever verified. The `link-confirm` password gate is skipped. Also for two distinct FB accounts sharing one email, the loser is authenticated as the winner's account.
- **Evidence:** Plan `phase-03-auth-endpoint-va-account-linking.md:56-59` pre-check throws `EMAIL_LINK_REQUIRED`; `:67-73` catch: `if (target.includes('email')) return prisma.user.findUniqueOrThrow({ where: { email: profile.email! } })`. The email branch returns the account instead of re-throwing the 409. Contradicts Requirement `:20` "email trùng user cũ → không auto-link, trả 409".
- **Suggested fix:** On `P2002`, only the **facebookId** target may safely refetch-and-return (idempotent same-identity race). For an **email**-only target, re-throw `ConflictException({ code: 'EMAIL_LINK_REQUIRED', email })` — never return the email-matched user. Add a Phase 4 test asserting the email-race path yields 409, not a JWT.

## Finding 4: JWKS fetch/network failure is misclassified as `401 Invalid Facebook token`
- **Severity:** High
- **Location:** Phase 2, "Architecture" (catch-all) vs "Risk Assessment"
- **Flaw:** `createRemoteJWKSet` fetches the keyset lazily on first `jwtVerify`. A DNS/timeout/5xx from `facebook.com` throws inside `jwtVerify` (e.g. `JWKSTimeout` or a fetch rejection). The plan catches **every** error → `UnauthorizedException('Invalid Facebook token')`. The Risk Assessment says to "log network errors separately," but the Architecture code has a single catch that erases that distinction.
- **Failure scenario:** Facebook JWKS endpoint is briefly unreachable (their outage, or the server's egress hiccup). Every legitimate user gets `401 Invalid Facebook token`. Clients are told their Facebook login is invalid and prompted to re-authenticate — which cannot help because the fault is server→Facebook, not the token. A transient 5xx-class condition is reported as a permanent 401 auth failure, and monitoring/alerting sees "auth failures" instead of "upstream down."
- **Evidence:** Plan `phase-02-facebook-verify-service.md:45` "Lỗi từ jose (...) → catch chung, ném `UnauthorizedException`"; `:62` step 4 "Catch mọi lỗi từ jwtVerify → UnauthorizedException"; contradicted by `:76-77` Risk "log rõ lỗi network riêng biệt" (not reflected in code).
- **Suggested fix:** Distinguish key/network failures (`JWKSTimeout`, `JWKSNoMatchingKey` due to fetch, generic fetch error) → `ServiceUnavailableException` (503) + log; only true token-validity errors (`JWTExpired`, `JWTClaimValidationFailed`, `JWSSignatureVerificationFailed`) → 401. Consider a short JWKS cache/cooldown so one outage doesn't 401 every request.

## Finding 5: Identity token is a replayable bearer credential — `nonce`/one-time-use is never enforced
- **Severity:** Medium
- **Location:** Phase 2, "Requirements" (verify iss/aud/exp/signature only)
- **Flaw:** The real Facebook Limited Login id_token contains a client-generated `nonce`, but the backend has no copy of it and cannot bind/verify it. The plan verifies signature + `iss` + `aud` + `exp` and nothing else, so any party that obtains the `identityToken` (logs, proxy, a leaked FE `console.log`) can replay it to `POST /auth/facebook` until `exp` and mint a valid system JWT for that user.
- **Failure scenario:** The FE currently `console.log`s the full token payload (`facebook-login-button.tsx`), and the token will transit to the backend over the network. An attacker who captures one identityToken within its (short) validity window replays it and receives a 7-day system JWT — full account access, no password. No replay store, no jti/nonce dedupe, no TLS-pinning note.
- **Evidence:** Plan `phase-02-facebook-verify-service.md:17` verifies only `iss`/`aud`/`exp`; brainstorm report `260703-facebook-token-backend-verify-mismatch.md` logged claims include `nonce` and `at_hash` (present but unused). FE `my-expo-app/src/features/vfit/components/facebook-login-button.tsx:70` logs full claims.
- **Suggested fix:** Accept the short-lived-token risk explicitly if that is the decision, but document it. Better: enforce TLS-only transport, short server-side dedupe on `jti`/`nonce`+`exp` to make tokens one-time, and reduce the issued system-JWT lifetime (7d for a login-by-replayable-token is generous). At minimum, remove the full-claims `console.log` from the FE before wiring the backend.

## Finding 6: Package-manager inconsistency — plan says `npm` (P1–P3) and `pnpm` (P4), repo is `yarn`
- **Severity:** Medium
- **Location:** Phase 1/2/3 "Implementation Steps" step 1 (`npm install ...`); Phase 4 "Success Criteria" (`pnpm test` / `pnpm test:e2e`)
- **Flaw:** The repo's committed lockfile is `yarn.lock` (no `package-lock.json`, no `pnpm-lock.yaml`). Phases 1–3 instruct `npm install`; Phase 4 instructs `pnpm test`. Three package managers in one plan against a yarn repo.
- **Failure scenario:** `npm install prisma @prisma/client ...` in a yarn project generates a competing `package-lock.json`, desyncing from `yarn.lock` (two sources of truth → nondeterministic installs, CI drift). `pnpm test` fails outright if pnpm isn't installed, or resolves a different tree. Onboarding/CI breaks depending on which lockfile wins.
- **Evidence:** Repo root: `yarn.lock` present (232k), `package-lock.json`/`pnpm-lock.yaml` absent. Plan `phase-01-...:61` `npm install prisma @prisma/client`; `phase-02-...:59` `npm install jose`; `phase-03-...:122` `npm install @nestjs/jwt ...`; `phase-04-...:46-47` `pnpm test` / `pnpm test:e2e`.
- **Suggested fix:** Pick one manager (repo signals yarn) and use it consistently: `yarn add ...`, `yarn test`, `yarn test:e2e`. Delete stray lockfiles if a switch is intended. Do not mix.

## Finding 7: Phase 2 "Modify `src/auth/auth.module.ts`" but that file is first *Created* in Phase 3
- **Severity:** Medium
- **Location:** Phase 2, "Related Code Files" (Modify `src/auth/auth.module.ts`); Phase 3, "Related Code Files" (Create `src/auth/auth.module.ts`)
- **Flaw:** Phase 2 depends only on `[1]` and instructs modifying/registering a provider in `src/auth/auth.module.ts`, but the AuthModule is listed as *Created* in Phase 3 (dep `[1,2]`). Executing phases in numeric order means Phase 2 edits a nonexistent file; executing by dependency means Phase 3 must partly precede Phase 2.
- **Failure scenario:** An executor following Phase 2 in isolation runs step 6 "Đăng ký service vào AuthModule" and `src/auth/auth.module.ts` does not exist → either it creates a partial module that Phase 3 then overwrites (losing the provider registration), or the step is silently skipped and `FacebookAuthService` is never provided → Phase 3 controller injection fails at boot.
- **Evidence:** Plan `phase-02-facebook-verify-service.md:54` "Modify: `src/auth/auth.module.ts`"; `phase-03-auth-endpoint-va-account-linking.md:113` "Create: `src/auth/auth.module.ts`". `src/auth/` does not exist (verified: `find src -type f` shows only app.* files).
- **Suggested fix:** Have Phase 2 *Create* `AuthModule` (it is the first phase to touch `src/auth/`), and Phase 3 *Modify* it. Align the dependency graph so the module's creator is unambiguous.

---

## Summary (severity-ordered)
- **Critical (2):** F1 Docker absent (Phase 1/4 unrunnable); F2 ConfigModule never wired → `JWT_SECRET`/`FACEBOOK_APP_ID` undefined at runtime.
- **High (2):** F3 `P2002`-email refetch bypasses the `409 EMAIL_LINK_REQUIRED` security gate; F4 JWKS network failure returned as 401.
- **Medium (3):** F5 replayable identity token / no nonce dedupe; F6 npm/pnpm/yarn inconsistency; F7 AuthModule create/modify ordering.

Verified-correct (no action): DTO rename has 0 consumers; jose error class names accurate; App ID / claim shape / `iss` match device log.
