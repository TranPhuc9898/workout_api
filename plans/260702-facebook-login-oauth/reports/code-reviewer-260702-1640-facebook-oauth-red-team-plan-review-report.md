# Red Team Review: B7 Facebook Login OAuth Plan

**Reviewer role:** Failure Mode Analyst (Murphy's Law: race conditions, data loss, cascading failures, recovery gaps, deployment risks, rollback holes) + Fact Checker + Contract Verifier (standard tier).
**Scope:** `plans/260702-facebook-login-oauth/{plan.md, phase-01..04}.md`, cross-checked against `brainstorm-260702-1633-facebook-login-oauth.md` (cited by plan.md:21 as the decision source) and the live repo.

**Codebase verification:** `src/` contains only `app.controller.ts`, `app.service.ts`, `app.module.ts`, `main.ts`, `app.controller.spec.ts` — no `prisma/`, no `src/auth`, no `.env`. `package.json` has zero Prisma/JWT/class-validator/config dependencies. This confirms the plan's own prerequisite disclaimer (plan.md:30) is accurate: B4 does not exist yet. `tsconfig.json:19` has `"strictNullChecks": true` — this means Phase 1's stated mitigation of running `tsc --noEmit` after making `email`/`passwordHash` nullable will actually surface a compile error (verified, not a flaw — noted only to show it was checked).

---

## Finding 1: Pre-account hijacking via unverified-email auto-link
- **Severity:** Critical
- **Location:** Phase 3, section "Architecture" (`findOrCreateFacebookUser`, branch 2) and "Risk Assessment" (line 68); brainstorm report §4c and §6 (line 92).
- **Flaw:** The auto-link branch trusts an email match against an existing password-based `User` row as sufficient proof of identity to attach a Facebook login to that account, with no verification that the Facebook user is the same person who originally registered that email/password account locally.
- **Failure scenario:** Per the brainstorm's own scout notes (line 26): "Roadmap (B4, đã định nghĩa sẵn nội dung — chưa code): model `User` dự kiến có `email` (unique) + `passwordHash`, route `POST /auth/register`, `POST /auth/login`" — no email-ownership verification (confirmation email/OTP) is mentioned anywhere in B4's or B7's scope. An attacker who knows a victim's email (`victim@company.com`) calls `POST /auth/register` with that email and an attacker-chosen password — this succeeds, since register never confirms the attacker owns that inbox. Later, the real victim's first-ever interaction with the app is "Login with Facebook," using their genuine Facebook account tied to `victim@company.com`. Per Phase 3 pseudocode (lines 29-35): `findUnique({facebookId})` → not found → `findUnique({email: profile.email})` → **finds the attacker's pre-planted row** → `prisma.user.update({..., facebookId: profile.facebookId})` → `return user`. The attacker still knows the password for this account (`POST /auth/login` still works for them) and now has standing access to the victim's identity in the app going forward. This is the well-documented "OAuth pre-authentication account takeover" pattern for auto-link-by-email flows.
- **Evidence:** Phase 3 architecture lines 31-35 (auto-link on email match, no ownership check). Phase 3 Risk Assessment line 68 only considers "Auto-link sai nếu 2 user khác nhau vô tình share chung email... không áp dụng ở đây vì `email` đã `@unique`" — this addresses a *different, structurally-impossible* threat (DB-level duplicate emails) and misses the actual attack (attacker pre-registers the victim's *locally-unverified* email before the victim ever touches Facebook login). Brainstorm line 92 makes the same reasoning gap: "Auto-link nhầm tài khoản nếu Facebook trả email chưa verify | Low | Facebook luôn trả email đã verify... — chấp nhận được" — true of Facebook's side, but irrelevant, since the attack requires only that B4's *local* registration is unverified, not that Facebook's email is unverified.
- **Suggested fix:** Do not silently auto-link on email match alone. Require proof of ownership of the existing password account before linking (this is exactly Option B from the brainstorm's own §4c table, explicitly rejected — resurface that trade-off given the concrete attack path above), or require B4 to add email verification before any account is treated as a trustworthy auto-link target.

## Finding 2: P2002 race/concurrency mitigation is asserted, never actually specified or tested
- **Severity:** Critical
- **Location:** Phase 3, "Architecture" and "Risk Assessment" (lines 66-68); Phase 3 "Implementation Steps" step 3 (line 52); Phase 4 "Risk Assessment" (line 43) and step 3 (line 30).
- **Flaw:** Risk Assessment (line 67) claims: "`facebookId` đã có `@unique` ở DB — request thứ 2 sẽ lỗi constraint, bắt lỗi Prisma `P2002` và fallback sang tìm lại user." But the Architecture pseudocode (lines 26-39) and Implementation Steps contain no try/catch, no `P2002` handling, no fallback query anywhere. Step 3 (line 52) says the opposite: "dùng transaction Prisma nếu cần atomic (**thường không bắt buộc cho case đơn giản này**)." The stated mitigation also only reasons about the `facebookId` unique index — the "create new user" branch (line 36) also writes `email`, which is independently `@unique`; a concurrent `POST /auth/register` (B4) racing this same email is never addressed, so `P2002` on the *email* column is equally unhandled and unconsidered.
- **Failure scenario:** Two concurrent `POST /auth/facebook` requests for the same not-yet-existing `facebookId` (mobile double-tap, retry-on-timeout) both read `findUnique({facebookId})` as null and both call `prisma.user.create()`. The second write throws `P2002`. With no catch specified anywhere, this surfaces as an unhandled 500 (default NestJS exception filter — potential Prisma-internals leak in logs/response) instead of the claimed graceful fallback. Separately, Phase 4's stated mitigation for this exact class of bug — "Ít nhất 1 e2e test chạy trên DB test thật... để bắt lỗi constraint thật" (line 43) — is never actually exercised, because Phase 4's Implementation Step 3 (line 30) only fires a single sequential `supertest` call, never a concurrent/parallel one. The plan's own quality gate gives false confidence that this race is "covered."
- **Evidence:** Line 67 (claim) vs. lines 26-39 (no catch in pseudocode) vs. line 52 (explicit "not required") vs. line 30 (sequential-only e2e test).
- **Suggested fix:** Add explicit catch-`P2002`-and-refetch logic (for both `facebookId` and `email` collisions) to the Architecture pseudocode as its own Implementation Step, and add a Phase 4 test that fires two concurrent requests against the real test DB and asserts no unhandled exception.

## Finding 3: `passwordHash` may leak into the JWT payload
- **Severity:** High
- **Location:** Phase 3, "Architecture" — every Prisma call in `findOrCreateFacebookUser` and `jwt = AuthService.signToken(user)` (lines 29-38); Phase 1 schema (lines 25-33) confirms `passwordHash` is a real column on the same model.
- **Flaw:** None of the three Prisma queries (`findUnique({facebookId})`, `findUnique({email})`, `create(...)`) specify a `select`/field allow-list. The full `User` record — including the bcrypt `passwordHash` — flows directly into `signToken(user)`. JWTs are signed, not encrypted; anything in the payload is trivially base64-decodable by the client or any log/APM capturing the response.
- **Failure scenario:** If `signToken` is implemented as something like `jwt.sign({ ...user })` (a common shortcut, especially likely from an AI-assisted implementer following this pseudocode literally), the password hash for the account ends up embedded in every issued token — exposed to the client and any request/response logging — enabling offline brute-force of the hash for any user who hits this code path, including non-Facebook accounts once auto-linked.
- **Evidence:** Phase 3 lines 29-38 — no `select` clause in any Prisma call; `return user` (full record) feeds `signToken(user)` directly.
- **Suggested fix:** Require `select: { id, email, name, avatarUrl, facebookId, createdAt }` (excluding `passwordHash`) on every read in `findOrCreateFacebookUser`, and require `signToken` to accept a minimal `{ id }`/`{ sub }` shape, not a raw Prisma `User`.

## Finding 4: Null `passwordHash` creates a user-enumeration oracle in B4's existing login flow
- **Severity:** High
- **Location:** Phase 1, "Risk Assessment" (lines 59-60); Phase 4, "Implementation Steps" step 4 (line 31) and "Success Criteria" (lines 35-38).
- **Flaw:** After Phase 1's migration, a Facebook-only user has `passwordHash = null`. Nothing in the plan requires `AuthService.login()` (B4) to guard against `passwordHash === null` before a call like `bcrypt.compare(password, user.passwordHash)`. The plan's only stated mitigation is "chạy `tsc --noEmit`... để bắt lỗi type" (line 60) — this only guarantees the compiler *complains*, not that the fix is security-correct. An implementer can silence the TS error with a non-null assertion (`user.passwordHash!`) instead of a proper guard, and nothing in Phase 4 would catch that.
- **Failure scenario:** Anyone calls `POST /auth/login` with the email of a Facebook-only account and any password. If the implementer bypassed the type error with `!`, `bcrypt.compare(guessedPassword, null)` throws a `TypeError` — either an unhandled 500 or, if caught generically, a response distinguishable from a normal wrong-password 401. Either way this becomes a user-enumeration oracle: an attacker can distinguish "email exists but is Facebook-only" from "email doesn't exist" from "email exists with a password," useful recon for targeted phishing/credential-stuffing.
- **Evidence:** Phase 1 lines 59-60 (mitigation is compile-time only). Phase 4 step 4 (line 31) only requires existing B4 tests to keep passing — it does not add the new edge case (login attempt against a null-`passwordHash` row), which is absent from every Phase 4 success criterion (lines 35-38).
- **Suggested fix:** Phase 1 or Phase 3 must explicitly require `AuthService.login()` to `if (!user.passwordHash) throw new UnauthorizedException('Invalid credentials')` before any bcrypt call, and Phase 4 must add a test: "login attempt with email of a Facebook-only account → 401, not 500."

## Finding 5: `prisma migrate dev` used exclusively — no production-safe deploy path documented
- **Severity:** High
- **Location:** Phase 1, "Related Code Files" and "Implementation Steps" (lines 41, 46, 52).
- **Flaw:** Every migration command referenced in the plan is `npx prisma migrate dev --name add_facebook_login`. `prisma migrate dev` is a development-only command that, on detecting drift between migration history and the live database, can prompt to **reset the entire database**. `prisma migrate deploy` (the non-interactive, production-safe command) is never mentioned anywhere across plan.md or any of the 4 phase files.
- **Failure scenario:** If followed literally against a shared staging/production database that already has real B4 users (exactly the scenario Phase 1's own Requirement is worried about — "Không được phá vỡ dữ liệu user hiện có"), running `migrate dev` there risks a full-database reset on drift detection, directly violating the phase's own stated requirement. The plan documents zero distinction between dev and any shared environment.
- **Evidence:** `grep -n "migrate deploy"` across all plan files returns zero matches; `grep -n "migrate dev"` returns exactly 3 matches, all in phase-01 (lines 41, 46, 52).
- **Suggested fix:** Add an explicit note: local dev uses `migrate dev`; any shared/staging/production rollout must use `prisma migrate deploy` via CI/CD, never `migrate dev`.

## Finding 6: Auto-link `update()` has no guard against overwriting an already-linked `facebookId`
- **Severity:** High
- **Location:** Phase 3, "Architecture", branch 2 (line 34).
- **Flaw:** Branch 2 unconditionally overwrites `facebookId` on the email-matched user: `prisma.user.update({ where: { id: user.id }, data: { facebookId: profile.facebookId, ... } })`. It never checks whether that user's `facebookId` is already non-null before overwriting. The inline comment "(user cũ có passwordHash, chưa có facebookId)" (line 33) is an unstated assumption, not a checked condition.
- **Failure scenario:** A user registers via B4 with `email=X`, later links Facebook account A via branch 2 (`facebookId=A`). If email X is later re-verified on a different Facebook account B (recycled/reassigned email, or a Facebook account-recovery flow), a new login attempt fails branch 1 (`facebookId=B` not found) but matches branch 2 by email — the same user row, which already has `facebookId=A` — and silently overwrites it to `B` with zero check, log, or notification. The original link to account A is destroyed with no audit trail, and whoever controls account B now has full login access to that user's app account.
- **Evidence:** Phase 3 line 34 — no `if (!user.facebookId)` guard, no branching on the existing value.
- **Suggested fix:** If `user.facebookId` is already set and differs from `profile.facebookId`, reject the link (409/403) instead of silently overwriting, or require the account's password before allowing a re-link.

## Finding 7: Auto-link branch returns the stale pre-update `user` object
- **Severity:** Medium
- **Location:** Phase 3, "Architecture" (lines 33-35).
- **Flaw:** `prisma.user.update({ where: { id: user.id }, data: { facebookId: profile.facebookId, ... } })` is called, but the pseudocode then does `return user` — the *original* variable captured before the update, not the update's return value. The object returned to the caller therefore does not reflect the `facebookId`/merged `name`/`avatarUrl` that was just written.
- **Failure scenario:** Any subsequent logic in the same request that inspects `user.facebookId` (e.g., token claims, response shaping) sees `null` even though the DB row is now linked — an inconsistent in-request state that only self-corrects on the *next* login.
- **Evidence:** Phase 3 lines 34-35: `→ prisma.user.update({...}) → return user` — the update's return value is discarded.
- **Suggested fix:** `return await prisma.user.update(...)` — use the write's return value, not the pre-update local variable.

## Finding 8: Ambiguous JWT-signing reuse contract risks a credential-check bypass path
- **Severity:** Medium
- **Location:** Phase 3, "Implementation Steps" step 4 (line 53).
- **Flaw:** "Tái dùng hàm sign JWT đã viết ở B4 (`AuthService.login()` hoặc helper riêng) — không viết lại logic JWT" leaves it ambiguous whether the Facebook flow calls `AuthService.login()` (which, in a typical B4 implementation, bundles *credential verification* with token signing) or a separate pure `signToken(user)` helper. Since B4 doesn't exist yet, the plan should be prescriptive rather than offering both as interchangeable.
- **Failure scenario:** If an implementer takes the `AuthService.login()` branch literally, and that method's real signature expects `(email, password)` and internally re-verifies credentials, they would need to fabricate a bypass (a sentinel value, or an `if` branch inside `login()` that skips password checks when called from the Facebook flow) — exactly the kind of ad hoc special-casing inside an authentication-critical function that tends to become a bypass usable by other callers later.
- **Evidence:** Phase 3 line 53, "`AuthService.login()` hoặc helper riêng" (both offered without a decision).
- **Suggested fix:** Mandate a dedicated `signToken(userId)` helper used by both B4's `login()` and B7's Facebook flow, so credential verification and token issuance stay structurally separate.

## Finding 9: Fragile, unguarded dependency on Facebook Graph API in the hot login path
- **Severity:** Medium
- **Location:** Phase 2, "Architecture" (lines 26-31) and "Risk Assessment" (line 64); Phase 3, "Architecture" (lines 26-30).
- **Flaw:** Three compounding issues, none addressed: (1) `/debug_token` and `/me` are called without an API version segment (`graph.facebook.com/debug_token`, not `graph.facebook.com/v21.0/debug_token`) — Facebook periodically sunsets unversioned/old API versions, which can silently change response shape or start rejecting calls; (2) the fetch-timeout mitigation is promised only in Risk Assessment ("Set timeout hợp lý cho `fetch` (AbortController ~5s)", line 64) but absent from Implementation Steps (line 49 just says "dùng `fetch`... không cần thêm HTTP client lib") and from every Success Criterion; (3) `verifyAccessToken()` is called unconditionally on every request (line 27) before branch dispatch, including for already-linked returning users (branch 1, lines 29-30) whose profile data is fetched and then discarded with no update — there is no cache, fallback, or circuit breaker anywhere in the plan.
- **Failure scenario:** A Facebook Graph API outage or elevated latency blocks 100% of Facebook logins, including for users who already have a fully resolved account and gain nothing from the round-trip; without the promised timeout, requests can hang indefinitely rather than failing fast. Months later, an unannounced Graph API version deprecation can silently break `/me`'s response shape (e.g., `picture?.data?.url`) or start rejecting the call outright, with no code change on this repo's side to explain the sudden failure — a difficult-to-diagnose production incident for a project with no monitoring described anywhere in the plan.
- **Evidence:** Phase 2 lines 26-31 (no `/vXX.X/` prefix in either endpoint) vs. line 64 (timeout promised) vs. line 49 (timeout absent from steps). Phase 3 lines 26-30 (unconditional verify call, branch 1 discards the fetched profile).
- **Suggested fix:** Pin an explicit Graph API version and note it needs periodic review; move the AbortController requirement into Implementation Steps as its own step with a corresponding Success Criterion asserting fast failure (not a hang) when Facebook is unreachable.

---

## Summary Table

| # | Title | Severity |
|---|-------|----------|
| 1 | Pre-account hijacking via unverified-email auto-link | Critical |
| 2 | P2002 race/concurrency mitigation asserted, never specified or tested | Critical |
| 3 | `passwordHash` may leak into JWT payload (no `select`) | High |
| 4 | Null `passwordHash` creates user-enumeration oracle in B4 login | High |
| 5 | `prisma migrate dev` only, no production-safe `migrate deploy` path | High |
| 6 | Auto-link `update()` has no guard against overwriting existing `facebookId` | High |
| 7 | Stale `user` object returned post auto-link update | Medium |
| 8 | Ambiguous JWT-signing reuse contract risks credential-check bypass | Medium |
| 9 | Fragile, unguarded Facebook Graph API dependency in hot login path | Medium |
