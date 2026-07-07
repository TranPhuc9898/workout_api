---
type: red-team-review
reviewer: code-reviewer (Security Adversary)
role: Fact Checker + Contract Verifier (Standard tier)
date: 2026-07-02
plan: plans/260702-facebook-login-oauth
round: re-review (Option B — no silent auto-link, 409 EMAIL_LINK_REQUIRED + /auth/facebook/link-confirm)
verdict: Option B core fixes present in pseudocode, BUT new content reopens the linking-security control under a race window and adds an unthrottled password-guessing surface
---

# Red Team Review — B7 Facebook Login (OAuth), Option B re-review

**Codebase verification (B1 confirmed):** `src/` contains only `app.controller.ts`, `app.service.ts`, `app.module.ts`, `main.ts`, `app.controller.spec.ts`. No `prisma/`, no `src/auth/`. `grep -rn "signToken|JwtAuthGuard|linkFacebookAccount|findOrCreateFacebookUser|EMAIL_LINK_REQUIRED|FacebookAuthService" src` → zero matches. `package.json` has no prisma/bcrypt/jwt/class-validator/config/throttler deps. Matches the plan's own prerequisite disclaimer (plan.md:32) — not a finding.

**Option B fixes verified as genuinely present (not fake-fixed in prose):**
- 409 gate instead of auto-link: phase-03:41-46 (`throw new ConflictException({ code: 'EMAIL_LINK_REQUIRED', ... })`) — real, replaces the old `update()`.
- facebookId-overwrite guard: phase-03:82-84 — real.
- stale-object fix: phase-03:90 `return await prisma.user.update(...)` — real.
- P2002 try/catch: phase-03:49-60 — real, handles both `facebookId` and `email` targets.
- signToken contract: b4-contract-stub.md:16-23 + phase-03:97 — consistent (`signToken(userId): string`, payload `{ sub: userId }`).
- global omit for passwordHash: b4-contract-stub.md:33-41 + phase-03:78,99 — consistent (query-level `omit: { passwordHash: false }` correctly overrides the client-init `omit: { user: { passwordHash: true } }`).

The findings below are NEW issues in the Option B content, not the already-fixed items above.

---

## Finding 1: P2002 `email`-target refetch silently reopens the exact auto-link takeover Option B was built to close
- **Severity:** Critical
- **Location:** Phase 3, "Architecture" — `findOrCreateFacebookUser` P2002 catch (phase-03:53-57), consumed by the JWT-issuing flow (phase-03:29-33)
- **Flaw:** In the non-race path an email match throws `409 EMAIL_LINK_REQUIRED` (phase-03:45) — the entire point of Option B: never hand out a session for a password account without password confirmation. But the P2002 catch does `if (target.includes('email')) return prisma.user.findUniqueOrThrow({ where: { email: profile.email! } })` (phase-03:57). That return value flows straight into `signToken(user.id)` (phase-03:32-33). So on the race path the caller receives a valid system JWT for an account matched **by email only, with zero password confirmation** — the precise outcome the 409 gate exists to prevent. This is a TOCTOU bypass: the `byEmail` check at phase-03:42 returns null, a concurrent write inserts that email, the `create` fails P2002 on `email`, and the "graceful fallback" hands back someone else's account.
- **Failure scenario:** Password account for `victim@example.com` does not yet exist at check time. Attacker's `POST /auth/facebook` (FB email spoofed to `victim@example.com` — unverifiable per research-260702-1706:41) reads `byEmail = null` (phase-03:42), then the victim's `POST /auth/register` (B4) commits `victim@example.com` in the window before the attacker's `create`. Attacker's `create` throws P2002 on `email` → refetch returns the victim's freshly-created **password** account → `signToken(victim.id)` issues the attacker a valid session for an account they never proved ownership of. A lower-bar variant needs no password account at all: two different Facebook identities (different `facebookId`, same email) racing → the loser's refetch returns the winner's account and mints a cross-identity JWT. Auth-path races are triggerable in practice (mobile double-fire, retry-on-timeout, scripted concurrency).
- **Evidence:** phase-03:57 (`return prisma.user.findUniqueOrThrow({ where: { email: profile.email! } })`); phase-03:45 (the 409 gate the branch bypasses); phase-03:32-33 (`signToken(user.id)` on the returned user); research-260702-1706:84-86 endorses this exact refetch — so the flaw is baked into the accepted research patch, not an implementer slip. Risk Assessment phase-03:133-134 only claims P2002 handling prevents a 500; it never notices that the `email` branch also discards the 409 security semantics.
- **Suggested fix:** In the P2002 `email`-target branch, do NOT return the row. Re-apply the same decision the check path makes: if the colliding email row has a `passwordHash` (or any state indicating a pre-existing/independent account), throw `409 EMAIL_LINK_REQUIRED` instead of returning it. Only the `facebookId`-target branch (same Facebook identity) is safe to refetch-and-return.

## Finding 2: `/auth/facebook/link-confirm` is an unthrottled password-guessing oracle, and the FB email it keys on is attacker-controlled
- **Severity:** High
- **Location:** Phase 3, "Architecture" — `linkFacebookAccount` (phase-03:75-88); whole plan (no rate-limit anywhere)
- **Flaw:** `linkFacebookAccount` looks up the account by `profile.email` (phase-03:77) and runs `bcrypt.compare(password, user.passwordHash)` (phase-03:86) with no attempt counter, lockout, backoff, or notification. Option B's own premise (research-260702-1706:41) is that Facebook's `/me` email is **not reliably verified** and cannot be checked at runtime. So an attacker can register a Facebook account with `email = victim@example.com` (Meta may return it unverified), obtain a token, hit `POST /auth/facebook` → 409, then hammer `POST /auth/facebook/link-confirm` with unlimited password guesses against the victim's account. On a hit, the attacker's `facebookId` is permanently linked (phase-03:90-93) and they own the account via Facebook login forever.
- **Failure scenario:** Attacker automates guesses at `/auth/facebook/link-confirm` with `{ accessToken: <attacker-fb-token-with-victim-email>, password: <guess> }`. Nothing in phase-03 or phase-04 rate-limits or locks the account; the account owner is never notified of the successful link. Option B thus trades the pre-account-hijacking vuln for a direct online brute-force endpoint against arbitrary victims' passwords.
- **Evidence:** `grep -rniE "throttl|rate.?limit|lockout|brute|attempt|@Throttle"` across all phase files returns only phase-02:63 ("Facebook Graph API rate-limit", unrelated) — no auth throttling anywhere. phase-03:86 (bcrypt compare, no counter). research-260702-1706:41 (FB email unverifiable = attacker can set victim's email). Note: research-260702-1706:37 recommended "Log/alert khi có auto-link xảy ra" for Option A; that compensating control was dropped in the switch to Option B, where link-confirm needs it more.
- **Suggested fix:** Add `@nestjs/throttler` (or equivalent) with a strict per-IP + per-email limit on `/auth/facebook/link-confirm`, an account-level failed-attempt lockout, and an email notification to the account owner on successful link. Add these as explicit Phase 3 requirements and Phase 4 tests.

## Finding 3: `FacebookProfile` field contract is inconsistent between Phase 2 (`facebookId`) and Phase 3 (`profile.id`) — every branch breaks at runtime
- **Severity:** High
- **Location:** Phase 2 "Architecture" mapping (phase-02:32) vs Phase 3 pseudocode (phase-03:38,51,56,82,92) [Contract Verifier / Fact Checker]
- **Flaw:** Phase 2 defines the profile object as `{ facebookId: id, name, email, avatarUrl }` (phase-02:32) — the identity field is `profile.facebookId`. Phase 3 consumes `profile.id` in every branch: `where: { facebookId: profile.id }` (phase-03:38,56), `data: { facebookId: profile.id }` (phase-03:51,92), `user.facebookId !== profile.id` (phase-03:82). `b4-contract-stub.md` defines B4's signatures but does **not** define `FacebookProfile`, so there is no authoritative shape reconciling the two. This is directly in scope per the round note (Phase 2 conflicts with the Phase 3 flow).
- **Failure scenario:** An implementer following Phase 2 literally produces `profile.facebookId`; `profile.id` is then `undefined`. `prisma.user.findUnique({ where: { facebookId: undefined } })` is a Prisma validation error (unique lookup with no value), and `create({ data: { facebookId: undefined } })` writes a null facebookId — collapsing the whole find-or-create logic. Even the overwrite guard `user.facebookId !== profile.id` becomes `!== undefined`, always true, defeating Finding-fix intent. Every branch of both new endpoints is affected.
- **Evidence:** phase-02:32 (`{ facebookId: id, ... }`); phase-03:38,51,56,82,92 (all use `profile.id`). research-260702-1706:63,75 also uses `profile.id`, so Phase 3 aligns with the research pseudocode but contradicts Phase 2's own output mapping. `b4-contract-stub.md` has no `FacebookProfile` definition.
- **Suggested fix:** Pin one `FacebookProfile` shape (recommend `{ id, name, email, avatarUrl }` to match Phase 3 and the research patch) and correct phase-02:32's mapping to `{ id, ... }`, or add `FacebookProfile` to `b4-contract-stub.md` (or a phase-02 interface section) as the single source of truth both phases cite.

## Finding 4: `link-confirm` with a null-email token throws an unhandled Prisma error (500 + internals) — no guard, unlike the sibling method
- **Severity:** Medium
- **Location:** Phase 3, "Architecture" — `linkFacebookAccount` (phase-03:76-77)
- **Flaw:** `findOrCreateFacebookUser` guards `if (profile.email)` before its email lookup (phase-03:41). `linkFacebookAccount` has **no** such guard — it calls `prisma.user.findUnique({ where: { email: profile.email } })` directly (phase-03:77). Phase 2 explicitly allows `email: null` when the user declined the email permission (phase-02:17,32). `email` is `String? @unique` (phase-01:27), so `findUnique({ where: { email: null } })` is a Prisma validation error, not a clean lookup.
- **Failure scenario:** An attacker (or any client) calls `POST /auth/facebook/link-confirm` directly with a valid FB token whose `/me` returned no email. `findUnique` throws `PrismaClientValidationError` → default NestJS filter returns a 500 with Prisma internals in logs/response, instead of a clean 400/401. Trust-boundary/robustness defect plus minor internals disclosure; the endpoint is directly reachable (not gated behind the 409 flow).
- **Evidence:** phase-03:76-77 (no null-email guard); contrast phase-03:41 (guard present in the sibling method); phase-02:17,32 (email legitimately null); phase-01:27 (`email String? @unique`).
- **Suggested fix:** Add `if (!profile.email) throw new UnauthorizedException('Invalid credentials')` (or `BadRequestException`) at the top of `linkFacebookAccount`, before the lookup — link-confirm is meaningless without an email to match.

## Finding 5: Phase 4 never tests the two most dangerous new code paths — the `email`-P2002 branch and the overwrite guard (e2e)
- **Severity:** Medium
- **Location:** Phase 4 test list (phase-04:32-42) vs Phase 3 Success Criteria (phase-03:123-129) [Contract Verifier]
- **Flaw:** (a) The concurrency e2e fires two requests with "cùng access_token/**facebookId** mới" (phase-04:42) — same facebookId, so it only exercises the `facebookId`-target P2002 branch (phase-03:56). The `email`-target branch (phase-03:57) — the one that reopens the auto-link bypass in Finding 1 — has **zero** coverage; no test fires concurrent requests with different facebookId + same email. (b) phase-03:126 declares "link-confirm khi user đã có `facebookId` khác → 409" a critical success criterion, but the e2e list (phase-04:37-42) omits it; it appears only as a mock-Prisma unit test (phase-04:33), which by phase-04's own reasoning (phase-04:56-57) cannot validate real constraint behavior. (c) No test for the null-email link-confirm path (Finding 4).
- **Failure scenario:** Implementation ships with the Finding-1 bypass and a possibly-broken overwrite guard, and Phase 4 passes green — false confidence identical to the "P2002 mitigation asserted but untested" problem flagged in round 1 (code-reviewer-260702-1640:18-24), now recurring for the email branch and the overwrite guard.
- **Evidence:** phase-04:42 (race test = same facebookId only); phase-03:57 (untested email-refetch branch); phase-03:126 vs phase-04:37-42 (overwrite guard absent from e2e list); phase-04:33 (overwrite only in mock unit test); phase-04:56-57 (plan's own admission that mock Prisma can't reproduce constraint behavior).
- **Suggested fix:** Add e2e cases on the real test DB: (1) two concurrent `POST /auth/facebook` with **different** facebookId + **same** email → assert neither request silently receives a JWT for the other's/an existing account (locks in the Finding-1 fix); (2) `link-confirm` when the email-matched user already has a different `facebookId` → 409, no overwrite; (3) `link-confirm` with a null-email token → clean 4xx, not 500.

## Finding 6: `/auth/facebook` 409-vs-200 is a user-enumeration oracle that also mints junk accounts, contradicting the plan's own anti-enumeration rationale
- **Severity:** Medium
- **Location:** Phase 3, "Architecture" (phase-03:41-51); Success Criteria (phase-03:123)
- **Flaw:** When an email matches an existing account, `/auth/facebook` returns `409 EMAIL_LINK_REQUIRED` and echoes the email back (phase-03:45); when it doesn't match, it creates a user and returns 200 + JWT (phase-03:50-51). The 409-vs-200 distinction is a reliable existence oracle, and the FB email keying it is attacker-settable (research-260702-1706:41). This directly contradicts the anti-enumeration hardening the plan mandates elsewhere — b4-contract-stub.md:27-32 and phase-03:87 insist on an identical "Invalid credentials" message specifically to prevent enumeration in `login()` — while `/auth/facebook` hands out a louder oracle for free. Worse, every negative probe **creates a real junk `User` row** (phase-03:50), so enumeration doubles as DB pollution / account spam with no rate limit (see Finding 2).
- **Failure scenario:** Attacker scripts `/auth/facebook` with spoofed FB emails across a target list; 409 = account exists, 200 = account created (and now a junk row exists). Result: reliable account enumeration for phishing/credential-stuffing recon, plus unbounded row creation. No throttle, no CAPTCHA, no acknowledgement of the trade-off in the plan.
- **Evidence:** phase-03:45 (409 + echoed email on match), phase-03:50-51 (create + 200 on no-match), b4-contract-stub.md:27-32 / phase-03:87 (identical-message anti-enumeration requirement the new endpoint undermines), research-260702-1706:41 (spoofable FB email). No throttling (grep in Finding 2).
- **Suggested fix:** Rate-limit `/auth/facebook` (shares the Finding-2 throttler), stop echoing the email in the 409 body, and explicitly document the residual enumeration trade-off inherent to Option B in Phase 3 rather than leaving it silent.

---

## Summary Table

| # | Title | Severity | Type |
|---|-------|----------|------|
| 1 | P2002 `email`-refetch reopens the auto-link takeover Option B closed | Critical | Security / TOCTOU |
| 2 | `link-confirm` = unthrottled brute-force oracle; FB email spoofable | High | Security / authz |
| 3 | `FacebookProfile` field mismatch (`facebookId` vs `profile.id`) breaks every branch | High | Contract Verifier |
| 4 | `link-confirm` null-email → unhandled Prisma 500 (no guard) | Medium | Robustness / trust boundary |
| 5 | Phase 4 never tests the email-P2002 branch or the overwrite guard (e2e) | Medium | Contract Verifier |
| 6 | `/auth/facebook` 409-vs-200 enumeration oracle + junk-account creation | Medium | Security / info disclosure |

## Unresolved questions
1. Does B4's future `login()` truly return `{ accessToken }` only (b4-contract-stub.md:18), or `{ accessToken, user }`? research-260702-1706:104's own test template asserts `body.user.id`, but phase-03:33 returns `{ accessToken: jwt }` with no `user`. The contract and the test template disagree on response shape — decide before Phase 4.
2. Is Meta's `/me` email genuinely spoofable to an arbitrary unverified value in your app's config (Findings 1, 2, 6 severity depends on this)? The research report asserts non-verifiability but did not empirically confirm attacker-settable arbitrary emails.
