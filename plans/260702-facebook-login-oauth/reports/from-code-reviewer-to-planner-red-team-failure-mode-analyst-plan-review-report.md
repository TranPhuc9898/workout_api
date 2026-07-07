---
type: red-team-review
reviewer: code-reviewer (Failure Mode Analyst + Fact Checker + Contract Verifier)
round: 3 (Option B re-review)
date: 2026-07-02
plan: plans/260702-facebook-login-oauth
verdict: not-implementation-ready — Option B fix is partially undone by the P2002 race path; link-confirm has new unhandled failure modes
---

# Red Team Re-Review — B7 Facebook Login (OAuth), Option B

**Scope of this round:** verify the Option B fixes (409 `EMAIL_LINK_REQUIRED`, `link-confirm` endpoint, facebookId-overwrite guard, P2002 try/catch) are genuinely resolved, and hunt for NEW failure modes introduced by the new content. Phase 2 skimmed only (out of scope per assignment).

**Codebase state (verified):** repo is at B1. `find src` → only `app.*`; `prisma/` absent; `grep -rn "signToken|JwtAuthGuard|PrismaService|findOrCreateFacebookUser|linkFacebookAccount|EMAIL_LINK_REQUIRED" src` → no matches; `package.json` has zero prisma/jwt/class-validator/config/bcrypt deps; no `.env`. This matches the plan's own prerequisite disclaimer (`plan.md:32`) — expected, not a finding.

**Prior findings confirmed genuinely resolved (not fake):**
- Prior Critical #1 (pre-account hijacking / silent auto-link): the auto-link branch is gone; email match now throws `409 EMAIL_LINK_REQUIRED` (`phase-03:45`). Resolved *in the non-race path only* — see Finding 1 for the race regression.
- Prior Finding 6/2 (facebookId overwrite): guard added at `phase-03:82-84`. Resolved.
- Prior Finding 5 (`migrate deploy`): added at `phase-01:47` and `phase-04:35`. Resolved (verified via grep).
- Prior Finding 8/1 (JWT-signing/`signToken(user)` ambiguity): `signToken(userId: string)` now pinned in `b4-contract-stub.md:19` and called as `signToken(user.id)` at `phase-03:32,70`. Contract-consistent (but see Finding 7 for a residual sync/async drift).
- Prior Finding 7 (stale returned user): link path now `return await prisma.user.update(...)` (`phase-03:90`). Resolved.

---

## Finding 1: The P2002 email-refetch path silently re-opens the exact Option B bypass it was added alongside
- **Severity:** Critical
- **Location:** Phase 3, "Architecture" — `findOrCreateFacebookUser` catch block (`phase-03:53-57`, specifically the email branch line 57)
- **Flaw:** Option B's whole purpose is that a Facebook login whose email matches an existing password account must NOT be silently authenticated — it must return `409 EMAIL_LINK_REQUIRED` (`phase-03:44-45`). But the P2002 catch added for the concurrency fix does the opposite on an email collision: `if (target.includes('email')) return prisma.user.findUniqueOrThrow({ where: { email: profile.email! } })` (`phase-03:57`). It blindly returns the email-matched row, which the controller immediately turns into a session: `jwt = AuthService.signToken(user.id); return { accessToken: jwt }` (`phase-03:32-33`). The refetch never re-applies the `passwordHash != null` / no-facebookId check that the synchronous branch enforces at line 44.
- **Failure scenario:** The pre-check at `phase-03:42` (`findUnique({email})` → null) and the `create` at line 50 are not atomic. Attacker pre-registers the victim's email via `POST /auth/register` (B4 has no email verification — see research report line 42). Victim logs in with genuine Facebook (same email). If the register write commits in the window between the victim request's line-42 read and its line-50 `create`, the create throws `P2002` on the `email` unique column → catch line 57 refetches the attacker's password row (facebookId=null) and **returns it** → victim is issued a valid JWT for the attacker's account (or, symmetrically, a Facebook login lands inside a password account with no link-confirm). This is the precise "silent auto-link / pre-account takeover" that round-1 Critical #1 blocked — reintroduced through the fix for round-1 Critical #2. Neither the research report (which authored this pattern, lines 84-85) nor `phase-03` flags it.
- **Evidence:** `phase-03:57` (`return prisma.user.findUniqueOrThrow({ where: { email: profile.email! } })`) vs. the guard it bypasses at `phase-03:44-45`; controller mints a session from the returned row at `phase-03:32-33`; research report `research-260702-1706-...md:84-85` proposes the same blind refetch. Phase 4's only concurrency test fires two requests with the *same facebookId* (`phase-04:42`) — the email-collision race is never exercised.
- **Suggested fix:** On an email-P2002 refetch, do NOT return the row. Re-run the branch logic on the refetched user: if it has `passwordHash` and its `facebookId` is null/differs, throw `ConflictException({ code: 'EMAIL_LINK_REQUIRED' })` exactly as the non-race path does. Only return directly when the refetched row's `facebookId === profile.id` (true same-identity race). Add a Phase 4 e2e that races `POST /auth/register` (same email) against `POST /auth/facebook` and asserts 409, never a 200 with a JWT.

## Finding 2: `linkFacebookAccount` never checks that `profile.id` is already linked to a *different* user, and has no P2002 handling → unhandled 500 + identity confusion
- **Severity:** High
- **Location:** Phase 3, "Architecture" — `linkFacebookAccount` (`phase-03:75-94`)
- **Flaw:** `findOrCreateFacebookUser` looks up by `facebookId` first (`phase-03:38`) so an already-linked identity logs straight in. `linkFacebookAccount` does NOT — it only looks up by `email` (`phase-03:76-77`). Its guard (`phase-03:82`) only catches "this email-row already has a *different* facebookId"; it never catches "this `profile.id` is already on some *other* row." The final `update({ data: { facebookId: profile.id } })` (`phase-03:90-93`) writes to a `@unique` column with no `try/catch` — unlike `findOrCreateFacebookUser`, which wraps its write (`phase-03:49-60`).
- **Failure scenario:** A Facebook-only user U2 was created earlier with `facebookId=F, email=null` (email permission denied — a supported path, `phase-02:32,59`). A separate password user U1 exists with `email=E1`. The Facebook account later exposes email E1 (user adds/verifies it). A client POSTs `/auth/facebook/link-confirm` with F's token (profile `{id:F, email:E1}`) + U1's password. `linkFacebookAccount` finds U1 by email E1, U1.facebookId is null so the guard at line 82 passes, bcrypt passes, then `update({ facebookId: F })` collides with U2's existing `facebookId=F` → `P2002` → no catch → unhandled 500 from the default NestJS filter. Beyond the crash, the design has no answer for "this Facebook identity already belongs to another account," so even a graceful version would be ambiguous.
- **Evidence:** `phase-03:76-77` (lookup by email only, no facebookId lookup), `phase-03:90-93` (unguarded `update` on unique `facebookId`), contrasted with the P2002 catch that exists only in `findOrCreateFacebookUser` at `phase-03:53-60`. Phase 4 has no test for this (`phase-04:37-42`).
- **Suggested fix:** In `linkFacebookAccount`, first `findUnique({ where: { facebookId: profile.id } })`; if it exists and is a different row than the email-matched user, reject (`409`) with a clear "this Facebook account is already linked elsewhere" code. Wrap the `update` in the same `P2002` catch as `findOrCreateFacebookUser`. Add Phase 4 coverage.

## Finding 3: `link-confirm` crashes on a null Facebook email — `findUnique({ where: { email: null } })` is invalid at runtime
- **Severity:** High
- **Location:** Phase 3, "Architecture" — `linkFacebookAccount` (`phase-03:76-77`); DTO steps (`phase-03:111-112`)
- **Flaw:** `POST /auth/facebook/link-confirm` validates only `accessToken` and `password` as non-empty strings (`phase-03:20,112`); it does not (and cannot) validate the Facebook profile's email. `linkFacebookAccount` then calls `prisma.user.findUnique({ where: { email: profile.email } })` (`phase-03:77`). `profile.email` is `email ?? null` (`phase-02:32`), so it can be `null`. Prisma `findUnique` requires a non-null value for a nullable unique field; `where: { email: null }` throws `PrismaClientValidationError` — which is NOT a `P2002` and is caught by nothing here → unhandled 500 on a public auth endpoint.
- **Failure scenario:** `link-confirm` is a public route. A token from a user who denied the `email` permission is valid (Phase 2 explicitly returns `email: null` without throwing, `phase-02:59`). A buggy or hostile client calls `link-confirm` directly with such a token → 500. The happy-path FE only reaches link-confirm after a 409 (which requires a non-null email), but a red-team assumes the endpoint is called directly; there is no boundary guard.
- **Evidence:** `phase-02:32` (`email: email ?? null`), `phase-03:77` (`findUnique({ where: { email: profile.email } })`), `phase-03:112` (DTO validates only accessToken+password). No `if (!profile.email)` guard anywhere in `phase-03`.
- **Suggested fix:** Guard at the top of `linkFacebookAccount`: `if (!profile.email) throw new BadRequestException(...)` (or `UnauthorizedException` to avoid oracle) before any Prisma call. Add a Phase 4 case: link-confirm with an email-less token → 400/401, not 500.

## Finding 4: P2002 recovery is fragile — `meta.target` shape is connector-dependent, and `findUniqueOrThrow` can itself throw on a rolled-back racer
- **Severity:** Medium
- **Location:** Phase 3, "Architecture" — catch block (`phase-03:55-57`)
- **Flaw:** Two recovery-path weaknesses. (a) `const target = (e.meta?.target as string[]) ?? []` (`phase-03:55`) hard-casts `meta.target` to a string array of field names, then `target.includes('facebookId')`. Prisma's `meta.target` shape is connector-dependent — on PostgreSQL it has historically been the constraint-name *string* (e.g. `"User_email_key"`), not a `['email']` array. `.includes()` on a string does a substring match, so this only works *by coincidence* (`"User_email_key".includes('email')` is true), and the `as string[]` cast is a lie. The plan pins no Prisma version (`package.json` has no prisma dep — verified), so a version/connector change that returns a different constraint name or a real field array silently breaks branch dispatch → falls through to `throw e` → 500. (b) If the winning racer's row is rolled back (e.g. the concurrent transaction aborts) between the P2002 and the refetch, `findUniqueOrThrow` (`phase-03:56-57`) throws `P2025` NotFound → unhandled 500.
- **Failure scenario:** After a Prisma major upgrade during B4/B5, `meta.target` returns `['email']` (array of field names) — substring logic still happens to work; but if it returns a differently-formatted constraint name, `.includes('facebookId')` is false and the genuine race surfaces as a 500 — the exact outcome the catch was written to prevent. Separately, a P2002-then-rollback race yields a `findUniqueOrThrow` P2025 crash.
- **Evidence:** `phase-03:55` (`as string[]` cast + `?? []`), `phase-03:56-57` (`findUniqueOrThrow`); no Prisma version pinned (`grep -nE "prisma" package.json` → no match).
- **Suggested fix:** Pin the Prisma version this pseudocode assumes and normalize `meta.target` defensively (handle both string and string[]); on refetch, use `findUnique` and re-throw the original `P2002` (or a 409) if the row is unexpectedly absent, rather than letting `findUniqueOrThrow`'s P2025 escape.

## Finding 5: Phase 1 migration has no rollback path once Facebook-only rows exist — down-migration to NOT NULL is impossible
- **Severity:** Medium
- **Location:** Phase 1, "Implementation Steps" / "Success Criteria" / "Risk Assessment" (`phase-01:44-61`)
- **Flaw:** The migration widens `email`/`passwordHash` from `NOT NULL` to nullable (`phase-01:36`) and the feature then creates rows with `passwordHash: null` (`phase-03:51`) and possibly `email: null`. Prisma migrations have no auto-generated down-migration. Phase 1 documents forward data-safety (`phase-01:16,54`) but says nothing about rollback. Once even one Facebook-only user exists, any attempt to revert the schema to `NOT NULL` fails (`ALTER COLUMN ... SET NOT NULL` errors on existing null rows).
- **Failure scenario:** B7 ships, Facebook-only users register (null passwordHash), a production incident forces a rollback of the B7 deploy. The application code reverts, but the DB schema cannot revert to the B4 shape without a manual data-backfill/cleanup step that is documented nowhere — leaving schema and code versions mismatched during the incident window (a Prisma Client generated for `passwordHash: string` reading `null` rows → runtime type violations).
- **Evidence:** `phase-01:36` (NOT NULL → nullable), `phase-03:51` (`passwordHash: null` on create); no "rollback" / "down migration" / "revert" text anywhere in `phase-01` (grep of the phase file). Prior rounds addressed forward `migrate deploy` (Finding 5) but not rollback.
- **Suggested fix:** Add a Phase 1 note: rollback is one-way once Facebook-only rows exist; document the required forward-fix (roll code forward, not schema back) or a data-cleanup precondition, and state that no automated down-migration exists.

## Finding 6: Phase 4 does not test the flows Phase 3 marks as critical — contract-verifier downstream gaps
- **Severity:** Medium
- **Location:** Phase 4, "Implementation Steps" (`phase-04:32-43`) vs. Phase 3 Success Criteria (`phase-03:119-129`)
- **Flaw:** Enumerating Phase 3's critical flows against Phase 4's test list:
  - Email-collision race (Finding 1) — Phase 4's only concurrency test uses the *same facebookId* (`phase-04:42`); the register-vs-facebook same-email race that triggers the security regression is untested.
  - `link-confirm` "already linked to a different facebookId → 409" — a Phase 3 Success Criterion (`phase-03:126`) — is only in the *mocked* unit test (`phase-04:33`), never e2e; a mock can't prove the guard fires against real DB state.
  - `link-confirm` with a null-email token (Finding 3) — not tested (`phase-04:37-42`).
  - `link-confirm` where `profile.id` is already on another row (Finding 2) — not tested.
  - The "prove the test isn't useless" mutation gates (`phase-04:49-50`) cover only the 409-revert and the facebookId-race 500 — they do not cover the email-P2002 path, so removing the Finding-1 fix would leave all tests green.
- **Failure scenario:** Phase 4 passes fully green while the Finding-1 bypass, the Finding-2 crash, and the Finding-3 crash all ship — the test suite gives false confidence exactly on the highest-severity flows.
- **Evidence:** `phase-04:42` (same-facebookId race only), `phase-04:33` (already-linked only mocked), `phase-04:37-42` (e2e list omits null-email and profile.id-already-used), `phase-04:49-50` (mutation gates omit email path); vs. `phase-03:123,126` (criteria that need e2e coverage).
- **Suggested fix:** Add e2e cases for: register-vs-facebook same-email race (assert 409, not a JWT); link-confirm against an already-linked-elsewhere facebookId; link-confirm with an email-less token. Add a mutation gate for the email-refetch bypass.

## Finding 7: `signToken` sync contract will silently serialize a Promise if B4 ships the common async JWT setup
- **Severity:** Medium
- **Location:** `b4-contract-stub.md:19`; Phase 3 (`phase-03:32,70`)
- **Flaw:** The stub pins `signToken(userId: string): string` — synchronous (`b4-contract-stub.md:19`) — and Phase 3 calls it unawaited: `jwt = AuthService.signToken(user.id); return { accessToken: jwt }` (`phase-03:32-33,70-71`). But the idiomatic NestJS pattern registers `JwtModule.registerAsync` with the secret from `ConfigService` and signs via `jwtService.signAsync(...)`, which returns `Promise<string>`. B4 does not exist yet, so nothing forces the sync shape. If B4 implements `signToken` as async (very common), `phase-03`'s unawaited call assigns a Promise to `jwt`, and `return { accessToken: <Promise> }` serializes to `{}` / `[object Promise]` — every Facebook login returns a broken token with no error.
- **Failure scenario:** B4 is built independently, uses `signAsync` (the default many tutorials/NestJS docs show). B7 is then coded literally per `phase-03` (no `await`). Login "succeeds" (200) but the token is unusable; `JwtAuthGuard` rejects it on the next call — a confusing, non-crashing failure that passes a naive "returns 200" smoke test.
- **Evidence:** `b4-contract-stub.md:19` (sync signature), `phase-03:32,70` (unawaited call). The stub's own escape clause ("if B4 deviates, resolve before B7") acknowledges drift is possible but does not make the sync choice safe against the more common async idiom.
- **Suggested fix:** Either make the contract `signToken(userId: string): Promise<string>` and `await` it in `phase-03` (safe against both sync and async JWT setups since `await` on a sync return is harmless), or add an explicit Phase 3 acceptance check that decodes the returned token and asserts `sub === user.id` (already listed at `phase-03:121`) is run as a real assertion, not just prose.

---

## Summary Table

| # | Title | Severity |
|---|-------|----------|
| 1 | P2002 email-refetch silently re-opens the Option B bypass under race | Critical |
| 2 | link-confirm: no already-linked-elsewhere check + no P2002 catch → 500 | High |
| 3 | link-confirm crashes on null Facebook email (`findUnique({email:null})`) | High |
| 4 | Fragile P2002 recovery: `meta.target` shape assumption + `findUniqueOrThrow` P2025 | Medium |
| 5 | Migration rollback hole once Facebook-only null rows exist | Medium |
| 6 | Phase 4 misses coverage for Phase 3's critical flows (incl. the Finding-1 path) | Medium |
| 7 | `signToken` sync contract breaks silently if B4 ships async JWT | Medium |

**Bottom line:** Findings 1 and 6 together mean the headline Option B security fix is not actually complete — the race path bypasses it and no test would catch the regression. Findings 2 and 3 are new unhandled-crash paths in the freshly-added `link-confirm` endpoint. Recommend blocking on Findings 1–3 before this plan is treated as implementation-ready.
