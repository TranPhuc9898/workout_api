---
type: red-team-review
reviewer: code-reviewer
date: 2026-07-02
plan: plans/260702-facebook-login-oauth
verdict: not-implementation-ready (blocked on B4 not existing; plan has unverified/inconsistent internal assumptions)
---

# Red Team Review — B7 Facebook Login (OAuth) Plan

## Finding 1: B4's `signToken`/`JwtAuthGuard` contract is invented, not verified
- **Severity:** Critical
- **Location:** plan.md, "Giải pháp đã chốt" (line 28); Phase 3, "Architecture" (line 37) and Success Criteria (line 58)
- **Flaw:** The plan repeatedly says it will "tái dùng `JwtAuthGuard` và cơ chế sign token đã có từ B4" and even names a specific method `AuthService.signToken(user)` (phase-03 line 37: `jwt = AuthService.signToken(user)  // tái dùng hàm đã có từ B4`). B4 does not exist anywhere in this repo or in any other plan — confirmed via `grep -rn "signToken\|JwtAuthGuard\|PrismaService\|AuthService" src` returning zero matches, and `plan.md` line 44 itself states B0-B6 "không có `blockedBy` cross-plan chính thức". There is no artifact anywhere that defines: the guard's exact name, the token payload shape (`sub`? `email`? `role`?), whether `signToken` takes a full Prisma `User` object or a DTO, or whether it's synchronous/async.
- **Failure scenario:** When B4 actually gets implemented (by a separate, unrelated task), the author is free to name the guard `AuthGuard`, use Passport's `JwtStrategy` decorator directly instead of a custom guard class, or write `AuthService.login(user)` that returns `{accessToken, user}` instead of a bare string. Phase 3 Implementation Step 4 ("Tái dùng hàm sign JWT đã viết ở B4 ... không viết lại logic JWT") then becomes unactionable — the engineer implementing B7 has to reverse-engineer B4's undocumented internals with no contract to check against, and Success Criteria's assumption ("decode được, có `sub` = user id", line 58) may simply be wrong for whatever B4 shipped.
- **Evidence:** `plan.md:28`, `phase-03...md:37`, `phase-03...md:58`; `grep -rn "signToken\|JwtAuthGuard\|PrismaService\|AuthService" src` → no output (B4 code does not exist).
- **Suggested fix:** Either (a) write a minimal B4 interface contract stub (method signatures only, no implementation) that this plan formally depends on and treat any deviation as a blocking incompatibility to resolve before Phase 3, or (b) explicitly mark Phase 3's JWT integration steps as "TBD — pending B4 contract inspection" rather than presenting a concrete pseudocode call as if it were verified.

## Finding 2: Account-linking (step 2) can silently overwrite an already-linked `facebookId`
- **Severity:** High
- **Location:** Phase 3, "Architecture" (lines 29-38), Requirements (line 17)
- **Flaw:** The pseudocode branch 2 is only reached "chưa có `facebookId`" for the *incoming* profile (step 1 lookup by the new `profile.facebookId` found nothing). It then finds a user by `profile.email` and unconditionally runs `prisma.user.update({ where: { id: user.id }, data: { facebookId: profile.facebookId, ... } })`. There is no check for whether that matched user **already has a different `facebookId` set**. Requirements (line 17) only describes "user cũ (đăng ký password)" for this branch, but the architecture doesn't actually verify `user.facebookId === null` before overwriting.
- **Failure scenario:** A user registered with email/password, later linked Facebook account A (`facebookId = "111"`). If that user's email is later associated with a different Facebook account B (e.g., they change their Facebook email to match, or an admin/attacker scenario), a login with account B's token would match by email in branch 2 and silently overwrite `facebookId` from "111" to account B's id — unlinking account A without any user consent flow, warning, or audit trail. This is a data-integrity/account-takeover-adjacent bug, not just an edge case.
- **Evidence:** Quote, phase-03 line 33-35: `2. if profile.email: user = prisma.user.findUnique({ where: { email: profile.email } }) → found (user cũ có passwordHash, chưa có facebookId) → prisma.user.update(...)`. The comment "chưa có facebookId" is asserted in prose but never checked in code.
- **Suggested fix:** Add an explicit guard: if the email-matched user already has a non-null `facebookId` different from `profile.facebookId`, this is an anomaly — reject (409/403) rather than silently overwrite, and log/alert. At minimum, add `AND facebookId: null` semantics or a runtime check before the `update`.

## Finding 3: Phase 4's e2e test DB strategy is unresolved — hedged on a nonexistent B5 pattern
- **Severity:** High
- **Location:** Phase 4, Implementation Steps (line 30), Risk Assessment (line 43)
- **Flaw:** Phase 4 step 3 says: "verify response có JWT hợp lệ và DB có user mới (**nếu dùng DB test riêng**) hoặc mock Prisma **tuỳ theo pattern e2e đã dùng ở B5**." Risk Assessment doubles down: "Ít nhất 1 e2e test chạy trên DB test thật (không mock Prisma) để bắt lỗi constraint thật." This assumes B5 already established a "DB test riêng" (dedicated test database) pattern. No B5 plan exists in this repo (`find plans -iname "*roadmap*"` and `find plans` return nothing beyond this single B7 plan directory), and the current test infra confirmed via `test/app.e2e-spec.ts` and `test/jest-e2e.json` has zero DB wiring — it only boots `AppModule` with no Prisma, no test-DB config, no `.env.test`. The plan's own dependency note (phase-02 line 35) references "`@nestjs/config` (đã setup ở B5)" as an assumption too — B5 is cited as settled fact in two different phases despite having no defined content anywhere in this codebase or plan tree.
- **Failure scenario:** When Phase 4 is actually implemented, there is no concrete decision on: test DB provisioning (docker-compose? separate schema? transactional rollback per test?), whether Prisma's real unique-constraint behavior (needed to validate the Finding-2/race-condition mitigation) is testable at all under the "mock Prisma" fallback path. The success criterion "Ít nhất 1 e2e test chạy trên DB test thật" cannot be verified as satisfied because the plan provides no environment/config for that DB to exist.
- **Evidence:** `phase-04...md:30`, `phase-04...md:43`, `phase-02...md:35`; `cat test/jest-e2e.json` (no DB env config); `find plans -iname "*roadmap*"` → no results in workout-api project (only unrelated files under a different project `VinGroup/flutter`).
- **Suggested fix:** Either write a B5 contract stub (test DB provisioning approach) as an explicit precondition of Phase 4, same as Finding 1's recommendation for B4, or scope Phase 4 down to fully-mocked Prisma tests only and explicitly flag the constraint-behavior gap (P2002 handling) as untested/unverified rather than implying it will be covered "tuỳ theo pattern."

## Finding 4: Race-condition mitigation described in Risk Assessment is absent from the actual Architecture/Implementation Steps, and doesn't cover the email-uniqueness collision case
- **Severity:** Medium
- **Location:** Phase 3, Implementation Steps (line 52) vs. Risk Assessment (lines 66-67)
- **Flaw:** Implementation Steps says: "Implement `findOrCreateFacebookUser()` ... dùng transaction Prisma **nếu cần atomic (thường không bắt buộc cho case đơn giản này)**" — i.e., no transaction, no explicit error handling written into the plan. Yet Risk Assessment for the exact same phase claims: "`facebookId` đã có `@unique` ở DB — request thứ 2 sẽ lỗi constraint, **bắt lỗi Prisma `P2002` và fallback sang tìm lại user**." No `try/catch` or `P2002` handling appears anywhere in the Architecture pseudocode (lines 26-39) or Implementation Steps (lines 50-55). The mitigation is asserted as if implemented but isn't specified as an actual step. Additionally, branch 3 (`prisma.user.create`) also writes `email: profile.email` — if two concurrent requests race with different `facebookId` but the same (rare, but possible via Facebook business/shared) `email`, a `P2002` can also fire on the `email` unique constraint, which the plan never mentions handling (only `facebookId` collision is discussed).
- **Failure scenario:** An engineer implementing this phase from the plan as written literally skips the transaction/catch logic per Implementation Steps' own "not required" guidance, then hits unhandled `PrismaClientKnownRequestError P2002` in production during a genuine concurrent double-tap (e.g., mobile app double-fires the Facebook login call), returning an unhandled 500 instead of the JWT — with no fallback code specified anywhere to actually retry the lookup.
- **Evidence:** `phase-03...md:52` vs `phase-03...md:66-67`.
- **Suggested fix:** Make the Implementation Steps explicit: wrap `create` in try/catch for `P2002` on both `facebookId` and `email`, and re-fetch-then-return on conflict. Remove the "thường không bắt buộc" hedge or justify it against the stated risk mitigation, since the two currently contradict each other.

## Finding 5: "At least one of passwordHash or facebookId" invariant is a stated Requirement with no implementation mechanism or test anywhere in the plan
- **Severity:** Medium
- **Location:** Phase 1, Requirements (line 18)
- **Flaw:** Phase 1 states as a hard requirement: "Tầng application (không phải DB constraint) phải đảm bảo mỗi user có ít nhất `passwordHash` HOẶC `facebookId` — Prisma không tự enforce 'at least one of N columns'." No phase (1, 2, 3, or 4) defines where this check lives — not a Prisma middleware, not a service-layer guard, not a DB `CHECK` constraint, nothing. Phase 4's test list (lines 34-38) covers auto-link regression and B4 regression but never tests this invariant.
- **Failure scenario:** Nothing in the current architecture actually violates this today (register requires both via DTO, Facebook flow always sets `facebookId`), so it happens to hold by accident of the two flows' current shape — but the plan calls out this exact invariant as something Prisma cannot protect and then never wires any enforcement or regression test for it. A future third registration path (e.g., admin-created user, bulk import script) could trivially create a user with neither field and there is no test or guard anywhere in this plan that would catch it.
- **Evidence:** `phase-01...md:18` (requirement stated) vs. `phase-04...md:33-38` (Success Criteria — no mention of this invariant).
- **Suggested fix:** Either add a concrete enforcement point (e.g., a Prisma `$use` middleware validating on write, or an explicit check inside every service method that creates a `User`) and a corresponding unit test, or downgrade the Phase 1 Requirement wording to reflect that it's currently only an emergent property of the two known call sites, not an enforced invariant.

## Finding 6: Precondition-gate document (`plans/visuals/nestjs-rest-postgres-learning-roadmap.html`) does not exist — B4 completion has no verifiable gate
- **Severity:** Medium
- **Location:** plan.md, "Dependencies" (line 44) and "⚠️ Điều kiện tiên quyết" callout (line 30)
- **Flaw:** plan.md explicitly names the roadmap HTML file as the authoritative tracker for B0-B6 status ("các bước đó được track qua checklist trong `plans/visuals/nestjs-rest-postgres-learning-roadmap.html`, không phải `ck plan`"), and frontmatter sets `blockedBy: []` (line 8) — meaning there is no tooling-level gate at all preventing this plan from being picked up for `/ck:cook` before B4 exists. A targeted search confirms this HTML file does not exist anywhere under `/Users/phucth13/Documents/workout-api` (checked `find ... -iname "*.html"` — only `node_modules` artifacts found) nor anywhere under `/Users/phucth13/Documents` outside an unrelated Flutter project.
- **Failure scenario:** The only thing standing between "project is at B1" and someone running `/ck:cook` on this B7 plan is a prose warning in the Overview section and a reference to a file that doesn't exist to check. If the roadmap file is created later in a different location or format than assumed, or if a future session doesn't re-read plan.md's prose carefully, there is no automated blocker — `blockedBy: []` means the plan system itself will not prevent premature execution.
- **Evidence:** `plan.md:30`, `plan.md:44`; `find /Users/phucth13/Documents/workout-api -iname "*.html"` → only `node_modules` files, no roadmap file; `find /Users/phucth13/Documents -iname "*roadmap*"` (excluding node_modules) → no match in workout-api.
- **Suggested fix:** Either create the referenced roadmap file now with at least a B4-status checkbox, or set `blockedBy` to reference a real tracked artifact (even a simple `plans/b4-auth-jwt.md` stub) so the dependency is mechanically checkable rather than only documented in prose.

## Finding 7: "Facebook luôn verify email" is asserted as a security-relevant fact with no way to check it in code
- **Severity:** Medium
- **Location:** Phase 2, Architecture (implicit) and the referenced brainstorm doc's Risk table (`brainstorm-260702-1633-facebook-login-oauth.md` line 92: "Auto-link nhầm tài khoản nếu Facebook trả email chưa verify | Low | Facebook luôn trả email đã verify (theo Graph API docs) — chấp nhận được"). Phase 3's auto-link branch (line 33-35) relies entirely on this assumption to justify trusting `profile.email` as an identity key strong enough to auto-link into an existing password account.
- **Flaw:** The plan treats "Facebook only returns verified emails" as a settled implementation fact, but Phase 2's `FacebookAuthService.verifyAccessToken()` (lines 24-33) never actually checks any verified-status field in the `/me` response — there isn't one requested (`fields=id,name,email,picture`, phase-02 line 31) and Meta's Graph API `/me` endpoint does not expose an explicit boolean `email_verified`/`verified` field for general Login (that field was deprecated years ago per public developer reports). The plan cannot verify its own trust assumption at runtime; it is pure reliance on undocumented platform behavior with no fallback or defense-in-depth check.
- **Failure scenario:** If Facebook's behavior differs for any account type not covered by the assumption (business-managed assets, accounts created via phone-only signup where email was added later without confirmation flow, or platform policy changes), `findOrCreateFacebookUser` will auto-link a Facebook identity onto an existing password-protected account using only email string equality — with zero code-level verification and zero test coverage of "what if the email isn't actually verified" (Phase 4's test list, lines 28-31, does not include this case).
- **Evidence:** Quote from brainstorm report line 92 (only doc containing the justification); `phase-02...md:31` (fields list has no verified-status field); Web search confirms behavior is described as generally-true-but-not-guaranteed-or-checkable via API ("the graph API only returns emails for users who have ... a verified email" — but no explicit verified field is fetched or checked by this plan).
- **Suggested fix:** At minimum, document this as an accepted residual risk explicitly in Phase 3 (not just buried in the brainstorm doc), and consider a defense-in-depth step: instead of auto-linking silently, send a confirmation notification (email or in-app) to the existing account when a Facebook-based auto-link occurs, so the account owner has visibility if this assumption ever fails.

## Finding 8: Swagger decorator step assumes an undeclared dependency and undefined prior style
- **Severity:** Low-Medium
- **Location:** Phase 3, Implementation Steps (line 54)
- **Flaw:** Step 5 says: "Thêm Swagger decorator (`@ApiOperation`, `@ApiBody`) khớp style B2/B4 đã dùng." This assumes (a) `@nestjs/swagger` is an installed dependency by the time B7 is implemented, and (b) B2/B4 established a specific decorator "style" to match. Confirmed via `cat package.json`: no `@nestjs/swagger` in current dependencies (expected, since B2/B4 aren't built yet), and — per Finding 6 — there's no tracked artifact defining what B2's Swagger style actually looks like once it exists.
- **Failure scenario:** Same class of problem as Finding 1/3: a concrete implementation step references a "style" from a phase that has no fixed specification anywhere in this repo, so the instruction is unverifiable at the time it would be executed and depends entirely on whatever ad hoc conventions happened to land in B2/B4.
- **Evidence:** `phase-03...md:54`; `grep swagger package.json` → no match (dependency doesn't exist yet, consistent with pre-B4 state, but the plan doesn't flag this as an open dependency to confirm).
- **Suggested fix:** Low priority given effort is "M" and this is a minor step, but should be marked explicitly as "pending B2 Swagger convention confirmation" rather than stated as a known, matchable style.

---

## Summary Table

| # | Title | Severity |
|---|---|---|
| 1 | B4 `signToken`/`JwtAuthGuard` contract invented, not verified | Critical |
| 2 | Account-linking can silently overwrite existing `facebookId` | High |
| 3 | Phase 4 e2e DB strategy hedged on nonexistent B5 pattern | High |
| 4 | Race-condition mitigation claimed but not in actual steps; email collision uncovered | Medium |
| 5 | "At least one of passwordHash/facebookId" invariant unenforced/untested | Medium |
| 6 | Roadmap tracking file referenced as gate does not exist | Medium |
| 7 | "Facebook always verifies email" unverifiable at runtime, no fallback | Medium |
| 8 | Swagger decorator step assumes undeclared dependency/style | Low-Medium |
