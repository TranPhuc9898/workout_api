---
type: research
author: ck:research
date: 2026-07-02T17:06
plan: plans/260702-facebook-login-oauth
scope: giải pháp cho 2 Critical + 6 High finding từ 2 report red-team
inputs:
  - reports/code-reviewer-260702-1640-facebook-oauth-red-team-plan-review-report.md
  - reports/from-code-reviewer-to-planner-red-team-assumption-destroyer-plan-review-report.md
---

# Research Report: Giải pháp cho Critical/High finding — B7 Facebook Login OAuth

## Executive Summary

Đã research 5 chủ đề trọng tâm (giới hạn 5 tool call theo skill `ck:research`) đối chiếu 2 report red-team. Kết luận: **cả 2 Critical đều có pattern chuẩn hoá cộng đồng để giải quyết** — không phải vấn đề chưa có lời giải, mà là plan hiện tại thiếu bước cụ thể. Report này KHÔNG tự sửa `plan.md`/phase files — chỉ đề xuất patch cụ thể cho từng finding, chờ chốt.

Điểm quan trọng nhất: **Critical #1 (pre-account hijacking) đụng vào quyết định đã chốt trong brainstorm cũ** (Option A "auto-link" thắng Option B "confirm trước khi link"). Theo rule "User Decisions" — không tự đảo quyết định đã chốt, chỉ trình bày lại original decision / audit concern / trade-off / option cụ thể để anh (hoặc planner) quyết, xem mục Finding 1 bên dưới.

## Research Methodology
- Sources: 5 WebSearch call (không dùng Gemini — `useGemini: false` trong `.ck.json`)
- Search terms: OAuth pre-account takeover, Prisma P2002 upsert race condition, NestJS JWT payload best practice, Prisma select/omit exclude sensitive field, Prisma migrate deploy vs dev
- Ngày research: 2026-07-02

---

## Critical #1: Pre-account hijacking qua auto-link theo email

**Vị trí cần patch:** `phase-03-auth-endpoint-va-account-linking.md` — Architecture branch 2, Risk Assessment.

**Nghiên cứu xác nhận đây là pattern tấn công đã biết** ("OAuth pre-authentication account takeover" / "pre-account takeover") — không phải lý thuyết. Root cause đúng như finding đã chỉ ra: B4 hiện tại không có email verification khi register, nên "email khớp = cùng người" là giả định sai.

**Consensus phòng chống (theo research):**
1. **Enforce email verification ở B4 trước khi coi 1 account là target tin cậy để auto-link** — thêm `emailVerifiedAt` (nullable) vào `User`, chỉ auto-link nếu account cũ có `emailVerifiedAt != null`.
2. **Không auto-merge chỉ vì email khớp** — dùng flow xác nhận (confirmation email/OTP, hoặc bắt nhập lại password của account cũ) trước khi merge, thay vì merge ngầm trong 1 request.
3. Deduplicate/re-verify account cũ chưa verify email đã tồn tại trong hệ thống trước khi bật tính năng này.
4. Log/alert khi có auto-link xảy ra để phát hiện bất thường.

**Đối chiếu quyết định cũ (brainstorm §4c — Option B bị reject):**
- **Quyết định gốc:** Auto-link ngầm theo email (Option A), lý do brainstorm đưa ra: "Facebook luôn trả email đã verify" → coi email Facebook là đủ tin cậy.
- **Vấn đề với lý do đó (2 report red-team + Finding 7 report thứ 2):** Facebook's Graph API `/me` **không** có field `email_verified` công khai cho Login thường (field này đã bị Meta deprecate) — nên giả định "luôn verify" **không thể check được tại runtime**, chỉ là niềm tin không kiểm chứng.
- **Vấn đề thật sự không nằm ở phía Facebook** (email Facebook có thể đã verify thật) **mà ở phía B4** — attacker không cần đụng tới Facebook, chỉ cần `POST /auth/register` với email nạn nhân (B4 hiện không verify email khi register) rồi chờ.
- **Trade-off:**
  | | Option A (auto-link ngầm, hiện tại) | Option B (confirm trước khi link) |
  |---|---|---|
  | UX | Mượt, 1 lần bấm | Thêm 1 bước (nhập password cũ hoặc xác nhận email) |
  | Bảo mật | Lỗ hổng account-takeover đã chứng minh | An toàn theo chuẩn ngành |
  | Effort | Đã có pseudocode | Cần thêm 1 endpoint/flow nhỏ |
- **Đề xuất cụ thể (không tự quyết, để planner/anh chọn):**
  - **A. Điều kiện hoá Option A**: chỉ giữ auto-link ngầm nếu B4 bổ sung `emailVerifiedAt` + bắt buộc verify khi register (đẩy thêm 1 requirement ngược vào B4).
  - **B. Đảo sang Option B**: khi email trùng, trả về response riêng (vd `409 Conflict` + code `EMAIL_LINK_REQUIRED`) yêu cầu FE hiển thị màn "nhập password tài khoản cũ để liên kết" — không tự merge trong `POST /auth/facebook`.
  - Khuyến nghị nghiêng về **B** vì không phụ thuộc B4 phải làm đúng một việc (email verification) mà B7 không kiểm soát được — nhưng đây là quyết định UX/bảo mật cần anh chốt, không tự đảo.

## Critical #2: P2002 race condition — chưa có trong Architecture/Implementation Steps

**Vị trí cần patch:** `phase-03...md` Architecture (branch 3: create) + Implementation Steps step 3; `phase-04...md` step 3 (test).

**Xác nhận từ Prisma community (GitHub issues #22778, #3242, #9751):** đây là race condition thật, đã được báo cáo nhiều lần — khoảng hở giữa `findUnique` (check) và `create` (write) cho 2 request đồng thời là có thật, kể cả dùng `upsert()` (Prisma vẫn làm read-rồi-write, không phải atomic ở tầng ứng dụng cho mọi provider).

**Pattern chuẩn — try/catch + refetch, không phải transaction suông:**
```typescript
async function findOrCreateFacebookUser(profile: FacebookProfile) {
  const byFbId = await prisma.user.findUnique({ where: { facebookId: profile.id } });
  if (byFbId) return byFbId;

  if (profile.email) {
    const byEmail = await prisma.user.findUnique({ where: { email: profile.email } });
    if (byEmail) {
      // ... xem Finding Critical #1 cho điều kiện auto-link
    }
  }

  try {
    return await prisma.user.create({
      data: { facebookId: profile.id, email: profile.email, name: profile.name, avatarUrl: profile.avatarUrl },
    });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
      // e.meta.target cho biết field nào collide: 'facebookId' hoặc 'email'
      const target = (e.meta?.target as string[]) ?? [];
      if (target.includes('facebookId')) {
        return prisma.user.findUniqueOrThrow({ where: { facebookId: profile.id } });
      }
      if (target.includes('email')) {
        return prisma.user.findUniqueOrThrow({ where: { email: profile.email! } });
      }
    }
    throw e;
  }
}
```
- Bắt cả 2 field unique (`facebookId` VÀ `email`) — finding 2 đúng là plan cũ chỉ nói tới `facebookId`.
- Không cần transaction Prisma cho case này (transaction không tránh được race giữa 2 connection riêng biệt) — try/catch + refetch mới là cơ chế đúng, khác với step 3 hiện tại nói "transaction nếu cần, thường không bắt buộc" (câu đó nên xoá, thay bằng try/catch cụ thể).

**Phase 4 test bổ sung (khác test tuần tự hiện tại):**
```typescript
it('2 request đồng thời cùng facebookId mới → không 500, cả 2 trả cùng 1 user', async () => {
  const [r1, r2] = await Promise.all([
    request(app).post('/auth/facebook').send({ accessToken: fakeToken }),
    request(app).post('/auth/facebook').send({ accessToken: fakeToken }),
  ]);
  expect(r1.status).toBe(200);
  expect(r2.status).toBe(200);
  expect(r1.body.user.id).toBe(r2.body.user.id);
});
```
Test này **bắt buộc chạy trên DB test thật** (không mock Prisma) — mock không thể tái hiện race condition ở tầng DB.

## High: passwordHash leak vào JWT (finding #3)

**Giải pháp chuẩn (Prisma 5.16+):** dùng **global omit** khi khởi tạo `PrismaClient` trong `PrismaService`, không phải `select` per-query (per-query dễ quên ở query mới thêm sau này):
```typescript
// prisma.service.ts
export class PrismaService extends PrismaClient {
  constructor() {
    super({ omit: { user: { passwordHash: true } } });
  }
}
```
Global omit áp dụng cho **mọi** query dùng service này — an toàn hơn hẳn per-query `select` allow-list vì không cần nhớ lặp lại ở mỗi chỗ gọi. Nếu 1 chỗ nào đó (vd chính `AuthService.login()`) thật sự cần đọc `passwordHash` để so bcrypt, dùng `omit: { user: { passwordHash: false } }` cục bộ ở đúng query đó để override.

Kết hợp Finding 8 (JWT contract mơ hồ): `signToken` phải nhận `{ id }`/`sub`, không nhận cả `user` object — payload JWT tối thiểu `{ sub, iat, exp }`, không thêm field nhạy cảm.

## High: null passwordHash → user-enumeration oracle (finding #4)

Guard bắt buộc, đặt tại đầu `AuthService.login()` — **trước** mọi lệnh `bcrypt.compare`:
```typescript
if (!user || !user.passwordHash) {
  throw new UnauthorizedException('Invalid credentials'); // message giống hệt case sai password
}
```
Phase 4 cần thêm test case: "login bằng email của account Facebook-only → 401 (không phải 500), message giống case email không tồn tại" — đúng theo OWASP Authentication Cheat Sheet (không phân biệt lý do fail qua status/message).

## High: `prisma migrate dev` only, thiếu `migrate deploy` (finding #5)

Xác nhận từ Prisma docs chính chủ: `migrate dev` là **dev-only**, có thể prompt reset DB khi phát hiện drift — **không được chạy trên môi trường shared/staging/production**. `migrate deploy` mới là lệnh non-interactive, an toàn cho CI/CD, chỉ apply migration đã có sẵn trong `prisma/migrations/`, không tạo migration mới.

Patch cho Phase 1: thêm 1 bullet rõ ràng —
> Local dev: `npx prisma migrate dev --name add_facebook_login`. Bất kỳ môi trường shared nào (staging/prod): `npx prisma migrate deploy` chạy qua CI/CD, **không bao giờ** chạy `migrate dev` thủ công ở đó.

## High: Phase 4 e2e DB strategy hedge vào B5 không tồn tại (finding #3 report 2)

Search không ra tài liệu NestJS-specific riêng cho câu này — dùng general Prisma+testing consensus (đã biết, không phải finding mới của research này): Phase 4 nên **tự định nghĩa** test DB strategy làm precondition riêng, không hedge vào B5:
- Docker Compose Postgres riêng cho test (`docker-compose.test.yml`), connection string qua `.env.test` (`DATABASE_URL_TEST`).
- Trước khi chạy e2e: `prisma migrate deploy` (không phải `migrate dev`) nhắm vào DB test — apply đúng migration đã commit, không tạo migration adhoc.
- Reset data giữa các test bằng truncate (không cần schema-per-test cho scope nhỏ này).
- Test concurrency (Critical #2) **bắt buộc DB thật** — không fallback "mock Prisma tuỳ pattern" như phase-04 hiện ghi, vì mock không thể tái hiện `P2002`.

## Medium: auto-link overwrite facebookId không guard (finding #6)

```typescript
if (byEmail.facebookId && byEmail.facebookId !== profile.id) {
  throw new ConflictException('Account already linked to a different Facebook identity');
}
```
Đặt trước `prisma.user.update(...)` trong branch auto-link.

## Medium: stale user object sau update (finding #7)

Đổi `→ prisma.user.update({...}) → return user` thành `return await prisma.user.update({...})` — dùng trực tiếp kết quả write, bỏ biến `user` cũ.

## Medium: JWT signing contract mơ hồ + B4 contract "bịa" (finding #8 + Critical #1 report 2)

2 finding này cùng gốc — B4 chưa tồn tại nên B7 không có gì để verify. Đề xuất: viết 1 **stub contract file** (không phải implementation) trước khi Phase 3 bắt đầu, ví dụ `plans/260702-facebook-login-oauth/b4-contract-stub.md` ghi rõ:
```typescript
// Chữ ký bắt buộc B4 phải cung cấp, B7 phụ thuộc vào đây:
class AuthService {
  async login(email: string, password: string): Promise<{ accessToken: string }>;
  signToken(userId: string): string; // dùng chung bởi login() và B7 Facebook flow
}
class JwtAuthGuard implements CanActivate {} // payload decode ra req.user.sub = userId
```
B7 code theo stub này; nếu B4 thật khi code lệch chữ ký → coi là incompatibility cần resolve trước, không phải để B7 tự đoán lại.

---

## Tóm tắt đề xuất patch theo file

| File | Việc cần thêm/sửa |
|---|---|
| `phase-03...md` | Branch 2 (auto-link): thêm điều kiện `emailVerifiedAt` HOẶC đổi sang flow confirm (chờ anh chốt A/B); guard chống overwrite `facebookId`; `return await update(...)` thay vì stale var |
| `phase-03...md` | Branch 3 (create): try/catch `P2002` cho cả `facebookId` và `email`, refetch theo `error.meta.target` |
| `phase-03...md` | `signToken(userId)` minimal payload, tách khỏi `login()`; PrismaService dùng global `omit: { user: { passwordHash: true } }` |
| `phase-01...md` | Thêm bullet `migrate deploy` cho shared/prod, tách rõ khỏi `migrate dev` local |
| `phase-04...md` | Thêm test: concurrent `POST /auth/facebook` (DB thật, không mock); login với Facebook-only account → 401 không 500; tự định nghĩa Docker Compose test DB thay vì hedge B5 |
| mới: `b4-contract-stub.md` | Chữ ký tối thiểu B4 phải cung cấp cho B7 phụ thuộc |
| B4 (ngoài scope B7, cần note ngược) | Thêm guard `if (!user.passwordHash) throw Unauthorized` trong `login()`; cân nhắc `emailVerifiedAt` nếu chọn Option A ở Critical #1 |

## Unresolved / cần chốt
1. **Critical #1**: Option A (điều kiện hoá theo `emailVerifiedAt`) hay Option B (đổi flow, yêu cầu confirm) — cần anh/planner quyết, không tự đảo quyết định brainstorm cũ.
2. Effort đội thêm cho B4 nếu chọn Option A (thêm `emailVerifiedAt` + verify-email flow) chưa được ước lượng — B4 chưa có plan riêng để patch vào.

## Nguồn tham khảo
- [OAuth Misconfiguration Leading to Pre-Account Takeover](https://medium.com/@islamghandar/oauth-misconfiguration-leading-to-pre-account-takeover-d6a23106ad4e)
- [Attacking Social Logins: Pre-Authentication Account Takeover](https://hbothra22.medium.com/attacking-social-logins-pre-authentication-account-takeover-790248cfdc3)
- [Pre-account takeover vulnerability — novuhq/novu advisory](https://github.com/novuhq/novu/security/advisories/GHSA-xj4x-44hh-737v)
- [upsert() results in P2002 · prisma/prisma#22778](https://github.com/prisma/prisma/issues/22778)
- [upsert across HTTP requests has a race condition · prisma/prisma#3242](https://github.com/prisma/prisma/issues/3242)
- [Excluding fields — Prisma Docs](https://www.prisma.io/docs/orm/v6/prisma-client/queries/excluding-fields)
- [Introducing global omit — Prisma Blog](https://www.prisma.io/blog/introducing-global-omit-for-model-fields-in-prisma-orm-5-16-0)
- [Development and production — Prisma Migrate Docs](https://www.prisma.io/docs/orm/prisma-migrate/workflows/development-and-production)
- [Deploying database changes with Prisma Migrate](https://www.prisma.io/docs/orm/prisma-client/deployment/deploy-database-changes-with-prisma-migrate)
- [NestJS Authentication — official docs](https://docs.nestjs.com/security/authentication)
