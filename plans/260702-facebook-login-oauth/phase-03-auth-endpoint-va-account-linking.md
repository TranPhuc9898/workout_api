---
phase: 3
title: "Auth Endpoint, JWT Infra va Account Linking"
status: pending
priority: P2
effort: "M"
dependencies: [1, 2]
---

# Phase 3: Auth Endpoint, JWT Infra va Account Linking

## Overview

B4 (Auth JWT baseline) chưa tồn tại trong repo — phase này tự bootstrap phần hạ tầng JWT tối thiểu mà Facebook flow cần (`signToken`, `JwtAuthGuard`), rồi thêm `POST /auth/facebook`: nhận `identityToken` từ client, verify qua `FacebookAuthService` (Phase 2), tìm/tạo `User` (Phase 1), phát JWT riêng hệ thống. Khi email trùng user cũ (đăng ký password), **không** tự động link — trả `409 EMAIL_LINK_REQUIRED`, yêu cầu xác nhận qua `POST /auth/facebook/link-confirm`. **Không build** `POST /auth/register`/`POST /auth/login` (password-based) — ngoài scope Path 2, xem `plan.md`.

## Requirements

- `signToken(userId: string)` tách biệt, payload tối thiểu `{ sub: userId }` — không nhận cả `user` object, không thêm field nhạy cảm (chữ ký này giữ nguyên cho `login()` dùng sau này nếu build).
- `JwtAuthGuard` decode JWT ra `req.user.sub = userId`.
- 3 nhánh xử lý user ở `POST /auth/facebook` phải đúng thứ tự ưu tiên: (1) đã có `facebookId` → login thẳng; (2) chưa có `facebookId` nhưng `email` trùng user cũ (có `passwordHash`) → **không auto-link**, trả `409` + code `EMAIL_LINK_REQUIRED`; (3) không match gì → tạo user mới.
- `POST /auth/facebook/link-confirm` là endpoint riêng, bắt buộc verify password tài khoản cũ trước khi set `facebookId` — không được link nếu thiếu bước xác nhận này. **Guard `passwordHash` null trước `bcrypt.compare`** (tránh crash/oracle nếu user cũ không có passwordHash).
- Response của cả 2 route luôn là JWT của hệ thống, không trả token Facebook ra ngoài.
- DTO validate `identityToken` là string bắt buộc, không rỗng; `link-confirm` thêm `password` string bắt buộc, không rỗng.
- Không guard nào được overwrite `facebookId` đã link cho user khác.
- Mọi Prisma query trả `User` không được để `passwordHash` lọt vào response/JWT (global `omit` đã set ở Phase 1).

## Architecture

**JWT infra tối thiểu (thay B4):**
```typescript
// AuthService
signToken(userId: string): string {
  return this.jwtService.sign({ sub: userId }); // ký qua JwtModule.registerAsync (đọc JWT_SECRET qua ConfigService, xem Implementation Steps)
}
```

**Lưu ý (red-team 260703, Security Adversary C3):** dùng `JwtModule.registerAsync({ useFactory: (config: ConfigService) => ({ secret: config.get('JWT_SECRET'), signOptions: { expiresIn: '7d' } }), inject: [ConfigService] })` — **không** dùng `JwtModule.register({ secret: process.env.JWT_SECRET, ... })` (sync). Lý do: `process.env.JWT_SECRET` được đọc ngay lúc `AppModule` decorator evaluate (import-time), TRƯỚC khi `ConfigModule.forRoot()` (Phase 2) kịp load `.env` — `JWT_SECRET` có thể là `undefined` tại thời điểm đó tuỳ thứ tự import module của Nest, khiến JWT ký với secret rỗng/không ổn định. `registerAsync` + inject `ConfigService` đảm bảo đọc sau khi `ConfigModule` đã load xong.
```typescript
// JwtAuthGuard — CanActivate tự decode qua JwtService.verifyAsync(), không cần passport
// vì repo chỉ có đúng 1 kiểu auth (JWT hệ thống), verify được → req.user = { sub: payload.sub }
```

**`POST /auth/facebook { identityToken: string }`:**

```
AuthController.loginWithFacebook(dto)
  → profile = FacebookAuthService.verifyIdentityToken(dto.identityToken)
  → AuthService.findOrCreateFacebookUser(profile)
  → jwt = AuthService.signToken(user.id)
  → return { accessToken: jwt }
```

```typescript
async function findOrCreateFacebookUser(profile: FacebookProfile) {
  const byFbId = await prisma.user.findUnique({ where: { facebookId: profile.facebookId } });
  if (byFbId) return byFbId;

  if (profile.email) {
    const byEmail = await prisma.user.findUnique({ where: { email: profile.email } });
    if (byEmail) {
      throw new ConflictException({ code: 'EMAIL_LINK_REQUIRED', email: profile.email });
    }
  }

  try {
    return await prisma.user.create({
      data: { facebookId: profile.facebookId, email: profile.email, name: profile.name, avatarUrl: profile.avatarUrl, passwordHash: null },
    });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
      const target = (e.meta?.target as string[] | string | undefined) ?? [];
      const targets = Array.isArray(target) ? target : [target]; // format target khác nhau tuỳ connector Prisma — chuẩn hoá về mảng
      // facebookId trùng: race giữa 2 request cùng identity token → an toàn refetch-and-return (không đổi ownership).
      if (targets.includes('facebookId')) return prisma.user.findUniqueOrThrow({ where: { facebookId: profile.facebookId } });
      // email trùng: PHẢI ném lại 409 giống nhánh check phía trên — refetch-and-return ở đây sẽ trả thẳng
      // JWT của user đã có password cho 1 request chỉ mới verify token Facebook, bỏ qua hoàn toàn gate
      // EMAIL_LINK_REQUIRED (account-takeover nếu attacker biết email nạn nhân và có Facebook riêng).
      // (red-team 260703, Security Adversary + Assumption Destroyer C1 — unanimous, không đảo lại account-linking
      // policy đã chốt 2026-07-02, đây là fix implement đúng chính sách đó, không phải đổi chính sách.)
      if (targets.includes('email')) throw new ConflictException({ code: 'EMAIL_LINK_REQUIRED', email: profile.email });
    }
    throw e;
  }
}
```

**`POST /auth/facebook/link-confirm { identityToken: string, password: string }`:**

```
AuthController.confirmFacebookLink(dto)
  → profile = FacebookAuthService.verifyIdentityToken(dto.identityToken)
  → AuthService.linkFacebookAccount(profile, dto.password)
  → jwt = AuthService.signToken(user.id)
  → return { accessToken: jwt }
```

```typescript
async function linkFacebookAccount(profile: FacebookProfile, password: string) {
  // profile.email có thể null (user từ chối permission "email" phía Facebook) — findUnique({ where: { email: null } })
  // không throw nhưng match sai (Prisma unique-null-semantics), phải chặn tường minh trước khi query.
  // (red-team 260703, Failure Mode Analyst M1)
  if (!profile.email) throw new BadRequestException('Facebook account has no email to link with');

  const user = await prisma.user.findUnique({
    where: { email: profile.email },
    omit: { passwordHash: false }, // override global omit — cần đọc passwordHash để so bcrypt
  });
  if (!user) throw new NotFoundException('No account found for this email');

  if (user.facebookId && user.facebookId !== profile.facebookId) {
    throw new ConflictException('Account already linked to a different Facebook identity');
  }

  if (!user.passwordHash || !(await bcrypt.compare(password, user.passwordHash))) {
    throw new UnauthorizedException('Invalid credentials');
  }

  // Giữa lúc check `user.facebookId` ở trên và update ở đây, 1 request khác có thể vừa link facebookId
  // này vào 1 user khác (race hẹp nhưng có thật) — bọc P2002 thay vì để 500 lan ra ngoài.
  // (red-team 260703, Failure Mode Analyst M1)
  try {
    return await prisma.user.update({
      where: { id: user.id },
      data: { facebookId: profile.facebookId, name: user.name ?? profile.name, avatarUrl: user.avatarUrl ?? profile.avatarUrl },
    });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
      throw new ConflictException('Account already linked to a different Facebook identity');
    }
    throw e;
  }
}
```

## Related Code Files

- Modify: `src/auth/auth.module.ts` — Phase 2 đã tạo file này cho `FacebookAuthService`; phase này thêm `JwtModule.registerAsync`, `AuthService`, `AuthController`, `JwtAuthGuard` (*ordering fix, red-team 260703 M5 — trước đây cả Phase 2 và Phase 3 đều ghi "Create" cùng 1 file*)
- Create: `src/auth/auth.service.ts`, `src/auth/auth.controller.ts`
- Create: `src/auth/jwt-auth.guard.ts`
- Create: `src/auth/dto/facebook-login.dto.ts` — `{ identityToken: string }` với `class-validator`
- Create: `src/auth/dto/facebook-link-confirm.dto.ts` — `{ identityToken: string; password: string }` với `class-validator`
- Modify: `.env`/`.env.example` — thêm `JWT_SECRET`
- Modify: `package.json` — thêm `@nestjs/jwt`, `bcrypt`, `@types/bcrypt`, `class-validator`, `class-transformer`, `@nestjs/throttler`

## Implementation Steps

1. `yarn add @nestjs/jwt bcrypt class-validator class-transformer @nestjs/throttler` + `yarn add -D @types/bcrypt` (repo chỉ có `yarn.lock` — *red-team 260703, M4*).
2. Modify `AuthModule` (đã tồn tại từ Phase 2) — thêm `JwtModule.registerAsync({ useFactory: (config: ConfigService) => ({ secret: config.get('JWT_SECRET'), signOptions: { expiresIn: '7d' } }), inject: [ConfigService] })` (**không** dùng `JwtModule.register` sync — xem Architecture).
3. Viết `signToken(userId)` trong `AuthService`, dùng chung cho 2 route Facebook (và cho `login()` sau này nếu build).
4. Viết `JwtAuthGuard` (`CanActivate`) verify JWT qua `JwtService.verifyAsync`, set `req.user = { sub: payload.sub }`.
5. Tạo `FacebookLoginDto`/`FacebookLinkConfirmDto` với `@IsString() @IsNotEmpty()`.
6. Bật `ValidationPipe` global ở `main.ts` (chưa có vì B2 chưa code).
7. Thêm route `POST /auth/facebook` và `POST /auth/facebook/link-confirm` trong `AuthController`. Áp `@Throttle` (từ `@nestjs/throttler`, vd. 5 request/phút/IP) riêng cho `link-confirm` — route này cho phép thử `password` nên cần rate-limit chống brute-force, khác với `/auth/facebook` (chỉ nhận identity token đã ký, không có gì để brute-force) *(red-team 260703, Failure Mode Analyst M3)*.
8. Implement `findOrCreateFacebookUser()` theo Architecture — branch email-match ném `ConflictException`; branch create bọc `try/catch` bắt `P2002`, **facebookId trùng → refetch-and-return; email trùng → ném lại `409 EMAIL_LINK_REQUIRED`, không refetch-and-return** (xem code + comment trong Architecture — fix C1). Không dùng transaction — transaction không tránh được race giữa 2 connection riêng biệt.
9. Implement `linkFacebookAccount()`: guard `profile.email` null trước khi query, guard `facebookId` cũ không bị overwrite, verify password bằng `bcrypt.compare` (guard null trước), bọc `update()` trong `try/catch P2002` (xem Architecture — fix M1).
10. `AuthModule` đã được đăng ký vào `AppModule` từ Phase 2 — verify vẫn còn đúng, không cần đăng ký lại.

## Success Criteria

- [ ] `POST /auth/facebook` với identity token hợp lệ, user mới → tạo `User` mới, trả JWT hệ thống hợp lệ (decode được, có `sub` = user id).
- [ ] Gọi lại lần 2 với cùng identity token/facebookId → không tạo user trùng, trả JWT cho user đã có.
- [ ] Tạo sẵn 1 user password-based (seed thủ công qua Prisma, vì không có `POST /auth/register`), login Facebook với cùng email → `POST /auth/facebook` trả `409` + code `EMAIL_LINK_REQUIRED`, **không** set `facebookId`, **không** tạo record mới.
- [ ] `POST /auth/facebook/link-confirm` với password đúng → set `facebookId` vào user cũ, trả JWT hợp lệ.
- [ ] `POST /auth/facebook/link-confirm` với password sai → `401`, `facebookId` không đổi.
- [ ] `POST /auth/facebook/link-confirm` khi user đã có `facebookId` khác → `409`, không overwrite.
- [ ] identity token invalid → BE trả `401`, không tạo user.
- [ ] JWT trả về decode đúng bằng `JwtAuthGuard` (test 1 route dummy `@UseGuards(JwtAuthGuard)`).
- [ ] Response JSON của mọi route trên không chứa field `passwordHash`.
- [ ] Race `email` trùng (2 request `POST /auth/facebook` đồng thời, cùng email, `facebookId` khác nhau) → **cả 2** trả `409 EMAIL_LINK_REQUIRED`, không request nào lọt qua thành JWT (test C1 fix).
- [ ] `POST /auth/facebook/link-confirm` với `profile.email = null` (giả lập token không có email) → `400`, không query DB với `email: null`.
- [ ] Gọi `link-confirm` quá ngưỡng rate-limit trong 1 phút → `429`.

## Risk Assessment

- **Risk:** Race condition nếu 2 request `POST /auth/facebook` cùng lúc tạo user mới với cùng `facebookId` hoặc cùng `email`.
  **Mitigation:** `facebookId` và `email` đều có `@unique` ở DB — request thua nhận Prisma `P2002`; nhánh `facebookId` refetch-and-return (an toàn, cùng identity), nhánh `email` ném lại `409 EMAIL_LINK_REQUIRED` thay vì refetch-and-return (fix C1 — bản cũ vô tình bypass gate 409 ở đúng nhánh race này).
- **Risk:** UX friction — Option B thêm 1 bước nhập password so với auto-link ngầm.
  **Mitigation:** Đánh đổi có chủ đích để tránh lỗ hổng account-takeover đã xác nhận qua red-team trước đó — không đảo lại sang auto-link.
- **Risk:** Không có `POST /auth/register` → khó test nhánh `409 EMAIL_LINK_REQUIRED` (cần 1 user password-based có sẵn).
  **Mitigation:** Test tạo user password-based trực tiếp qua Prisma seed/script (không qua HTTP endpoint) — chấp nhận được vì chỉ phục vụ test Phase 4.
- **Risk (mới, red-team 260703):** `link-confirm` nhận `password` từ client — không rate-limit thì có thể brute-force password tài khoản cũ qua route này.
  **Mitigation:** `@Throttle` áp riêng route này (bước 7).
- **Risk (mới, red-team 260703):** `linkFacebookAccount` giữa lúc check `facebookId` cũ và lúc `update()` có khoảng hở — 1 request khác có thể vừa chiếm `facebookId` này.
  **Mitigation:** Bọc `update()` trong `try/catch P2002` → `409` thay vì `500` (xem Architecture).
