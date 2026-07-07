---
phase: 2
title: "Facebook Verify Service (JWKS)"
status: pending
priority: P2
dependencies: [1]
---

# Phase 2: Facebook Verify Service (JWKS)

## Overview

Verify JWT (`AuthenticationToken`/OIDC id_token) do FE gửi lên qua Facebook JWKS — **không** gọi Graph API `/debug_token`+`/me` (thiết kế gốc cho classic access token, không áp dụng được vì FE dùng Limited Login, xem `plan.md` mục "Đổi hướng verify"). Field lấy thẳng từ claims đã verify chữ ký, không cần request HTTP thứ 2 nào tới Facebook.

## Requirements

- Verify chữ ký JWT bằng JWKS remote (`https://www.facebook.com/.well-known/oauth/openid/jwks/`), check `iss === 'https://www.facebook.com'`, `aud === FACEBOOK_APP_ID`, `exp` chưa hết hạn.
- Xử lý được `email` null/thiếu trong claims (user từ chối permission `email`).
- Token invalid/hết hạn/sai `aud`/sai chữ ký → ném lỗi rõ ràng để controller trả 401.
- Field `picture` trong claims là **string URL trực tiếp** (đã confirm bằng claims thật từ device) — khác `picture.data.url` nested của Graph API `/me`, không transform gì thêm.

## Architecture

`FacebookAuthService` (trong `AuthModule`):

```typescript
import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://www.facebook.com/.well-known/oauth/openid/jwks/'));

async function verifyIdentityToken(identityToken: string): Promise<FacebookProfile> {
  if (!this.facebookAppId) {
    // fail-fast: nếu FACEBOOK_APP_ID rỗng, `audience: undefined` khiến jose BỎ QUA check aud hoàn toàn
    throw new Error('FACEBOOK_APP_ID not configured');
  }
  const { payload } = await jwtVerify(identityToken, JWKS, {
    issuer: 'https://www.facebook.com',
    audience: this.facebookAppId, // từ ConfigService, validate non-empty ở AuthModule bootstrap (xem Implementation Steps)
    algorithms: ['RS256'], // chặn "alg confusion" / accept mọi alg JWKS công bố
  }); // jose tự throw nếu sai chữ ký / sai iss / sai aud / hết hạn exp
  return {
    facebookId: payload.sub!,
    name: (payload.name as string) ?? null,
    email: (payload.email as string) ?? null,
    avatarUrl: (payload.picture as string) ?? null,
  };
}
```

Phân loại lỗi từ `jwtVerify` — **không catch chung 1 loại nữa** *(red-team 260703, Failure Mode Analyst H1)*:
- Lỗi thuộc `joseErrors.JOSEError` (claim/signature/expired — token thật sự invalid) → `UnauthorizedException('Invalid Facebook token')`.
- Lỗi khác (network/timeout khi fetch JWKS, DNS fail, `createRemoteJWKSet` internal fetch error) → KHÔNG phải lỗi của client, ném `ServiceUnavailableException('Facebook verification temporarily unavailable')` (503) + log riêng — nếu để lẫn vào 401, client/FE sẽ hiểu nhầm "token invalid" và không tự retry được, trong khi 503 hợp lý để FE retry.

`FACEBOOK_APP_ID` đọc qua `@nestjs/config` — **không cần `FACEBOOK_APP_SECRET`** nữa (JWKS chỉ cần App ID để check `aud`, khác Graph API cần Secret để đổi App Token). Đây là biến `@nestjs/config` **đầu tiên** repo dùng → phase này chịu trách nhiệm bootstrap `ConfigModule.forRoot({ isGlobal: true })` vào `AppModule` *(red-team 260703, Security Adversary C3, tự verify: `src/app.module.ts` hiện `imports: []`, không có `ConfigModule`/`ConfigService`/`dotenv` ở đâu trong `src/`)*.

**Risk chấp nhận, không fix ở v1 (`nonce`):** JWKS verify ở trên **không** check claim `nonce` — về lý thuyết, 1 `identityToken` hợp lệ bị lộ (network log, MITM trên thiết bị jailbreak...) có thể bị replay để mint JWT hệ thống mới trong lúc token Facebook còn hạn. Fix đúng cần FE sinh `nonce` random mỗi lần login, gửi cho Facebook SDK, rồi BE so khớp `payload.nonce` — nhưng `facebook-login-button.tsx` phía FE hiện **không** set `nonce` khi gọi SDK, nên đây là thay đổi 2 phía, ngoài scope backend-only của plan này *(red-team 260703, Security Adversary H3)*. Document rõ risk này, không block phase.

## Related Code Files

- Create: `src/auth/facebook-auth.service.ts`
- Create: `src/auth/interfaces/facebook-profile.interface.ts`
- Create: `src/auth/auth.module.ts` — module `AuthModule` mới, đăng ký `FacebookAuthService` provider (phase này là nơi ĐẦU TIÊN tạo file này; Phase 3 sẽ **Modify** thêm `AuthService`/`AuthController`/JWT — *sửa ordering, red-team 260703 M5*)
- Modify: `.env` / `.env.example` — thêm `FACEBOOK_APP_ID` (bỏ `FACEBOOK_APP_SECRET`, không cần nữa)
- Modify: `src/app.module.ts` — thêm `ConfigModule.forRoot({ isGlobal: true })` + import `AuthModule`
- Modify: `package.json` — thêm dependency `jose`, `@nestjs/config`

## Implementation Steps

1. `yarn add jose @nestjs/config` (repo chỉ có `yarn.lock` — *red-team 260703, M4*).
2. Thêm `ConfigModule.forRoot({ isGlobal: true })` vào `imports` của `AppModule` (hiện đang `imports: []`) — bắt buộc để mọi `ConfigService` inject sau này (Phase 2 + Phase 3 JWT) hoạt động.
3. Thêm `FACEBOOK_APP_ID` vào `.env`/`.env.example` (giá trị thật `1548957553621793`, khớp app "VFIT Workout" đã tạo — lấy từ `my-expo-app/.env`; **không cần** `FACEBOOK_APP_SECRET`). Validate ở constructor `FacebookAuthService`: nếu `configService.get('FACEBOOK_APP_ID')` rỗng/undefined → throw ngay khi app boot (fail-fast), không để tới lúc request đầu tiên mới phát hiện `aud` check bị bỏ qua.
4. Tạo `src/auth/auth.module.ts`, viết `FacebookAuthService.verifyIdentityToken()` theo Architecture — `createRemoteJWKSet` tạo 1 lần (module-level, `jose` tự cache/refetch JWKS).
5. Catch lỗi từ `jwtVerify`: phân loại `joseErrors.JOSEError` → 401, lỗi khác (network) → 503 + log riêng (theo Architecture).
6. `email`/`picture`/`name` thiếu trong claims → set `null`, không throw.
7. Đăng ký `FacebookAuthService` provider vào `AuthModule`, import `AuthModule` vào `AppModule`.

## Success Criteria

- [ ] `AppModule` có `ConfigModule.forRoot({ isGlobal: true })`; app boot fail rõ ràng nếu `FACEBOOK_APP_ID` rỗng.
- [ ] Verify JWT thật từ device (claims đã log ở `my-expo-app` brainstorm report) → trả đúng `facebookId` (=`sub`), `name`, `email`, `avatarUrl` (=`picture` string).
- [ ] JWT hết hạn (test bằng token cũ) → throw `UnauthorizedException`, không crash.
- [ ] JWT với `aud` không khớp `FACEBOOK_APP_ID` → throw `UnauthorizedException`.
- [ ] JWT chữ ký sai (test bằng token bị sửa 1 ký tự) → throw `UnauthorizedException`.
- [ ] Claims thiếu `email` → service vẫn trả object với `email: null`, không lỗi.
- [ ] Giả lập lỗi network khi fetch JWKS (mock `createRemoteJWKSet` reject non-jose error) → trả `503`, không lẫn với `401`.

## Risk Assessment

- **Risk:** `createRemoteJWKSet` fetch JWKS timeout/network lỗi khi verify.
  **Mitigation:** Phân loại lỗi rõ ràng (jose error → 401, network error → 503 + log riêng) theo Architecture — không còn catch-all 1 loại như trước.
- **Risk:** Facebook đổi cấu trúc claims/JWKS endpoint trong tương lai (rủi ro chung mọi hướng, không riêng JWKS).
  **Mitigation:** Không mitigate thêm ở v1 — chấp nhận rủi ro dài hạn đã nêu ở brainstorm report.
- **Risk (mới, red-team 260703):** `FACEBOOK_APP_ID` thiếu/rỗng → `audience: undefined` khiến `jose` bỏ qua hoàn toàn check `aud`, một token JWKS hợp lệ ký cho **app Facebook khác** vẫn pass verify.
  **Mitigation:** Validate `FACEBOOK_APP_ID` non-empty khi boot (fail-fast), không chỉ dựa vào runtime check.
- **Risk (mới, red-team 260703):** Không check `nonce` → identity token replay được trong thời hạn còn hiệu lực.
  **Mitigation:** Chấp nhận ở v1 (đổi cần sửa cả FE), document rõ trong Architecture ở trên; ưu tiên fix nếu app này sau này cần security bar cao hơn (submit App Review, sản phẩm thật).
