---
phase: 4
title: "Tests"
status: pending
priority: P2
effort: "S"
dependencies: [1, 2, 3]
---

# Phase 4: Tests

## Overview

Unit test cho `FacebookAuthService` (mock `jose`/JWKS) và `AuthService` (mock Prisma cho case không cần DB thật), cộng e2e test flow `POST /auth/facebook` + `POST /auth/facebook/link-confirm` trên DB test thật riêng (Docker Compose).

## Requirements

- Không gọi Facebook thật (JWKS endpoint) trong unit test — mock `jose.jwtVerify`/`createRemoteJWKSet`.
- Cover đủ 3 nhánh của `POST /auth/facebook` (login thẳng / `409 EMAIL_LINK_REQUIRED` / tạo mới) + `POST /auth/facebook/link-confirm` (password đúng/sai/đã link khác) + case token invalid + case email null.
- Race condition (`P2002`) bắt buộc test trên DB thật — mock Prisma không thể tái hiện unique constraint.
- Case `passwordHash = null` trong `linkFacebookAccount` phải trả lỗi tương đương `401`, không `500` (không có `POST /auth/login` riêng ở scope này — `linkFacebookAccount` là chỗ duy nhất gọi `bcrypt.compare`, test qua đây là đủ).

## Related Code Files

- Create: `src/auth/facebook-auth.service.spec.ts`
- Create: `src/auth/auth.service.spec.ts`
- Create: `test/auth-facebook.e2e-spec.ts`
- Create: `docker-compose.test.yml` — Postgres riêng cho e2e test, port host **`5433:5432`** (khác `5432` của Phase 1 để chạy song song không đụng), kèm `healthcheck` (đồng bộ Phase 1 — *red-team 260703 H2*)
- Create: `.env.test` — `DATABASE_URL` (**không phải `DATABASE_URL_TEST`** — Prisma chỉ đọc đúng tên biến khai trong `schema.prisma`'s `env("DATABASE_URL")`, một biến tên khác sẽ bị bỏ qua hoàn toàn) trỏ vào Postgres test ở port `5433`. Đã thêm `.env.test` vào `.gitignore` ở Phase 1 (*red-team 260703 H4*).
- Modify: `package.json` — thêm dependency `dotenv-cli` (dev) để load `.env.test` khi chạy migrate/test

## Implementation Steps

1. `facebook-auth.service.spec.ts`: mock `jose` (`jwtVerify` resolve/reject), test 4 case — token hợp lệ trả đủ profile; token hợp lệ nhưng email null; `jwtVerify` throw (hết hạn); `aud` không khớp (`JWTClaimValidationFailed`); **thêm case lỗi network (non-jose error) → verify service throw `ServiceUnavailableException` không phải `UnauthorizedException`** (test cho fix H1 ở Phase 2).
2. `auth.service.spec.ts` (mock `PrismaService`): test nhánh `facebookId` match (login thẳng); nhánh email match (ném `ConflictException` code `EMAIL_LINK_REQUIRED`, không update); nhánh không match nào (create); `linkFacebookAccount` với password đúng/sai/`facebookId` đã link khác/`passwordHash` null/**`profile.email = null` (→ `400`, test fix M1)**.
3. Setup DB test: `docker-compose.test.yml` chạy Postgres riêng ở port `5433`, đợi container `healthy` (script `wait-on tcp:5433` hoặc healthcheck poll, đồng bộ pattern Phase 1). Trước khi chạy e2e: `yarn dotenv -e .env.test -- npx prisma migrate deploy` — `dotenv-cli` nạp `.env.test` để chính `DATABASE_URL` (không phải 1 biến `_TEST` riêng) trỏ vào Postgres test, `migrate deploy` (không phải `migrate dev`) chỉ apply migration đã commit *(red-team 260703, Failure Mode Analyst C4 — bản cũ định nghĩa `DATABASE_URL_TEST` nhưng Prisma không có cơ chế nào đọc biến đó)*. Reset data giữa các test bằng truncate — thêm guard: script truncate phải assert `DATABASE_URL` hiện tại chứa tên DB test (vd. `_test`) trước khi truncate, phòng trường hợp `.env.test` bị load nhầm/thiếu và lỡ truncate DB dev.
4. E2e (`test/auth-facebook.e2e-spec.ts`, DB test thật, mock `FacebookAuthService.verifyIdentityToken` qua override provider), chạy qua `yarn dotenv -e .env.test -- jest --config ./test/jest-e2e.json` để cùng nạp `.env.test`:
   - `POST /auth/facebook` user mới → 200, JWT hợp lệ, 1 row `User` mới.
   - `POST /auth/facebook` user đã có `facebookId` → 200, không tạo row mới.
   - Seed trực tiếp qua Prisma 1 user password-based (không qua HTTP, vì không có `/auth/register`), `POST /auth/facebook` cùng email → `409` + `EMAIL_LINK_REQUIRED`, `facebookId` vẫn null trong DB.
   - `POST /auth/facebook/link-confirm` sau case trên, password đúng → 200, `facebookId` đã set trong DB.
   - `POST /auth/facebook/link-confirm` password sai → 401, `facebookId` vẫn null.
   - 2 request `POST /auth/facebook` đồng thời (`Promise.all`) cùng identity token/facebookId mới → cả 2 trả 200, cùng 1 `user.id`, chỉ 1 row `User` trong DB (test race condition thật, không mock).
   - **Mới (fix C1):** seed 1 user password-based, 2 request `POST /auth/facebook` đồng thời cùng email nhưng **`facebookId` khác nhau** (giả lập race đúng path bug cũ) → **cả 2** trả `409 EMAIL_LINK_REQUIRED`, không request nào trả JWT, `facebookId` của user seed vẫn null sau cùng.
   - **Mới (fix M1):** `POST /auth/facebook/link-confirm` khi `facebookId` vừa bị 1 request khác chiếm mất giữa lúc check và update (mock/seed race) → `409`, không `500`.

## Success Criteria

- [ ] `yarn test` pass toàn bộ, cover `FacebookAuthService` và `AuthService` (cả `findOrCreateFacebookUser` và `linkFacebookAccount`) — *pnpm→yarn, red-team 260703 M4 (repo chỉ có `yarn.lock`)*.
- [ ] `yarn dotenv -e .env.test -- yarn test:e2e` pass trên DB test thật (Docker Compose port `5433`), có test cho `POST /auth/facebook`, `POST /auth/facebook/link-confirm`, và race condition đồng thời (cả 2 loại: cùng facebookId, và cùng email khác facebookId).
- [ ] Cố tình bỏ check `409 EMAIL_LINK_REQUIRED` (revert về auto-link) → test phải fail — chứng minh test không vô dụng.
- [ ] Cố tình đổi nhánh `email` trong P2002 catch về refetch-and-return (revert fix C1) → test race "cùng email khác facebookId" phải fail.
- [ ] Cố tình bỏ `try/catch P2002` ở `findOrCreateFacebookUser` → test race condition đồng thời (cùng facebookId) phải fail (500 thay vì 200).
- [ ] Test `linkFacebookAccount` với `passwordHash = null` trả lỗi tương đương `401`, không `500`.
- [ ] Test `linkFacebookAccount` với `profile.email = null` trả `400`, không query DB với `email: null`.

## Risk Assessment

- **Risk:** Mock Prisma không khớp behavior thật của `@unique` constraint (vd. test tưởng pass nhưng thực tế DB throw `P2002`).
  **Mitigation:** Test race condition và toàn bộ flow `link-confirm`/`409` chạy trên DB test thật (Docker Compose), không mock Prisma cho các case này.
- **Risk:** DB test không được reset đúng giữa các test → test sau bị ảnh hưởng bởi data test trước.
  **Mitigation:** Truncate toàn bộ bảng liên quan trước mỗi test file/suite, kèm guard assert tên DB chứa `_test` trước khi truncate.
- **Risk (mới, red-team 260703):** `DATABASE_URL_TEST` (tên biến cũ trong plan) không được Prisma đọc → `migrate deploy`/test thực chất chạy nhắm vào `DATABASE_URL` mặc định = **DB dev** (Phase 1), có thể xoá/ghi đè data dev thật.
  **Mitigation:** Đổi hẳn sang cơ chế `dotenv-cli` nạp `.env.test` để chính `DATABASE_URL` trỏ đúng DB test (xem Implementation Steps) — không có biến `_TEST` nào tồn tại nữa để nhầm.
- **Risk (mới, red-team 260703):** `docker-compose.test.yml` container Postgres chưa sẵn sàng nhận connection khi `migrate deploy`/e2e chạy ngay sau `up -d`.
  **Mitigation:** `healthcheck` + đợi `healthy` trước khi chạy migrate/e2e (đồng bộ Phase 1).
