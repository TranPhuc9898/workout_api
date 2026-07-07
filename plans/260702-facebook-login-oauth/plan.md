---
title: "B7 - Facebook Login (OAuth)"
description: "Vertical slice: POST /auth/facebook + link-confirm, verify JWT Facebook qua JWKS, tự bootstrap Prisma+Postgres+JWT infra tối thiểu (không chờ B4)."
status: pending
priority: P2
branch: "master"
tags: [auth, oauth, facebook, roadmap-b7]
blockedBy: []
blocks: []
created: "2026-07-02T09:37:14.182Z"
createdBy: "ck:plan"
source: skill
---

# B7 - Facebook Login (OAuth)

## Overview

Xây `POST /auth/facebook` + `POST /auth/facebook/link-confirm` cho `workout-api`, verify token Facebook qua JWKS (không phải Graph API — xem "Đổi hướng verify" bên dưới). Plan này ban đầu viết như bước B7 trong roadmap học NestJS+REST+Postgres, xây trên nền B4 (Auth JWT). **Quyết định 2026-07-03: chuyển sang vertical slice** — tự bootstrap hạ tầng auth tối thiểu (Prisma+Postgres, JWT signing, guard) ngay trong plan này, không chờ B4/B5/B6 làm riêng.

## Quyết định phạm vi (2026-07-03)

Repo thực tế lúc viết lại plan: chỉ có `nest new` skeleton (0 Prisma, 0 auth lib, 0 `.env`, 0 commit git). Bản gốc của plan này gate B7 chờ B4 (Auth JWT, tự viết register/login) xong. User đã confirm **Path 2**: build đủ hạ tầng để `/auth/facebook` chạy được (Prisma+Postgres, `signToken`/`JwtAuthGuard`, verify service), **bỏ qua** `POST /auth/register`/`POST /auth/login` (password-based) cho vòng này — schema Prisma vẫn giữ sẵn cột `passwordHash` cho việc đó sau.

**Lưu ý tự nêu (chưa re-confirm được với user — 2 lần `AskUserQuestion` đều timeout, quyết định theo phán đoán tốt nhất dựa trên xác nhận gần nhất "confirm path 2, lên plan đi"):** roadmap gốc của repo sâu hơn ban đầu tưởng khi brainstorm — không chỉ B4, mà B2 (REST CRUD)/B3 (Postgres+Prisma)/B5 (`@nestjs/config`)/B6 cũng chưa có code thật, và B4 có thể mang chủ đích học tự viết password auth chứ không chỉ là hạ tầng thuần. Plan này **không** build lại toàn bộ B2-B6 theo đúng roadmap gốc — chỉ build phần hạ tầng tối thiểu mà Facebook flow cần. Nếu muốn giữ đúng thứ tự roadmap học (build B2→B6 đầy đủ trước khi có Facebook login), cần review lại quyết định này và tách 1 plan riêng cho phần đó.

## Đổi hướng verify (2026-07-03)

FE (`my-expo-app`, `facebook-login-button.tsx`) không xin App Tracking Transparency → FBSDKLoginKit iOS luôn fallback Limited Login → trả JWT (`AuthenticationToken`/OIDC id_token), không phải Graph API `AccessToken` cổ điển. Phase 2 gốc thiết kế cho access token cổ điển (`/debug_token` + `/me`) — **không dùng được** với JWT thật của FE. Đã brainstorm (`my-expo-app/plans/260702-facebook-login-button/reports/260703-facebook-token-backend-verify-mismatch.md`) và chốt: verify JWT qua Facebook JWKS (`https://www.facebook.com/.well-known/oauth/openid/jwks/`, thư viện `jose`), lấy thẳng field từ claims đã verify — không gọi Graph API nữa. Đã confirm field mapping bằng claims thật log từ device (`facebookId=sub, email, name, avatarUrl=picture` — string URL trực tiếp, không nested như Graph API).

DTO field đổi tên `accessToken` → `identityToken` (khớp đúng bản chất JWT) — đổi an toàn vì chưa có consumer nào gọi route này (FE chưa gọi backend, 0 code backend tồn tại trước plan này).

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Bootstrap Prisma+Postgres va Schema User](./phase-01-schema-prisma-user.md) | Pending |
| 2 | [Facebook Verify Service (JWKS)](./phase-02-facebook-verify-service.md) | Pending |
| 3 | [Auth Endpoint, JWT Infra va Account Linking](./phase-03-auth-endpoint-va-account-linking.md) | Pending |
| 4 | [Tests](./phase-04-tests.md) | Pending |

## Cập nhật bảo mật (giữ nguyên, 2026-07-02)

Quyết định auto-link theo email đã bị **đảo** thành Option B (không auto-link, yêu cầu `link-confirm` xác nhận password) sau khi red-team phát hiện lỗ hổng pre-account hijacking — xem `phase-03-auth-endpoint-va-account-linking.md`. Không đổi lại quyết định này.

## Red Team Review (2026-07-03)

3 reviewer (Security Adversary, Assumption Destroyer, Failure Mode Analyst), Standard verification tier (Fact Checker + Contract Verifier). 23 finding thô → dedupe 13 unique. Tất cả có `file:line` evidence, tự verify thêm bằng bash trực tiếp trên repo (docker absent, `.gitignore` thiếu `.env.test`, `app.module.ts` `imports: []`, chỉ có `yarn.lock`). Không finding nào đảo lại quyết định đã chốt của user (Path 2 scope, account-linking Option B 2026-07-02) — tất cả là fix implement đúng quyết định đã chốt, không phải đổi hướng.

**Disposition:** Toàn bộ 13/13 accepted và applied (0 rejected) — `AskUserQuestion` xác nhận timeout không phản hồi, tiến hành theo phán đoán tốt nhất vì mọi finding đã tự verify bằng evidence cụ thể trên máy/repo thật, không phải suy đoán trừu tượng.

| # | Finding | Severity | Applied To |
|---|---------|----------|------------|
| C1 | `P2002` nhánh `email` refetch-and-return bypass gate `409 EMAIL_LINK_REQUIRED` | Critical | Phase 3 |
| C2 | Docker chưa cài trên máy dev — hard blocker Phase 1/4 | Critical | Phase 1 |
| C3 | `JwtModule.register` sync đọc `process.env.JWT_SECRET` trước khi `ConfigModule` load; `ConfigModule` chưa từng wired | Critical | Phase 2, Phase 3 |
| C4 | `DATABASE_URL_TEST` không phải biến Prisma đọc được — test có thể chạy nhầm vào DB dev | Critical | Phase 1 (risk note), Phase 4 |
| H1 | Lỗi network khi fetch JWKS bị catch chung thành `401` giống lỗi token invalid | High | Phase 2 |
| H2 | Không có healthcheck/đợi Postgres sẵn sàng trước khi migrate/connect | High | Phase 1, Phase 4 |
| H3 | Không verify claim `nonce` — identity token replay được trong hạn | High | Phase 2 (documented, chấp nhận risk) |
| H4 | `.gitignore` thiếu `.env.test` (chỉ có `.env.test.local`) | High | Phase 1, Phase 4 |
| M1 | `linkFacebookAccount`: `profile.email` null crash tiềm ẩn, không bắt `P2002` khi `facebookId` bị chiếm giữa chừng | Medium | Phase 3, test ở Phase 4 |
| M2 | `jwtVerify` thiếu `algorithms: ['RS256']` allowlist | Medium | Phase 2 |
| M3 | `link-confirm` không rate-limit → brute-force password | Medium | Phase 3 |
| M4 | Plan ghi `npm install`/`pnpm test` nhưng repo chỉ có `yarn.lock` | Medium | Phase 1, 2, 3, 4 |
| M5 | `auth.module.ts` vừa "Create" ở Phase 2 vừa "Create" ở Phase 3 (ordering contradiction) | Medium | Phase 2 (Create), Phase 3 (Modify) |

### Whole-Plan Consistency Sweep

Re-đọc `plan.md` + 4 `phase-*.md` sau khi áp fix:
- Package manager: cả 4 phase file đã đồng bộ `yarn`/`npx` (không còn `npm install`/`pnpm` sót lại).
- `auth.module.ts`: Phase 2 = Create (đầu tiên), Phase 3 = Modify — nhất quán 2 chiều, không còn mâu thuẫn.
- `DATABASE_URL`/`.env.test`: Phase 1 tạo `.gitignore` entry, Phase 4 dùng đúng biến `DATABASE_URL` (không phải `DATABASE_URL_TEST`) qua `dotenv-cli` — nhất quán, Prisma `schema.prisma` (Phase 1) không cần đổi vì vẫn chỉ đọc `env("DATABASE_URL")`.
- `findOrCreateFacebookUser`/`linkFacebookAccount` pseudocode chỉ xuất hiện 1 nơi (Phase 3) — không có bản sao lệch ở file khác.
- Không tìm thấy thuật ngữ cũ/giả định đã bác bỏ nào còn sót (đã dò `accessToken` cũ — chỉ còn xuất hiện trong `b4-contract-stub.md` với nhãn SUPERSEDED, đúng như thiết kế).
- Kết quả: **0 mâu thuẫn chưa giải quyết.**

## Dependencies

- Không còn phụ thuộc B4/B5 làm riêng trước — Phase 1 & 3 tự bootstrap hạ tầng tối thiểu cần (Prisma+Postgres, JWT sign+guard). Nội dung `b4-contract-stub.md` đã gộp vào Phase 1/Phase 3, file giữ lại chỉ làm lịch sử quyết định (xem `b4-contract-stub.md`).
- `POST /auth/register`/`POST /auth/login` (password-based) KHÔNG nằm trong scope plan này.
- Liên quan FE: `my-expo-app/plans/260702-facebook-login-button/` — component `FacebookLoginButton` đã login thành công trên device, hiện chưa gọi backend. Cần 1 phase FE riêng để wire vào `/auth/facebook` sau khi backend này xong (ngoài scope plan này).
