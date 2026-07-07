---
phase: 1
title: "Bootstrap Prisma+Postgres va Schema User"
status: pending
priority: P2
dependencies: []
---

# Phase 1: Bootstrap Prisma+Postgres va Schema User

## Overview

Repo hiện chỉ là `nest new` skeleton — chưa có Prisma/Postgres nào (roadmap B2/B3 chưa code). Phase này cài Prisma, dựng Postgres local (docker-compose), tạo `PrismaModule`/`PrismaService`, rồi định nghĩa thẳng model `User` bản cuối (facebookId/name/avatarUrl + email/passwordHash optional) — không phải migration từ 1 model B4 cũ, vì B4 chưa tồn tại.

## Requirements

- `facebookId` phải unique để tránh 2 record cùng 1 Facebook account.
- Tầng application (không phải DB constraint) phải đảm bảo mỗi user có ít nhất `passwordHash` HOẶC `facebookId` — Prisma không tự enforce "at least one of N columns".
- `PrismaService` dùng global `omit: { user: { passwordHash: true } }` — `passwordHash` không được leak vào response/JWT ở bất kỳ query nào, override cục bộ (`omit: { passwordHash: false }`) chỉ ở chỗ thật sự cần so bcrypt (Phase 3: `linkFacebookAccount`).
- Postgres local qua Docker — không cài Postgres native lên máy.

## Architecture

`schema.prisma` — model `User` (bản cuối, tạo thẳng, không qua bước migrate-từ-required):

```prisma
model User {
  id           String   @id @default(uuid())
  email        String?  @unique
  passwordHash String?
  facebookId   String?  @unique
  name         String?
  avatarUrl    String?
  createdAt    DateTime @default(now())
}
```

`PrismaService`:
```typescript
export class PrismaService extends PrismaClient implements OnModuleInit {
  constructor() {
    super({ omit: { user: { passwordHash: true } } });
  }
  async onModuleInit() { await this.$connect(); }
}
```

`docker-compose.yml` (root, dev only): 1 service `postgres:16`, port map `5432:5432`, volume named để giữ data giữa các lần `docker compose down`/`up`, **`healthcheck`** (`pg_isready -U postgres`, interval 2s) để Phase này và Phase 4 không migrate/connect trước khi Postgres sẵn sàng nhận connection *(red-team 260703, Failure Mode Analyst H2)*.

## Related Code Files

- Create: `docker-compose.yml` — Postgres local dev (có `healthcheck`)
- Create: `.env` (không commit) + `.env.example` — thêm `DATABASE_URL=postgresql://...`
- Create: `prisma/schema.prisma` — datasource + model `User`
- Create: `src/prisma/prisma.module.ts`, `src/prisma/prisma.service.ts`
- Modify: `src/app.module.ts` — import `PrismaModule`
- Modify: `.gitignore` — thêm `.env` **và `.env.test`** nếu chưa có (repo hiện chỉ ignore `.env.test.local`, không ignore `.env.test` — sẽ dùng ở Phase 4) *(red-team 260703, Security Adversary H4 + Failure Mode Analyst, tự verify: `.gitignore` hiện tại thiếu dòng `.env.test`)*

## Implementation Steps

0. **Precondition:** verify `docker --version` && `docker info` chạy được. Máy dev hiện tại (2026-07-03) **chưa cài Docker** — nếu thiếu, cài Docker Desktop trước khi tiếp tục; không có fallback Postgres native cho phase này *(red-team 260703, Assumption Destroyer C2, tự verify: `which docker` → not found)*.
1. `yarn add prisma @prisma/client` (repo chỉ có `yarn.lock`, không dùng `npm`/`pnpm` để tránh lockfile lẫn lộn — *red-team 260703, M4*).
2. `npx prisma init` → sinh `prisma/schema.prisma` + `.env` mẫu.
3. Viết `docker-compose.yml` Postgres 16 (kèm `healthcheck`), `docker compose up -d`.
4. Set `DATABASE_URL` trong `.env` trỏ vào Postgres local vừa lên.
5. Sửa `prisma/schema.prisma` theo Architecture (model `User` bản cuối).
6. Đợi container `healthy` (`docker compose ps` hoặc `depends_on: condition: service_healthy` nếu có service khác), rồi `npx prisma migrate dev --name init` — migration đầu tiên của repo.
7. Tạo `PrismaModule`/`PrismaService` theo Architecture, import vào `AppModule`.
8. Verify `.env` **và `.env.test`** đã bị `.gitignore` (repo chưa từng có `.env` — double-check cả 2 dòng tồn tại, không chỉ `.env*.local`).

## Success Criteria

- [ ] `docker --version` && `docker info` chạy được trước khi bắt đầu (nếu fail: dừng, cài Docker Desktop trước).
- [ ] `docker compose up -d` chạy Postgres local thành công, container báo `healthy`.
- [ ] `npx prisma migrate dev --name init` chạy xong không lỗi, tạo bảng `User` với đủ 6 cột.
- [ ] `npx prisma studio` hiển thị bảng `User` đúng schema.
- [ ] `npx tsc --noEmit` (hoặc `npm run build`) pass sau khi Prisma Client generate type `email: string | null`.
- [ ] `git status` không show `.env` (chỉ `.env.example`).
- [ ] `git check-ignore .env .env.test` cả 2 đều được `.gitignore` match.

## Risk Assessment

- **Risk:** Chạy `migrate dev` nhắm nhầm vào DB không phải local (nếu sau này thêm `.env.test`/staging).
  **Mitigation:** Chỉ dùng `migrate dev` cho local; mọi môi trường shared khác dùng `migrate deploy` — nhắc lại rõ ở Phase 4 (setup DB test). Phase 4 dùng `dotenv-cli` load `.env.test` để chính `DATABASE_URL` trỏ đúng DB test, không dùng biến `DATABASE_URL_TEST` riêng (Prisma không tự đọc biến đó) *(red-team 260703, Failure Mode Analyst C4)*.
- **Risk:** Thiếu constraint "phải có passwordHash hoặc facebookId" ở DB → có thể tạo user rỗng cả 2 nếu code Phase 3 có bug.
  **Mitigation:** Guard ở tầng application (Phase 3: `findOrCreateFacebookUser` luôn set 1 trong 2), không cần DB CHECK constraint cho v1.
- **Risk (mới, red-team 260703):** Docker chưa cài trên máy dev hiện tại → toàn bộ phase này không chạy được cho tới khi cài.
  **Mitigation:** Step 0 precondition check ở trên; không tự động fallback sang Postgres native (giữ đúng quyết định "không cài Postgres native" đã chốt).
- **Risk (mới, red-team 260703):** `docker compose up -d` return ngay khi container start, không đợi Postgres nhận connection được → `migrate dev`/`$connect()` chạy sớm, race.
  **Mitigation:** `healthcheck` trong `docker-compose.yml` + đợi `healthy` trước khi migrate (step 6); `PrismaService.onModuleInit` nên có retry ngắn (2-3 lần, backoff) quanh `$connect()` thay vì gọi 1 lần rồi throw.
