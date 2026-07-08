# Tổng kết: Public hoá workout-api + fix login app

_Ngày: 2026-07-08_

Mục tiêu ban đầu: đưa `workout-api` (đang chạy local) lên public để test trên nhiều thiết bị, rồi làm app Expo login được qua backend public.

---

## 1. Deploy backend `workout-api` lên Railway ✅

- **URL public**: `https://workoutapi-production-2ae6.up.railway.app`
- **Nền tảng**: Railway (PaaS) — đã cân nhắc và loại Vercel (Nest là long-running server, không hợp serverless).
- **Auto-deploy**: push lên nhánh `main` (GitHub `TranPhuc9898/workout_api`) → Railway tự build + deploy.
- **Build**: qua `Dockerfile` (node:22-slim). Đã chuyển Yarn PnP → `nodeLinker: node-modules` vì PnP làm Railway fail checksum.
- **CMD**: `yarn prisma migrate deploy && node dist/main`.
- **Env trên Railway**: `DATABASE_URL=${{Postgres.DATABASE_URL}}`, `JWT_SECRET`, `FACEBOOK_APP_ID`.
- **Database**: PostgreSQL trên Railway. Gói Trial ~1GB (đủ hàng triệu user); nâng Hobby = 5GB, Pro = tới 1TB.

**Gotchas đã fix trong lúc deploy:**
- YN0018 checksum → chuyển sang `node-modules` + `yarn install --immutable`.
- `PrismaConfigEnvError` → thiếu Postgres/env, đã tạo service + 3 biến.
- `MODULE_NOT_FOUND dist/main` → `tsconfig.build.json` phải exclude `prisma.config.ts`.

**Đã verify sống:** `GET /` → 200, `GET /auth/me` (no token) → 401, `POST /auth/facebook` (rỗng) → 400.

---

## 2. Trỏ app Expo (`my-expo-app`) sang backend Railway ✅

- `.env`: `EXPO_PUBLIC_API_URL=https://workoutapi-production-2ae6.up.railway.app` (trước là LAN IP `192.168.1.35:3000`).
- Gỡ `.env` khỏi `.gitignore` và commit (chỉ chứa `EXPO_PUBLIC_API_URL` — biến public, không phải secret) → để EAS Build / Xcode archive đọc được URL.
- Commit + push lên branch `feature/sdk-native-option-menu`.

**Lý do quan trọng:** `EXPO_PUBLIC_*` được nhúng cứng vào bundle **lúc build/start**, không đọc runtime. Đổi `.env` xong phải build lại (hoặc `expo start --clear`) thì app mới dùng URL mới.

---

## 3. Fix Facebook login mismatch (nguyên nhân lỗi 400) ✅

**Triệu chứng:** sau khi trỏ sang Railway, login báo `400`.

**Root cause:** app và backend dùng 2 kiểu Facebook login khác nhau:
- **Backend** (`facebook-auth.service.ts`) dùng **Facebook Limited Login (OIDC)** — verify một JWT bằng Facebook JWKS, DTO đòi field `identityToken`.
- **App** (cũ) dùng **Graph login** — gửi field `accessToken` (Graph token). → ValidationPipe reject → 400.
- Trước đây login được vì app trỏ backend **local** (bản cũ nhận accessToken); backend Railway đã lên chuẩn OIDC.

**Đã sửa (app, iOS):**
- `facebook-login-button.tsx`: dùng `AuthenticationToken.getAuthenticationTokenIOS()` (Limited Login) thay `AccessToken`, gửi `{ identityToken }`.
- `link-confirm-sheet.tsx`: prop + body đổi `accessToken` → `identityToken` (khớp `/auth/facebook/link-confirm`).
- `npx tsc --noEmit` → **0 lỗi**.

> Lưu ý: Limited Login qua `getAuthenticationTokenIOS()` là **iOS-only**. Android cần xử lý riêng sau.

---

## Trạng thái hiện tại

| Thành phần | Trạng thái |
|---|---|
| Backend Railway | ✅ Live, verified, **không cần làm gì thêm** |
| Database Postgres | ✅ Online, migrations đã chạy |
| App `.env` → Railway URL | ✅ Đã đổi + commit |
| Fix login OIDC | ✅ Code xong, typecheck sạch |

## Việc còn lại (của anh)

1. Trong Xcode: **Clean Build Folder (⇧⌘K)** để bung cache URL/bundle cũ.
2. **Archive lại** (Release) → bundle mới có cả URL Railway + fix login.
3. Cài bản mới lên máy → thử login Facebook → phải vào được.

_Backend Railway **không cần** deploy lại — lần này chỉ sửa app._
