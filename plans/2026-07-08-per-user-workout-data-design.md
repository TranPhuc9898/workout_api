# Thiết kế: Data bài tập riêng theo từng user (per-user workout data)

_Ngày: 2026-07-08 · Trạng thái: PHÂN TÍCH — chưa chốt scope_

## Nhu cầu

Mỗi user đăng nhập chỉ thấy data bài tập của riêng mình — "thằng A bài tập khác thằng B".

**Đính chính quan trọng:** KHÔNG tạo 1 bảng riêng cho mỗi user (anti-pattern). Dùng **1 bảng chung + cột `userId`** (quan hệ One-to-Many: 1 User → nhiều bản ghi). Đăng nhập là A → query `WHERE userId = A`. Cùng bảng, mỗi người thấy data riêng. Backend đã có `JwtAuthGuard` cấp `userId` sẵn.

## Hiện trạng data trong app `my-expo-app` (đã scout)

3 tầng:

| Tầng | Nguồn hiện tại | Chung / Riêng |
|---|---|---|
| **1. Catalog bài tập** | `SEED_EXERCISES` + `gym-dataset.json` (~83k dòng, ExerciseDB) — bundle cứng trong app | **CHUNG** (giữ static, không cần server) |
| **2. Favourites + Custom** | `src/features/exercises/store.ts` — zustand **thuần RAM, KHÔNG persist** | **RIÊNG / user** |
| **3. History (buổi tập)** | `Session` type — mock/local | **RIÊNG / user** |

**Shape `Exercise`** (`src/features/exercises/types.ts`): `id, name, eq, cat(MuscleCat), sets, reps, load, custom?, gifUrl?, videoUrl?, instructions?...`

**Shape `Session`** (`history/SessionTimeline/types.ts`): `id, dateLabel, name, lbs, reps, score?, pr?`

## 🔴 Vấn đề cốt lõi

`useExerciseStore` là zustand **không có persist** → favourites + bài tự tạo của user **mất mỗi lần tắt app**, chưa gắn user, chưa lên server. Đây là thứ cần fix, KHÔNG phải catalog.

## Trả lời "A khác B làm sao"

A và B **dùng chung** thư viện 83k bài (static). Khác nhau chỉ ở: **fav nào / custom nào / đã tập buổi nào** → data gắn `userId`, backend lọc theo user. Cùng bảng, khác `WHERE`.

## Hướng đề xuất

Đưa tầng 2 + 3 lên backend Railway, gắn `userId`, persist thật. App đổi từ zustand-RAM sang gọi API.

```
Backend (workout-api / Railway)          App (my-expo-app)
├─ model Favourite      {userId, exId}  → store gọi API thay RAM
├─ model CustomExercise {userId, ...}   → add-exercise POST server
└─ model WorkoutSession {userId, ...}   → history đọc từ server
```

Mỗi model theo pattern có sẵn: controller + service + DTO + `JwtAuthGuard` (tự lọc `req.user.id`).

## Quyết định CÒN MỞ (chờ user chốt)

Làm mảng nào trước (khuyên làm từng mảng, đơn giản → phức tạp):
1. **Favourites** — đơn giản nhất (`userId` + `exerciseId`), học pattern nhanh.
2. **Custom exercises** — user tự tạo bài, lưu server.
3. **History / buổi tập** — phức tạp nhất (log sets/reps/kg theo ngày).

→ Chốt xong 1 mảng thì mới sang `/ck:plan` để dựng schema + API cụ thể.

## Ràng buộc / lưu ý

- Catalog 83k bài: giữ static bundle, KHÔNG nhồi lên Postgres (read-only reference, tốn DB vô ích).
- Custom exercise phải tham chiếu được về catalog khi log buổi tập (exerciseId có thể là id catalog hoặc id custom).
- Backend Railway đang chạy; thêm model = thêm migration Prisma + `migrate deploy` (Dockerfile CMD đã có sẵn).
