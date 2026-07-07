---
type: contract-stub
plan: plans/260702-facebook-login-oauth
status: superseded
source: reports/research-260702-1706-critical-high-findings-resolution.md
---

# B4 Contract Stub — SUPERSEDED (2026-07-03)

Nội dung gốc file này (chữ ký `signToken`/`JwtAuthGuard`, guard `passwordHash` null trước `bcrypt.compare`, `PrismaService` global `omit`) mô tả những gì B4 (Auth JWT, làm riêng trước B7) phải cung cấp cho B7.

**Quyết định 2026-07-03 (Path 2 — vertical slice):** B7 không còn chờ B4 làm riêng. Toàn bộ nội dung ở trên đã gộp trực tiếp vào:
- `phase-01-schema-prisma-user.md` — `PrismaService` global `omit` config.
- `phase-03-auth-endpoint-va-account-linking.md` — `signToken`, `JwtAuthGuard`, guard `passwordHash` null trước `bcrypt.compare`.

File này giữ lại chỉ để làm lịch sử quyết định (repo chưa có git commit nào, xoá sẽ mất dấu vết). Không còn là "hợp đồng chờ B4" — nếu sau này build B4 (register/login) thật, cần đối chiếu ngược lại chữ ký đã thực tế implement ở Phase 3, không phải file này.
