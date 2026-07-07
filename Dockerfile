FROM node:22-slim
WORKDIR /app

# openssl cần cho Prisma
RUN corepack enable \
  && apt-get update -y \
  && apt-get install -y openssl \
  && rm -rf /var/lib/apt/lists/*

COPY . .

RUN yarn install --immutable
RUN DATABASE_URL="postgresql://u:p@localhost:5432/db" yarn prisma generate
RUN yarn build

CMD yarn prisma migrate deploy && node dist/main
