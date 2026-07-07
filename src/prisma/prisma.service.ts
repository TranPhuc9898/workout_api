import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '../generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';

const CONNECT_RETRIES = 3;
const CONNECT_RETRY_DELAY_MS = 500;

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger(PrismaService.name);

  constructor() {
    const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });
    super({ adapter, omit: { user: { passwordHash: true } } });
  }

  async onModuleInit() {
    for (let attempt = 1; attempt <= CONNECT_RETRIES; attempt++) {
      try {
        await this.$connect();
        return;
      } catch (err) {
        if (attempt === CONNECT_RETRIES) throw err;
        this.logger.warn(`Postgres connect attempt ${attempt} failed, retrying...`);
        await new Promise((resolve) => setTimeout(resolve, attempt * CONNECT_RETRY_DELAY_MS));
      }
    }
  }
}
