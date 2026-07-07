import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Prisma } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { FacebookProfile } from './interfaces/facebook-profile.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  signToken(userId: string): string {
    return this.jwtService.sign({ sub: userId });
  }

  async findOrCreateFacebookUser(profile: FacebookProfile) {
    const byFbId = await this.prisma.user.findUnique({ where: { facebookId: profile.facebookId } });
    if (byFbId) {
      // FB CDN avatar URLs carry expiring signatures — refresh stored profile on every login.
      return this.prisma.user.update({
        where: { id: byFbId.id },
        data: {
          name: profile.name ?? byFbId.name,
          avatarUrl: profile.avatarUrl ?? byFbId.avatarUrl,
        },
      });
    }

    if (profile.email) {
      const byEmail = await this.prisma.user.findUnique({ where: { email: profile.email } });
      if (byEmail) {
        throw new ConflictException({ code: 'EMAIL_LINK_REQUIRED', email: profile.email });
      }
    }

    try {
      return await this.prisma.user.create({
        data: {
          facebookId: profile.facebookId,
          email: profile.email,
          name: profile.name,
          avatarUrl: profile.avatarUrl,
          passwordHash: null,
        },
      });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
        const target = (e.meta?.target as string[] | string | undefined) ?? [];
        const targets = Array.isArray(target) ? target : [target];
        if (targets.includes('facebookId')) {
          return this.prisma.user.findUniqueOrThrow({ where: { facebookId: profile.facebookId } });
        }
        if (targets.includes('email')) {
          throw new ConflictException({ code: 'EMAIL_LINK_REQUIRED', email: profile.email });
        }
      }
      throw e;
    }
  }

  async linkFacebookAccount(profile: FacebookProfile, password: string) {
    if (!profile.email) throw new BadRequestException('Facebook account has no email to link with');

    const user = await this.prisma.user.findUnique({
      where: { email: profile.email },
      omit: { passwordHash: false },
    });
    if (!user) throw new NotFoundException('No account found for this email');

    if (user.facebookId && user.facebookId !== profile.facebookId) {
      throw new ConflictException('Account already linked to a different Facebook identity');
    }

    if (!user.passwordHash || !(await bcrypt.compare(password, user.passwordHash))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    try {
      return await this.prisma.user.update({
        where: { id: user.id },
        data: {
          facebookId: profile.facebookId,
          name: user.name ?? profile.name,
          avatarUrl: user.avatarUrl ?? profile.avatarUrl,
        },
      });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
        throw new ConflictException('Account already linked to a different Facebook identity');
      }
      throw e;
    }
  }

  getUserById(id: string) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  toPublicUser(user: { id: string; name: string | null; email: string | null; avatarUrl: string | null }) {
    // Explicit pick, never spread — passwordHash/facebookId must not leak even if the schema grows.
    return { id: user.id, name: user.name, email: user.email, avatarUrl: user.avatarUrl };
  }
}
