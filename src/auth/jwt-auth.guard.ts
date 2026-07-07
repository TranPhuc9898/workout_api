import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

type RequestWithUser = Request & { user?: { sub: string } };

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const authHeader = request.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined;
    if (!token) throw new UnauthorizedException('Missing bearer token');

    try {
      const payload = await this.jwtService.verifyAsync<{ sub: string }>(token);
      request.user = { sub: payload.sub };
      return true;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}
