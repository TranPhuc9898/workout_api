import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { FacebookAuthService } from './facebook-auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { FacebookLoginDto } from './dto/facebook-login.dto';
import { FacebookLinkConfirmDto } from './dto/facebook-link-confirm.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly facebookAuthService: FacebookAuthService,
  ) {}

  @Post('facebook')
  @HttpCode(HttpStatus.OK)
  async loginWithFacebook(@Body() dto: FacebookLoginDto) {
    const profile = await this.facebookAuthService.verifyIdentityToken(dto.identityToken);
    const user = await this.authService.findOrCreateFacebookUser(profile);
    return {
      accessToken: this.authService.signToken(user.id),
      user: this.authService.toPublicUser(user),
    };
  }

  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @Post('facebook/link-confirm')
  @HttpCode(HttpStatus.OK)
  async confirmFacebookLink(@Body() dto: FacebookLinkConfirmDto) {
    const profile = await this.facebookAuthService.verifyIdentityToken(dto.identityToken);
    const user = await this.authService.linkFacebookAccount(profile, dto.password);
    return {
      accessToken: this.authService.signToken(user.id),
      user: this.authService.toPublicUser(user),
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async me(@Req() req: { user: { sub: string } }) {
    const user = await this.authService.getUserById(req.user.sub);
    // Token can outlive the row it points to (user deleted) — treat as unauthenticated.
    if (!user) throw new UnauthorizedException();
    return this.authService.toPublicUser(user);
  }
}
