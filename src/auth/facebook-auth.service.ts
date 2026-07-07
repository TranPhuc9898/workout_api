import {
  Injectable,
  Logger,
  OnModuleInit,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createRemoteJWKSet, errors as joseErrors, jwtVerify } from 'jose';
import { FacebookProfile } from './interfaces/facebook-profile.interface';

const FACEBOOK_JWKS_URL = 'https://www.facebook.com/.well-known/oauth/openid/jwks/';
const FACEBOOK_ISSUER = 'https://www.facebook.com';

const JWKS = createRemoteJWKSet(new URL(FACEBOOK_JWKS_URL));

@Injectable()
export class FacebookAuthService implements OnModuleInit {
  private readonly logger = new Logger(FacebookAuthService.name);
  private facebookAppId: string;

  constructor(private readonly configService: ConfigService) {}

  onModuleInit() {
    const appId = this.configService.get<string>('FACEBOOK_APP_ID');
    if (!appId) {
      throw new Error('FACEBOOK_APP_ID not configured');
    }
    this.facebookAppId = appId;
  }

  async verifyIdentityToken(identityToken: string): Promise<FacebookProfile> {
    let payload;
    try {
      ({ payload } = await jwtVerify(identityToken, JWKS, {
        issuer: FACEBOOK_ISSUER,
        audience: this.facebookAppId,
        algorithms: ['RS256'],
      }));
    } catch (err) {
      if (err instanceof joseErrors.JOSEError) {
        throw new UnauthorizedException('Invalid Facebook token');
      }
      this.logger.error('Facebook JWKS verification failed unexpectedly', err as Error);
      throw new ServiceUnavailableException('Facebook verification temporarily unavailable');
    }

    return {
      facebookId: payload.sub as string,
      name: (payload.name as string) ?? null,
      email: (payload.email as string) ?? null,
      avatarUrl: (payload.picture as string) ?? null,
    };
  }
}
