import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { errors as joseErrors, jwtVerify } from 'jose';
import { FacebookAuthService } from './facebook-auth.service';

// jose v6 ships ESM-only — requireActual can't load it under jest's CJS transform,
// so the error classes are faked here. instanceof still matches: the service imports
// the same mocked module.
jest.mock('jose', () => {
  class JOSEError extends Error {}
  class JWTExpired extends JOSEError {
    constructor(message: string, _payload: unknown) {
      super(message);
    }
  }
  class JWTClaimValidationFailed extends JOSEError {
    constructor(message: string, _payload: unknown, _claim?: string) {
      super(message);
    }
  }
  return {
    errors: { JOSEError, JWTExpired, JWTClaimValidationFailed },
    createRemoteJWKSet: jest.fn().mockReturnValue(jest.fn()),
    jwtVerify: jest.fn(),
  };
});

describe('FacebookAuthService', () => {
  let service: FacebookAuthService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const moduleRef = await Test.createTestingModule({
      providers: [
        FacebookAuthService,
        { provide: ConfigService, useValue: { get: jest.fn().mockReturnValue('test-app-id') } },
      ],
    }).compile();

    service = moduleRef.get(FacebookAuthService);
    await moduleRef.init();
  });

  it('returns full profile when token is valid', async () => {
    (jwtVerify as jest.Mock).mockResolvedValue({
      payload: { sub: 'fb-123', name: 'Alice', email: 'alice@example.com', picture: 'http://pic' },
    });

    await expect(service.verifyIdentityToken('token')).resolves.toEqual({
      facebookId: 'fb-123',
      name: 'Alice',
      email: 'alice@example.com',
      avatarUrl: 'http://pic',
    });
  });

  it('returns null email when the claim is missing', async () => {
    (jwtVerify as jest.Mock).mockResolvedValue({
      payload: { sub: 'fb-123', name: 'Alice' },
    });

    const profile = await service.verifyIdentityToken('token');
    expect(profile.email).toBeNull();
  });

  it('throws UnauthorizedException when the token is expired', async () => {
    (jwtVerify as jest.Mock).mockRejectedValue(new joseErrors.JWTExpired('expired', {}));
    await expect(service.verifyIdentityToken('token')).rejects.toThrow(UnauthorizedException);
  });

  it('throws UnauthorizedException when the audience does not match', async () => {
    (jwtVerify as jest.Mock).mockRejectedValue(
      new joseErrors.JWTClaimValidationFailed('aud mismatch', {}, 'aud'),
    );
    await expect(service.verifyIdentityToken('token')).rejects.toThrow(UnauthorizedException);
  });

  it('throws ServiceUnavailableException for non-jose errors', async () => {
    (jwtVerify as jest.Mock).mockRejectedValue(new Error('network down'));
    await expect(service.verifyIdentityToken('token')).rejects.toThrow(ServiceUnavailableException);
  });
});
