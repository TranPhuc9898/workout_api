import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtAuthGuard } from './jwt-auth.guard';

const makeContext = (request: Record<string, unknown>) =>
  ({ switchToHttp: () => ({ getRequest: () => request }) }) as unknown as ExecutionContext;

describe('JwtAuthGuard', () => {
  const verifyAsync = jest.fn();
  const guard = new JwtAuthGuard({ verifyAsync } as unknown as JwtService);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('throws UnauthorizedException when the Authorization header is missing', async () => {
    await expect(guard.canActivate(makeContext({ headers: {} }))).rejects.toThrow(
      UnauthorizedException,
    );
    expect(verifyAsync).not.toHaveBeenCalled();
  });

  it('throws UnauthorizedException when the token fails verification', async () => {
    verifyAsync.mockRejectedValueOnce(new Error('jwt malformed'));

    await expect(
      guard.canActivate(makeContext({ headers: { authorization: 'Bearer garbage' } })),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('attaches user.sub to the request when the token is valid', async () => {
    verifyAsync.mockResolvedValueOnce({ sub: 'u1' });
    const request: Record<string, unknown> = { headers: { authorization: 'Bearer good' } };

    await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
    expect(request.user).toEqual({ sub: 'u1' });
  });
});
