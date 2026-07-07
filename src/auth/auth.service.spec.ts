import { Test } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import {
  BadRequestException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';

jest.mock('bcrypt');

const mockPrisma = {
  user: {
    findUnique: jest.fn(),
    findUniqueOrThrow: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  },
};

const FB_PROFILE = {
  facebookId: 'fb-1',
  name: 'Alice',
  email: 'alice@example.com',
  avatarUrl: 'http://pic',
};

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const moduleRef = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: JwtService, useValue: { sign: jest.fn().mockReturnValue('signed-jwt') } },
      ],
    }).compile();

    service = moduleRef.get(AuthService);
  });

  describe('findOrCreateFacebookUser', () => {
    it('refreshes name/avatarUrl from the FB profile when facebookId already matches', async () => {
      const existing = { id: 'u1', facebookId: 'fb-1', name: 'Old Name', avatarUrl: 'http://old-pic' };
      mockPrisma.user.findUnique.mockResolvedValueOnce(existing);
      const updated = { ...existing, name: FB_PROFILE.name, avatarUrl: FB_PROFILE.avatarUrl };
      mockPrisma.user.update.mockResolvedValueOnce(updated);

      const result = await service.findOrCreateFacebookUser(FB_PROFILE);

      expect(result).toBe(updated);
      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { id: existing.id },
        data: { name: FB_PROFILE.name, avatarUrl: FB_PROFILE.avatarUrl },
      });
      expect(mockPrisma.user.create).not.toHaveBeenCalled();
    });

    it('keeps existing name/avatarUrl when the FB profile returns null for them', async () => {
      const existing = { id: 'u1', facebookId: 'fb-1', name: 'Old Name', avatarUrl: 'http://old-pic' };
      mockPrisma.user.findUnique.mockResolvedValueOnce(existing);
      mockPrisma.user.update.mockResolvedValueOnce(existing);

      await service.findOrCreateFacebookUser({ ...FB_PROFILE, name: null, avatarUrl: null });

      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { id: existing.id },
        data: { name: existing.name, avatarUrl: existing.avatarUrl },
      });
    });

    it('throws EMAIL_LINK_REQUIRED when the email belongs to another user', async () => {
      mockPrisma.user.findUnique
        .mockResolvedValueOnce(null) // by facebookId
        .mockResolvedValueOnce({ id: 'u2', email: FB_PROFILE.email }); // by email

      await expect(service.findOrCreateFacebookUser(FB_PROFILE)).rejects.toMatchObject({
        response: { code: 'EMAIL_LINK_REQUIRED', email: FB_PROFILE.email },
      });
      expect(mockPrisma.user.create).not.toHaveBeenCalled();
    });

    it('creates a new user when nothing matches', async () => {
      mockPrisma.user.findUnique.mockResolvedValueOnce(null).mockResolvedValueOnce(null);
      const created = { id: 'u3', ...FB_PROFILE };
      mockPrisma.user.create.mockResolvedValueOnce(created);

      const result = await service.findOrCreateFacebookUser(FB_PROFILE);

      expect(result).toBe(created);
      expect(mockPrisma.user.create).toHaveBeenCalledWith({
        data: {
          facebookId: FB_PROFILE.facebookId,
          email: FB_PROFILE.email,
          name: FB_PROFILE.name,
          avatarUrl: FB_PROFILE.avatarUrl,
          passwordHash: null,
        },
      });
    });
  });

  describe('linkFacebookAccount', () => {
    it('throws BadRequestException when the Facebook profile has no email', async () => {
      await expect(
        service.linkFacebookAccount({ ...FB_PROFILE, email: null }, 'pw'),
      ).rejects.toThrow(BadRequestException);
      expect(mockPrisma.user.findUnique).not.toHaveBeenCalled();
    });

    it('links the account when the password matches', async () => {
      const existing = {
        id: 'u1',
        email: FB_PROFILE.email,
        passwordHash: 'hash',
        facebookId: null,
        name: null,
        avatarUrl: null,
      };
      mockPrisma.user.findUnique.mockResolvedValueOnce(existing);
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
      const updated = { ...existing, facebookId: FB_PROFILE.facebookId };
      mockPrisma.user.update.mockResolvedValueOnce(updated);

      const result = await service.linkFacebookAccount(FB_PROFILE, 'correct-password');

      expect(result).toBe(updated);
      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { id: existing.id },
        data: { facebookId: FB_PROFILE.facebookId, name: FB_PROFILE.name, avatarUrl: FB_PROFILE.avatarUrl },
      });
    });

    it('throws UnauthorizedException when the password is wrong', async () => {
      const existing = { id: 'u1', email: FB_PROFILE.email, passwordHash: 'hash', facebookId: null };
      mockPrisma.user.findUnique.mockResolvedValueOnce(existing);
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

      await expect(service.linkFacebookAccount(FB_PROFILE, 'wrong-password')).rejects.toThrow(
        UnauthorizedException,
      );
      expect(mockPrisma.user.update).not.toHaveBeenCalled();
    });

    it('throws UnauthorizedException when passwordHash is null instead of crashing', async () => {
      const existing = { id: 'u1', email: FB_PROFILE.email, passwordHash: null, facebookId: null };
      mockPrisma.user.findUnique.mockResolvedValueOnce(existing);

      await expect(service.linkFacebookAccount(FB_PROFILE, 'any-password')).rejects.toThrow(
        UnauthorizedException,
      );
      expect(bcrypt.compare).not.toHaveBeenCalled();
    });

    it('throws ConflictException when the account is already linked to a different Facebook identity', async () => {
      const existing = {
        id: 'u1',
        email: FB_PROFILE.email,
        passwordHash: 'hash',
        facebookId: 'other-fb-id',
      };
      mockPrisma.user.findUnique.mockResolvedValueOnce(existing);

      await expect(service.linkFacebookAccount(FB_PROFILE, 'any-password')).rejects.toThrow(
        ConflictException,
      );
      expect(mockPrisma.user.update).not.toHaveBeenCalled();
    });
  });
});
