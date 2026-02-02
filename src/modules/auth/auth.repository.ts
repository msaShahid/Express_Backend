import { prisma } from '../../prisma/client.js';
import type { User, RefreshToken } from '../../../generated/prisma/index.js';
import { logger } from '@/utils/logger.js';

export class AuthRepository {

  static async createUser(data: {
    name: string;
    email: string;
    password: string;
    role?: 'USER' | 'ADMIN';
  }): Promise<User> {
    try {
      return await prisma.user.create({
        data: {
          ...data,
          status: 'ACTIVE',
          emailVerified: false,
          failedLoginAttempts: 0,
        },
      });
    } catch (error) {
      logger.error('Failed to create user', {
        email: data.email,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  static async findUserById(id: string): Promise<User | null> {
    try {
      return await prisma.user.findUnique({
        where: { id },
      });
    } catch (error) {
      logger.error('Failed to find user by ID', { userId: id, error });
      return null;
    }
  }

  static async findUserByEmail(email: string): Promise<User | null> {
    try {
      return await prisma.user.findUnique({
        where: { email: email.toLowerCase() },
      });
    } catch (error) {
      logger.error('Failed to find user by email', { email, error });
      return null;
    }
  }

  static async updateLastLogin(userId: string): Promise<void> {
    try {
      await prisma.user.update({
        where: { id: userId },
        data: {
          lastLoginAt: new Date(),
        },
      });
    } catch (error) {
      logger.error('Failed to update last login', { userId, error });
    }
  }

  static async incrementFailedLoginAttempts(userId: string): Promise<void> {
    try {
      await prisma.user.update({
        where: { id: userId },
        data: {
          failedLoginAttempts: { increment: 1 },
          lastFailedLogin: new Date(),
        },
      });
    } catch (error) {
      logger.error('Failed to increment login attempts', { userId, error });
    }
  }

  static async resetFailedLoginAttempts(userId: string): Promise<void> {
    try {
      await prisma.user.update({
        where: { id: userId },
        data: {
          failedLoginAttempts: 0,
          lastFailedLogin: null,
          lockedUntil: null,
          status: 'ACTIVE',
        },
      });
    } catch (error) {
      logger.error('Failed to reset login attempts', { userId, error });
    }
  }

  static async lockAccount(userId: string, until: Date): Promise<void> {
    try {
      await prisma.user.update({
        where: { id: userId },
        data: {
          lockedUntil: until,
          status: 'LOCKED',
        },
      });
      logger.warn('Account locked', { userId, until });
    } catch (error) {
      logger.error('Failed to lock account', { userId, error });
    }
  }

  static async saveRefreshToken(
    userId: string,
    token: string,
    sessionId: string,
    expiresAt: Date,
    ipAddress?: string | null,
    userAgent?: string | null
  ): Promise<void> {
    try {
      await prisma.refreshToken.upsert({
        where: {
          userId_sessionId: {
            userId,
            sessionId,
          },
        },
        create: {
          userId,
          token,
          sessionId,
          expiresAt,
          ipAddress,
          userAgent,
          revoked: false,
        },
        update: {
          token,
          expiresAt,
          ipAddress,
          userAgent,
          revoked: false,
        },
      });
    } catch (error) {
      logger.error('Failed to save refresh token', { userId, error });
      throw error;
    }
  }


  static async findRefreshToken(token: string) {
    try {
      return await prisma.refreshToken.findUnique({
        where: { token },
        include: { user: true },
      });
    } catch (error) {
      logger.error('Failed to find refresh token', { error });
      return null;
    }
  }

  static async revokeRefreshToken(token: string): Promise<void> {
    try {
      await prisma.refreshToken.update({
        where: { token },
        data: {
          revoked: true,
          revokedAt: new Date(),
        },
      });
    } catch (error) {
      logger.error('Failed to revoke refresh token', { error });
    }
  }

  static async revokeUserSessions(
    userId: string,
    sessionId?: string
  ): Promise<void> {
    try {
      if (sessionId) {
        // Revoke specific session
        await prisma.refreshToken.updateMany({
          where: { userId, sessionId },
          data: {
            revoked: true,
            revokedAt: new Date(),
          },
        });
      } else {
        // Revoke all sessions
        await prisma.refreshToken.updateMany({
          where: { userId },
          data: {
            revoked: true,
            revokedAt: new Date(),
          },
        });
      }
    } catch (error) {
      logger.error('Failed to revoke user sessions', { userId, error });
    }
  }

  static async cleanupExpiredTokens(): Promise<void> {
    try {
      const deleted = await prisma.refreshToken.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            {
              revoked: true,
              revokedAt: {
                lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
              },
            },
          ],
        },
      });
      logger.info('Cleaned up expired tokens', { count: deleted.count });
    } catch (error) {
      logger.error('Failed to cleanup expired tokens', { error });
    }
  }
}