import { Request } from 'express';
import { AuthRepository } from './auth.repository.js';
import { AuthErrors } from './auth.errors.js';
import { RegisterDto, LoginDto } from './auth.schemas.js';
import { AuthResponse } from './auth.types.js';
import { hashPassword, compareHash } from './utils/password.js';
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  AccessTokenPayload,
  RefreshTokenPayload,
} from './utils/jwt.js';
import { generateSessionId } from './utils/session.js';
import { getRequestMeta } from './utils/request-meta.js';
import { logger } from '@/utils/logger.js';
import { AuditLogger, AuditAction } from '@/utils/audit-logger.js';

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MINUTES = 30;

export class AuthService {
  
  private static async issueTokens(
    user: any,
    sessionId: string,
    req: Request
  ): Promise<AuthResponse> {
    const meta = getRequestMeta(req);

    const accessPayload: AccessTokenPayload = {
      userId: user.id,
      role: user.role,
      sessionId,
    };

    const refreshPayload: RefreshTokenPayload = {
      userId: user.id,
      sessionId,
    };

    const accessToken = signAccessToken(accessPayload);
    const refreshToken = signRefreshToken(refreshPayload);

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await AuthRepository.saveRefreshToken(
      user.id,
      refreshToken,
      sessionId,
      expiresAt
    );

    logger.info('Tokens issued', {
      userId: user.id,
      sessionId,
      ipAddress: meta.ipAddress,
    });

    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      tokens: {
        accessToken,
        refreshToken,
      },
    };
  }

  static async register(dto: RegisterDto, req: Request): Promise<AuthResponse> {
    const meta = getRequestMeta(req);

    logger.info('Registration attempt', {
      email: dto.email,
      ipAddress: meta.ipAddress,
    });

    const existing = await AuthRepository.findUserByEmail(dto.email);
    if (existing) {
      logger.warn('Registration failed - email exists', {
        email: dto.email,
        ipAddress: meta.ipAddress,
      });

      await AuditLogger.logFailure(AuditAction.USER_REGISTERED, {
        email: dto.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Email already exists' },
      });

      throw AuthErrors.EMAIL_EXISTS();
    }

    const user = await AuthRepository.createUser({
      name: dto.name,
      email: dto.email,
      password: await hashPassword(dto.password),
      role: dto.role,
    });

    logger.info('User registered successfully', {
      userId: user.id,
      email: user.email,
      ipAddress: meta.ipAddress,
    });

    await AuditLogger.logSuccess(AuditAction.USER_REGISTERED, {
      userId: user.id,
      email: user.email,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
    });

    return this.issueTokens(user, generateSessionId(), req);
  }

  static async login(dto: LoginDto, req: Request): Promise<AuthResponse> {
    const meta = getRequestMeta(req);

    logger.info('Login attempt', {
      email: dto.email,
      ipAddress: meta.ipAddress,
    });

    const user = await AuthRepository.findUserByEmail(dto.email);

    if (!user) {
      logger.warn('Login failed - user not found', {
        email: dto.email,
        ipAddress: meta.ipAddress,
      });

      await AuditLogger.logFailure(AuditAction.LOGIN_FAILED, {
        email: dto.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'User not found' },
      });

      throw AuthErrors.INVALID_CREDENTIALS();
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      logger.warn('Login failed - account locked', {
        userId: user.id,
        email: dto.email,
        lockedUntil: user.lockedUntil,
      });

      throw AuthErrors.ACCOUNT_LOCKED(user.lockedUntil);
    }

    if (user.status === 'INACTIVE') {
      logger.warn('Login failed - account inactive', {
        userId: user.id,
        email: dto.email,
      });

      await AuditLogger.logFailure(AuditAction.LOGIN_FAILED, {
        userId: user.id,
        email: dto.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Account inactive' },
      });

      throw AuthErrors.USER_INACTIVE();
    }

    const isPasswordValid = await compareHash(dto.password, user.password);

    if (!isPasswordValid) {
      await AuthRepository.incrementFailedLoginAttempts(user.id);

      const attempts = user.failedLoginAttempts + 1;

      logger.warn('Login failed - invalid password', {
        userId: user.id,
        email: dto.email,
        attempts,
        ipAddress: meta.ipAddress,
      });

      await AuditLogger.logFailure(AuditAction.LOGIN_FAILED, {
        userId: user.id,
        email: dto.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Invalid password', attempts },
      });

      if (attempts >= MAX_FAILED_ATTEMPTS) {
        const lockUntil = new Date(
          Date.now() + LOCK_DURATION_MINUTES * 60 * 1000
        );
        await AuthRepository.lockAccount(user.id, lockUntil);

        logger.error('Account locked due to failed attempts', {
          userId: user.id,
          email: dto.email,
          attempts,
          lockUntil,
        });

        await AuditLogger.logSuccess(AuditAction.ACCOUNT_LOCKED, {
          userId: user.id,
          email: dto.email,
          ipAddress: meta.ipAddress,
          userAgent: meta.userAgent,
          metadata: { attempts, lockUntil },
        });

        throw AuthErrors.ACCOUNT_LOCKED(lockUntil);
      }

      throw AuthErrors.INVALID_CREDENTIALS();
    }

    await AuthRepository.resetFailedLoginAttempts(user.id);

    logger.info('Login successful', {
      userId: user.id,
      email: user.email,
      ipAddress: meta.ipAddress,
    });

    await AuditLogger.logSuccess(AuditAction.USER_LOGIN, {
      userId: user.id,
      email: user.email,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
    });

    return this.issueTokens(user, generateSessionId(), req);
  }

  static async refresh(refreshToken: string): Promise<AuthResponse> {
    logger.info('Token refresh attempt');

    let payload: RefreshTokenPayload;
    try {
      payload = verifyRefreshToken(refreshToken);
    } catch (error) {
      logger.warn('Invalid refresh token', { error });

      await AuditLogger.logFailure(AuditAction.TOKEN_REFRESHED, {
        metadata: { reason: 'Invalid token' },
      });

      throw AuthErrors.INVALID_REFRESH_TOKEN();
    }

    const tokenRecord = await AuthRepository.findRefreshToken(refreshToken);

    if (!tokenRecord || tokenRecord.revoked) {
      logger.warn('Refresh token not found or revoked', {
        userId: payload.userId,
      });

      await AuditLogger.logFailure(AuditAction.TOKEN_REFRESHED, {
        userId: payload.userId,
        metadata: { reason: 'Token revoked or not found' },
      });

      throw AuthErrors.INVALID_REFRESH_TOKEN();
    }

    if (tokenRecord.expiresAt < new Date()) {
      logger.warn('Refresh token expired', {
        userId: payload.userId,
        expiresAt: tokenRecord.expiresAt,
      });

      await AuditLogger.logFailure(AuditAction.TOKEN_REFRESHED, {
        userId: payload.userId,
        metadata: { reason: 'Token expired' },
      });

      throw AuthErrors.INVALID_REFRESH_TOKEN();
    }

    const user = await AuthRepository.findUserById(payload.userId);

    if (!user || user.status === 'INACTIVE') {
      logger.warn('User not found or inactive during token refresh', {
        userId: payload.userId,
      });

      throw AuthErrors.USER_NOT_FOUND();
    }

    await AuthRepository.revokeRefreshToken(refreshToken);

    logger.info('Token refreshed successfully', {
      userId: user.id,
      sessionId: payload.sessionId,
    });

    await AuditLogger.logSuccess(AuditAction.TOKEN_REFRESHED, {
      userId: user.id,
      email: user.email,
    });

    // Create a mock request for issueTokens
    const mockReq = {
      headers: {},
      socket: { remoteAddress: 'refresh' },
    } as Request;

    return this.issueTokens(user, payload.sessionId, mockReq);
  }

  static async logout(userId: string, sessionId?: string): Promise<void> {
    logger.info('Logout attempt', { userId, sessionId });

    await AuthRepository.revokeUserSessions(userId, sessionId);

    logger.info('Logout successful', {
      userId,
      sessionId,
      scope: sessionId ? 'single-session' : 'all-sessions',
    });

    await AuditLogger.logSuccess(AuditAction.USER_LOGOUT, {
      userId,
      metadata: { sessionId, scope: sessionId ? 'single' : 'all' },
    });
  }
}