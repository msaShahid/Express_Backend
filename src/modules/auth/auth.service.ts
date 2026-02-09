import { Request } from 'express';
import { AuthRepository } from './auth.repository.js';
import { AuthErrors } from './auth.errors.js';
import { RegisterDto, LoginDto, ChangePasswordDto, ResetPasswordDto, ForgotPasswordDto } from './auth.schemas.js';
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
import { EmailService } from '@/utils/email.js';
import { generateResetToken, getResetTokenExpiry, hashResetToken } from './utils/reset-token.js';

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

  /**
 * Request password reset - sends email with reset link
 */
  static async forgotPassword(
    dto: ForgotPasswordDto,
    req: Request
  ): Promise<{ message: string }> {
    const meta = getRequestMeta(req);

    logger.info('Password reset requested', {
      email: dto.email,
      ipAddress: meta.ipAddress,
    });

    const user = await AuthRepository.findUserByEmail(dto.email);

    // Always return success to prevent email enumeration
    if (!user) {
      logger.warn('Password reset requested for non-existent email', {
        email: dto.email,
        ipAddress: meta.ipAddress,
      });

      // Still log the attempt but don't reveal user doesn't exist
      await AuditLogger.logFailure(AuditAction.PASSWORD_RESET_REQUESTED, {
        email: dto.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'User not found' },
      });

      // Return success anyway to prevent email enumeration
      return {
        message: 'If your email is registered, you will receive a password reset link.',
      };
    }

    // Check if account is active
    if (user.status !== 'ACTIVE') {
      logger.warn('Password reset requested for inactive account', {
        userId: user.id,
        email: dto.email,
        status: user.status,
      });

      await AuditLogger.logFailure(AuditAction.PASSWORD_RESET_REQUESTED, {
        userId: user.id,
        email: dto.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Account not active', status: user.status },
      });

      return {
        message: 'If your email is registered, you will receive a password reset link.',
      };
    }

    // Rate limiting: max 3 requests per hour
    const recentRequests = await AuthRepository.countRecentResetRequests(
      user.id,
      60
    );

    if (recentRequests >= 3) {
      logger.warn('Too many password reset requests', {
        userId: user.id,
        email: dto.email,
        count: recentRequests,
      });

      await AuditLogger.logFailure(AuditAction.PASSWORD_RESET_REQUESTED, {
        userId: user.id,
        email: dto.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Rate limit exceeded', count: recentRequests },
      });

      throw AuthErrors.RATE_LIMIT_RESET();
    }

    // Generate reset token
    const plainToken = generateResetToken();
    const hashedToken = hashResetToken(plainToken);
    const expiresAt = getResetTokenExpiry();

    // Save token to database
    await AuthRepository.createPasswordResetToken(
      user.id,
      hashedToken,
      expiresAt,
      meta.ipAddress,
      meta.userAgent
    );

    // Send email
    const emailSent = await EmailService.sendPasswordResetEmail(
      user.email,
      user.name,
      plainToken
    );

    if (!emailSent) {
      logger.error('Failed to send password reset email', {
        userId: user.id,
        email: user.email,
      });

      await AuditLogger.logFailure(AuditAction.PASSWORD_RESET_REQUESTED, {
        userId: user.id,
        email: user.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Email sending failed' },
      });

      throw new Error('Failed to send password reset email');
    }

    logger.info('Password reset email sent', {
      userId: user.id,
      email: user.email,
      ipAddress: meta.ipAddress,
    });

    await AuditLogger.logSuccess(AuditAction.PASSWORD_RESET_REQUESTED, {
      userId: user.id,
      email: user.email,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
    });

    return {
      message: 'If your email is registered, you will receive a password reset link.',
    };
  }

  /**
   * Reset password using token from email
   */
  static async resetPassword(
    dto: ResetPasswordDto,
    req: Request
  ): Promise<{ message: string }> {
    const meta = getRequestMeta(req);

    logger.info('Password reset attempt', {
      ipAddress: meta.ipAddress,
    });

    // Hash the provided token to match database
    const hashedToken = hashResetToken(dto.token);

    // Find reset token
    const resetToken = await AuthRepository.findPasswordResetToken(hashedToken);

    if (!resetToken) {
      logger.warn('Invalid reset token used', {
        ipAddress: meta.ipAddress,
      });

      await AuditLogger.logFailure(AuditAction.PASSWORD_RESET_FAILED, {
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Token not found' },
      });

      throw AuthErrors.INVALID_RESET_TOKEN();
    }

    // Check if token is expired
    if (resetToken.expiresAt < new Date()) {
      logger.warn('Expired reset token used', {
        userId: resetToken.userId,
        ipAddress: meta.ipAddress,
      });

      await AuditLogger.logFailure(AuditAction.PASSWORD_RESET_FAILED, {
        userId: resetToken.userId,
        email: resetToken.user.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Token expired' },
      });

      throw AuthErrors.RESET_TOKEN_EXPIRED();
    }

    // Check if token has already been used
    if (resetToken.usedAt) {
      logger.warn('Already used reset token', {
        userId: resetToken.userId,
        ipAddress: meta.ipAddress,
      });

      await AuditLogger.logFailure(AuditAction.PASSWORD_RESET_FAILED, {
        userId: resetToken.userId,
        email: resetToken.user.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Token already used' },
      });

      throw AuthErrors.RESET_TOKEN_ALREADY_USED();
    }

    // Check if new password is same as old password
    const isSamePassword = await compareHash(
      dto.password,
      resetToken.user.password
    );

    if (isSamePassword) {
      logger.warn('User tried to reuse old password', {
        userId: resetToken.userId,
        email: resetToken.user.email,
      });

      await AuditLogger.logFailure(AuditAction.PASSWORD_RESET_FAILED, {
        userId: resetToken.userId,
        email: resetToken.user.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Same password as before' },
      });

      throw AuthErrors.SAME_PASSWORD();
    }

    // Hash new password
    const hashedPassword = await hashPassword(dto.password);

    // Update password
    await AuthRepository.updatePassword(resetToken.userId, hashedPassword);

    // Mark token as used
    await AuthRepository.markResetTokenAsUsed(hashedToken);

    // Revoke all user sessions for security
    await AuthRepository.revokeUserSessions(resetToken.userId);

    // Send confirmation email
    await EmailService.sendPasswordChangedEmail(
      resetToken.user.email,
      resetToken.user.name
    );

    logger.info('Password reset successful', {
      userId: resetToken.userId,
      email: resetToken.user.email,
      ipAddress: meta.ipAddress,
    });

    await AuditLogger.logSuccess(AuditAction.PASSWORD_RESET_COMPLETED, {
      userId: resetToken.userId,
      email: resetToken.user.email,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
    });

    return {
      message: 'Password reset successful. Please login with your new password.',
    };
  }

  /**
   * Change password for authenticated user
   */
  static async changePassword(
    userId: string,
    dto: ChangePasswordDto,
    req: Request
  ): Promise<{ message: string }> {
    const meta = getRequestMeta(req);

    logger.info('Password change attempt', {
      userId,
      ipAddress: meta.ipAddress,
    });

    const user = await AuthRepository.findUserById(userId);

    if (!user) {
      throw AuthErrors.USER_NOT_FOUND();
    }

    // Verify current password
    const isCurrentPasswordValid = await compareHash(
      dto.currentPassword,
      user.password
    );

    if (!isCurrentPasswordValid) {
      logger.warn('Password change failed - invalid current password', {
        userId,
        ipAddress: meta.ipAddress,
      });

      await AuditLogger.logFailure(AuditAction.PASSWORD_CHANGED, {
        userId,
        email: user.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Invalid current password' },
      });

      throw AuthErrors.INVALID_CREDENTIALS();
    }

    // Check if new password is same as current
    const isSamePassword = await compareHash(dto.newPassword, user.password);

    if (isSamePassword) {
      logger.warn('User tried to reuse current password', {
        userId,
        email: user.email,
      });

      await AuditLogger.logFailure(AuditAction.PASSWORD_CHANGED, {
        userId,
        email: user.email,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: 'Same as current password' },
      });

      throw AuthErrors.SAME_PASSWORD();
    }

    // Hash new password
    const hashedPassword = await hashPassword(dto.newPassword);

    // Update password
    await AuthRepository.updatePassword(userId, hashedPassword);

    // Revoke all other sessions for security (keep current session)
    // Note: This would require tracking current sessionId, for now revoke all
    await AuthRepository.revokeUserSessions(userId);

    // Send confirmation email
    await EmailService.sendPasswordChangedEmail(user.email, user.name);

    logger.info('Password changed successfully', {
      userId,
      email: user.email,
      ipAddress: meta.ipAddress,
    });

    await AuditLogger.logSuccess(AuditAction.PASSWORD_CHANGED, {
      userId,
      email: user.email,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
    });

    return {
      message: 'Password changed successfully. Please login again.',
    };
  }

}