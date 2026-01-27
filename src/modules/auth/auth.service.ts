import { Request } from "express";
import { AuthRepository } from "./auth.repository.js";
import { LoginDto, RegisterDto, AuthResponse } from "./auth.types.js";
import {signAccessToken, signRefreshToken, verifyRefreshToken, } from "./utils/jwt.js";
import { compareHash, hashPassword, hashToken } from "./utils/password.js";
import { AuthErrors } from "./auth.errors.js";
import { generateSessionId } from "./utils/session.js";
import { getRequestMeta } from "./utils/request-meta.js";

export class AuthService {

  static async register(dto: RegisterDto, req: Request): Promise<AuthResponse> {
    const existingUser = await AuthRepository.findUserByEmail(dto.email);
    if (existingUser) throw AuthErrors.EMAIL_EXISTS();

    const password = await hashPassword(dto.password);

    const user = await AuthRepository.createUser({
      name: dto.name,
      email: dto.email,
      password,
      role: dto.role,
    });

    const sessionId = generateSessionId();
    const meta = getRequestMeta(req);

    return this.issueTokens(user, sessionId, meta);
  }

  static async login(dto: LoginDto, req: Request): Promise<AuthResponse> {
    const user = await AuthRepository.findUserByEmail(dto.email);
    if (!user) throw AuthErrors.INVALID_CREDENTIALS();

    if (!user.isActive) throw AuthErrors.USER_INACTIVE();

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw AuthErrors.ACCOUNT_LOCKED(user.lockedUntil);
    }

    const valid = await compareHash(dto.password, user.password);
    if (!valid) {
      await this.handleFailedLogin(user);
      throw AuthErrors.INVALID_CREDENTIALS();
    }

    await AuthRepository.resetFailedAttempts(user.id);

    const sessionId = generateSessionId();
    const meta = getRequestMeta(req);

    return this.issueTokens(user, sessionId, meta);
  }

  static async refresh(refreshToken: string): Promise<AuthResponse> {
    let payload: { userId: string; sessionId: string };

    try {
      payload = verifyRefreshToken(refreshToken) as {
        userId: string;
        sessionId: string;
      };
    } catch {
      throw AuthErrors.INVALID_REFRESH_TOKEN();
    }

    const token = await AuthRepository.findRefreshToken(
      payload.userId,
      payload.sessionId
    );

    // THEFT DETECTION
    if (!token || token.revokedAt || token.expiresAt < new Date()) {
      await AuthRepository.deleteAllRefreshTokens(payload.userId);
      throw AuthErrors.INVALID_REFRESH_TOKEN();
    }

    const valid = await compareHash(refreshToken, token.tokenHash);
    if (!valid) {
      await AuthRepository.deleteAllRefreshTokens(payload.userId);
      throw AuthErrors.INVALID_REFRESH_TOKEN();
    }

    await AuthRepository.revokeRefreshToken(token.id);

    const user = await AuthRepository.findUserById(payload.userId);
    if (!user) throw AuthErrors.USER_NOT_FOUND();

    return this.issueTokens(user, payload.sessionId, {
      ipAddress: token.ipAddress,
      userAgent: token.userAgent,
    });
  }

  static async logout(userId: string, sessionId?: string) {
    if (sessionId) {
      await AuthRepository.revokeBySession(userId, sessionId);
    } else {
      await AuthRepository.deleteAllRefreshTokens(userId);
    }
  }

  private static async issueTokens(
    user: any,
    sessionId: string,
    meta: { ipAddress?: string | null; userAgent?: string | null }
  ): Promise<AuthResponse> {
    const accessToken = signAccessToken({
      userId: user.id,
      role: user.role,
    });

    const refreshToken = signRefreshToken({
      userId: user.id,
      sessionId,
    });

    await AuthRepository.createRefreshToken({
      userId: user.id,
      sessionId,
      tokenHash: await hashToken(refreshToken),
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        emailVerified: user.emailVerified,
        isActive: user.isActive,
        createdAt: user.createdAt,
      },
      accessToken,
      refreshToken,
    };
  }

  private static async handleFailedLogin(user: any) {
    const attempts = user.failedLoginAttempts + 1;

    if (attempts >= 5) {
      await AuthRepository.lockUser(
        user.id,
        new Date(Date.now() + 15 * 60 * 1000)
      );
    } else {
      await AuthRepository.incrementFailedAttempts(user.id);
    }
  }
}
