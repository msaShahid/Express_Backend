import { Request } from "express";
import { AuthRepository } from "./auth.repository.js";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "./utils/jwt.js";
import { compareHash, hashPassword, hashToken } from "./utils/password.js";
import { AuthErrors } from "./auth.errors.js";
import { generateSessionId } from "./utils/session.js";
import { getRequestMeta } from "./utils/request-meta.js";
import { LoginDto, RegisterDto, AuthResponse, UserResponse } from "./auth.types.js";

export class AuthService {

  static async register(dto: RegisterDto, req: Request): Promise<AuthResponse> {
    const existing = await AuthRepository.findUserByEmail(dto.email);
    if (existing) throw AuthErrors.EMAIL_EXISTS();

    const user = await AuthRepository.createUser({
      name: dto.name,
      email: dto.email,
      password: await hashPassword(dto.password),
      role: dto.role,
    });

    return this.issueTokens(user, generateSessionId(), getRequestMeta(req));
  }

  static async login(dto: LoginDto, req: Request): Promise<AuthResponse> {
    const user = await AuthRepository.findUserByEmail(dto.email);
    if (!user) throw AuthErrors.INVALID_CREDENTIALS();

    const valid = await compareHash(dto.password, user.password);
    if (!valid) throw AuthErrors.INVALID_CREDENTIALS();

    await AuthRepository.resetFailedAttempts(user.id);

    return this.issueTokens(user, generateSessionId(), getRequestMeta(req));
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

    if (!token || token.revokedAt || token.expiresAt < new Date()) {
      await AuthRepository.deleteAllRefreshTokens(payload.userId);
      throw AuthErrors.INVALID_REFRESH_TOKEN();
    }

    const valid = await compareHash(refreshToken, token.tokenHash);
    if (!valid) {
      await AuthRepository.deleteAllRefreshTokens(payload.userId);
      throw AuthErrors.INVALID_REFRESH_TOKEN();
    }

    const user = await AuthRepository.findUserById(payload.userId);
    if (!user) throw AuthErrors.USER_NOT_FOUND();

    // ROTATE refresh token (UPDATE SAME ROW)
    const newRefreshToken = signRefreshToken({
      userId: user.id,
      sessionId: payload.sessionId,
    });

    await AuthRepository.rotateRefreshToken({
      userId: user.id,
      sessionId: payload.sessionId,
      tokenHash: await hashToken(newRefreshToken),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ipAddress: token.ipAddress,
      userAgent: token.userAgent,
    });

    const accessToken = signAccessToken({
      userId: user.id,
      role: user.role,
      sessionId: payload.sessionId,
    });

    return {
      user: this.mapUser(user),
      accessToken,
      refreshToken: newRefreshToken,
    };
  }

  static async logout(userId: string, sessionId?: string) {
    if (sessionId) {
      await AuthRepository.revokeBySession(userId, sessionId);
    } else {
      await AuthRepository.deleteAllRefreshTokens(userId);
    }
  }

  // ---------------- PRIVATE ----------------

  private static async issueTokens(
    user: UserResponse,
    sessionId: string,
    meta: { ipAddress?: string | null; userAgent?: string | null }
  ): Promise<AuthResponse> {

    const accessToken = signAccessToken({
      userId: user.id,
      role: user.role,
      sessionId,
    });

    const refreshToken = signRefreshToken({
      userId: user.id,
      sessionId,
    });

    await AuthRepository.createRefreshToken({
      userId: user.id,
      sessionId,
      tokenHash: await hashToken(refreshToken),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
    });

    return {
      user: this.mapUser(user),
      accessToken,
      refreshToken,
    };
  }

  private static mapUser(user: UserResponse) {
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      failedLoginAttempts: user.failedLoginAttempts,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
      createdAt: user.createdAt,
    };
  }
}
