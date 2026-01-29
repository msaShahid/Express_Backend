import { prisma } from "../../prisma/client.js";
import type { User, RefreshToken } from "../../../generated/prisma/index.js";

export class AuthRepository {

  static createUser(data: {
    name: string;
    email: string;
    password: string;
    role?: "USER" | "ADMIN";
  }): Promise<User> {
    return prisma.user.create({ data });
  }

  static findUserById(id: string) {
    return prisma.user.findUnique({ where: { id } });
  }

  static findUserByEmail(email: string) {
    return prisma.user.findUnique({ where: { email } });
  }

  static resetFailedAttempts(userId: string) {
    return prisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: 0, lastLoginAt: new Date() },
    });
  }

  // ---------- REFRESH TOKENS ----------

  static createRefreshToken(data: {
    userId: string;
    sessionId: string;
    tokenHash: string;
    expiresAt: Date;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<RefreshToken> {
    return prisma.refreshToken.create({ data });
  }

  static findRefreshToken(userId: string, sessionId: string) {
    return prisma.refreshToken.findUnique({
      where: { userId_sessionId: { userId, sessionId } },
    });
  }

  static rotateRefreshToken(data: {
    userId: string;
    sessionId: string;
    tokenHash: string;
    expiresAt: Date;
    ipAddress?: string | null;
    userAgent?: string | null;
  }) {
    return prisma.refreshToken.update({
      where: {
        userId_sessionId: {
          userId: data.userId,
          sessionId: data.sessionId,
        },
      },
      data: {
        tokenHash: data.tokenHash,
        expiresAt: data.expiresAt,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
        revokedAt: null,
      },
    });
  }

  static revokeBySession(userId: string, sessionId: string) {
    return prisma.refreshToken.updateMany({
      where: { userId, sessionId },
      data: { revokedAt: new Date() },
    });
  }

  static deleteAllRefreshTokens(userId: string) {
    return prisma.refreshToken.deleteMany({ where: { userId } });
  }
}
