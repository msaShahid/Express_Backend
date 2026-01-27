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

  static lockUser(userId: string, until: Date) {
    return prisma.user.update({
      where: { id: userId },
      data: { lockedUntil: until },
    });
  }

  static incrementFailedAttempts(userId: string) {
    return prisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: { increment: 1 } },
    });
  }

  static resetFailedAttempts(userId: string) {
    return prisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: 0, lastLoginAt: new Date() },
    });
  }

  // ---------------- REFRESH TOKENS ----------------

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

  static revokeRefreshToken(id: string) {
    return prisma.refreshToken.update({
      where: { id },
      data: { revokedAt: new Date() },
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
