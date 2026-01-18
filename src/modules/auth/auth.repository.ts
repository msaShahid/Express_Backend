import prisma from "../../prisma/client.js";
import type { User, RefreshToken } from "@prisma/client";


export class AuthRepository {

  static createUser(data: { email: string; passwordHash: string; role?: "USER" | "ADMIN"; }): Promise<User> {
    return prisma.user.create({
      data: {
        email: data.email,
        passwordHash: data.passwordHash,
        role: data.role || "USER",
      },
    });
  }

  static findUserById(id: string) {
    return prisma.user.findUnique({ where: { id } });
  }

  static lockUser(userId: string, until: Date) {
    return prisma.user.update({
      where: { id: userId },
      data: { lockedUntil: until },
    });
  }

  static findUserByEmail(email: string): Promise<User | null> {
    return prisma.user.findUnique({ where: { email } });
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

  static createRefreshToken(data: { userId: string; tokenHash: string; expiresAt: Date; }): Promise<RefreshToken> {
    return prisma.refreshToken.create({ data });
  }

  static deleteRefreshToken(id: string) {
    return prisma.refreshToken.delete({ where: { id } });
  }

  static findLatestRefreshToken(userId: string): Promise<RefreshToken | null> {
    return prisma.refreshToken.findFirst({
      where: { userId },
      orderBy: { createdAt: "desc" },
    });
  }

  static deleteAllRefreshTokens(userId: string) {
    return prisma.refreshToken.deleteMany({ where: { userId } });
  }


}
